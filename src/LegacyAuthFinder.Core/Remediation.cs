namespace LegacyAuthFinder.Core;

/// <summary>Where the fix has to be made.</summary>
public enum FixTarget
{
    Client,
    Account,
    ServiceAccount,
    DomainControllers,
    DomainPolicy,
}

/// <summary>One thing to fix: a device, an account or a policy, with the concrete step and the evidence behind it.</summary>
public sealed class FixItem
{
    public int Rank { get; internal set; }
    public required LegacyKind Kind { get; init; }
    public required FixTarget TargetType { get; init; }
    public required string Target { get; init; }
    public required string Problem { get; init; }
    public required string Action { get; init; }
    public long Events { get; internal set; }
    public int Rows { get; internal set; }
    public DateTime FirstSeen { get; internal set; } = DateTime.MaxValue;
    public DateTime LastSeen { get; internal set; } = DateTime.MinValue;
    public SortedSet<string> Accounts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SortedSet<string> Clients { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SortedSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SortedSet<string> Computers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string KindLabel => Guidance.Label(Kind);

    public string TargetTypeText => TargetType switch
    {
        FixTarget.Client => "Client",
        FixTarget.Account => "Account",
        FixTarget.ServiceAccount => "Service account",
        FixTarget.DomainControllers => "Domain controllers",
        _ => "Domain policy",
    };

    public string AccountsText => List(Accounts);
    public string ClientsText => List(Clients);
    public string ServicesText => List(Services);
    public string ComputersText => List(Computers);

    public static string List(IReadOnlyCollection<string> items, int max = 8) => items.Count <= max
        ? string.Join(", ", items)
        : string.Join(", ", items.Take(max)) + $" and {items.Count - max} more";

    public bool Matches(IReadOnlyList<string> terms) => terms.All(t =>
        Target.Contains(t, StringComparison.OrdinalIgnoreCase)
        || Problem.Contains(t, StringComparison.OrdinalIgnoreCase)
        || KindLabel.Contains(t, StringComparison.OrdinalIgnoreCase)
        || TargetTypeText.Contains(t, StringComparison.OrdinalIgnoreCase)
        || Accounts.Any(a => a.Contains(t, StringComparison.OrdinalIgnoreCase))
        || Clients.Any(c => c.Contains(t, StringComparison.OrdinalIgnoreCase))
        || Services.Any(s => s.Contains(t, StringComparison.OrdinalIgnoreCase))
        || Computers.Any(c => c.Contains(t, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>
/// Turns the summary ("who uses what") into a fix list ("what to change where"). The rules follow how Kerberos picks
/// encryption types: the ticket is encrypted with the service account's key, the session key is the strongest type
/// both the client and the service support, and a TGT uses the account's own key.
/// </summary>
public static class Remediation
{
    private const string Unknown = "(not logged)";

    public static IReadOnlyList<FixItem> Build(IEnumerable<SummaryRow> rows)
    {
        var items = new Dictionary<(LegacyKind, FixTarget, string, string), FixItem>(new KeyComparer());
        foreach (var row in rows)
        {
            var (type, target, problem, action) = Rule(row);
            if (target.Length == 0) target = Unknown;
            var key = (row.Kind, type, target, problem);
            if (!items.TryGetValue(key, out var item))
            {
                item = new FixItem { Kind = row.Kind, TargetType = type, Target = target, Problem = problem, Action = action };
                items[key] = item;
            }
            item.Rows++;
            item.Events += row.Count;
            if (row.FirstSeen < item.FirstSeen) item.FirstSeen = row.FirstSeen;
            if (row.LastSeen > item.LastSeen) item.LastSeen = row.LastSeen;
            if (row.Account.Length > 0) item.Accounts.Add(row.Account);
            if (row.Client.Length > 0) item.Clients.Add(row.Client);
            if (row.Service.Length > 0) item.Services.Add(row.Service);
            item.Computers.UnionWith(row.Computers);
        }
        var list = items.Values
            .OrderBy(i => Scanner.KindOrder(i.Kind))
            .ThenBy(i => i.Target == Unknown)
            .ThenByDescending(i => i.Events)
            .ToList();
        for (var i = 0; i < list.Count; i++) list[i].Rank = i + 1;
        return list;
    }

    internal static (FixTarget Type, string Target, string Problem, string Action) Rule(SummaryRow r)
    {
        var account = r.Account;
        var client = r.Client;
        var service = r.Service;
        var variants = r.Variants;
        bool Any(string text) => variants.Any(v => v.Contains(text, StringComparison.OrdinalIgnoreCase));

        switch (r.Kind)
        {
            case LegacyKind.Ntlmv1 when Any("single sign-on"):
                return (FixTarget.Client, Or(client, account), "Single sign-on with NTLMv1-derived credentials",
                    "Move the Wi-Fi, wired or VPN profile on this device from MS-CHAPv2 to certificate based authentication (EAP-TLS), or turn on Credential Guard. "
                    + "Once BlockNtlmv1SSO is enforced, single sign-on with these credentials stops working.");
            case LegacyKind.Ntlmv1 when client.Length > 0:
                return (FixTarget.Client, client, "Signs in with NTLMv1 or LM",
                    "Update the device or its software so it uses NTLMv2 or Kerberos. On Windows set \"Network security: LAN Manager authentication level\" "
                    + "to send NTLMv2 responses only (LmCompatibilityLevel 3 or higher). Copiers, NAS boxes and scanners usually need a firmware update or a setting change.");
            case LegacyKind.Ntlmv1:
                return (FixTarget.Account, account, "Signs in with NTLMv1 or LM, client not logged",
                    $"The client is not in the event. Find where {Or(account, "this account")} signs in from (Security event 4624 on the server, or the NTLM Operational log) and update that device.");

            case LegacyKind.Des when service.Length > 0 && !IsKrbtgt(service):
                return (FixTarget.ServiceAccount, service, "Kerberos tickets with DES",
                    $"Find the account behind the SPN with setspn -Q {service}. Clear \"Use only Kerberos DES encryption types for this account\", "
                    + "set msDS-SupportedEncryptionTypes to AES (24) and reset the password so AES keys exist. Windows Server 2025 no longer supports DES.");
            case LegacyKind.Des:
                return (FixTarget.Account, account, "Gets DES tickets",
                    $"Clear \"Use only Kerberos DES encryption types for this account\" on {Or(account, "the account")}, set msDS-SupportedEncryptionTypes to AES (24) "
                    + $"and reset the password. Then update the system that asks for DES{(client.Length > 0 ? $" ({client})" : "")}.");

            case LegacyKind.Rc4 when KdcEvent(variants) is { } id:
                return id switch
                {
                    201 or 203 => (FixTarget.Client, Or(client, account), "Offers only RC4",
                        "The client asks for RC4 only. Update its operating system, Kerberos library or keytab so it offers AES, or replace the device."),
                    202 or 204 or 206 => (FixTarget.ServiceAccount, Or(service, account), "Service without AES keys",
                        "Set msDS-SupportedEncryptionTypes on the account behind this service to AES (24) and reset its password so it gets AES keys."),
                    207 or 209 => (FixTarget.Account, Or(account, service), "Account without AES keys",
                        $"Reset the password of {Or(account, "the account")}. Passwords set before the domain supported AES only have RC4 keys. Then check msDS-SupportedEncryptionTypes."),
                    205 => (FixTarget.DomainPolicy, "Kerberos encryption types policy", "Insecure ciphers allowed by domain policy",
                        "Remove DES and RC4 from \"Network security: Configure encryption types allowed for Kerberos\" once nothing in this list depends on them."),
                    _ => (FixTarget.Account, Or(account, service), "RC4 warning from the domain controller",
                        "Check the KDCSVC event text on the domain controller and the account's msDS-SupportedEncryptionTypes."),
                };
            case LegacyKind.Rc4 when service.Length == 0 || IsKrbtgt(service):
                return (FixTarget.Account, account, "Gets RC4 TGTs",
                    $"Reset the password of {Or(account, "the account")} so it gets AES keys, then check that msDS-SupportedEncryptionTypes is empty or includes AES. "
                    + "Accounts whose password has not changed in many years often have only RC4 keys.");
            case LegacyKind.Rc4 when Any("Ticket RC4"):
                return (FixTarget.ServiceAccount, service, "Service tickets with RC4",
                    $"Find the account behind the SPN with setspn -Q {service}. Set its msDS-SupportedEncryptionTypes to AES (24) and reset its password so it has AES keys. Test the application afterwards.");
            case LegacyKind.Rc4:
                return (FixTarget.Client, Or(client, account), "Asks for RC4 session keys",
                    $"The ticket is AES but the session key is RC4. Check that the client offers AES and that the account behind {Or(service, "the service")} "
                    + "lists AES in msDS-SupportedEncryptionTypes.");

            case LegacyKind.LdapSigning when client.Contains("daily summary", StringComparison.OrdinalIgnoreCase):
                return (FixTarget.DomainControllers, Or(r.ComputersText, "Domain controllers"), "Unsigned LDAP binds, clients unknown",
                    "Set the \"16 LDAP Interface Events\" diagnostic value to 2 on these domain controllers so event 2889 names each client, then scan the Directory Service logs again.");
            case LegacyKind.LdapSigning when Any("Simple bind"):
                return (FixTarget.Client, Or(client, account), "Simple LDAP bind with a cleartext password",
                    "Configure the application on this client to use LDAPS (port 636) or StartTLS. A simple bind on port 389 sends the password in clear text.");
            case LegacyKind.LdapSigning:
                return (FixTarget.Client, Or(client, account), "LDAP bind without signing",
                    "Turn on LDAP signing in the client or application, or switch it to LDAPS. Windows clients sign when \"Network security: LDAP client signing requirements\" is set to negotiate or require.");

            case LegacyKind.LdapChannelBinding:
                return (FixTarget.Client, Or(client, account), "LDAPS without channel binding",
                    "Update the operating system or LDAP library on this client so it sends channel binding tokens. Then set \"Domain controller: LDAP server channel binding token requirements\" to Always.");

            case LegacyKind.EtypeFailure when Any("client offered"):
                return (FixTarget.Client, Or(client, account), "Kerberos fails, client offers only old ciphers",
                    "The client offers only DES or RC4 and the account or domain controller no longer accepts them. Update or reconfigure the client to support AES.");
            case LegacyKind.EtypeFailure:
                return (FixTarget.Account, Or(account, service), "Kerberos fails, no common encryption type",
                    $"Compare the requested and available types in the events. Reset the password of {Or(account, "the account")} so it gets AES keys and include AES in msDS-SupportedEncryptionTypes.");

            case LegacyKind.Smb1:
                return (FixTarget.Client, client, "Connects with SMBv1",
                    "Turn on SMB 2 or 3 on this client, or replace it. Old copiers, scanners and NAS boxes often have a firmware update for it. When no client is left, remove SMB1 from the servers.");

            default:
                return NtlmRule(r);
        }
    }

    private static readonly (string Reason, string Action)[] NtlmReasons =
    [
        ("target name is an IP address", "Connect by host name instead of IP address, Kerberos needs a name."),
        ("target name not resolved by Kerberos", "Register the SPN of the target service with setspn -S and check that DNS resolves the name."),
        ("target name duplicated in Active Directory", "Remove the duplicate SPN, setspn -X lists them."),
        ("target name missing or empty", "Configure the application with the server's host name or SPN."),
        ("called directly by the application", "Change the application to use Negotiate instead of NTLM."),
        ("local account", "A local account was used. Use a domain account or plan an exception."),
        ("no line of sight to a domain controller", "The client could not reach a domain controller. Check the network path to the domain controllers."),
        ("null session", "Anonymous access. Find the process and turn off null sessions."),
        ("loopback", "A connection to itself, usually harmless. Plan an exception."),
        ("cloud account", "A cloud account was used. Check how the device is joined and how the user signs in."),
    ];

    private static (FixTarget, string, string, string) NtlmRule(SummaryRow r)
    {
        var reasons = NtlmReasons.Where(x => r.Variants.Any(v => v.Contains(x.Reason, StringComparison.OrdinalIgnoreCase))).ToList();
        var type = r.Client.Length > 0 ? FixTarget.Client : FixTarget.Account;
        var target = r.Client.Length > 0 ? r.Client : r.Account;
        var problem = reasons.Count > 0 ? $"Uses NTLM: {string.Join(", ", reasons.Select(x => x.Reason))}" : "Uses NTLM";
        var action = reasons.Count > 0
            ? string.Join(" ", reasons.Select(x => x.Action))
            : "Find out why NTLM is used here. With NTLM Enhanced Logging on, events 4020 and 4022 record the reason. Usually the fix is to connect by host name, register the SPN or switch the application to Negotiate.";
        if (r.Service.Length > 0) action += $" Target: {r.Service}.";
        return (type, target, problem, action);
    }

    private static int? KdcEvent(IEnumerable<string> variants)
    {
        foreach (var v in variants)
        {
            if (v.StartsWith("KDC event ", StringComparison.Ordinal) && int.TryParse(v.AsSpan(10), out var id)) return id;
        }
        return null;
    }

    private static bool IsKrbtgt(string service) =>
        service.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) || service.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase);

    private static string Or(string value, string fallback) => value.Length > 0 ? value : fallback;

    private sealed class KeyComparer : IEqualityComparer<(LegacyKind, FixTarget, string, string)>
    {
        private static readonly StringComparer Text = StringComparer.OrdinalIgnoreCase;

        public bool Equals((LegacyKind, FixTarget, string, string) a, (LegacyKind, FixTarget, string, string) b) =>
            a.Item1 == b.Item1 && a.Item2 == b.Item2 && Text.Equals(a.Item3, b.Item3) && a.Item4 == b.Item4;

        public int GetHashCode((LegacyKind, FixTarget, string, string) k) => HashCode.Combine(k.Item1, k.Item2, Text.GetHashCode(k.Item3), k.Item4);
    }
}
