namespace LegacyAuthFinder.Core;

/// <summary>Where the fix has to be made.</summary>
public enum FixTarget
{
    Client,
    Account,
    ServiceAccount,
    ComputerAccount,
    Server,
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

    /// <summary>The summary rows behind this item, so "Show these events" can show exactly their events.</summary>
    public List<SummaryRow> SourceRows { get; } = [];
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
        FixTarget.ComputerAccount => "Computer account",
        FixTarget.Server => "Server",
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
/// encryption types: a service ticket is encrypted with the key of the service account (named in the ServiceName of
/// 4769, an account, not an SPN), the session key is the strongest type both the client and the service support, and
/// pre-authentication uses the account's own key. KDCSVC events 201 to 209 follow Microsoft's CVE-2026-20833 KB.
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
            if (row.SeveralDomains && row.Account.Length > 0)
            {
                action += $" The name {row.Account} was logged in more than one domain ({row.DomainsText}). These are different accounts: check each one.";
            }
            var key = (row.Kind, type, target, problem);
            if (!items.TryGetValue(key, out var item))
            {
                item = new FixItem { Kind = row.Kind, TargetType = type, Target = target, Problem = problem, Action = action };
                items[key] = item;
            }
            item.Rows++;
            item.SourceRows.Add(row);
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

    /// <summary>
    /// Names that end with $ are computer accounts or managed service accounts (gMSA, sMSA). The event alone cannot
    /// tell them apart, so the advice covers both.
    /// </summary>
    internal static bool IsComputer(string account) => account.EndsWith('$');

    /// <summary>A failed service ticket request names the SPN (HOST/vm01.contoso.com), a successful one the account.</summary>
    internal static bool IsSpn(string service) => service.Contains('/');

    private const string ComputerAction =
        "If this is a computer account, Windows sets its msDS-SupportedEncryptionTypes itself from the computer's policy \"Network security: Configure encryption types allowed for Kerberos\", "
        + "so a manual change is overwritten. Allow AES in that policy on the computer, and update or replace an operating system that cannot use AES. "
        + "If its password is very old, reset the machine password (Reset-ComputerMachinePassword). "
        + "If it is a managed service account (gMSA or sMSA), Active Directory rotates its password and it has AES keys: allow AES on it with Set-ADServiceAccount -KerberosEncryptionType AES128,AES256.";

    /// <summary>
    /// The fix for a service account without AES keys, in the order Microsoft's CVE-2026-20833 guidance implies: keys
    /// first, then AES only. Setting AES only before the account has AES keys is exactly what makes the domain
    /// controller block its tickets (KDCSVC 207 and 209).
    /// </summary>
    private static (FixTarget, string, string, string) ServiceFix(string service, string problem, string extra = "")
    {
        if (IsComputer(service)) return (FixTarget.ComputerAccount, service, problem, ComputerAction + extra);
        var name = Or(service, "the account behind the service");
        var find = IsSpn(service) ? $"Find the account behind it with setspn -Q {service}. Then reset the password of that account" : $"Reset the password of {name}";
        return (FixTarget.ServiceAccount, service, problem,
            $"{find} so it gets AES keys, and update the password everywhere the service runs. For a keytab on a non-Windows system, export a new keytab with AES keys. "
            + "Check that new tickets for it use AES (event 4769), then set its msDS-SupportedEncryptionTypes to AES only (0x18). "
            + "If a device behind it cannot use AES yet, 0x24 (RC4 with AES session keys) is Microsoft's stopgap until it is replaced. "
            + $"setspn -L {(IsSpn(service) ? "<account>" : Or(service, "<account>"))} lists the services that run under it: test them afterwards.{extra}");
    }

    private static (FixTarget, string, string, string) AccountFix(string account, string problem)
    {
        if (IsComputer(account)) return (FixTarget.ComputerAccount, account, problem, ComputerAction);
        if (Classifier.IsKrbtgtName(account)) return KrbtgtFix(problem);
        return (FixTarget.Account, account, problem,
            $"Reset the password of {Or(account, "the account")} so it gets AES keys. Passwords set before the domain supported AES only have RC4 keys. "
            + "Then check that msDS-SupportedEncryptionTypes is empty or includes AES.");
    }

    /// <summary>krbtgt encrypts every TGT. Its password is reset twice, because the domain keeps the previous one too.</summary>
    private static (FixTarget, string, string, string) KrbtgtFix(string problem) =>
        (FixTarget.DomainControllers, "krbtgt", problem,
            "The krbtgt account has no AES keys, so every TGT of the domain is encrypted with RC4. Reset the krbtgt password twice, "
            + "at least 10 hours apart (the maximum ticket lifetime), and let replication finish in between. Microsoft's New-KrbtgtKeys script does it safely. "
            + "Read-only domain controllers have their own krbtgt_NNNNN accounts. Check the domain controllers' Kerberos encryption policy allows AES.");

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
                    "Move the Wi-Fi, wired or VPN profile on this device from MS-CHAPv2 (PEAP-MSCHAPv2, EAP-MSCHAPv2) to certificate based authentication (EAP-TLS or PEAP-TLS). "
                    + "Credential Guard and an enforced BlockNtlmv1SSO both stop single sign-on with these credentials, so users have to type their password until the profile is moved.");
            case LegacyKind.Ntlmv1 when client.Length > 0:
                return (FixTarget.Client, client, "Signs in with NTLMv1 or LM",
                    "Update the device or its software so it uses NTLMv2 or Kerberos. On Windows set \"Network security: LAN Manager authentication level\" "
                    + "to send NTLMv2 responses only (LmCompatibilityLevel 3 or higher). Copiers, NAS boxes and scanners usually need a firmware update or a setting change.");
            case LegacyKind.Ntlmv1:
                return (FixTarget.Account, account, "Signs in with NTLMv1 or LM, client not logged",
                    $"The client is not in the event. Find where {Or(account, "this account")} signs in from (Security event 4624 on the server, or the NTLM Operational log) and update that device.");

            case LegacyKind.Des when service.Length > 0 && !IsKrbtgt(service):
                return ServiceFix(service, "Kerberos tickets with DES",
                    " Also clear \"Use only Kerberos DES encryption types for this account\" on it. Windows Server 2025 no longer supports DES.");
            case LegacyKind.Des:
                var desFix = AccountFix(account, "Gets DES tickets");
                return desFix with
                {
                    Item4 = desFix.Item1 != FixTarget.Account ? desFix.Item4
                        : $"Clear \"Use only Kerberos DES encryption types for this account\" on {Or(account, "the account")} and reset its password so it gets AES keys. "
                          + $"Then set msDS-SupportedEncryptionTypes to AES (0x18) and update the system that asks for DES{(client.Length > 0 ? $" ({client})" : "")}.",
                };

            case LegacyKind.Rc4 when KdcEvent(variants) is { } id:
                return id switch
                {
                    201 or 203 => (FixTarget.Client, Or(client, account), "Offers only RC4",
                        "The client asks for RC4 only. Update its operating system, Kerberos library or keytab so it offers AES, or replace the device."),
                    206 or 208 => (FixTarget.Client, Or(client, account), "Offers only RC4 to an AES-only service",
                        "The service accepts only AES, but this client offers only RC4. Update its operating system, Kerberos library or keytab so it offers AES. "
                        + (id == 208 ? "The domain controller already blocks these requests." : "Once enforcement starts these requests fail.")),
                    202 or 204 => ServiceFix(Or(service, account), "Service account without AES keys"),
                    207 or 209 => ServiceFix(Or(service, account), "AES-only service account without AES keys",
                        id == 209 ? " The domain controller already blocks these requests." : ""),
                    205 => (FixTarget.DomainPolicy, "DefaultDomainSupportedEncTypes", "Domain controllers allow more than AES by default",
                        "The registry value DefaultDomainSupportedEncTypes (HKLM\\SYSTEM\\CurrentControlSet\\Services\\KDC) on the domain controllers includes RC4 or DES. "
                        + "Remove them once nothing in this list depends on them. Event 205 is logged at every KDC start while it allows more than AES."),
                    _ => (FixTarget.Account, Or(account, service), "RC4 warning from the domain controller",
                        "Check the KDCSVC event text on the domain controller and the account's msDS-SupportedEncryptionTypes."),
                };
            case LegacyKind.Rc4 when Any("krbtgt has no AES keys"):
                return KrbtgtFix("TGTs with RC4, krbtgt has no AES keys");
            case LegacyKind.Rc4 when Any("Pre-auth") && Any("client offered no AES"):
                return (FixTarget.Client, Or(client, account), "Signs in with RC4, the client offers no AES",
                    $"The client offered only RC4 or DES for the pre-authentication of {Or(account, "the account")}. Update or reconfigure it to offer AES. "
                    + "If the account has no AES keys either (AccountAvailableKeys in the details), reset its password too.");
            case LegacyKind.Rc4 when Any("Pre-auth"):
                return AccountFix(account, "Signs in with an RC4 key (pre-authentication)");
            case LegacyKind.Rc4 when (service.Length == 0 || IsKrbtgt(service)) && Any("Session key") && !Any("Ticket RC4"):
                return (FixTarget.Client, Or(client, account), "Asks for RC4 TGT session keys",
                    "The client asked for RC4 in its TGT request. Update or reconfigure it so it offers AES. "
                    + $"If {Or(account, "the account")} has no AES keys either, reset its password.");
            case LegacyKind.Rc4 when service.Length == 0 || IsKrbtgt(service):
                // Older domain controllers do not log the pre-authentication type, so the event alone cannot tell
                // whether the account has no AES keys or the client asked for RC4. The keys are in the details.
                var tgt = AccountFix(account, "Gets RC4 TGTs");
                return tgt.Item1 == FixTarget.ComputerAccount ? tgt : tgt with
                {
                    Item4 = $"Look at AccountAvailableKeys in the event details. Without AES keys, reset the password of {Or(account, "the account")} so it gets them. "
                        + $"With AES keys, the client{(client.Length > 0 ? $" {client}" : "")} asked for RC4: update or reconfigure it to offer AES.",
                };
            case LegacyKind.Rc4 when Any("Ticket RC4"):
                return ServiceFix(service, "Service tickets with RC4");
            case LegacyKind.Rc4:
                return (FixTarget.Client, Or(client, account), "Asks for RC4 session keys",
                    $"The ticket is AES but the session key is RC4. Check that the client offers AES and that {Or(service, "the service account")} "
                    + "lists AES in msDS-SupportedEncryptionTypes.");

            case LegacyKind.NoPreAuth:
                return (FixTarget.Account, account, "Kerberos pre-authentication is off (AS-REP roastable)",
                    $"Clear \"Do not require Kerberos preauthentication\" on {Or(account, "the account")} (Set-ADAccountControl -DoesNotRequirePreAuth $false). "
                    + "If an old system really needs it, give the account a long random password and AES keys."
                    + (Any("RC4") || Any("DES")
                        ? " Its TGTs were also issued with RC4 or DES, which makes them even easier to crack: reset the password so it gets AES keys, and check AccountAvailableKeys in the details."
                        : ""));

            case LegacyKind.LdapSigning when client.Contains("daily summary", StringComparison.OrdinalIgnoreCase) && Any("rejected"):
                return (FixTarget.DomainControllers, Or(r.ComputersText, "Domain controllers"), "Unsigned LDAP binds are rejected, clients unknown",
                    "Signing is enforced and some clients still fail. Set the \"16 LDAP Interface Events\" diagnostic value to 2 on these domain controllers so event 2889 names them, then fix those clients. They are already broken.");
            case LegacyKind.LdapSigning when client.Contains("daily summary", StringComparison.OrdinalIgnoreCase):
                return (FixTarget.DomainControllers, Or(r.ComputersText, "Domain controllers"), "Unsigned LDAP binds, clients unknown",
                    "Set the \"16 LDAP Interface Events\" diagnostic value to 2 on these domain controllers so event 2889 names each client, then scan the Directory Service logs again.");
            case LegacyKind.LdapSigning when Any("Simple bind"):
                return (FixTarget.Client, Or(client, account), "Simple LDAP bind with a cleartext password",
                    "Configure the application on this client to use LDAPS (port 636) or StartTLS. A simple bind on port 389 sends the password in clear text.");
            case LegacyKind.LdapSigning:
                return (FixTarget.Client, Or(client, account), "LDAP bind without signing",
                    "Turn on LDAP signing in the client or application, or switch it to LDAPS. Windows clients sign when \"Network security: LDAP client signing requirements\" is set to negotiate or require.");

            case LegacyKind.LdapChannelBinding when client.Contains("daily summary", StringComparison.OrdinalIgnoreCase):
                return (FixTarget.DomainControllers, Or(r.ComputersText, "Domain controllers"), "LDAPS binds without channel binding, clients unknown",
                    "Set \"Domain controller: LDAP server channel binding token requirements\" to \"When supported\" and the \"16 LDAP Interface Events\" diagnostic value to 2, "
                    + "so events 3039, 3074 and 3075 name each client. Then scan the Directory Service logs again.");
            case LegacyKind.LdapChannelBinding:
                return (FixTarget.Client, Or(client, account), "LDAPS without channel binding",
                    "Update the operating system or LDAP library on this client so it sends channel binding tokens. Then set \"Domain controller: LDAP server channel binding token requirements\" to Always.");

            case LegacyKind.EtypeFailure when Any("client offered"):
                return (FixTarget.Client, Or(client, account), "Kerberos fails, client offers only old ciphers",
                    "The client offers only DES or RC4 and the account or domain controller no longer accepts them. Update or reconfigure the client to support AES.");
            case LegacyKind.EtypeFailure when Any("without AES, account has"):
                return (FixTarget.Client, Or(client, account), "Kerberos fails, the request offers no AES",
                    $"{Or(account, "The account")} has AES keys, but the request offered only RC4 or DES. Find the requesting client (Security event 4769 with status 0xE at the same time) "
                    + "and update or reconfigure it to offer AES. Also check the target service's msDS-SupportedEncryptionTypes and the domain controllers' DefaultDomainSupportedEncTypes.");
            case LegacyKind.EtypeFailure when Any("service account has no AES keys"):
                return ServiceFix(Or(service, account), "Kerberos fails, service account has no AES keys");
            case LegacyKind.EtypeFailure when Any("check the target service"):
                return ServiceFix(Or(service, account), "Kerberos fails, target service without a common encryption type",
                    " Microsoft's example of this case is a target whose msDS-SupportedEncryptionTypes is 0x4 (RC4 only). The requesting user's password does not matter here.");
            case LegacyKind.EtypeFailure when Any("account has no AES keys") && IsSpnOrService(service, account):
                return ServiceFix(account, "Kerberos fails, service account has no AES keys");
            case LegacyKind.EtypeFailure:
                return AccountFix(Or(account, service), "Kerberos fails, no common encryption type") is var fix && fix.Item1 == FixTarget.Account
                    ? fix with { Item4 = $"Compare the requested and available types in the events. {fix.Item4}" }
                    : fix;

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
        // 8002 and 4002 do not name the remote side: the fix starts on the server that received the NTLM sign-in.
        if (r.Client.Length == 0 && r.Account.Length == 0)
        {
            return (FixTarget.Server, Or(r.Service, r.ComputersText), "Receives NTLM, clients not logged",
                "This server accepts NTLM sign-ins but the event does not name the client. Turn on \"NTLM Enhanced Logging\" (Windows 11 24H2, Windows Server 2025, "
                + "Server 2019 and 2022 with the October 2026 updates) so events 4022 and 4023 name each client, or audit with \"Restrict NTLM: Audit incoming NTLM traffic\".");
        }
        var reasons = NtlmReasons.Where(x => r.Variants.Any(v => v.Contains(x.Reason, StringComparison.OrdinalIgnoreCase))).ToList();
        var blocked = r.Variants.Any(v => v.Contains("blocked", StringComparison.OrdinalIgnoreCase));
        var type = r.Client.Length > 0 ? FixTarget.Client : FixTarget.Account;
        var target = r.Client.Length > 0 ? r.Client : r.Account;
        var problem = (blocked ? "NTLM is or would be blocked" : "Uses NTLM") + (reasons.Count > 0 ? $": {string.Join(", ", reasons.Select(x => x.Reason))}" : "");
        var action = reasons.Count > 0
            ? string.Join(" ", reasons.Select(x => x.Action))
            : "Find out why NTLM is used here. With NTLM Enhanced Logging on, events 4020 and 4022 record the reason. Usually the fix is to connect by host name, register the SPN or switch the application to Negotiate.";
        if (blocked) action = "This NTLM sign-in fails or will fail when the Restrict NTLM policy is enforced. " + action;
        if (r.Service.Length > 0) action += $" Target: {r.Service}.";
        return (type, target, problem, action);
    }

    /// <summary>KDC event 16 names the service account to fix: it is the account, and the target service is its SPN.</summary>
    internal static bool IsSpnOrService(string service, string account) => service.Length > 0 && account.Length > 0
        && !service.Equals(account, StringComparison.OrdinalIgnoreCase) && IsSpn(service) && !Classifier.IsKrbtgtName(service);

    private static int? KdcEvent(IEnumerable<string> variants)
    {
        foreach (var v in variants)
        {
            if (v.StartsWith("KDC event ", StringComparison.Ordinal) && int.TryParse(v.AsSpan(10), out var id)) return id;
        }
        return null;
    }

    private static bool IsKrbtgt(string service) => Classifier.IsKrbtgtName(service);

    private static string Or(string value, string fallback) => value.Length > 0 ? value : fallback;

    private sealed class KeyComparer : IEqualityComparer<(LegacyKind, FixTarget, string, string)>
    {
        private static readonly StringComparer Text = StringComparer.OrdinalIgnoreCase;

        public bool Equals((LegacyKind, FixTarget, string, string) a, (LegacyKind, FixTarget, string, string) b) =>
            a.Item1 == b.Item1 && a.Item2 == b.Item2 && Text.Equals(a.Item3, b.Item3) && a.Item4 == b.Item4;

        public int GetHashCode((LegacyKind, FixTarget, string, string) k) => HashCode.Combine(k.Item1, k.Item2, Text.GetHashCode(k.Item3), k.Item4);
    }
}
