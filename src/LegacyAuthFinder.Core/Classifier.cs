using System.Globalization;

namespace LegacyAuthFinder.Core;

/// <summary>Decides which legacy authentication an event shows and pulls out the columns.</summary>
public static class Classifier
{
    public const uint DesCbcCrc = 0x1;
    public const uint DesCbcMd5 = 0x3;
    public const uint Rc4Hmac = 0x17;
    public const uint Rc4HmacExp = 0x18;

    /// <summary>KDC_ERR_ETYPE_NOSUPP: client and KDC found no common encryption type.</summary>
    public const uint EtypeNotSupported = 0xE;

    /// <summary>Extra fields kept for the detail view, in display order.</summary>
    private static readonly string[] DetailFields =
    [
        "LogonType", "AuthenticationPackageName", "LmPackageName", "KeyLength", "LogonProcessName", "ProcessName",
        "WorkstationName", "IpAddress", "Status", "SubStatus",
        "TicketOptions", "PreAuthType", "PreAuthEncryptionType", "FailureCode", "ClientAdvertizedEncryptionTypes",
        "AccountSupportedEncryptionTypes", "AccountAvailableKeys",
        "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys",
        "DCSupportedEncryptionTypes", "DCAvailableKeys",
        "TargetMachine", "TargetIP", "TargetName", "ClientNetworkName", "SChannelName",
        "ChannelBindingStatus", "Mic Status", "StatusMsg",
    ];

    public static AuthEvent? Classify(RawEvent e, string file, StringPool pool) => e.EventId switch
    {
        4624 or 4625 when e.Provider is "" or Providers.SecurityAuditing => Ntlm(e, file, pool),
        4768 when (e.Provider is "" or Providers.SecurityAuditing) && IsNoPreAuth(e) => NoPreAuth(e, file, pool),
        4768 or 4769 or 4770 or 4771 when e.Provider is "" or Providers.SecurityAuditing =>
            IsEtypeFailure(e) ? SecurityEtypeFailure(e, file, pool) : e.EventId == 4771 ? null : Kerberos(e, file, pool),
        4776 when e.Provider is "" or Providers.SecurityAuditing => NtlmValidation(e, file, pool),
        >= 201 and <= 209 when Providers.IsKdc(e.Provider) => KdcWarning(e, file, pool),
        14 or 16 or 26 or 27 when Providers.IsKdc(e.Provider) => KdcEtypeError(e, file, pool),
        2887 or 2888 or 2889 or 3039 or 3040 or 3074 or 3075 when e.Provider is "" || Providers.IsDirectoryService(e.Provider) => Ldap(e, file, pool),
        (>= 8001 and <= 8004) or (>= 4001 and <= 4006) or 4013 or (>= 4020 and <= 4027) or (>= 4030 and <= 4033)
            when e.Provider is "" || Providers.IsNtlm(e.Provider) => NtlmUse(e, file, pool),
        3000 when e.Provider is "" || e.Provider.Equals(Providers.SmbServer, StringComparison.OrdinalIgnoreCase) => Smb1(e, file, pool),
        _ => null,
    };

    /// <summary>The well-known SID of anonymous sessions. Microsoft: ignore NTLM V1 in 4624 for ANONYMOUS LOGON.</summary>
    public const string AnonymousSid = "S-1-5-7";

    /// <summary>A successful TGT request without Kerberos pre-authentication (PreAuthType 0): the account can be AS-REP roasted.</summary>
    internal static bool IsNoPreAuth(RawEvent e) =>
        Clean(e["PreAuthType"]) == "0" && ParseEtype(e["Status"]) is null or 0;

    /// <summary>True when an encryption type list ("AES256-SHA1, RC4", "0x12 0x17", "18 17 23") contains an AES type.</summary>
    internal static bool HasAes(string list)
    {
        if (list.Contains("AES", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var part in list.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (ParseEtype(part) is 0x11 or 0x12 or 0x13 or 0x14) return true;
        }
        return false;
    }

    /// <summary>"bob@LAB.LOCAL" becomes ("bob", "LAB.LOCAL"), so 4768, 4769 and 4624 group under the same account.</summary>
    internal static (string Account, string Domain) SplitRealm(string account, string domain)
    {
        var at = account.LastIndexOf('@');
        if (at <= 0 || at == account.Length - 1) return (account, domain);
        return (account[..at], domain.Length > 0 ? domain : account[(at + 1)..]);
    }

    /// <summary>Reason IDs of the enhanced NTLM events, from Microsoft's NTLM auditing overview.</summary>
    public static string NtlmReason(string id) => id.Trim() switch
    {
        "0" => "unknown reason",
        "1" => "called directly by the application",
        "2" => "local account",
        "4" => "cloud account",
        "5" => "target name missing or empty",
        "6" => "target name not resolved by Kerberos",
        "7" => "target name is an IP address",
        "8" => "target name duplicated in Active Directory",
        "9" => "no line of sight to a domain controller",
        "10" => "loopback",
        "11" => "null session",
        _ => "",
    };

    /// <summary>"NTLMv1", "1", "NTLM V1" and "v1" become "NTLMv1", the same for v2. LM stays LM, unknown text is kept.</summary>
    public static string NtlmVersion(string value)
    {
        value = Clean(value);
        if (value.Length == 0) return "";
        if (value.Equals("LM", StringComparison.OrdinalIgnoreCase)) return "LM";
        var digits = value.Where(char.IsDigit).ToArray();
        return digits.Length == 0 ? value : digits[^1] switch
        {
            '1' => "NTLMv1",
            '2' => "NTLMv2",
            _ => value,
        };
    }

    /// <summary>
    /// NTLM Operational log. Field names from the provider manifests:
    /// 4020/4021 (outgoing, on the client): Username, DomainName, Hostname, TargetMachine, TargetService, TargetIP, NtlmUsageId, NtlmUsageReason, NtlmVersion.
    /// 4022/4023 (incoming, on the server): Username, DomainName, RemoteClientMachine, ClientIP, ClientNetworkName, NtlmVersion.
    /// 4030 to 4033 (domain controller): AccountName, AccountDomain, AccountMachine, ServerName, NtlmVersion.
    /// 4024/4025 (NTLMv1-derived single sign-on) and 8001: TargetName, UserName, DomainName, ProcessName.
    /// 8002: ClientUserName, ClientDomainName. 8003: UserName, DomainName, Workstation. 8004: SChannelName, UserName, DomainName, WorkstationName.
    /// 4004 to 4006 (Netlogon, NTLM to a domain controller blocked) have the same fields as 8004.
    /// The odd numbers 4021, 4023, 4031 and 4033 are warnings, logged for a security downgrade such as NTLMv1.
    /// </summary>
    private static AuthEvent NtlmUse(RawEvent e, string file, StringPool pool)
    {
        var version = NtlmVersion(e["NtlmVersion"]);
        // The ID maps to fixed wording that the fix list understands. The logged text is the fallback for new IDs.
        var reason = NtlmReason(e["NtlmUsageId"]);
        if (reason.Length == 0) reason = First(e, "NtlmUsageReason");
        var weak = version is "NTLMv1" or "LM";
        var downgrade = e.EventId is 4021 or 4023 or 4031 or 4033;
        string Ver(string fallback) => version.Length > 0 ? version : fallback;
        string With(string text) => reason.Length > 0 ? $"{text}, {reason}" : text;

        var (account, domain, client, service, variant) = e.EventId switch
        {
            4020 or 4021 => (First(e, "Username", "UserName"), Clean(e["DomainName"]), First(e, "Hostname").Length > 0 ? First(e, "Hostname") : ShortHost(e.Computer),
                First(e, "TargetService", "TargetMachine", "TargetIP"), With($"Outgoing {Ver("NTLM")}")),
            // The machine name is preferred over the address, so the same client lines up with 4020 and 4030 to 4033.
            4022 or 4023 => (First(e, "Username", "UserName"), Clean(e["DomainName"]), CleanIp(First(e, "RemoteClientMachine", "ClientIP", "ClientNetworkName")),
                "", $"Incoming {Ver("NTLM")}"),
            >= 4030 and <= 4033 => (Clean(e["AccountName"]), Clean(e["AccountDomain"]), Clean(e["AccountMachine"]), Clean(e["ServerName"]),
                $"Checked by the domain controller, {Ver("NTLM")}"),
            4024 => (First(e, "UserName", "ClientUserName"), First(e, "DomainName", "ClientDomainName"), ShortHost(e.Computer), Clean(e["TargetName"]),
                "NTLMv1-derived single sign-on credentials (audit)"),
            4025 => (First(e, "UserName", "ClientUserName"), First(e, "DomainName", "ClientDomainName"), ShortHost(e.Computer), Clean(e["TargetName"]),
                "NTLMv1-derived single sign-on credentials blocked"),
            8001 => (First(e, "UserName", "ClientUserName"), First(e, "DomainName", "ClientDomainName"), ShortHost(e.Computer), Clean(e["TargetName"]),
                "Outgoing NTLM (audit 8001)"),
            // 8002 and 4002 name the local server process (often SYSTEM), not the remote user. The fix is on this server.
            8002 => ("", "", "", ShortHost(e.Computer), "Incoming NTLM, client not logged (audit 8002)"),
            4002 => ("", "", "", ShortHost(e.Computer), "Incoming NTLM blocked, client not logged (4002)"),
            8003 => (Clean(e["UserName"]), Clean(e["DomainName"]), Clean(e["Workstation"]), "", "Incoming NTLM with a domain account (audit 8003)"),
            4003 => (Clean(e["UserName"]), Clean(e["DomainName"]), Clean(e["Workstation"]), "", "Incoming NTLM with a domain account blocked (4003)"),
            4001 => (First(e, "UserName", "ClientUserName"), First(e, "DomainName", "ClientDomainName"), ShortHost(e.Computer), Clean(e["TargetName"]),
                "Outgoing NTLM blocked (4001)"),
            // 4013 (NTLMv1BlockedByCredGuard): Credential Guard stopped single sign-on with NTLMv1, usually a Wi-Fi or VPN profile.
            4013 => (First(e, "UserName", "ClientUserName"), First(e, "DomainName", "ClientDomainName"), ShortHost(e.Computer), Clean(e["TargetName"]),
                "NTLMv1 single sign-on blocked by Credential Guard (4013)"),
            >= 4004 and <= 4006 => (Clean(e["UserName"]), Clean(e["DomainName"]), Clean(e["WorkstationName"]), Clean(e["SChannelName"]),
                $"NTLM to the domain controller blocked ({e.EventId})"),
            4026 or 4027 => (First(e, "Username", "UserName"), Clean(e["DomainName"]), First(e, "Hostname").Length > 0 ? First(e, "Hostname") : ShortHost(e.Computer),
                First(e, "TargetService", "TargetMachine", "TargetIP"),
                With(e.EventId == 4026 ? $"Outgoing {Ver("NTLM")}, would be blocked (audit)" : $"Outgoing {Ver("NTLM")}, blocked by policy")),
            _ => (Clean(e["UserName"]), Clean(e["DomainName"]), Clean(e["WorkstationName"]), Clean(e["SChannelName"]), "NTLM checked by the domain controller (audit 8004)"),
        };
        if (downgrade && !weak) variant += ", security downgrade";
        var kind = weak || e.EventId is 4024 or 4025 or 4013 ? LegacyKind.Ntlmv1 : LegacyKind.Ntlm;
        return Build(e, file, pool, kind, variant, account, domain, client, service, "", "",
            extra: [("Reason", reason), ("NTLM version", version)]);
    }

    /// <summary>SMBServer Audit 3000: "SMB1 access, Client Address: %1". The field is called ClientName.</summary>
    private static AuthEvent Smb1(RawEvent e, string file, StringPool pool)
    {
        var client = CleanIp(Clean(e["ClientName"]).TrimStart('\\'));
        return Build(e, file, pool, LegacyKind.Smb1, "SMBv1 connection", "", "", client, "SMB", "", "",
            extra: [("Client address", Clean(e["ClientName"]))]);
    }

    private static string ShortHost(string computer)
    {
        var dot = computer.IndexOf('.');
        return dot > 0 ? computer[..dot] : computer;
    }

    private static bool IsEtypeFailure(RawEvent e) =>
        ParseEtype(e["Status"]) == EtypeNotSupported || ParseEtype(e["FailureCode"]) == EtypeNotSupported;

    /// <summary>
    /// Status 0xE. The side to blame is the one without AES: the client's offer, the service account's keys (4769) or
    /// the account's keys (4768, 4771). A failed 4769 often has every key field empty ("-", see Microsoft's RC4 guide).
    /// A service ticket does not depend on the requesting user's keys, so then the target service is the likely cause.
    /// </summary>
    private static AuthEvent SecurityEtypeFailure(RawEvent e, string file, StringPool pool)
    {
        var offered = Clean(e["ClientAdvertizedEncryptionTypes"]);
        var serviceKeys = Clean(e["ServiceAvailableKeys"]);
        var accountKeys = Clean(e["AccountAvailableKeys"]);
        var variant = offered.Length > 0 && !HasAes(offered) ? $"No common encryption type, client offered {offered}"
            : e.EventId == 4769 && serviceKeys.Length > 0 && !HasAes(serviceKeys) ? $"No common encryption type, service account has no AES keys ({serviceKeys})"
            : e.EventId == 4769 ? "No common encryption type, check the target service's encryption types (0xE)"
            : accountKeys.Length > 0 && !HasAes(accountKeys) ? $"No common encryption type, account has no AES keys ({accountKeys})"
            : "No common encryption type (0xE)";
        var (account, domain) = SplitRealm(Clean(e["TargetUserName"]), Clean(e["TargetDomainName"]));
        return Build(e, file, pool, LegacyKind.EtypeFailure, variant,
            account: account,
            domain: domain,
            client: CleanIp(e["IpAddress"]),
            service: Clean(e["ServiceName"]),
            ticket: "",
            session: "");
    }

    /// <summary>4768 with PreAuthType 0: a TGT was issued without pre-authentication (AS-REP roastable account).</summary>
    private static AuthEvent NoPreAuth(RawEvent e, string file, StringPool pool)
    {
        var ticket = ParseEtype(e["TicketEncryptionType"]);
        var (account, domain) = SplitRealm(Clean(e["TargetUserName"]), Clean(e["TargetDomainName"]));
        return Build(e, file, pool, LegacyKind.NoPreAuth,
            ticket is { } t ? $"TGT without pre-authentication, {EtypeName(t)}" : "TGT without pre-authentication",
            account, domain, CleanIp(e["IpAddress"]), Clean(e["ServiceName"]), ticket is { } tt ? EtypeName(tt) : "", "");
    }

    /// <summary>
    /// 4776: the domain controller validated NTLM credentials. Logged for every NTLM sign-in that reaches the DC. Member
    /// servers and workstations log it too, for local accounts, also for a sign-in or unlock at the console. Those name
    /// the computer itself as the workstation and are not network NTLM, so they are left out.
    /// </summary>
    private static AuthEvent? NtlmValidation(RawEvent e, string file, StringPool pool)
    {
        var workstation = Clean(e["Workstation"]);
        if (workstation.Length > 0 && workstation.Equals(ShortHost(e.Computer), StringComparison.OrdinalIgnoreCase)) return null;
        var status = ParseEtype(e["Status"]);
        return Build(e, file, pool, LegacyKind.Ntlm,
            status is null or 0 ? "NTLM validated by the domain controller (4776)" : $"NTLM validation failed (4776, 0x{status:x})",
            Clean(e["TargetUserName"]), "", workstation, "", "", "");
    }

    /// <summary>
    /// KDC events 14, 16, 26 and 27. Microsoft documents the insertion strings as: %1 target service, %2 account,
    /// %3 missing key ID, %4 requested etypes, %5 the account's available etypes, and for 16 also %6, the account whose
    /// password reset "will generate a proper key". In 16, %2 is often the requesting user while %6 is the service
    /// account to fix, so %6 wins and %2 is kept as the requester.
    /// </summary>
    private static AuthEvent KdcEtypeError(RawEvent e, string file, StringPool pool)
    {
        var requested = EtypeList(e.At(3));
        var available = EtypeList(e.At(4));
        var named = Clean(e.At(1));
        var toFix = e.EventId == 16 ? Clean(e.At(5)) : "";
        // The account has AES keys but the request offered none: the requesting side or its policy is the problem.
        var variant = requested.Length > 0 && !HasAes(requested) && HasAes(available) ? $"Requested {requested} without AES, account has {available}"
            : available.Length > 0 && !HasAes(available) ? $"Requested {Or(requested, "?")}, account has no AES keys ({available})"
            : requested.Length > 0 || available.Length > 0 ? $"Requested {Or(requested, "?")}, account has {Or(available, "no usable key")}"
            : $"KDC event {e.EventId}";
        return Build(e, file, pool, LegacyKind.EtypeFailure, variant,
            account: toFix.Length > 0 ? toFix : named,
            domain: "",
            client: toFix.Length > 0 && !toFix.Equals(named, StringComparison.OrdinalIgnoreCase) ? named : "",
            service: Clean(e.At(0)),
            ticket: "",
            session: "",
            extra: [("Requested etypes", requested), ("Available etypes", available), ("Missing key ID", Clean(e.At(2))),
                ("Account named in the event", named), ("Account to reset (16)", toFix)]);
    }

    /// <summary>
    /// Directory Service events. 2889: %1 client IP:port, %2 identity, %3 binding type (0 unsigned SASL,
    /// 1 simple bind without TLS). 2887: %1 simple binds without TLS, %2 SASL binds without signing (last 24 hours).
    /// 3039, 3074, 3075: %1 client IP:port, %2 identity.
    /// </summary>
    private static AuthEvent Ldap(RawEvent e, string file, StringPool pool)
    {
        if (e.EventId is 2887 or 2888)
        {
            var simple = Clean(e.At(0));
            var sasl = Clean(e.At(1));
            var what = e.EventId == 2888 ? "rejected" : "accepted";
            return Build(e, file, pool, LegacyKind.LdapSigning,
                $"Daily summary: {Or(simple, "?")} simple binds without TLS, {Or(sasl, "?")} SASL binds without signing ({what})",
                "", "", "all clients (daily summary)", "", "", "",
                extra: [("Simple binds without TLS", simple), ("SASL binds without signing", sasl)]);
        }
        if (e.EventId == 3040)
        {
            var count = Clean(e.At(0));
            return Build(e, file, pool, LegacyKind.LdapChannelBinding,
                $"Daily summary: {Or(count, "?")} LDAPS binds without channel binding",
                "", "", "all clients (daily summary)", "LDAPS", "", "",
                extra: [("LDAPS binds without channel binding", count)]);
        }

        var client = LdapClient(e.At(0));
        var (account, domain) = SplitIdentity(Clean(e.At(1)));
        if (e.EventId == 2889)
        {
            var bindType = Clean(e.At(2));
            var variant = bindType switch
            {
                "0" => "SASL bind without signing",
                "1" => "Simple bind without TLS (cleartext password)",
                _ => $"Unsigned bind (type {bindType})",
            };
            return Build(e, file, pool, LegacyKind.LdapSigning, variant, account, domain, client, "LDAP", "", "",
                extra: [("Client address", Clean(e.At(0))), ("Binding type", bindType)]);
        }

        var cbt = e.EventId switch
        {
            3039 => "Channel binding token missing or invalid",
            3074 => "Would fail channel binding when enforced",
            _ => "Client sent no channel binding information",
        };
        return Build(e, file, pool, LegacyKind.LdapChannelBinding, cbt, account, domain, client, "LDAPS", "", "",
            extra: [("Client address", Clean(e.At(0)))]);
    }

    /// <summary>"10.0.0.5:51234" becomes "10.0.0.5", "[fe80::1]:389" becomes "fe80::1". Loopback becomes "localhost" like elsewhere.</summary>
    internal static string LdapClient(string value)
    {
        value = Clean(value);
        var end = value.IndexOf(']');
        if (value.StartsWith('[') && end > 0) return CleanIp(value[1..end]);
        return CleanIp(value.Count(c => c == ':') == 1 ? value[..value.IndexOf(':')] : value);
    }

    private static (string Account, string Domain) SplitIdentity(string identity)
    {
        var slash = identity.IndexOf('\\');
        return slash > 0 ? (identity[(slash + 1)..], identity[..slash]) : (identity, "");
    }

    /// <summary>"18 17 23" becomes "AES256-SHA1, AES128-SHA1, RC4-HMAC". Unknown or negative values stay numbers.</summary>
    internal static string EtypeList(string value)
    {
        var parts = Clean(value)
            .Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Select(p => uint.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? EtypeName(n) : p);
        return string.Join(", ", parts);
    }

    private static string Or(string value, string fallback) => value.Length > 0 ? value : fallback;

    private static AuthEvent? Ntlm(RawEvent e, string file, StringPool pool)
    {
        var lm = e["LmPackageName"].Trim();
        string variant;
        if (lm.Equals("NTLM V1", StringComparison.OrdinalIgnoreCase)) variant = "NTLM V1";
        else if (lm.Equals("LM", StringComparison.OrdinalIgnoreCase)) variant = "LM";
        else return null;
        // Windows logs NTLM V1 for every anonymous session because it has no key material. Microsoft recommends ignoring them.
        if (Clean(e["TargetUserSid"]) == AnonymousSid || Clean(e["TargetUserName"]).Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)) return null;

        // The machine name lines up with the NTLM Operational events (4020, 4022, 4030) of the same device. The address stays in the details.
        var ip = CleanIp(e["IpAddress"]);
        var workstation = Clean(e["WorkstationName"]);
        return Build(e, file, pool, LegacyKind.Ntlmv1, variant,
            account: Clean(e["TargetUserName"]),
            domain: Clean(e["TargetDomainName"]),
            client: workstation.Length > 0 ? workstation : ip,
            service: "",
            ticket: "",
            session: "");
    }

    private static AuthEvent? Kerberos(RawEvent e, string file, StringPool pool)
    {
        var ticket = ParseEtype(e["TicketEncryptionType"]);
        var session = ParseEtype(e["SessionKeyEncryptionType"]);
        // 4768 since 2025: the type the account's own key used for pre-authentication.
        var preAuth = e.EventId == 4768 ? ParseEtype(e["PreAuthEncryptionType"]) : null;
        var kind = Worst(ticket, session, preAuth);
        if (kind is null) return null;

        var offered = Clean(e["ClientAdvertizedEncryptionTypes"]);
        var service = Clean(e["ServiceName"]);
        var parts = new List<string>();
        if (ticket is { } t && KindOf(t) is not null)
        {
            parts.Add($"Ticket {EtypeName(t)}");
            // A TGT is encrypted with the key of krbtgt. Without AES keys on krbtgt every TGT is RC4.
            var krbtgtKeys = Clean(e["ServiceAvailableKeys"]);
            if (IsKrbtgtName(service) && krbtgtKeys.Length > 0 && !HasAes(krbtgtKeys)) parts.Add("krbtgt has no AES keys");
        }
        if (session is { } s && KindOf(s) is not null) parts.Add($"Session key {EtypeName(s)}");
        if (preAuth is { } pa && KindOf(pa) is not null)
        {
            // The pre-authentication type is picked from what the client offers. An offer without AES points to the client.
            parts.Add(offered.Length > 0 && !HasAes(offered) ? $"Pre-auth {EtypeName(pa)}, client offered no AES" : $"Pre-auth {EtypeName(pa)}");
        }

        var (account, domain) = SplitRealm(Clean(e["TargetUserName"]), Clean(e["TargetDomainName"]));
        return Build(e, file, pool, kind.Value, string.Join(", ", parts),
            account: account,
            domain: domain,
            client: CleanIp(e["IpAddress"]),
            service: service,
            ticket: ticket is { } tt ? EtypeName(tt) : "",
            session: session is { } ss ? EtypeName(ss) : "");
    }

    internal static bool IsKrbtgtName(string service) =>
        service.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) || service.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase);

    private static AuthEvent KdcWarning(RawEvent e, string file, StringPool pool)
    {
        // Field names of the KDCSVC events are not documented, so take the common ones when present.
        var account = First(e, "AccountName", "ClientName", "Client", "TargetUserName", "UserName");
        var service = First(e, "ServiceName", "Service", "TargetName");
        var client = CleanIp(First(e, "IpAddress", "ClientAddress", "Address"));
        return Build(e, file, pool, LegacyKind.Rc4, $"KDC event {e.EventId}", account, "", client, service, "", "");
    }

    private static AuthEvent Build(RawEvent e, string file, StringPool pool, LegacyKind kind, string variant,
        string account, string domain, string client, string service, string ticket, string session,
        (string Label, string Value)[]? extra = null)
    {
        var fields = new List<KeyValuePair<string, string>>();
        foreach (var (label, value) in extra ?? [])
        {
            if (value.Length > 0) fields.Add(new(label, pool.Get(value)));
        }
        foreach (var name in DetailFields)
        {
            var value = Clean(e[name]);
            if (value.Length > 0) fields.Add(new(name, pool.Get(value)));
        }
        // Undocumented fields of the KDCSVC events are kept as they are.
        if (Providers.IsKdc(e.Provider) && extra is null)
        {
            foreach (var (k, v) in e.Data.Where(d => !DetailFields.Contains(d.Key) && Clean(d.Value).Length > 0))
            {
                fields.Add(new(k, pool.Get(v)));
            }
        }

        return new AuthEvent(
            e.Time,
            pool.Get(e.Computer),
            e.EventId,
            kind,
            pool.Get(variant),
            pool.Get(account),
            pool.Get(domain),
            pool.Get(client),
            pool.Get(service),
            pool.Get(ticket),
            pool.Get(session),
            pool.Get(file),
            e.RecordId,
            fields.ToArray());
    }

    /// <summary>DES is worse than RC4, so DES wins when ticket and session key differ.</summary>
    internal static LegacyKind? Worst(params uint?[] etypes)
    {
        var kinds = etypes.Where(x => x is not null).Select(x => KindOf(x!.Value)).Where(k => k is not null).ToList();
        if (kinds.Contains(LegacyKind.Des)) return LegacyKind.Des;
        if (kinds.Contains(LegacyKind.Rc4)) return LegacyKind.Rc4;
        return null;
    }

    public static LegacyKind? KindOf(uint etype) => etype switch
    {
        DesCbcCrc or DesCbcMd5 => LegacyKind.Des,
        Rc4Hmac or Rc4HmacExp => LegacyKind.Rc4,
        _ => null,
    };

    /// <summary>Parses "0x17", "23" or "0x17 (RC4)" style values. Returns null for empty or unknown text.</summary>
    public static uint? ParseEtype(string value)
    {
        value = value.Trim();
        if (value.Length == 0 || value == "-") return null;
        var space = value.IndexOf(' ');
        if (space > 0) value = value[..space];
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
        {
            return hex;
        }
        return uint.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec) ? dec : null;
    }

    public static string EtypeName(uint etype) => etype switch
    {
        DesCbcCrc => "DES-CBC-CRC",
        DesCbcMd5 => "DES-CBC-MD5",
        0x11 => "AES128-SHA1",
        0x12 => "AES256-SHA1",
        Rc4Hmac => "RC4-HMAC",
        Rc4HmacExp => "RC4-HMAC-EXP",
        0xFFFFFFFF => "none (request failed)",
        _ => $"0x{etype:x}",
    };

    internal static string Clean(string value)
    {
        value = value.Trim();
        return value is "-" or "N/A" ? "" : value;
    }

    internal static string CleanIp(string ip)
    {
        ip = Clean(ip);
        if (ip.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) ip = ip[7..];
        return ip is "::1" or "127.0.0.1" ? "localhost" : ip;
    }

    private static string First(RawEvent e, params string[] names) =>
        names.Select(n => Clean(e[n])).FirstOrDefault(v => v.Length > 0) ?? "";
}

public static class Providers
{
    public const string SecurityAuditing = "Microsoft-Windows-Security-Auditing";
    public const string Kdc = "Microsoft-Windows-Kerberos-Key-Distribution-Center";
    public const string KdcSvc = "KDCSVC";
    public const string Ntlm = "Microsoft-Windows-NTLM";
    public const string Netlogon = "Microsoft-Windows-Security-Netlogon";
    public const string SmbServer = "Microsoft-Windows-SMBServer";

    public static bool IsNtlm(string provider) =>
        provider.Equals(Ntlm, StringComparison.OrdinalIgnoreCase) || provider.Equals(Netlogon, StringComparison.OrdinalIgnoreCase);

    public const string DirectoryService = "Microsoft-Windows-ActiveDirectory_DomainService";

    public static bool IsDirectoryService(string provider) =>
        provider.Equals(DirectoryService, StringComparison.OrdinalIgnoreCase) || provider.StartsWith("NTDS", StringComparison.OrdinalIgnoreCase);

    public static bool IsKdc(string provider) =>
        provider.Equals(Kdc, StringComparison.OrdinalIgnoreCase) || provider.Equals(KdcSvc, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Shares identical strings between events. Millions of events repeat the same few hundred accounts and hosts.</summary>
public sealed class StringPool
{
    // Lock-free reads. A plain dictionary behind one lock made parallel scans wait on each other.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _pool = new(StringComparer.Ordinal);

    public string Get(string value) => value.Length == 0 ? "" : _pool.GetOrAdd(value, value);
}
