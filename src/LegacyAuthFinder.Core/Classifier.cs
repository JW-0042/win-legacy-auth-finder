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
        "WorkstationName", "IpAddress", "IpPort", "Status", "SubStatus",
        "TicketOptions", "PreAuthType", "FailureCode", "ClientAdvertizedEncryptionTypes",
        "AccountSupportedEncryptionTypes", "AccountAvailableKeys",
        "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys",
        "DCSupportedEncryptionTypes", "DCAvailableKeys",
    ];

    public static AuthEvent? Classify(RawEvent e, string file, StringPool pool) => e.EventId switch
    {
        4624 or 4625 when e.Provider is "" or Providers.SecurityAuditing => Ntlm(e, file, pool),
        4768 or 4769 or 4770 or 4771 when e.Provider is "" or Providers.SecurityAuditing =>
            IsEtypeFailure(e) ? SecurityEtypeFailure(e, file, pool) : e.EventId == 4771 ? null : Kerberos(e, file, pool),
        >= 201 and <= 209 when Providers.IsKdc(e.Provider) => KdcWarning(e, file, pool),
        14 or 16 or 26 or 27 when Providers.IsKdc(e.Provider) => KdcEtypeError(e, file, pool),
        2887 or 2889 or 3039 or 3074 or 3075 when e.Provider is "" || Providers.IsDirectoryService(e.Provider) => Ldap(e, file, pool),
        _ => null,
    };

    private static bool IsEtypeFailure(RawEvent e) =>
        ParseEtype(e["Status"]) == EtypeNotSupported || ParseEtype(e["FailureCode"]) == EtypeNotSupported;

    private static AuthEvent SecurityEtypeFailure(RawEvent e, string file, StringPool pool)
    {
        var offered = Clean(e["ClientAdvertizedEncryptionTypes"]);
        return Build(e, file, pool, LegacyKind.EtypeFailure,
            offered.Length > 0 ? $"No common encryption type, client offered {offered}" : "No common encryption type (0xE)",
            account: Clean(e["TargetUserName"]),
            domain: Clean(e["TargetDomainName"]),
            client: CleanIp(e["IpAddress"]),
            service: Clean(e["ServiceName"]),
            ticket: "",
            session: "");
    }

    /// <summary>
    /// KDC events 14, 16, 26 and 27. Microsoft documents the insertion strings as: %1 target service,
    /// %2 account, %3 missing key ID, %4 requested etypes, %5 the account's available etypes.
    /// </summary>
    private static AuthEvent KdcEtypeError(RawEvent e, string file, StringPool pool)
    {
        var requested = EtypeList(e.At(3));
        var available = EtypeList(e.At(4));
        var variant = requested.Length > 0 || available.Length > 0
            ? $"Requested {Or(requested, "?")}, account has {Or(available, "no usable key")}"
            : $"KDC event {e.EventId}";
        return Build(e, file, pool, LegacyKind.EtypeFailure, variant,
            account: Clean(e.At(1)),
            domain: "",
            client: "",
            service: Clean(e.At(0)),
            ticket: "",
            session: "",
            extra: [("Requested etypes", requested), ("Available etypes", available), ("Missing key ID", Clean(e.At(2)))]);
    }

    /// <summary>
    /// Directory Service events. 2889: %1 client IP:port, %2 identity, %3 binding type (0 unsigned SASL,
    /// 1 simple bind without TLS). 2887: %1 simple binds without TLS, %2 SASL binds without signing (last 24 hours).
    /// 3039, 3074, 3075: %1 client IP:port, %2 identity.
    /// </summary>
    private static AuthEvent Ldap(RawEvent e, string file, StringPool pool)
    {
        if (e.EventId == 2887)
        {
            var simple = Clean(e.At(0));
            var sasl = Clean(e.At(1));
            return Build(e, file, pool, LegacyKind.LdapSigning,
                $"Daily summary: {Or(simple, "?")} simple binds without TLS, {Or(sasl, "?")} SASL binds without signing",
                "", "", "all clients (daily summary)", "", "", "",
                extra: [("Simple binds without TLS", simple), ("SASL binds without signing", sasl)]);
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

    /// <summary>"10.0.0.5:51234" becomes "10.0.0.5", "[fe80::1]:389" becomes "fe80::1".</summary>
    internal static string LdapClient(string value)
    {
        value = Clean(value);
        var end = value.IndexOf(']');
        if (value.StartsWith('[') && end > 0) return value[1..end];
        return value.Count(c => c == ':') == 1 ? value[..value.IndexOf(':')] : value;
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

        var ip = CleanIp(e["IpAddress"]);
        var workstation = Clean(e["WorkstationName"]);
        return Build(e, file, pool, LegacyKind.Ntlmv1, variant,
            account: Clean(e["TargetUserName"]),
            domain: Clean(e["TargetDomainName"]),
            client: ip.Length > 0 ? ip : workstation,
            service: "",
            ticket: "",
            session: "");
    }

    private static AuthEvent? Kerberos(RawEvent e, string file, StringPool pool)
    {
        var ticket = ParseEtype(e["TicketEncryptionType"]);
        var session = ParseEtype(e["SessionKeyEncryptionType"]);
        var kind = Worst(ticket, session);
        if (kind is null) return null;

        var parts = new List<string>();
        if (ticket is { } t && KindOf(t) is not null) parts.Add($"Ticket {EtypeName(t)}");
        if (session is { } s && KindOf(s) is not null) parts.Add($"Session key {EtypeName(s)}");

        return Build(e, file, pool, kind.Value, string.Join(", ", parts),
            account: Clean(e["TargetUserName"]),
            domain: Clean(e["TargetDomainName"]),
            client: CleanIp(e["IpAddress"]),
            service: Clean(e["ServiceName"]),
            ticket: ticket is { } tt ? EtypeName(tt) : "",
            session: session is { } ss ? EtypeName(ss) : "");
    }

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
            fields);
    }

    /// <summary>DES is worse than RC4, so DES wins when ticket and session key differ.</summary>
    internal static LegacyKind? Worst(uint? ticket, uint? session)
    {
        var kinds = new[] { ticket, session }.Where(x => x is not null).Select(x => KindOf(x!.Value)).Where(k => k is not null).ToList();
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

    public const string DirectoryService = "Microsoft-Windows-ActiveDirectory_DomainService";

    public static bool IsDirectoryService(string provider) =>
        provider.Equals(DirectoryService, StringComparison.OrdinalIgnoreCase) || provider.StartsWith("NTDS", StringComparison.OrdinalIgnoreCase);

    public static bool IsKdc(string provider) =>
        provider.Equals(Kdc, StringComparison.OrdinalIgnoreCase) || provider.Equals(KdcSvc, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Shares identical strings between events. Millions of events repeat the same few hundred accounts and hosts.</summary>
public sealed class StringPool
{
    private readonly Dictionary<string, string> _pool = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    public string Get(string value)
    {
        if (value.Length == 0) return "";
        lock (_lock)
        {
            if (_pool.TryGetValue(value, out var existing)) return existing;
            _pool[value] = value;
            return value;
        }
    }
}
