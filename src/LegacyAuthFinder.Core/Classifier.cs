using System.Globalization;

namespace LegacyAuthFinder.Core;

/// <summary>Decides whether an event shows NTLMv1, RC4 or DES and pulls out the columns.</summary>
public static class Classifier
{
    public const uint DesCbcCrc = 0x1;
    public const uint DesCbcMd5 = 0x3;
    public const uint Rc4Hmac = 0x17;
    public const uint Rc4HmacExp = 0x18;

    /// <summary>Extra fields kept for the detail view, in display order.</summary>
    private static readonly string[] DetailFields =
    [
        "LogonType", "AuthenticationPackageName", "LmPackageName", "KeyLength", "LogonProcessName", "ProcessName",
        "WorkstationName", "IpAddress", "IpPort", "Status", "SubStatus",
        "TicketOptions", "PreAuthType", "ClientAdvertizedEncryptionTypes",
        "AccountSupportedEncryptionTypes", "AccountAvailableKeys",
        "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys",
        "DCSupportedEncryptionTypes", "DCAvailableKeys",
    ];

    public static AuthEvent? Classify(RawEvent e, string file, StringPool pool) => e.EventId switch
    {
        4624 or 4625 when e.Provider is "" or Providers.SecurityAuditing => Ntlm(e, file, pool),
        4768 or 4769 or 4770 when e.Provider is "" or Providers.SecurityAuditing => Kerberos(e, file, pool),
        >= 201 and <= 209 when Providers.IsKdc(e.Provider) => KdcWarning(e, file, pool),
        _ => null,
    };

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
        string account, string domain, string client, string service, string ticket, string session)
    {
        var fields = new List<KeyValuePair<string, string>>();
        foreach (var name in DetailFields)
        {
            var value = Clean(e[name]);
            if (value.Length > 0) fields.Add(new(name, pool.Get(value)));
        }
        // Undocumented fields of the KDC events are kept as they are.
        if (Providers.IsKdc(e.Provider))
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
