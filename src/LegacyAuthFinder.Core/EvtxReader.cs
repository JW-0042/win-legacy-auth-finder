using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security.Principal;
using System.Xml.Linq;

namespace LegacyAuthFinder.Core;

/// <summary>
/// One filtered pass over a file. The XPath filter runs inside the Windows event log API, so a 4 GB file is
/// streamed and only matching records reach .NET. Fields are pulled by name with a property selector, which is
/// much faster than rendering XML. Fields null means the full EventData is read through XML (used for rare events),
/// unless <paramref name="Positional"/> is set: then the unnamed insertion strings are read in order, which is fast.
/// The built-in parser (<see cref="EvtxFileReader"/>) does not use XPath. It applies <paramref name="EventIds"/>,
/// <paramref name="Providers"/> and <paramref name="Filter"/>, which must select exactly the same records.
/// </summary>
public sealed record EvtxQuery(string Name, string Channel, string XPath, IReadOnlyList<string>? Fields, bool Positional = false,
    IReadOnlySet<int>? EventIds = null, IReadOnlyList<string>? Providers = null, Func<IRecordView, bool>? Filter = null);

public interface IEvtxReader
{
    LogFileInfo Inspect(string path);

    /// <param name="alive">Called now and then while the file is being read but nothing has matched yet.</param>
    IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null);
}

public static class Queries
{
    public static readonly IReadOnlyList<string> NtlmFields =
    [
        "TargetUserName", "TargetDomainName", "TargetUserSid", "WorkstationName", "IpAddress", "IpPort", "LogonType",
        "LmPackageName", "AuthenticationPackageName", "KeyLength", "LogonProcessName", "ProcessName", "Status", "SubStatus",
    ];

    public static readonly IReadOnlyList<string> KerberosFields =
    [
        "TargetUserName", "TargetDomainName", "ServiceName", "IpAddress", "IpPort", "TicketOptions", "Status", "PreAuthType",
        "TicketEncryptionType", "SessionKeyEncryptionType", "PreAuthEncryptionType", "ClientAdvertizedEncryptionTypes",
        "AccountSupportedEncryptionTypes", "AccountAvailableKeys", "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys",
        "DCSupportedEncryptionTypes", "DCAvailableKeys",
    ];

    public static readonly IReadOnlyList<string> KerberosFailureFields = [.. KerberosFields, "FailureCode"];

    private static readonly string[] WeakEtypes = ["0x17", "0x18", "0x1", "0x3"];

    private static IReadOnlySet<int> Ids(params int[] ids) => new HashSet<int>(ids);

    private static IReadOnlySet<int> Range(int from, int to) => new HashSet<int>(Enumerable.Range(from, to - from + 1));

    private static bool Weak(IRecordView v, string field) => v.Number(field) is 0x17 or 0x18 or 0x1 or 0x3;

    private static bool Is0xE(IRecordView v, string field) => v.Number(field) == Classifier.EtypeNotSupported;

    public static EvtxQuery Ntlmv1 { get; } = new("NTLMv1 logons", Channels.Security,
        "*[System[(EventID=4624 or EventID=4625)] and EventData[Data[@Name='LmPackageName']='NTLM V1' or Data[@Name='LmPackageName']='LM']]",
        NtlmFields, EventIds: Ids(4624, 4625), Filter: v => v.Get("LmPackageName") is "NTLM V1" or "LM");

    public static EvtxQuery Kerberos { get; } = new("RC4 and DES Kerberos tickets", Channels.Security,
        "*[System[(EventID=4768 or EventID=4769 or EventID=4770)] and EventData["
        + string.Join(" or ", WeakEtypes.SelectMany(t => new[]
        {
            $"Data[@Name='TicketEncryptionType']='{t}'",
            $"Data[@Name='SessionKeyEncryptionType']='{t}'",
            $"Data[@Name='PreAuthEncryptionType']='{t}'",
        }))
        + "]]",
        KerberosFields, EventIds: Ids(4768, 4769, 4770),
        Filter: v => Weak(v, "TicketEncryptionType") || Weak(v, "SessionKeyEncryptionType") || (v.EventId == 4768 && Weak(v, "PreAuthEncryptionType")));

    // A TGT issued without pre-authentication: the account has "Do not require Kerberos preauthentication" set.
    public static EvtxQuery NoPreAuth { get; } = new("Accounts without Kerberos pre-authentication", Channels.Security,
        "*[System[EventID=4768] and EventData[Data[@Name='PreAuthType']='0']]",
        KerberosFields, EventIds: Ids(4768), Filter: v => v.Get("PreAuthType") == "0");

    // Domain controllers log 4776 for every NTLM credential validation, also where the enhanced NTLM events do not exist yet.
    public static EvtxQuery NtlmValidation { get; } = new("NTLM validation on domain controllers", Channels.Security,
        "*[System[EventID=4776]]", ["TargetUserName", "Workstation", "Status", "PackageName"], EventIds: Ids(4776));

    public static EvtxQuery KdcWarnings { get; } = new("KDC RC4 warnings", Channels.System,
        $"*[System[(Provider[@Name='{Providers.KdcSvc}'] or Provider[@Name='{Providers.Kdc}']) and (EventID>=201 and EventID<=209)]]",
        null, EventIds: Range(201, 209), Providers: [Providers.KdcSvc, Providers.Kdc]);

    // KDC_ERR_ETYPE_NOSUPP. Hex values are rendered in lower case, the upper case variant is only a safety net.
    public static EvtxQuery KerberosEtypeFailures { get; } = new("Kerberos encryption type failures", Channels.Security,
        "*[System[(EventID=4768 or EventID=4769 or EventID=4771)] and EventData["
        + "Data[@Name='Status']='0xe' or Data[@Name='Status']='0xE' or Data[@Name='FailureCode']='0xe' or Data[@Name='FailureCode']='0xE']]",
        KerberosFailureFields, EventIds: Ids(4768, 4769, 4771), Filter: v => Is0xE(v, "Status") || Is0xE(v, "FailureCode"));

    public static EvtxQuery KdcEtypeErrors { get; } = new("KDC encryption type errors", Channels.System,
        $"*[System[Provider[@Name='{Providers.Kdc}'] and (EventID=14 or EventID=16 or EventID=26 or EventID=27)]]",
        null, Positional: true, EventIds: Ids(14, 16, 26, 27), Providers: [Providers.Kdc]);

    // Logged on domain controllers. 2889 needs the "16 LDAP Interface Events" diagnostic value set to 2.
    public static EvtxQuery Ldap { get; } = new("LDAP signing and channel binding", Channels.DirectoryService,
        "*[System[(EventID=2887 or EventID=2888 or EventID=2889 or EventID=3039 or EventID=3040 or EventID=3074 or EventID=3075)]]",
        null, Positional: true, EventIds: Ids(2887, 2888, 2889, 3039, 3040, 3074, 3075));

    // Field names taken from the provider manifests (Get-WinEvent -ListProvider). XPath compares names case-sensitively,
    // so both spellings Microsoft uses (Username in 4020 to 4023, UserName in 4024, 4025 and 8001 to 8004) are listed.
    public static readonly IReadOnlyList<string> NtlmOperationalFields =
    [
        "Username", "UserName", "DomainName", "Hostname", "ProcessName", "TargetMachine", "TargetDomain", "TargetService",
        "TargetIP", "NtlmUsageId", "NtlmUsageReason", "NtlmVersion", "RemoteClientMachine", "ClientIP", "ClientNetworkName",
        "Status", "StatusMsg", "TargetName", "ClientUserName", "ClientDomainName", "Workstation", "WorkstationName",
        "LogonType", "SChannelName", "SChannelType", "AccountName", "AccountDomain", "AccountMachine", "ServerName",
        "ServerDomain", "ServerIP", "ForwarderName", "ForwarderIP", "ChannelBindingStatus", "Mic Status", "DCName",
        "NtlmBlockingReason",
    ];

    // Enhanced NTLM auditing (Windows 11 24H2, Windows Server 2025, Server 2019 and 2022 from the October 2026 updates):
    // 4020 to 4023 on clients and servers, 4030 to 4033 on domain controllers, 4024 and 4025 for NTLMv1-derived
    // single sign-on, 4026 and 4027 for NTLM that would be or was blocked. 4013 is a failed NTLMv1 attempt.
    // The "Restrict NTLM" events are read as well: 8001 to 8004 in audit mode, 4001 to 4006 when blocking (4004 to 4006
    // are the domain controller's own, from Security-Netlogon).
    public static EvtxQuery NtlmOperational { get; } = new("NTLM use", Channels.NtlmOperational,
        "*[System[(EventID=8001 or EventID=8002 or EventID=8003 or EventID=8004 or (EventID>=4001 and EventID<=4006) or EventID=4013"
        + " or (EventID>=4020 and EventID<=4027) or (EventID>=4030 and EventID<=4033))]]",
        NtlmOperationalFields, EventIds: new HashSet<int>([.. Enumerable.Range(8001, 4), .. Enumerable.Range(4001, 6), 4013, .. Enumerable.Range(4020, 8), .. Enumerable.Range(4030, 4)]));

    // Logged only after Set-SmbServerConfiguration -AuditSmb1Access $true.
    public static EvtxQuery Smb1 { get; } = new("SMBv1 access", Channels.SmbServerAudit,
        "*[System[EventID=3000]]", ["ClientName"], EventIds: Ids(3000));

    public static IReadOnlyList<EvtxQuery> All { get; } =
        [Ntlmv1, Kerberos, KerberosEtypeFailures, NoPreAuth, NtlmValidation, KdcWarnings, KdcEtypeErrors, Ldap, NtlmOperational, Smb1];

    public static IEnumerable<EvtxQuery> For(string channel) => All.Where(q => q.Channel == channel);
}

public sealed class WindowsEvtxReader : IEvtxReader
{
    /// <summary>Optional: called with the file path and "opening query", "reading" or "closing query". Used by the diagnostic log.</summary>
    public Action<string, string>? OnPhase { get; set; }

    /// <summary>Optional diagnostic log for the timings of <see cref="Inspect"/>.</summary>
    public DiagLog? Log { get; set; }

    private static readonly HashSet<string> HexFields = new(StringComparer.Ordinal)
    {
        "TicketEncryptionType", "SessionKeyEncryptionType", "PreAuthEncryptionType", "TicketOptions", "Status", "SubStatus", "FailureCode",
    };

    public LogFileInfo Inspect(string path)
    {
        long size = 0;
        try
        {
            size = new FileInfo(path).Length;
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var info = EventLogSession.GlobalSession.GetLogInformation(path, PathType.FilePath);
            var tInfo = clock.ElapsedMilliseconds;
            var (channel, computer, first, firstId) = Edge(path, reverse: false);
            var tFirst = clock.ElapsedMilliseconds;
            var (_, _, last, lastId) = Edge(path, reverse: true);
            Log?.Write("INSPECT", $"{Path.GetFileName(path)}: log information {tInfo} ms, first record {tFirst - tInfo} ms, last record {clock.ElapsedMilliseconds - tFirst} ms");
            return new LogFileInfo(path, size, channel ?? "(empty)", computer ?? "", info.RecordCount ?? 0, info.OldestRecordNumber ?? 0, first, last,
                FirstRecordId: firstId, LastRecordId: lastId);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException)
        {
            Log?.Write("INSPECT", $"{Path.GetFileName(path)}: Windows API cannot read it: {ex.GetType().Name}: {ex.Message.Trim()}");
            return new LogFileInfo(path, size, "", "", 0, 0, null, null, $"Cannot read this file. It may be damaged or not an event log file. ({ex.Message.Trim()})");
        }
    }

    // Exported and archived logs keep their original record IDs, so the first ID is rarely 1.
    private static (string? Channel, string? Computer, DateTime? Time, long RecordId) Edge(string path, bool reverse)
    {
        using var reader = new EventLogReader(new EventLogQuery(path, PathType.FilePath, "*") { ReverseDirection = reverse });
        using var record = reader.ReadEvent();
        return record is null ? (null, null, null, 0) : (record.LogName, record.MachineName, record.TimeCreated, record.RecordId ?? 0);
    }

    /// <summary>
    /// How long one read may run before it comes back without a result. The event log service scans the whole file
    /// for the next match, so without this a file with no findings is one long blocking call that cannot be cancelled.
    /// </summary>
    internal static TimeSpan ReadSlice { get; set; } = TimeSpan.FromMilliseconds(500);

    private static readonly string TimeoutMessage = new Win32Exception(ErrorTimeout).Message;
    private const int ErrorTimeout = 1460;

    /// <summary>The API reports an expired read slice as a generic exception, so it is told apart by its message.</summary>
    internal static bool IsTimeout(EventLogException ex) => ex.Message == TimeoutMessage;

    public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null)
    {
        var phase = OnPhase;
        phase?.Invoke(path, "opening query");
        using var reader = new EventLogReader(new EventLogQuery(path, PathType.FilePath, query.XPath));
        using var closing = new PhaseOnDispose(phase, path, "closing query");
        phase?.Invoke(path, "reading");
        using var selector = query.Fields is null
            ? null
            : new EventLogPropertySelector(query.Fields.Select(f => $"Event/EventData/Data[@Name='{f}']"));
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EventRecord? record;
            try
            {
                record = reader.ReadEvent(ReadSlice);
            }
            catch (EventLogException ex) when (IsTimeout(ex))
            {
                alive?.Invoke();
                continue;
            }
            using var _ = record;
            if (record is null) yield break;
            Dictionary<string, string> data;
            IReadOnlyList<string>? values = null;
            if (query.Positional)
            {
                data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                values = record.Properties.Select(p => Format("", p.Value)).ToList();
            }
            else if (selector is null || record is not EventLogRecord typed)
            {
                (data, values) = EventDataFromXml(record.ToXml());
            }
            else
            {
                data = Named(query.Fields!, typed.GetPropertyValues(selector));
            }
            yield return new RawEvent(record.Id, record.ProviderName ?? "", record.TimeCreated ?? DateTime.MinValue,
                record.MachineName ?? "", record.RecordId ?? 0, data, values);
        }
    }

    /// <summary>Reports the closing phase before the reader is disposed (disposal runs in reverse order).</summary>
    private sealed class PhaseOnDispose(Action<string, string>? phase, string path, string name) : IDisposable
    {
        public void Dispose() => phase?.Invoke(path, name);
    }

    private static Dictionary<string, string> Named(IReadOnlyList<string> names, IList<object?> values)
    {
        var data = new Dictionary<string, string>(names.Count, StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < names.Count && i < values.Count; i++)
        {
            var text = Format(names[i], values[i]);
            if (text.Length > 0) data[names[i]] = text;
        }
        return data;
    }

    internal static string Format(string field, object? value) => value switch
    {
        null => "",
        string s => s,
        uint u when HexFields.Contains(field) => $"0x{u:x}",
        int i when HexFields.Contains(field) => $"0x{i:x}",
        ulong ul when HexFields.Contains(field) => $"0x{ul:x}",
        SecurityIdentifier sid => sid.Value,
        byte[] bytes => Convert.ToHexString(bytes),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    internal static (Dictionary<string, string> Data, List<string> Values) EventDataFromXml(string xml)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var values = new List<string>();
        var root = XDocument.Parse(xml).Root;
        if (root?.Element(Ns + "EventData") is { } eventData)
        {
            var i = 0;
            foreach (var d in eventData.Elements(Ns + "Data"))
            {
                i++;
                data[d.Attribute("Name")?.Value ?? $"Param{i}"] = d.Value;
                values.Add(d.Value);
            }
        }
        if (root?.Element(Ns + "UserData") is { } userData)
        {
            foreach (var leaf in userData.Descendants().Where(e => !e.HasElements))
            {
                data[leaf.Name.LocalName] = leaf.Value;
                values.Add(leaf.Value);
            }
        }
        return (data, values);
    }
}
