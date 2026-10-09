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
/// </summary>
public sealed record EvtxQuery(string Name, string Channel, string XPath, IReadOnlyList<string>? Fields, bool Positional = false);

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
        "TargetUserName", "TargetDomainName", "WorkstationName", "IpAddress", "IpPort", "LogonType",
        "LmPackageName", "AuthenticationPackageName", "KeyLength", "LogonProcessName", "ProcessName", "Status", "SubStatus",
    ];

    public static readonly IReadOnlyList<string> KerberosFields =
    [
        "TargetUserName", "TargetDomainName", "ServiceName", "IpAddress", "IpPort", "TicketOptions", "Status", "PreAuthType",
        "TicketEncryptionType", "SessionKeyEncryptionType", "ClientAdvertizedEncryptionTypes",
        "AccountSupportedEncryptionTypes", "AccountAvailableKeys", "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys",
        "DCSupportedEncryptionTypes", "DCAvailableKeys",
    ];

    public static readonly IReadOnlyList<string> KerberosFailureFields = [.. KerberosFields, "FailureCode"];

    private static readonly string[] WeakEtypes = ["0x17", "0x18", "0x1", "0x3"];

    public static EvtxQuery Ntlmv1 { get; } = new("NTLMv1 logons", Channels.Security,
        "*[System[(EventID=4624 or EventID=4625)] and EventData[Data[@Name='LmPackageName']='NTLM V1' or Data[@Name='LmPackageName']='LM']]",
        NtlmFields);

    public static EvtxQuery Kerberos { get; } = new("RC4 and DES Kerberos tickets", Channels.Security,
        "*[System[(EventID=4768 or EventID=4769 or EventID=4770)] and EventData["
        + string.Join(" or ", WeakEtypes.SelectMany(t => new[]
        {
            $"Data[@Name='TicketEncryptionType']='{t}'",
            $"Data[@Name='SessionKeyEncryptionType']='{t}'",
        }))
        + "]]",
        KerberosFields);

    public static EvtxQuery KdcWarnings { get; } = new("KDC RC4 warnings", Channels.System,
        $"*[System[(Provider[@Name='{Providers.KdcSvc}'] or Provider[@Name='{Providers.Kdc}']) and (EventID>=201 and EventID<=209)]]",
        null);

    // KDC_ERR_ETYPE_NOSUPP. Hex values are rendered in lower case, the upper case variant is only a safety net.
    public static EvtxQuery KerberosEtypeFailures { get; } = new("Kerberos encryption type failures", Channels.Security,
        "*[System[(EventID=4768 or EventID=4769 or EventID=4771)] and EventData["
        + "Data[@Name='Status']='0xe' or Data[@Name='Status']='0xE' or Data[@Name='FailureCode']='0xe' or Data[@Name='FailureCode']='0xE']]",
        KerberosFailureFields);

    public static EvtxQuery KdcEtypeErrors { get; } = new("KDC encryption type errors", Channels.System,
        $"*[System[Provider[@Name='{Providers.Kdc}'] and (EventID=14 or EventID=16 or EventID=26 or EventID=27)]]",
        null, Positional: true);

    // Logged on domain controllers. 2889 needs the "16 LDAP Interface Events" diagnostic value set to 2.
    public static EvtxQuery Ldap { get; } = new("LDAP signing and channel binding", Channels.DirectoryService,
        "*[System[(EventID=2887 or EventID=2889 or EventID=3039 or EventID=3074 or EventID=3075)]]",
        null, Positional: true);

    public static IReadOnlyList<EvtxQuery> All { get; } = [Ntlmv1, Kerberos, KerberosEtypeFailures, KdcWarnings, KdcEtypeErrors, Ldap];

    public static IEnumerable<EvtxQuery> For(string channel) => All.Where(q => q.Channel == channel);
}

public sealed class WindowsEvtxReader : IEvtxReader
{
    private static readonly HashSet<string> HexFields = new(StringComparer.Ordinal)
    {
        "TicketEncryptionType", "SessionKeyEncryptionType", "TicketOptions", "Status", "SubStatus", "FailureCode",
    };

    public LogFileInfo Inspect(string path)
    {
        var size = new FileInfo(path).Length;
        try
        {
            var info = EventLogSession.GlobalSession.GetLogInformation(path, PathType.FilePath);
            var (channel, computer, first, firstId) = Edge(path, reverse: false);
            var (_, _, last, lastId) = Edge(path, reverse: true);
            return new LogFileInfo(path, size, channel ?? "(empty)", computer ?? "", info.RecordCount ?? 0, info.OldestRecordNumber ?? 0, first, last,
                FirstRecordId: firstId, LastRecordId: lastId);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException)
        {
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
        using var reader = new EventLogReader(new EventLogQuery(path, PathType.FilePath, query.XPath));
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
