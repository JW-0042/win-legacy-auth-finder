namespace LegacyAuthFinder.Core;

/// <summary>The legacy protocols and ciphers the tool looks for.</summary>
public enum LegacyKind
{
    Ntlmv1,
    Rc4,
    Des,
    /// <summary>LDAP binds without signing or with a cleartext password (Directory Service 2887, 2889).</summary>
    LdapSigning,
    /// <summary>LDAP over TLS without a channel binding token (Directory Service 3039, 3074, 3075).</summary>
    LdapChannelBinding,
    /// <summary>Kerberos requests that failed because no common encryption type was found (KDC 14/16/26/27, status 0xE).</summary>
    EtypeFailure,
}

/// <summary>One .evtx file found in the folder, before it is scanned.</summary>
public sealed record LogFileInfo(
    string Path,
    long Size,
    string Channel,
    string Computer,
    long RecordCount,
    long OldestRecordNumber,
    DateTime? First,
    DateTime? Last,
    string? Error = null,
    long FirstRecordId = 0,
    long LastRecordId = 0)
{
    public string Name => System.IO.Path.GetFileName(Path);

    /// <summary>Only Security, System and Directory Service logs can contain the events this tool looks for.</summary>
    public bool IsRelevant => Error is null && Channel is Channels.Security or Channels.System or Channels.DirectoryService;
}

public static class Channels
{
    public const string Security = "Security";
    public const string System = "System";
    public const string DirectoryService = "Directory Service";
}

/// <summary>
/// An event as read from a file: system fields plus the named EventData values that were asked for.
/// <paramref name="Values"/> keeps EventData in document order for older events whose fields have no names.
/// </summary>
public sealed record RawEvent(
    int EventId,
    string Provider,
    DateTime Time,
    string Computer,
    long RecordId,
    IReadOnlyDictionary<string, string> Data,
    IReadOnlyList<string>? Values = null)
{
    public string this[string name] => Data.TryGetValue(name, out var v) ? v : "";

    /// <summary>The n-th EventData value (0-based), or an empty string.</summary>
    public string At(int index) => Values is { } v && index < v.Count ? v[index] : "";
}

/// <summary>A legacy authentication event, reduced to what people search and group by.</summary>
public sealed record AuthEvent(
    DateTime Time,
    string Computer,
    int EventId,
    LegacyKind Kind,
    string Variant,
    string Account,
    string Domain,
    string Client,
    string Service,
    string TicketEncryption,
    string SessionEncryption,
    string File,
    long RecordId,
    IReadOnlyList<KeyValuePair<string, string>> Fields)
{
    public string KindLabel => Guidance.Label(Kind);

    public string What => EventId switch
    {
        4624 => "Successful logon",
        4625 => "Failed logon",
        4768 => "Kerberos TGT request",
        4769 => "Kerberos service ticket",
        4770 => "Kerberos ticket renewed",
        4771 => "Kerberos pre-authentication failed",
        2887 => "LDAP daily summary",
        2889 => "LDAP bind without signing",
        3039 => "LDAP channel binding failed",
        3074 => "LDAP bind would fail channel binding",
        3075 => "LDAP bind without channel binding info",
        _ => Guidance.KdcEventText(EventId),
    };

    /// <summary>True when every search term appears in at least one of the visible columns.</summary>
    public bool Matches(IReadOnlyList<string> terms)
    {
        foreach (var term in terms)
        {
            if (!(Account.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || Client.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || Service.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || Computer.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || Domain.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || Variant.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || KindLabel.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || File.Contains(term, StringComparison.OrdinalIgnoreCase)
                  || EventId.ToString() == term))
            {
                return false;
            }
        }
        return true;
    }
}

/// <summary>Grouping key of the summary. Account, client and service compare case-insensitively.</summary>
public readonly record struct SummaryKey(LegacyKind Kind, string Account, string Client, string Service)
{
    public static IEqualityComparer<SummaryKey> Comparer { get; } = new KeyComparer();

    private sealed class KeyComparer : IEqualityComparer<SummaryKey>
    {
        private static readonly StringComparer Text = StringComparer.OrdinalIgnoreCase;

        public bool Equals(SummaryKey a, SummaryKey b) =>
            a.Kind == b.Kind && Text.Equals(a.Account, b.Account) && Text.Equals(a.Client, b.Client) && Text.Equals(a.Service, b.Service);

        public int GetHashCode(SummaryKey k) =>
            HashCode.Combine(k.Kind, Text.GetHashCode(k.Account), Text.GetHashCode(k.Client), Text.GetHashCode(k.Service));
    }
}

/// <summary>Events grouped by who and what: the list to work through when fixing things.</summary>
public sealed class SummaryRow
{
    public static void Add(Dictionary<SummaryKey, SummaryRow> rows, AuthEvent e)
    {
        var key = new SummaryKey(e.Kind, e.Account, e.Client, e.Service);
        if (!rows.TryGetValue(key, out var row))
        {
            row = new SummaryRow { Kind = e.Kind, Account = e.Account, Client = e.Client, Service = e.Service };
            rows[key] = row;
        }
        row.Count++;
        if (e.Time < row.FirstSeen) row.FirstSeen = e.Time;
        if (e.Time > row.LastSeen) row.LastSeen = e.Time;
        if (e.Computer.Length > 0) row.Computers.Add(e.Computer);
        row.Variants.Add(e.Variant);
    }

    /// <summary>Adds another row for the same key, for example from another file.</summary>
    public void Absorb(SummaryRow other)
    {
        Count += other.Count;
        if (other.FirstSeen < FirstSeen) FirstSeen = other.FirstSeen;
        if (other.LastSeen > LastSeen) LastSeen = other.LastSeen;
        Computers.UnionWith(other.Computers);
        Variants.UnionWith(other.Variants);
    }

    public required LegacyKind Kind { get; init; }
    public required string Account { get; init; }
    public required string Client { get; init; }
    public required string Service { get; init; }
    public long Count { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.MaxValue;
    public DateTime LastSeen { get; set; } = DateTime.MinValue;
    public SortedSet<string> Computers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SortedSet<string> Variants { get; } = new(StringComparer.Ordinal);

    public string KindLabel => Guidance.Label(Kind);
    public string ComputersText => string.Join(", ", Computers);
    public string VariantsText => string.Join(", ", Variants);

    public bool Matches(IReadOnlyList<string> terms) => terms.All(t =>
        Account.Contains(t, StringComparison.OrdinalIgnoreCase)
        || Client.Contains(t, StringComparison.OrdinalIgnoreCase)
        || Service.Contains(t, StringComparison.OrdinalIgnoreCase)
        || ComputersText.Contains(t, StringComparison.OrdinalIgnoreCase)
        || VariantsText.Contains(t, StringComparison.OrdinalIgnoreCase)
        || KindLabel.Contains(t, StringComparison.OrdinalIgnoreCase));
}

public enum FileState
{
    Queued,
    Skipped,
    Scanning,
    Done,
    Cancelled,
    Error,
}

public sealed record FileProgress(string Path, FileState State, long Hits, double? Percent, string Message);

public sealed record ScanResult(
    IReadOnlyList<LogFileInfo> Files,
    IReadOnlyList<AuthEvent> Events,
    IReadOnlyList<SummaryRow> Summary,
    IReadOnlyDictionary<string, FileProgress> FileResults,
    long TotalHits,
    bool Truncated,
    bool Cancelled,
    TimeSpan Duration,
    string Scope)
{
    public long Count(LegacyKind kind) => Summary.Where(s => s.Kind == kind).Sum(s => s.Count);
}
