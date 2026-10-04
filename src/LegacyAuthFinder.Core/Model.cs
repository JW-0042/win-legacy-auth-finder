namespace LegacyAuthFinder.Core;

/// <summary>The legacy protocols and ciphers the tool looks for.</summary>
public enum LegacyKind
{
    Ntlmv1,
    Rc4,
    Des,
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
    string? Error = null)
{
    public string Name => System.IO.Path.GetFileName(Path);

    /// <summary>Only Security and System logs can contain the events this tool looks for.</summary>
    public bool IsRelevant => Error is null && Channel is Channels.Security or Channels.System;
}

public static class Channels
{
    public const string Security = "Security";
    public const string System = "System";
}

/// <summary>An event as read from a file: system fields plus the named EventData values that were asked for.</summary>
public sealed record RawEvent(
    int EventId,
    string Provider,
    DateTime Time,
    string Computer,
    long RecordId,
    IReadOnlyDictionary<string, string> Data)
{
    public string this[string name] => Data.TryGetValue(name, out var v) ? v : "";
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

/// <summary>Events grouped by who and what: the list to work through when fixing things.</summary>
public sealed class SummaryRow
{
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
