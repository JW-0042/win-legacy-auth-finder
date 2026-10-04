using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace LegacyAuthFinder.Core;

public sealed record ScanOptions(int Threads = 2, int MaxEvents = Scanner.DefaultMaxEvents);

public static class Scanner
{
    /// <summary>Events kept for the event list. The summary always counts every event, also beyond this limit.</summary>
    public const int DefaultMaxEvents = 5_000_000;

    private const int FlushSize = 4096;
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(300);

    /// <summary>Finds all .evtx files and works out which log each one belongs to.</summary>
    public static IReadOnlyList<LogFileInfo> Inventory(IEvtxReader reader, string folder, bool recurse,
        IProgress<LogFileInfo>? progress = null, CancellationToken cancellationToken = default)
    {
        var paths = Directory.EnumerateFiles(folder, "*.evtx", new EnumerationOptions
            {
                RecurseSubdirectories = recurse,
                IgnoreInaccessible = true,
                MatchCasing = MatchCasing.CaseInsensitive,
            })
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var result = new LogFileInfo[paths.Count];
        Parallel.For(0, paths.Count, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = cancellationToken }, i =>
        {
            result[i] = reader.Inspect(paths[i]);
            progress?.Report(result[i]);
        });
        return result;
    }

    public static ScanResult Scan(IEvtxReader reader, IReadOnlyList<LogFileInfo> files, string scope, ScanOptions options,
        IProgress<FileProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clock = Stopwatch.StartNew();
        var pool = new StringPool();
        var gate = new Lock();
        var events = new List<AuthEvent>();
        var summary = new Dictionary<(LegacyKind, string, string, string), SummaryRow>();
        var results = new ConcurrentDictionary<string, FileProgress>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        var truncated = false;

        void Report(FileProgress p)
        {
            results[p.Path] = p;
            progress?.Report(p);
        }

        void Flush(List<AuthEvent> batch)
        {
            lock (gate)
            {
                foreach (var e in batch)
                {
                    total++;
                    var key = (e.Kind, e.Account.ToLowerInvariant(), e.Client.ToLowerInvariant(), e.Service.ToLowerInvariant());
                    if (!summary.TryGetValue(key, out var row))
                    {
                        row = new SummaryRow { Kind = e.Kind, Account = e.Account, Client = e.Client, Service = e.Service };
                        summary[key] = row;
                    }
                    row.Count++;
                    if (e.Time < row.FirstSeen) row.FirstSeen = e.Time;
                    if (e.Time > row.LastSeen) row.LastSeen = e.Time;
                    if (e.Computer.Length > 0) row.Computers.Add(e.Computer);
                    row.Variants.Add(e.Variant);
                    if (events.Count < options.MaxEvents) events.Add(e);
                    else truncated = true;
                }
            }
            batch.Clear();
        }

        foreach (var file in files.Where(f => !f.IsRelevant))
        {
            Report(new FileProgress(file.Path, file.Error is null ? FileState.Skipped : FileState.Error, 0, null,
                file.Error ?? $"Skipped: {file.Channel} log cannot contain these events"));
        }
        var relevant = files.Where(f => f.IsRelevant).ToList();
        foreach (var file in relevant) Report(new FileProgress(file.Path, FileState.Queued, 0, null, "Waiting"));

        var cancelled = false;
        try
        {
            Parallel.ForEach(relevant, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Threads), CancellationToken = cancellationToken }, file =>
            {
                Report(new FileProgress(file.Path, FileState.Scanning, 0, 0, "Scanning"));
                var batch = new List<AuthEvent>(FlushSize);
                long hits = 0;
                var lastReport = Stopwatch.StartNew();
                try
                {
                    foreach (var query in Queries.For(file.Channel))
                    {
                        foreach (var raw in reader.Read(file.Path, query, cancellationToken))
                        {
                            var e = Classifier.Classify(raw, file.Name, pool);
                            if (e is null) continue;
                            hits++;
                            batch.Add(e);
                            if (batch.Count >= FlushSize) Flush(batch);
                            if (lastReport.Elapsed > ProgressInterval)
                            {
                                Report(new FileProgress(file.Path, FileState.Scanning, hits, Percent(file, raw.RecordId), $"{query.Name}: {hits:N0} found"));
                                lastReport.Restart();
                            }
                        }
                    }
                    Flush(batch);
                    Report(new FileProgress(file.Path, FileState.Done, hits, 1, hits == 0 ? "Nothing found" : $"{hits:N0} events found"));
                }
                catch (OperationCanceledException)
                {
                    Flush(batch);
                    Report(new FileProgress(file.Path, FileState.Cancelled, hits, null, "Cancelled"));
                    throw;
                }
                catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException or System.Xml.XmlException)
                {
                    Flush(batch);
                    Report(new FileProgress(file.Path, FileState.Error, hits, null, ex.Message.Trim()));
                }
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
            foreach (var file in relevant.Where(f => results[f.Path].State == FileState.Queued))
            {
                Report(new FileProgress(file.Path, FileState.Cancelled, 0, null, "Cancelled"));
            }
        }

        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        var rows = summary.Values
            .OrderBy(r => KindOrder(r.Kind))
            .ThenByDescending(r => r.Count)
            .ToList();
        return new ScanResult(files, events, rows, results, total, truncated, cancelled, clock.Elapsed, scope);
    }

    /// <summary>Most severe first: DES, then NTLMv1, then RC4.</summary>
    public static int KindOrder(LegacyKind kind) => kind switch
    {
        LegacyKind.Des => 0,
        LegacyKind.Ntlmv1 => 1,
        _ => 2,
    };

    /// <summary>How far into the file the last match was. Records are read oldest first.</summary>
    internal static double? Percent(LogFileInfo file, long recordId)
    {
        if (file.RecordCount <= 0 || recordId <= 0) return null;
        var done = (double)(recordId - file.OldestRecordNumber + 1) / file.RecordCount;
        return Math.Clamp(done, 0, 1);
    }
}
