using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace LegacyAuthFinder.Core;

public sealed record ScanOptions(int Threads = 2, int MaxEvents = Scanner.DefaultMaxEvents);

public static class Scanner
{
    /// <summary>Events kept for the event list. The summary always counts every event, also beyond this limit.</summary>
    public const int DefaultMaxEvents = 2_000_000;

    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(300);

    /// <summary>Finds all .evtx files and works out which log each one belongs to.</summary>
    public static IReadOnlyList<LogFileInfo> Inventory(IEvtxReader reader, string folder, bool recurse,
        IProgress<LogFileInfo>? progress = null, int maxParallel = 4, CancellationToken cancellationToken = default)
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
        Parallel.For(0, paths.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, maxParallel), CancellationToken = cancellationToken }, i =>
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
        var summary = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        var results = new ConcurrentDictionary<string, FileProgress>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        long kept = 0;
        var truncated = 0;

        void Report(FileProgress p)
        {
            results[p.Path] = p;
            progress?.Report(p);
        }

        // Each file builds its own summary and event list without any locking. They are merged once, when the file
        // is finished. A shared lock per event made 16 parallel files no faster than 2.
        void Merge(Dictionary<SummaryKey, SummaryRow> local, List<AuthEvent> localEvents, long hits)
        {
            lock (gate)
            {
                total += hits;
                events.AddRange(localEvents);
                foreach (var (key, row) in local)
                {
                    if (summary.TryGetValue(key, out var existing)) existing.Absorb(row);
                    else summary[key] = row;
                }
            }
        }

        foreach (var file in files.Where(f => !f.IsRelevant))
        {
            Report(new FileProgress(file.Path, file.Error is null ? FileState.Skipped : FileState.Error, 0, null,
                file.Error ?? $"Skipped: {file.Channel} log cannot contain these events"));
        }
        // Largest files first, so a big file does not start last and keep the scan running alone at the end.
        var relevant = files.Where(f => f.IsRelevant).OrderByDescending(f => f.Size).ToList();
        foreach (var file in relevant) Report(new FileProgress(file.Path, FileState.Queued, 0, null, "Waiting"));

        var cancelled = false;
        try
        {
            // NoBuffering: a worker takes exactly one file at a time, so a waiting file starts as soon as any slot is free.
            var source = Partitioner.Create(relevant, EnumerablePartitionerOptions.NoBuffering);
            var parallel = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Threads), CancellationToken = cancellationToken };
            Parallel.ForEach(source, parallel, file =>
            {
                Report(new FileProgress(file.Path, FileState.Scanning, 0, 0, "Scanning"));
                var local = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
                var localEvents = new List<AuthEvent>();
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
                            SummaryRow.Add(local, e);
                            if (Interlocked.Increment(ref kept) <= options.MaxEvents) localEvents.Add(e);
                            else Volatile.Write(ref truncated, 1);
                            if (lastReport.Elapsed > ProgressInterval)
                            {
                                Report(new FileProgress(file.Path, FileState.Scanning, hits, Percent(file, raw.RecordId), $"{query.Name}: {hits:N0} found"));
                                lastReport.Restart();
                            }
                        }
                    }
                    Merge(local, localEvents, hits);
                    Report(new FileProgress(file.Path, FileState.Done, hits, 1, hits == 0 ? "Nothing found" : $"{hits:N0} events found"));
                }
                catch (OperationCanceledException)
                {
                    Merge(local, localEvents, hits);
                    Report(new FileProgress(file.Path, FileState.Cancelled, hits, null, "Cancelled"));
                    throw;
                }
                catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException or System.Xml.XmlException)
                {
                    Merge(local, localEvents, hits);
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
        return new ScanResult(files, events, rows, results, total, truncated == 1, cancelled, clock.Elapsed, scope);
    }

    /// <summary>Most urgent first, see <see cref="Guidance.Order"/>.</summary>
    public static int KindOrder(LegacyKind kind) => Guidance.Order.ToList().IndexOf(kind);

    /// <summary>How far into the file the last match was. Records are read oldest first.</summary>
    internal static double? Percent(LogFileInfo file, long recordId)
    {
        if (file.RecordCount <= 0 || recordId <= 0) return null;
        var done = (double)(recordId - file.OldestRecordNumber + 1) / file.RecordCount;
        return Math.Clamp(done, 0, 1);
    }
}
