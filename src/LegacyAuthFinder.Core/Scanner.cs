using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace LegacyAuthFinder.Core;

/// <param name="Log">Diagnostic log. When set, the scan writes per-file timings and a heartbeat with the state of every running file.</param>
/// <param name="Heartbeat">How often the heartbeat is written, 10 seconds by default.</param>
/// <param name="StallAfter">A running file without any return from the event log API for this long is logged as stalled, 15 seconds by default.</param>
public sealed record ScanOptions(int Threads = 2, int MaxEvents = Scanner.DefaultMaxEvents, DiagLog? Log = null,
    TimeSpan? Heartbeat = null, TimeSpan? StallAfter = null);

public static class Scanner
{
    /// <summary>Events kept for the event list. The summary always counts every event, also beyond this limit.</summary>
    public const int DefaultMaxEvents = 2_000_000;

    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan LongGap = TimeSpan.FromSeconds(2);

    /// <summary>Finds all .evtx files and works out which log each one belongs to.</summary>
    public static IReadOnlyList<LogFileInfo> Inventory(IEvtxReader reader, string folder, bool recurse,
        IProgress<LogFileInfo>? progress = null, int maxParallel = 4, CancellationToken cancellationToken = default, DiagLog? log = null)
    {
        var clock = Stopwatch.StartNew();
        var paths = Directory.EnumerateFiles(folder, "*.evtx", new EnumerationOptions
            {
                RecurseSubdirectories = recurse,
                IgnoreInaccessible = true,
                MatchCasing = MatchCasing.CaseInsensitive,
            })
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        log?.Write("FOLDER", $"{paths.Count} .evtx files found in {clock.ElapsedMilliseconds} ms (subfolders {recurse}), reading headers {maxParallel} at once");
        var result = new LogFileInfo[paths.Count];
        Parallel.For(0, paths.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, maxParallel), CancellationToken = cancellationToken }, i =>
        {
            var one = Stopwatch.StartNew();
            result[i] = reader.Inspect(paths[i]);
            var f = result[i];
            log?.Write("FILE", $"{Relative(folder, f.Path)}: {Reports.SizeText(f.Size)} ({f.Size:N0} bytes), log '{f.Channel}', records {f.RecordCount:N0}, "
                + $"IDs {f.FirstRecordId}..{f.LastRecordId}, {f.First:yyyy-MM-dd HH:mm} to {f.Last:yyyy-MM-dd HH:mm}, header read in {one.ElapsedMilliseconds} ms"
                + (f.Error is null ? (f.IsRelevant ? "" : ", not scanned") : $", ERROR {f.Error}"));
            progress?.Report(result[i]);
        });
        log?.Write("FOLDER", $"Inventory done in {clock.Elapsed.TotalSeconds:0.0} s: {result.Count(f => f.IsRelevant)} files to scan, "
            + $"{Reports.SizeText(result.Where(f => f.IsRelevant).Sum(f => f.Size))} in total, {result.Count(f => f.Error is not null)} unreadable");
        return result;
    }

    public static ScanResult Scan(IEvtxReader reader, IReadOnlyList<LogFileInfo> files, string scope, ScanOptions options,
        IProgress<FileProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clock = Stopwatch.StartNew();
        var log = options.Log;
        var pool = new StringPool();
        var gate = new Lock();
        var events = new List<AuthEvent>();
        var summary = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        var results = new ConcurrentDictionary<string, FileProgress>(StringComparer.OrdinalIgnoreCase);
        var work = new ConcurrentDictionary<string, FileWork>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        long kept = 0;
        var truncated = 0;
        long cancelledAt = 0;

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
        for (var i = 0; i < relevant.Count; i++)
        {
            work[relevant[i].Path] = new FileWork(relevant[i], i + 1);
            Report(new FileProgress(relevant[i].Path, FileState.Queued, 0, null, "Waiting"));
        }

        var threads = Math.Max(1, options.Threads);
        log?.Write("SCAN", $"Start: {relevant.Count} files, {Reports.SizeText(relevant.Sum(f => f.Size))}, {threads} at once, event list limit {options.MaxEvents:N0}");
        foreach (var f in relevant)
        {
            log?.Write("SCAN", $"  [{work[f.Path].Order:00}] {f.Name} {Reports.SizeText(f.Size)} '{f.Channel}': {string.Join(", ", Queries.For(f.Channel).Select(q => q.Name))}");
        }

        // The Windows reader reports when it opens and closes a query, so the log shows where a file waits.
        var windows = reader as WindowsEvtxReader;
        if (windows is not null && log is not null)
        {
            windows.OnPhase = (path, phase) =>
            {
                if (work.TryGetValue(path, out var w)) w.Enter(phase);
            };
        }
        using var monitor = log is null ? null : new ScanMonitor(log, work, options.Heartbeat ?? TimeSpan.FromSeconds(10), options.StallAfter ?? TimeSpan.FromSeconds(15));
        using var onCancel = cancellationToken.Register(() =>
        {
            Interlocked.Exchange(ref cancelledAt, Stopwatch.GetTimestamp());
            log?.Write("SCAN", $"Cancel requested after {clock.Elapsed.TotalSeconds:0.0} s. Running: "
                + string.Join(", ", work.Values.Where(w => !IsIdle(w.Phase)).Select(w => $"[{w.Order:00}] {w.Phase}")));
        });

        var cancelled = false;
        try
        {
            // The workers block in the event log API. Make sure the thread pool has them ready instead of adding
            // one blocked thread per second, which looked like files that never start.
            ThreadPool.GetMinThreads(out var minWorkers, out var minIo);
            if (minWorkers < threads + 2) ThreadPool.SetMinThreads(threads + 2, minIo);
            log?.Write("SCAN", SystemProbe.ThreadPoolText());

            // NoBuffering: a worker takes exactly one file at a time, so a waiting file starts as soon as any slot is free.
            var source = Partitioner.Create(relevant, EnumerablePartitionerOptions.NoBuffering);
            var parallel = new ParallelOptions { MaxDegreeOfParallelism = threads, CancellationToken = cancellationToken };
            Parallel.ForEach(source, parallel, file =>
            {
                var w = work[file.Path];
                w.ThreadId = Environment.CurrentManagedThreadId;
                w.StartedAt = Stopwatch.GetTimestamp();
                w.Enter("starting");
                w.Life();
                log?.Write("FILE", $"[{w.Order:00}] start {file.Name} after {clock.Elapsed.TotalSeconds:0.0} s, {SystemProbe.ThreadPoolText()}");
                Report(new FileProgress(file.Path, FileState.Scanning, 0, 0, "Scanning"));
                var local = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
                var localEvents = new List<AuthEvent>();
                long hits = 0;
                var lastReport = Stopwatch.StartNew();
                try
                {
                    foreach (var query in Queries.For(file.Channel))
                    {
                        var currentQuery = query;
                        var queryClock = Stopwatch.StartNew();
                        long queryRecords = 0, queryHits = 0, querySlices = 0;
                        var firstLife = TimeSpan.Zero;
                        w.Query = query.Name;
                        w.Enter("reading");
                        w.Life();

                        void Gap()
                        {
                            var gap = w.Life();
                            if (firstLife == TimeSpan.Zero) firstLife = queryClock.Elapsed;
                            if (gap < LongGap) return;
                            if (Interlocked.Increment(ref w.LongGaps) <= 20)
                            {
                                log?.Write("SLOW", $"[{w.Order:00}] {file.Name} {currentQuery.Name}: the event log API took {gap.TotalSeconds:0.0} s to return "
                                    + $"(read slice {WindowsEvtxReader.ReadSlice.TotalSeconds:0.0} s), phase '{w.Phase}'");
                            }
                        }

                        void Alive()
                        {
                            querySlices++;
                            Interlocked.Increment(ref w.Slices);
                            Gap();
                            if (lastReport.Elapsed <= ProgressInterval) return;
                            Report(new FileProgress(file.Path, FileState.Scanning, hits, null,
                                hits == 0 ? $"{currentQuery.Name}: reading, nothing matched yet" : $"{currentQuery.Name}: reading, {hits:N0} found so far"));
                            lastReport.Restart();
                        }

                        foreach (var raw in reader.Read(file.Path, query, cancellationToken, Alive))
                        {
                            queryRecords++;
                            Interlocked.Increment(ref w.Records);
                            w.LastRecordId = raw.RecordId;
                            Gap();
                            var e = Classifier.Classify(raw, file.Name, pool);
                            if (e is null) continue;
                            hits++;
                            queryHits++;
                            w.Hits = hits;
                            SummaryRow.Add(local, e);
                            if (Interlocked.Increment(ref kept) <= options.MaxEvents) localEvents.Add(e);
                            else Volatile.Write(ref truncated, 1);
                            if (lastReport.Elapsed > ProgressInterval)
                            {
                                Report(new FileProgress(file.Path, FileState.Scanning, hits, Percent(file, raw.RecordId), $"{query.Name}: {hits:N0} found"));
                                lastReport.Restart();
                            }
                        }
                        var seconds = queryClock.Elapsed.TotalSeconds;
                        log?.Write("QUERY", $"[{w.Order:00}] {file.Name} {query.Name}: {seconds:0.0} s, {queryRecords:N0} records, {queryHits:N0} found, "
                            + $"{querySlices:N0} empty slices, first return after {firstLife.TotalSeconds:0.0} s, {(seconds > 0 ? queryRecords / seconds : 0):0} records/s");
                    }
                    w.Enter("merging");
                    Merge(local, localEvents, hits);
                    w.Enter("done");
                    var took = Stopwatch.GetElapsedTime(w.StartedAt).TotalSeconds;
                    log?.Write("FILE", $"[{w.Order:00}] done {file.Name} in {took:0.0} s, {hits:N0} found, {Reports.SizeText((long)(file.Size / Math.Max(0.001, took)))}/s");
                    Report(new FileProgress(file.Path, FileState.Done, hits, 1, hits == 0 ? "Nothing found" : $"{hits:N0} events found"));
                }
                catch (OperationCanceledException)
                {
                    Merge(local, localEvents, hits);
                    w.Enter("cancelled");
                    var at = Interlocked.Read(ref cancelledAt);
                    var since = at > 0 ? Stopwatch.GetElapsedTime(at).TotalSeconds : 0;
                    log?.Write("FILE", $"[{w.Order:00}] cancelled {file.Name} after {Stopwatch.GetElapsedTime(w.StartedAt).TotalSeconds:0.0} s, stopped {since:0.0} s after the cancel");
                    Report(new FileProgress(file.Path, FileState.Cancelled, hits, null, "Cancelled"));
                    throw;
                }
                catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException or System.Xml.XmlException)
                {
                    Merge(local, localEvents, hits);
                    w.Enter("error");
                    log?.Error("FILE", $"[{w.Order:00}] {file.Name} {w.Query}", ex);
                    Report(new FileProgress(file.Path, FileState.Error, hits, null, ex.Message.Trim()));
                }
                catch (Exception ex)
                {
                    w.Enter("error");
                    log?.Error("FILE", $"[{w.Order:00}] {file.Name} {w.Query} unexpected", ex);
                    throw;
                }
            });
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
            foreach (var file in relevant.Where(f => results[f.Path].State == FileState.Queued))
            {
                work[file.Path].Enter("cancelled");
                Report(new FileProgress(file.Path, FileState.Cancelled, 0, null, "Cancelled"));
            }
        }
        catch (Exception ex)
        {
            log?.Error("SCAN", "scan failed", ex);
            throw;
        }
        finally
        {
            if (windows is not null && log is not null) windows.OnPhase = null;
            monitor?.Tick();
        }

        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        var rows = summary.Values
            .OrderBy(r => KindOrder(r.Kind))
            .ThenByDescending(r => r.Count)
            .ToList();
        log?.Write("SCAN", $"{(cancelled ? "Cancelled" : "Finished")} after {clock.Elapsed.TotalSeconds:0.0} s: {total:N0} events, {rows.Count:N0} summary rows, "
            + $"{results.Values.Count(r => r.State == FileState.Error)} files with errors, stalls logged {monitor?.Stalls ?? 0}");
        return new ScanResult(files, events, rows, results, total, truncated == 1, cancelled, clock.Elapsed, scope);
    }

    internal static bool IsIdle(string phase) => phase is "queued" or "done" or "cancelled" or "error";

    /// <summary>Most urgent first, see <see cref="Guidance.Order"/>.</summary>
    public static int KindOrder(LegacyKind kind) => Guidance.Order.ToList().IndexOf(kind);

    private static string Relative(string folder, string path)
    {
        try
        {
            return Path.GetRelativePath(folder, path);
        }
        catch (ArgumentException)
        {
            return path;
        }
    }

    /// <summary>
    /// How far into the file the last match was. Records are read oldest first. Uses the real first and last record
    /// IDs, because exported logs keep their original numbering and do not start at 1.
    /// </summary>
    internal static double? Percent(LogFileInfo file, long recordId)
    {
        if (recordId <= 0) return null;
        long first = file.FirstRecordId, last = file.LastRecordId;
        if (first <= 0 || last < first)
        {
            if (file.RecordCount <= 0) return null;
            first = file.OldestRecordNumber;
            last = first + file.RecordCount - 1;
        }
        var done = (double)(recordId - first + 1) / (last - first + 1);
        return Math.Clamp(done, 0, 1);
    }
}
