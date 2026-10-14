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
    /// <summary>Events kept for the event list (the newest ones). The summary always counts every event, also beyond this limit.</summary>
    public const int DefaultMaxEvents = 2_000_000;

    /// <summary>Rough memory of one kept event with its detail fields, used to lower the limit on small machines.</summary>
    private const long BytesPerEvent = 800;

    /// <summary>Events a file collects before they go to the shared list, so a big file does not hold millions on its own.</summary>
    private const int EventBatch = 65_536;

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
            try
            {
                result[i] = reader.Inspect(paths[i]);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A file that disappears or cannot be opened must not stop the whole folder.
                result[i] = new LogFileInfo(paths[i], 0, "", "", 0, 0, null, null, $"Cannot read this file. ({ex.Message.Trim()})");
            }
            var f = result[i];
            log?.Write("FILE", $"{Relative(folder, f.Path)}: {Reports.SizeText(f.Size)} ({f.Size:N0} bytes), log '{f.Channel}', records {f.RecordCount:N0}, "
                + $"IDs {f.FirstRecordId}..{f.LastRecordId}, {f.First:yyyy-MM-dd HH:mm} to {f.Last:yyyy-MM-dd HH:mm}, header read in {one.ElapsedMilliseconds} ms"
                + (f.Error is null ? (f.IsRelevant ? "" : ", not scanned") : $", ERROR {f.Error}"));
            progress?.Report(result[i]);
        });
        log?.Write("FOLDER", $"Inventory done in {clock.Elapsed.TotalSeconds:0.0} s: {result.Count(f => f.IsRelevant)} files to scan, "
            + $"{Reports.SizeText(result.Where(f => f.IsRelevant).Sum(f => f.Size))} in total, {result.Count(f => f.Error is not null)} unreadable");
        // File names only: the computer name stays out of the log like in the FILE lines.
        foreach (var (a, b) in Overlaps(result)) log?.Write("FOLDER", $"OVERLAP: {a.Name} and {b.Name} contain the same records of one log, duplicates are counted once");
        return result;
    }

    /// <summary>
    /// Pairs of files of the same computer and log whose record ID ranges and time ranges overlap: cumulative exports or
    /// an archive next to a copy of the live log. Their shared records must be counted once. Record IDs start again at 1
    /// when a log is cleared or a domain controller is rebuilt, so an old archive and a new log with the same IDs but
    /// different times are not an overlap.
    /// </summary>
    public static IEnumerable<(LogFileInfo A, LogFileInfo B)> Overlaps(IEnumerable<LogFileInfo> files)
    {
        foreach (var group in files.Where(f => f.IsRelevant && f.FirstRecordId > 0 && f.LastRecordId >= f.FirstRecordId)
                     .GroupBy(f => (f.Computer.ToUpperInvariant(), f.Channel.ToUpperInvariant())))
        {
            var list = group.OrderBy(f => f.FirstRecordId).ToList();
            for (var i = 0; i < list.Count; i++)
            {
                for (var j = i + 1; j < list.Count && list[j].FirstRecordId <= list[i].LastRecordId; j++)
                {
                    if (TimesOverlap(list[i], list[j])) yield return (list[i], list[j]);
                }
            }
        }
    }

    private static bool TimesOverlap(LogFileInfo a, LogFileInfo b) =>
        a.First is null || a.Last is null || b.First is null || b.Last is null || (a.First <= b.Last && b.First <= a.Last);

    /// <summary>The record IDs a file shares with other files, and a number for its computer and log.</summary>
    internal static Dictionary<string, (int Group, List<(long From, long To)> Ranges)> SharedRanges(IEnumerable<LogFileInfo> files)
    {
        var shared = new Dictionary<string, (int, List<(long, long)>)>(StringComparer.Ordinal);
        var groups = new Dictionary<(string, string), int>();
        foreach (var (a, b) in Overlaps(files))
        {
            var key = (a.Computer.ToUpperInvariant(), a.Channel.ToUpperInvariant());
            if (!groups.TryGetValue(key, out var group)) groups[key] = group = groups.Count;
            var range = (Math.Max(a.FirstRecordId, b.FirstRecordId), Math.Min(a.LastRecordId, b.LastRecordId));
            foreach (var f in new[] { a, b })
            {
                if (!shared.TryGetValue(f.Path, out var entry)) shared[f.Path] = entry = (group, []);
                entry.Item2.Add(range);
            }
        }
        return shared;
    }

    /// <summary>Lower than <paramref name="wanted"/> on machines without enough memory for it.</summary>
    internal static int EventLimit(int wanted)
    {
        var available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        var fits = available > 0 ? available / 2 / BytesPerEvent : wanted;
        return (int)Math.Max(Math.Min(wanted, 100_000), Math.Min(wanted, fits));
    }

    /// <summary>Keeps the newest <paramref name="limit"/> events. Older ones are dropped, the summary still counts them.</summary>
    private static void KeepNewest(List<AuthEvent> list, int limit)
    {
        if (list.Count <= limit) return;
        list.Sort((a, b) => b.Time.CompareTo(a.Time));
        list.RemoveRange(limit, list.Count - limit);
    }

    public static ScanResult Scan(IEvtxReader reader, IReadOnlyList<LogFileInfo> files, string scope, ScanOptions options,
        IProgress<FileProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clock = Stopwatch.StartNew();
        var log = options.Log;
        var pool = new StringPool();
        var gate = new Lock();
        var limit = EventLimit(options.MaxEvents);
        var events = new List<AuthEvent>();
        var summary = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        // Paths compare exactly: a case-sensitive folder can hold Security.evtx and security.evtx.
        var results = new ConcurrentDictionary<string, FileProgress>(StringComparer.Ordinal);
        var work = new ConcurrentDictionary<string, FileWork>(StringComparer.Ordinal);
        // Records of overlapping files already counted: log, record ID and time (IDs alone repeat after a log is cleared).
        var seen = new ConcurrentDictionary<(int, long, long), byte>();
        // Events older than this can no longer be among the newest ones the list keeps. Set once the list is full.
        long cutoff = long.MinValue;
        long total = 0;
        long duplicates = 0;
        long matched = 0;
        var failed = 0;
        var truncated = 0;
        long cancelledAt = 0;

        void Report(FileProgress p)
        {
            results[p.Path] = p;
            progress?.Report(p);
        }

        // Each file builds its own summary without any locking and merges it once, when the file is finished. Events go
        // to the shared list in batches, so the memory stays near the limit however many files run at once. A shared
        // lock per event made 16 parallel files no faster than 2.
        void Flush(List<AuthEvent> localEvents)
        {
            if (localEvents.Count == 0) return;
            lock (gate)
            {
                events.AddRange(localEvents);
                if (events.Count > limit * 2L)
                {
                    KeepNewest(events, limit);
                    Volatile.Write(ref cutoff, events[^1].Time.Ticks);
                    Volatile.Write(ref truncated, 1);
                }
            }
            localEvents.Clear();
        }

        void Merge(Dictionary<SummaryKey, SummaryRow> local, List<AuthEvent> localEvents, long hits)
        {
            Flush(localEvents);
            lock (gate)
            {
                total += hits;
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
        // Only the records a file shares with another file of the same log need the duplicate check.
        var shared = SharedRanges(relevant);

        var threads = Math.Max(1, options.Threads);
        var mode = reader is IMultiQueryReader ? "built-in .evtx reader, one pass per file" : "Windows event log API, one pass per query";
        if (reader is EvtxFileReader parser) parser.ChunkWorkers = Math.Clamp(Environment.ProcessorCount / threads, 1, 8);
        log?.Write("SCAN", $"Start: {relevant.Count} files, {Reports.SizeText(relevant.Sum(f => f.Size))}, {threads} at once, {mode}"
            + $"{(reader is EvtxFileReader p2 ? $", {p2.ChunkWorkers} chunk workers per file" : "")}, event list limit {limit:N0}, {shared.Count} files with overlapping records");
        foreach (var f in relevant)
        {
            log?.Write("SCAN", $"  [{work[f.Path].Order:00}] {f.Name} {Reports.SizeText(f.Size)} '{f.Channel}': {string.Join(", ", Queries.For(f.Channel).Select(q => q.Name))}");
        }

        // The Windows reader reports when it opens and closes a query, so the log shows where a file waits.
        var windows = reader as WindowsEvtxReader ?? (reader as EvtxFileReader)?.Fallback as WindowsEvtxReader;
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

        // The workers block in file reads. Make sure the thread pool has them ready instead of adding one blocked
        // thread per second, which looked like files that never start. Restored afterwards, the setting is process-wide.
        ThreadPool.GetMinThreads(out var minWorkers, out var minIo);
        if (minWorkers < threads + 2) ThreadPool.SetMinThreads(threads + 2, minIo);
        var cancelled = false;
        try
        {
            log?.Write("SCAN", SystemProbe.ThreadPoolText());

            // NoBuffering: a worker takes exactly one file at a time, so a waiting file starts as soon as any slot is free.
            var source = Partitioner.Create(relevant, EnumerablePartitionerOptions.NoBuffering);
            var parallel = new ParallelOptions { MaxDegreeOfParallelism = threads, CancellationToken = cancellationToken };
            Parallel.ForEach(source, parallel, file =>
            {
                var w = work[file.Path];
                w.ThreadId = Environment.CurrentManagedThreadId;
                w.StartedAt = Stopwatch.GetTimestamp();
                w.Start();
                log?.Write("FILE", $"[{w.Order:00}] start {file.Name} after {clock.Elapsed.TotalSeconds:0.0} s, {SystemProbe.ThreadPoolText()}");
                Report(new FileProgress(file.Path, FileState.Scanning, 0, 0, "Scanning"));
                var local = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
                var localEvents = new List<AuthEvent>();
                // Only the Windows API path can return a record twice within one file (two queries that both match).
                var localSeen = reader is IMultiQueryReader ? null : new HashSet<long>();
                var (group, ranges) = shared.TryGetValue(file.Path, out var mine) ? mine : (-1, null);
                long hits = 0;
                var lastReport = Stopwatch.StartNew();
                var fileNote = "";
                var partly = false;

                // One matched event: skip duplicates, classify, count.
                void Handle(RawEvent raw)
                {
                    Interlocked.Increment(ref w.Records);
                    w.LastRecordId = raw.RecordId;
                    if (raw.RecordId > 0)
                    {
                        // Two queries of the Windows API path can return the same record: not a duplicate between files.
                        if (localSeen is not null && !localSeen.Add(raw.RecordId)) return;
                        if (ranges is not null && InRanges(ranges, raw.RecordId) && !seen.TryAdd((group, raw.RecordId, raw.Time.Ticks), 0))
                        {
                            Interlocked.Increment(ref duplicates);
                            return;
                        }
                    }
                    var e = Classifier.Classify(raw, file.Name, pool);
                    if (e is null) return;
                    hits++;
                    w.Hits = hits;
                    Interlocked.Increment(ref matched);
                    SummaryRow.Add(local, e);
                    if (e.Time.Ticks < Volatile.Read(ref cutoff))
                    {
                        // Counted in the summary, but too old for the event list.
                        Volatile.Write(ref truncated, 1);
                        return;
                    }
                    localEvents.Add(e);
                    if (localEvents.Count >= EventBatch) Flush(localEvents);
                }

                try
                {
                    // Built-in parser: one pass over the file answers every query, progress comes from the bytes read.
                    if (reader is IMultiQueryReader multi)
                    {
                        var queries = Queries.For(file.Channel).ToList();
                        var stats = new ReadStats();
                        var passClock = Stopwatch.StartNew();
                        var fraction = 0.0;
                        w.Query = "one pass";
                        w.Enter("parsing");
                        w.Life();

                        void Step(double share)
                        {
                            if (share >= 0)
                            {
                                fraction = share;
                                w.Fraction = share;
                            }
                            else
                            {
                                Interlocked.Increment(ref w.Slices);
                            }
                            w.Life();
                            if (lastReport.Elapsed <= ProgressInterval) return;
                            // A sign of life without a new share keeps the last share, so the bar does not jump back.
                            Report(new FileProgress(file.Path, FileState.Scanning, hits, fraction,
                                hits == 0 ? $"Reading, nothing found yet ({fraction:P0})" : $"Reading, {hits:N0} found ({fraction:P0})"));
                            lastReport.Restart();
                        }

                        foreach (var (_, raw) in multi.ReadAll(file.Path, queries, cancellationToken, Step, stats))
                        {
                            w.Life();
                            Handle(raw);
                        }
                        var passSeconds = passClock.Elapsed.TotalSeconds;
                        log?.Write("PARSE", $"[{w.Order:00}] {file.Name}: {passSeconds:0.0} s, "
                            + $"{(stats.Fallback is null ? $"{stats.Bytes / 1048576.0 / Math.Max(0.001, passSeconds):0} MB/s, " : "")}{stats}");
                        if (stats.Partial)
                        {
                            // Missing parts can hold findings, so the file counts as partly read and the result as incomplete.
                            partly = true;
                            var parts = new List<string>();
                            if (stats.BadChunks > 0) parts.Add($"{stats.BadChunks:N0} damaged chunks skipped");
                            if (stats.BadRecords > 0) parts.Add($"{stats.BadRecords:N0} unreadable records skipped");
                            if (stats.MissingBytes > 0) parts.Add($"the file is cut off, {Reports.SizeText(stats.MissingBytes)} missing");
                            if (stats.FailedQueries > 0) parts.Add($"{stats.FailedQueries} of {queries.Count} queries failed");
                            fileNote = ", " + string.Join(", ", parts);
                        }
                    }
                    else
                    {
                        var queries = Queries.For(file.Channel).ToList();
                        for (var qi = 0; qi < queries.Count; qi++)
                        {
                            var query = queries[qi];
                            var queryIndex = qi;
                            var queryClock = Stopwatch.StartNew();
                            long queryRecords = 0, querySlices = 0;
                            var firstLife = TimeSpan.Zero;
                            double? lastShare = (double)queryIndex / queries.Count;
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
                                    log?.Write("SLOW", $"[{w.Order:00}] {file.Name} {query.Name}: the event log API took {gap.TotalSeconds:0.0} s to return "
                                        + $"(read slice {WindowsEvtxReader.ReadSlice.TotalSeconds:0.0} s), phase '{w.Phase}'");
                                }
                            }

                            void Alive()
                            {
                                querySlices++;
                                Interlocked.Increment(ref w.Slices);
                                Gap();
                                if (lastReport.Elapsed <= ProgressInterval) return;
                                Report(new FileProgress(file.Path, FileState.Scanning, hits, lastShare,
                                    hits == 0 ? $"{query.Name}: reading, nothing matched yet" : $"{query.Name}: reading, {hits:N0} found so far"));
                                lastReport.Restart();
                            }

                            try
                            {
                                foreach (var raw in reader.Read(file.Path, query, cancellationToken, Alive))
                                {
                                    queryRecords++;
                                    Gap();
                                    Handle(raw);
                                    if (lastReport.Elapsed > ProgressInterval)
                                    {
                                        // Every query reads the file from the start, so its share is scaled into the file's total.
                                        if (Percent(file, raw.RecordId) is { } pct) lastShare = (queryIndex + pct) / queries.Count;
                                        Report(new FileProgress(file.Path, FileState.Scanning, hits, lastShare, $"{query.Name}: {hits:N0} found"));
                                        lastReport.Restart();
                                    }
                                }
                            }
                            catch (EventLogException ex) when (!cancellationToken.IsCancellationRequested)
                            {
                                // A damaged part ends this query only. The other queries still read the file.
                                partly = true;
                                fileNote += $", {query.Name} stopped: {ex.Message.Trim()}";
                                log?.Write("FILE", $"[{w.Order:00}] {file.Name} {query.Name} stopped after {queryRecords:N0} records: {ex.GetType().Name}: {ex.Message.Trim()}");
                            }
                            var seconds = queryClock.Elapsed.TotalSeconds;
                            log?.Write("QUERY", $"[{w.Order:00}] {file.Name} {query.Name}: {seconds:0.0} s, {queryRecords:N0} records, "
                                + $"{querySlices:N0} empty slices, first return after {firstLife.TotalSeconds:0.0} s, {(seconds > 0 ? queryRecords / seconds : 0):0} records/s");
                        }
                    }
                    w.Enter("merging");
                    Merge(local, localEvents, hits);
                    w.Enter(partly ? "error" : "done");
                    var took = Stopwatch.GetElapsedTime(w.StartedAt).TotalSeconds;
                    log?.Write("FILE", $"[{w.Order:00}] done {file.Name} in {took:0.0} s, {hits:N0} found, {Reports.SizeText((long)(file.Size / Math.Max(0.001, took)))}/s{fileNote}");
                    if (partly)
                    {
                        Interlocked.Increment(ref failed);
                        Report(new FileProgress(file.Path, FileState.Error, hits, null, $"Partly read, {hits:N0} events found{fileNote}"));
                    }
                    else
                    {
                        Report(new FileProgress(file.Path, FileState.Done, hits, 1, (hits == 0 ? "Nothing found" : $"{hits:N0} events found") + fileNote));
                    }
                }
                catch (OperationCanceledException)
                {
                    Merge(local, localEvents, hits);
                    w.Enter("cancelled");
                    Interlocked.CompareExchange(ref cancelledAt, Stopwatch.GetTimestamp(), 0);
                    var since = Stopwatch.GetElapsedTime(Interlocked.Read(ref cancelledAt)).TotalSeconds;
                    log?.Write("FILE", $"[{w.Order:00}] cancelled {file.Name} after {Stopwatch.GetElapsedTime(w.StartedAt).TotalSeconds:0.0} s, stopped {since:0.0} s after the cancel");
                    Report(new FileProgress(file.Path, FileState.Cancelled, hits, null, "Cancelled"));
                    throw;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    // Whatever goes wrong with one file stays with that file: its partial results are kept, the
                    // others go on. Only running out of memory ends the scan.
                    Merge(local, localEvents, hits);
                    w.Enter("error");
                    Interlocked.Increment(ref failed);
                    log?.Write("FILE", $"[{w.Order:00}] {file.Name} {w.Query} failed: {Describe(ex)}");
                    Report(new FileProgress(file.Path, FileState.Error, hits, null, ex.Message.Trim()));
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
            ThreadPool.GetMinThreads(out _, out var currentIo);
            ThreadPool.SetMinThreads(minWorkers, currentIo);
            if (windows is not null && log is not null) windows.OnPhase = null;
            monitor?.FinalTick();
        }

        if (events.Count > limit || Interlocked.Read(ref matched) > limit) truncated = 1;
        KeepNewest(events, limit);
        events.Sort((a, b) => a.Time.CompareTo(b.Time));
        var rows = summary.Values
            .OrderBy(r => KindOrder(r.Kind))
            .ThenByDescending(r => r.Count)
            .ToList();
        log?.Write("SCAN", $"{(cancelled ? "Cancelled" : "Finished")} after {clock.Elapsed.TotalSeconds:0.0} s: {total:N0} events, {rows.Count:N0} summary rows, "
            + $"{duplicates:N0} duplicates skipped, {failed} files with errors, stalls logged {monitor?.Stalls ?? 0}");
        return new ScanResult(files, events, rows, results, total, truncated == 1, cancelled, clock.Elapsed, scope, duplicates,
            failed + files.Count(f => !f.IsRelevant && f.Error is not null));
    }

    /// <summary>
    /// For the diagnostic log. XML and decoder messages can quote parts of the event, so only their type is written.
    /// </summary>
    internal static string Describe(Exception ex) => ex is System.Xml.XmlException or System.Text.DecoderFallbackException
        ? ex.GetType().Name
        : $"{ex.GetType().Name}: {ex.Message.Trim()}{Environment.NewLine}{ex.StackTrace}";

    private static bool InRanges(List<(long From, long To)> ranges, long id)
    {
        foreach (var (from, to) in ranges)
        {
            if (id >= from && id <= to) return true;
        }
        return false;
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
