using System.Collections.Concurrent;
using System.Diagnostics;

namespace LegacyAuthFinder.Core;

/// <summary>
/// What one file is doing right now, for the diagnostic log. A "sign of life" is any return from the event log API:
/// a matching record or an expired read slice. Reads come back at least every half second, so a long gap means the
/// call itself is blocked, usually in the Event Log service or on the disk.
/// </summary>
internal sealed class FileWork(LogFileInfo file, int order)
{
    private long _phaseSince = Stopwatch.GetTimestamp();
    private long _lastLife = Stopwatch.GetTimestamp();
    private string _phase = "queued";

    public LogFileInfo File { get; } = file;
    public int Order { get; } = order;
    public int ThreadId;
    public long StartedAt;
    public string Query = "";
    public long Records;
    public long Hits;
    public long Slices;
    public long LongestGapTicks;
    public long LongGaps;
    public long LastRecordId;
    public double Fraction = -1;
    public bool StallReported;

    public string Phase => Volatile.Read(ref _phase);
    public TimeSpan InPhase => Stopwatch.GetElapsedTime(Interlocked.Read(ref _phaseSince));
    public TimeSpan SinceLife => Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastLife));

    public void Enter(string phase)
    {
        Volatile.Write(ref _phase, phase);
        Interlocked.Exchange(ref _phaseSince, Stopwatch.GetTimestamp());
    }

    /// <summary>Returns the gap since the previous sign of life.</summary>
    public TimeSpan Life()
    {
        var now = Stopwatch.GetTimestamp();
        var gap = now - Interlocked.Exchange(ref _lastLife, now);
        if (gap > LongestGapTicks) LongestGapTicks = gap;
        StallReported = false;
        return Stopwatch.GetElapsedTime(0, gap);
    }
}

/// <summary>Writes scan progress and the state of every running file to the diagnostic log at a fixed interval.</summary>
internal sealed class ScanMonitor : IDisposable
{
    private readonly DiagLog _log;
    private readonly ConcurrentDictionary<string, FileWork> _work;
    private readonly TimeSpan _stallAfter;
    private readonly Timer _timer;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Lock _tickGate = new();
    private SystemProbe.ProcessSample? _self = SystemProbe.Self();
    private SystemProbe.ProcessSample? _service = SystemProbe.EventLogService();
    private int _ticks;

    public ScanMonitor(DiagLog log, ConcurrentDictionary<string, FileWork> work, TimeSpan interval, TimeSpan stallAfter)
    {
        _log = log;
        _work = work;
        _stallAfter = stallAfter;
        _timer = new Timer(_ => Tick(), null, interval, interval);
    }

    public int Stalls { get; private set; }

    public void Tick()
    {
        if (!_tickGate.TryEnter()) return;
        try
        {
            _ticks++;
            var all = _work.Values.ToList();
            var running = all.Where(w => !Scanner.IsIdle(w.Phase)).OrderBy(w => w.Order).ToList();
            var done = all.Count(w => w.Phase is "done" or "cancelled" or "error");
            var self = SystemProbe.Self();
            var service = SystemProbe.EventLogService();
            _log.Write("BEAT", $"#{_ticks} after {_clock.Elapsed:hh\\:mm\\:ss}: {done} of {all.Count} files finished, {running.Count} running, {all.Count - done - running.Count} queued");
            _log.Write("BEAT", $"  this process: {SystemProbe.Delta(_self, self)}, {SystemProbe.Describe(self)}");
            _log.Write("BEAT", $"  Event Log service: {SystemProbe.Delta(_service, service)}, {SystemProbe.Describe(service)}");
            _log.Write("BEAT", $"  {SystemProbe.ThreadPoolText()}");
            _log.Write("BEAT", $"  {SystemProbe.GcText()}, system memory {SystemProbe.Memory()}");
            _self = self;
            _service = service;
            foreach (var w in running)
            {
                var quiet = w.SinceLife;
                _log.Write("BEAT", $"  [{w.Order:00}] {w.File.Name} ({Reports.SizeText(w.File.Size)}) T{w.ThreadId} {w.Query} | {w.Phase} for {Seconds(w.InPhase)}"
                    + $" | last sign of life {Seconds(quiet)} ago | records {w.Records:N0}, found {w.Hits:N0}, empty slices {w.Slices:N0}"
                    + $" | longest gap {Seconds(Stopwatch.GetElapsedTime(0, w.LongestGapTicks))}, gaps over 2 s {w.LongGaps}"
                    + (w.Fraction >= 0 ? $" | {w.Fraction:P1} of the file read" : $" | at record {w.LastRecordId} of {w.File.FirstRecordId}..{w.File.LastRecordId}"));
                if (quiet >= _stallAfter && !w.StallReported && w.Phase != "merging")
                {
                    w.StallReported = true;
                    Stalls++;
                    _log.Write("STALL", $"[{w.Order:00}] {w.File.Name}: no progress for {Seconds(quiet)} while '{w.Phase}' ({w.Query}). "
                        + $"Running files: {running.Count}. Event Log service: {SystemProbe.Delta(_service, service)}");
                }
            }
        }
        catch (Exception ex)
        {
            _log.Error("BEAT", "heartbeat failed", ex);
        }
        finally
        {
            _tickGate.Exit();
        }
    }

    public static string Seconds(TimeSpan t) => t.TotalSeconds < 100 ? $"{t.TotalSeconds:0.0} s" : $"{t:hh\\:mm\\:ss}";

    public void Dispose()
    {
        using var done = new ManualResetEvent(false);
        _timer.Dispose(done);
        done.WaitOne(TimeSpan.FromSeconds(5));
    }
}
