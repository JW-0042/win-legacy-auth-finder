using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

public sealed class DiagLogTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-log-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Read(DiagLog log)
    {
        log.Dispose();
        return File.ReadAllText(log.Path);
    }

    /// <summary>A reader whose first read blocks without any sign of life, like a call stuck in the Event Log service.</summary>
    private sealed class StuckReader(TimeSpan block) : IEvtxReader
    {
        public LogFileInfo Inspect(string path) => throw new NotSupportedException();

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null)
        {
            Thread.Sleep(block);
            cancellationToken.ThrowIfCancellationRequested();
            yield return new RawEvent(4769, Providers.SecurityAuditing, new DateTime(2026, 10, 1), "DC01", 5,
                new Dictionary<string, string> { ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = "svc", ["ServiceName"] = "HTTP/app" });
        }
    }

    [Fact]
    public void Header_describes_the_machine_without_its_name()
    {
        var log = DiagLog.Create("test", Path.Combine(_dir, "a.log"));
        var text = Read(log);
        output.WriteLine(text);
        Assert.Contains("diagnostic log (test)", text);
        Assert.Contains("logical CPUs", text);
        Assert.Contains("Event Log service", text);
        Assert.DoesNotContain(Environment.MachineName, text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Scan_writes_files_queries_and_the_result()
    {
        var reader = new FakeReader();
        reader.Events["a.evtx"] = [new RawEvent(4624, Providers.SecurityAuditing, new DateTime(2026, 10, 1), "FS01", 9,
            new Dictionary<string, string> { ["LmPackageName"] = "NTLM V1", ["TargetUserName"] = "secret-user", ["IpAddress"] = "10.9.9.9" })];
        var log = DiagLog.Create("test", Path.Combine(_dir, "b.log"));
        Scanner.Scan(reader, [new LogFileInfo("a.evtx", 1000, "Security", "FS01", 10, 1, null, null)], "test", new ScanOptions(Log: log));
        var text = Read(log);
        output.WriteLine(text);
        Assert.Contains("SCAN     Start: 1 files", text);
        Assert.Contains("QUERY    [01] a.evtx NTLMv1 logons", text);
        Assert.Contains("done a.evtx", text);
        Assert.Contains("Finished after", text);
        // Event content never goes to the log.
        Assert.DoesNotContain("secret-user", text);
        Assert.DoesNotContain("10.9.9.9", text);
    }

    [Fact]
    public void A_blocked_read_is_reported_as_a_stall()
    {
        var log = DiagLog.Create("test", Path.Combine(_dir, "c.log"));
        var options = new ScanOptions(Threads: 2, Log: log, Heartbeat: TimeSpan.FromMilliseconds(100), StallAfter: TimeSpan.FromMilliseconds(400));
        var r = Scanner.Scan(new StuckReader(TimeSpan.FromSeconds(2)), [new LogFileInfo("big.evtx", 4L << 30, "Security", "DC01", 10, 1, null, null)], "test", options);
        var text = Read(log);
        output.WriteLine(text);
        Assert.Equal(FileState.Done, r.FileResults["big.evtx"].State);
        Assert.Contains("STALL", text);
        Assert.Contains("no progress for", text);
        Assert.Contains("BEAT", text);
        Assert.Contains("SLOW", text);
    }

    [Fact]
    public void Cancel_is_logged_with_the_running_files()
    {
        var log = DiagLog.Create("test", Path.Combine(_dir, "d.log"));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var r = Scanner.Scan(new StuckReader(TimeSpan.FromSeconds(1)), [new LogFileInfo("x.evtx", 1, "Security", "DC01", 10, 1, null, null)], "test",
            new ScanOptions(Log: log), cancellationToken: cts.Token);
        var text = Read(log);
        output.WriteLine(text);
        Assert.True(r.Cancelled);
        Assert.Contains("Cancel requested", text);
        Assert.Contains("cancelled x.evtx", text);
    }

    [Fact]
    public void Old_logs_are_pruned()
    {
        for (var i = 0; i < DiagLog.KeepFiles + 5; i++)
        {
            var old = Path.Combine(_dir, $"legacy-auth-finder-2026010{i:00}.log");
            File.WriteAllText(old, "x");
            File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddMinutes(-100 + i));
        }
        DiagLog.Create("test", Path.Combine(_dir, "legacy-auth-finder-new.log")).Dispose();
        Assert.Equal(DiagLog.KeepFiles, Directory.GetFiles(_dir, "legacy-auth-finder-*.log").Length);
    }

    [Fact]
    public void System_process_list_matches_this_process()
    {
        using var me = System.Diagnostics.Process.GetCurrentProcess();
        var listed = SystemProbe.FromSystemList(Environment.ProcessId);
        Assert.NotNull(listed);
        output.WriteLine($"list: {SystemProbe.Describe(listed)}; process: {me.WorkingSet64 / 1048576} MB, {me.Threads.Count} threads, {me.HandleCount} handles, CPU {me.TotalProcessorTime.TotalSeconds:0.0} s");
        Assert.InRange(listed.Threads, me.Threads.Count / 2, me.Threads.Count * 2);
        Assert.InRange(listed.Handles, me.HandleCount / 2, me.HandleCount * 2);
        Assert.InRange(listed.WorkingSet, me.WorkingSet64 / 2, me.WorkingSet64 * 2);
        Assert.InRange(listed.Cpu.TotalSeconds, me.TotalProcessorTime.TotalSeconds * 0.5, me.TotalProcessorTime.TotalSeconds * 2 + 1);
        // The Event Log service is readable without admin rights through the same list.
        Assert.NotNull(SystemProbe.EventLogService());
    }

    [Fact]
    public void Probes_do_not_throw()
    {
        output.WriteLine(SystemProbe.EventLogServiceText());
        output.WriteLine(SystemProbe.Describe(SystemProbe.Self()));
        output.WriteLine(SystemProbe.ThreadPoolText());
        output.WriteLine(SystemProbe.GcText());
        output.WriteLine(Storage.Explain(_dir));
        Assert.NotNull(SystemProbe.Self());
    }
}
