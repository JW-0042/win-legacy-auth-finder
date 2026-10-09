using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// Runs the real Windows event log API against logs exported from the machine running the tests.
/// The System log can be exported without admin rights. The Security log needs admin (CI runners have it).
/// </summary>
public sealed class WindowsReaderTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-").FullName;
    private readonly WindowsEvtxReader _reader = new();

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string? Export(string log, string name)
    {
        var path = Path.Combine(_dir, name);
        using var p = Process.Start(new ProcessStartInfo("wevtutil", $"epl {log} \"{path}\"") { RedirectStandardError = true, RedirectStandardOutput = true })!;
        p.WaitForExit(120_000);
        return p.ExitCode == 0 && File.Exists(path) ? path : null;
    }

    [Fact]
    public void Inventory_detects_the_log_of_each_file()
    {
        var system = Export("System", "Archive-System-1.evtx")!;
        Assert.NotNull(system);
        File.WriteAllText(Path.Combine(_dir, "broken.evtx"), "not an event log");

        var files = Scanner.Inventory(_reader, _dir, recurse: true);
        var sys = files.Single(f => f.Name == "Archive-System-1.evtx");
        Assert.Equal("System", sys.Channel);
        Assert.True(sys.RecordCount > 0);
        Assert.NotNull(sys.First);
        Assert.True(sys.IsRelevant);
        Assert.NotNull(files.Single(f => f.Name == "broken.evtx").Error);
    }

    [Fact]
    public void All_queries_are_valid_xpath_for_the_event_log_api()
    {
        var system = Export("System", "sys.evtx")!;
        foreach (var q in Queries.All)
        {
            // Throws EventLogException when the query is malformed. On this file they simply match nothing.
            var found = _reader.Read(system, q, CancellationToken.None).Count();
            output.WriteLine($"{q.Name}: {found}");
        }
    }

    [Fact]
    public void Named_fields_are_read_with_the_property_selector()
    {
        var system = Export("System", "sys.evtx")!;
        // Kernel-General 16 (registry hive flushed) is on every Windows machine and has a string and a number field.
        var query = new EvtxQuery("test", "System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=16]]", ["HiveName", "KeysUpdated", "DoesNotExist"]);
        var events = _reader.Read(system, query, CancellationToken.None).Take(20).ToList();
        if (events.Count == 0)
        {
            output.WriteLine("No Kernel-General 16 events on this machine.");
            return;
        }
        Assert.All(events, e =>
        {
            Assert.Contains("\\", e["HiveName"]);
            Assert.True(uint.TryParse(e["KeysUpdated"], out _));
            Assert.Equal("", e["DoesNotExist"]);
            Assert.True(e.RecordId > 0);
        });
    }

    [Fact]
    public void Security_log_fields_are_read_when_the_log_can_be_exported()
    {
        var security = Export("Security", "sec.evtx");
        if (security is null)
        {
            output.WriteLine("Security log export needs admin rights. Skipped.");
            return;
        }
        // Same field list as the NTLM query, but matching any network logon so the runner has data.
        var query = Queries.Ntlmv1 with { XPath = "*[System[EventID=4624]]" };
        var events = _reader.Read(security, query, CancellationToken.None).Take(50).ToList();
        output.WriteLine($"4624 events read: {events.Count}");
        Assert.All(events, e => Assert.False(string.IsNullOrEmpty(e["TargetUserName"])));

        var kerberos = Queries.Kerberos with { XPath = "*[System[(EventID=4768 or EventID=4769)]]" };
        foreach (var e in _reader.Read(security, kerberos, CancellationToken.None).Take(20))
        {
            Assert.StartsWith("0x", e["TicketEncryptionType"]);
        }
    }

    [Fact]
    public void Scanning_a_large_file_is_fast_when_nothing_matches()
    {
        var system = Export("System", "big.evtx")!;
        var info = _reader.Inspect(system);
        var clock = Stopwatch.StartNew();
        var result = Scanner.Scan(_reader, [info with { Channel = "Security" }], "perf", new ScanOptions());
        clock.Stop();
        var mbPerSecond = info.Size / 1_048_576.0 / Math.Max(clock.Elapsed.TotalSeconds, 0.001);
        output.WriteLine($"{info.Size / 1_048_576.0:0.0} MB, {info.RecordCount} records in {clock.ElapsedMilliseconds} ms ({mbPerSecond:0} MB/s)");
        Assert.Equal(FileState.Done, result.FileResults[system].State);
    }

    [Fact]
    public void Inventory_records_the_real_record_id_range()
    {
        var system = Export("System", "ids.evtx")!;
        var info = _reader.Inspect(system);
        Assert.True(info.FirstRecordId > 0);
        Assert.True(info.LastRecordId >= info.FirstRecordId);
        output.WriteLine($"records {info.FirstRecordId} to {info.LastRecordId}, oldest reported as {info.OldestRecordNumber}");
    }

    [Fact]
    public void Reading_in_slices_keeps_every_record_and_stays_cancellable()
    {
        var system = Export("System", "slices.evtx")!;
        var info = _reader.Inspect(system);
        // Only the last 200 records match, so the API scans most of the file before the first result.
        var query = new EvtxQuery("tail", "System", $"*[System[EventRecordID>={info.LastRecordId - 199}]]", null, Positional: true);
        var full = _reader.Read(system, query, CancellationToken.None).Count();
        var old = WindowsEvtxReader.ReadSlice;
        try
        {
            WindowsEvtxReader.ReadSlice = TimeSpan.FromMilliseconds(1);
            var alive = 0;
            var sliced = _reader.Read(system, query, CancellationToken.None, () => alive++).Count();
            output.WriteLine($"{full} records, {alive} empty slices");
            Assert.Equal(full, sliced);
            Assert.True(full > 0);

            // A cancelled scan must stop at the next slice instead of waiting for the end of the file.
            using var cts = new CancellationTokenSource();
            Assert.Throws<OperationCanceledException>(() =>
                _reader.Read(system, query, cts.Token, () => cts.Cancel()).Count());
        }
        finally
        {
            WindowsEvtxReader.ReadSlice = old;
        }
    }

    [Fact]
    public void Other_errors_are_not_mistaken_for_a_timeout()
    {
        // The positive case is covered by Reading_in_slices_keeps_every_record_and_stays_cancellable, which counts
        // real expired slices. EventLogException builds its message from the Win32 code, so it cannot be faked here.
        Assert.False(WindowsEvtxReader.IsTimeout(new EventLogException("The event log file is corrupted.")));
    }

    [Fact]
    public void Storage_of_the_temp_folder_is_detected()
    {
        var kind = Storage.Detect(_dir);
        output.WriteLine($"{_dir}: {kind}, recommended {Storage.RecommendedThreads(kind)} files at once");
        Assert.NotEqual(StorageKind.Network, kind);
    }

    [Fact]
    public void Format_turns_numbers_into_hex_for_encryption_fields()
    {
        Assert.Equal("0x17", WindowsEvtxReader.Format("TicketEncryptionType", 23u));
        Assert.Equal("3", WindowsEvtxReader.Format("LogonType", 3u));
        Assert.Equal("", WindowsEvtxReader.Format("X", null));
        Assert.Equal("0xe", WindowsEvtxReader.Format("FailureCode", 14u));
    }

    [Fact]
    public void Positional_queries_return_values_in_order()
    {
        var system = Export("System", "sys-pos.evtx")!;
        var query = new EvtxQuery("test", "System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=16]]", null, Positional: true);
        var events = _reader.Read(system, query, CancellationToken.None).Take(10).ToList();
        if (events.Count == 0)
        {
            output.WriteLine("No Kernel-General 16 events on this machine.");
            return;
        }
        // Kernel-General 16: HiveNameLength, HiveName, KeysUpdated, DirtyPages.
        Assert.All(events, e => Assert.Contains("\\", e.At(1)));
    }
}
