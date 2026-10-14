using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// The built-in parser is checked against the Windows event log API on real logs exported from the machine running
/// the tests: every record, every system field and every value must come out the same. CI runners add the Security log.
/// </summary>
public sealed class EvtxParserTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-parse-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string? Export(string log)
    {
        var path = Path.Combine(_dir, log.Replace('/', '_') + ".evtx");
        using var p = Process.Start(new ProcessStartInfo("wevtutil", $"epl \"{log}\" \"{path}\"") { RedirectStandardError = true, RedirectStandardOutput = true })!;
        p.WaitForExit(180_000);
        return p.ExitCode == 0 && File.Exists(path) ? path : null;
    }

    public static readonly TheoryData<string> Logs = new()
    {
        "System", "Application", "Security", "Microsoft-Windows-NTLM/Operational", "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational", "Setup",
    };

    [Theory]
    [MemberData(nameof(Logs))]
    public void Every_record_matches_the_windows_api(string log)
    {
        var path = Export(log);
        if (path is null)
        {
            output.WriteLine($"{log}: cannot be exported on this machine, skipped.");
            return;
        }
        const int Limit = 40_000;
        var stats = new ReadStats();
        var clock = Stopwatch.StartNew();
        var ours = EvtxFileReader.ReadEverything(path, stats).Take(Limit * 2).ToDictionary(r => r.RecordId);
        output.WriteLine($"{log}: {new FileInfo(path).Length / 1048576.0:0.0} MB, parsed {ours.Count:N0} records in {clock.ElapsedMilliseconds} ms ({stats.Chunks} chunks)");

        var selectors = new Dictionary<string, EventLogPropertySelector>();
        var mismatches = new List<string>();
        var compared = 0;
        // The XML rendering is slow, so the XML-style values (used for KDC warnings) are compared on fewer records.
        const int XmlLimit = 4_000;
        using var reader = new EventLogReader(new EventLogQuery(path, PathType.FilePath, "*"));
        while (compared < Limit && reader.ReadEvent() is EventLogRecord w)
        {
            using var _ = w;
            compared++;
            var id = w.RecordId ?? 0;
            if (!ours.TryGetValue(id, out var r))
            {
                mismatches.Add($"record {id}: missing in the parser");
                continue;
            }
            if (r.Error is not null)
            {
                mismatches.Add($"record {id} (event {w.Id} {w.ProviderName}): parser error {r.Error}");
                continue;
            }
            void Check(string what, object? expected, object? actual)
            {
                if (!Equals(expected, actual)) mismatches.Add($"record {id} (event {w.Id} {w.ProviderName}) {what}: windows '{expected}', parser '{actual}'");
            }
            Check("event id", w.Id, r.EventId);
            Check("provider", w.ProviderName ?? "", r.Provider);
            Check("time", w.TimeCreated, (DateTime?)r.Time);
            Check("computer", w.MachineName ?? "", r.Computer);
            Check("channel", w.LogName ?? "", r.Channel);
            var props = w.Properties.Select(p => WindowsEvtxReader.Format("", p.Value)).ToList();
            Check("value count", props.Count, r.Positional.Count);
            for (var i = 0; i < Math.Min(props.Count, r.Positional.Count); i++) Check($"value {i}", props[i], r.Positional[i]);
            if (r.Named.Count > 0)
            {
                var names = r.Named.Keys.ToList();
                var key = string.Join('\u0001', names);
                if (!selectors.TryGetValue(key, out var selector))
                {
                    selector = new EventLogPropertySelector(names.Select(n => $"Event/EventData/Data[@Name='{n}']"));
                    selectors[key] = selector;
                }
                var values = w.GetPropertyValues(selector);
                for (var i = 0; i < names.Count; i++) Check($"field {names[i]}", WindowsEvtxReader.Format(names[i], values[i]), r.Named[names[i]]);
            }
            if (compared <= XmlLimit)
            {
                var (xmlData, xmlValues) = WindowsEvtxReader.EventDataFromXml(w.ToXml());
                Check("xml value count", xmlValues.Count, r.Xml.Values.Count);
                for (var i = 0; i < Math.Min(xmlValues.Count, r.Xml.Values.Count); i++) Check($"xml value {i}", xmlValues[i], r.Xml.Values[i]);
                foreach (var (k, v) in xmlData) Check($"xml field {k}", v, r.Xml.Data.GetValueOrDefault(k));
            }
            if (mismatches.Count > 200) break;
        }
        foreach (var s in selectors.Values) s.Dispose();
        output.WriteLine($"{log}: compared {compared:N0} records, {mismatches.Count} differences");
        // Group by kind of difference, so one run shows every distinct problem.
        foreach (var g in mismatches.GroupBy(m =>
                 {
                     var rest = System.Text.RegularExpressions.Regex.Replace(m, @"^record \d+ ", "");
                     return rest[..Math.Min(60, rest.Length)];
                 }).Take(25))
        {
            var m = g.First();
            output.WriteLine($"  {g.Count()}x {(m.Length > 400 ? m[..400] : m).Replace("\r", "\\r").Replace("\n", "\\n")}");
        }
        Assert.Empty(mismatches);
    }

    [Fact]
    public void Scan_with_the_parser_finds_what_the_windows_api_finds()
    {
        var system = Export("System");
        var security = Export("Security");
        Assert.NotNull(system);
        var windows = new WindowsEvtxReader();
        var parser = new EvtxFileReader(windows);
        var files = Scanner.Inventory(parser, _dir, recurse: false);
        var viaWindows = Scanner.Scan(windows, files, "w", new ScanOptions(Threads: 2));
        var viaParser = Scanner.Scan(parser, files, "p", new ScanOptions(Threads: 2));
        output.WriteLine($"security log {(security is null ? "not available" : "included")}: windows {viaWindows.TotalHits} events, parser {viaParser.TotalHits} events");
        Assert.Equal(viaWindows.TotalHits, viaParser.TotalHits);
        Assert.Equal(viaWindows.Summary.Select(s => (s.Kind, s.Account, s.Client, s.Service, s.Count)), viaParser.Summary.Select(s => (s.Kind, s.Account, s.Client, s.Service, s.Count)));
        Assert.All(files.Where(f => f.IsRelevant), f => Assert.Equal(FileState.Done, viaParser.FileResults[f.Path].State));
    }

    [Fact]
    public void Inspect_matches_the_windows_api()
    {
        var system = Export("System")!;
        var w = new WindowsEvtxReader().Inspect(system);
        var p = new EvtxFileReader().Inspect(system);
        output.WriteLine($"windows: {w}");
        output.WriteLine($"parser:  {p}");
        Assert.Equal(w.Channel, p.Channel);
        Assert.Equal(w.Computer, p.Computer);
        Assert.Equal(w.FirstRecordId, p.FirstRecordId);
        Assert.Equal(w.LastRecordId, p.LastRecordId);
        Assert.Equal(w.First, p.First);
        Assert.Equal(w.Last, p.Last);
    }

    [Fact]
    public void Damaged_chunks_are_skipped_and_the_rest_is_read()
    {
        var system = Export("System")!;
        var all = EvtxFileReader.ReadEverything(system).Count();
        var damaged = Path.Combine(_dir, "damaged.evtx");
        var bytes = File.ReadAllBytes(system);
        var chunks = (bytes.Length - EvtxFileReader.HeaderSize) / EvtxFileReader.ChunkSize;
        Assert.True(chunks >= 3, "needs a System log of at least 3 chunks");
        // Garbage in the records of the second chunk, a broken signature on the third.
        var second = EvtxFileReader.HeaderSize + EvtxFileReader.ChunkSize;
        new Random(1).NextBytes(bytes.AsSpan(second + 600, 4000));
        bytes[second + EvtxFileReader.ChunkSize] = (byte)'X';
        File.WriteAllBytes(damaged, bytes);

        var stats = new ReadStats();
        var events = new EvtxFileReader().ReadAll(damaged, [Queries.KdcWarnings, Queries.KdcEtypeErrors], CancellationToken.None, null, stats).Count();
        output.WriteLine($"{all} records in the original, damaged copy: {stats}");
        Assert.Equal(1, stats.BadChunks);
        Assert.True(stats.Records > all / 2);
        Assert.True(events >= 0);
    }

    [Fact]
    public void A_file_that_is_not_evtx_goes_to_the_fallback()
    {
        var bad = Path.Combine(_dir, "not-evtx.evtx");
        File.WriteAllText(bad, "this is not an event log");
        var stats = new ReadStats();
        // The Windows API cannot read it either: every query is counted as failed and the file as partly read.
        Assert.Empty(new EvtxFileReader(new WindowsEvtxReader()).ReadAll(bad, [Queries.Ntlmv1, Queries.Kerberos], CancellationToken.None, null, stats));
        Assert.NotNull(stats.Fallback);
        Assert.Equal(2, stats.FailedQueries);
        Assert.True(stats.Partial);
        Assert.Throws<EvtxFormatException>(() => new EvtxFileReader().ReadAll(bad, [Queries.Ntlmv1], CancellationToken.None).ToList());
        Assert.NotNull(new EvtxFileReader().Inspect(bad).Error);
    }

    [Fact]
    public void Random_damage_never_crashes_the_parser()
    {
        var system = Export("System")!;
        var original = File.ReadAllBytes(system).AsSpan(0, Math.Min(File.ReadAllBytes(system).Length, EvtxFileReader.HeaderSize + 4 * EvtxFileReader.ChunkSize)).ToArray();
        var random = new Random(7);
        var path = Path.Combine(_dir, "fuzz.evtx");
        for (var round = 0; round < 60; round++)
        {
            var bytes = (byte[])original.Clone();
            for (var i = 0; i < 40; i++) bytes[EvtxFileReader.HeaderSize + random.Next(bytes.Length - EvtxFileReader.HeaderSize)] = (byte)random.Next(256);
            File.WriteAllBytes(path, bytes);
            var stats = new ReadStats();
            _ = new EvtxFileReader().ReadAll(path, Queries.All, CancellationToken.None, null, stats).Count();
            _ = EvtxFileReader.ReadEverything(path).Count();
        }
    }

    [Fact]
    public void Parser_speed()
    {
        var system = Export("System")!;
        var size = new FileInfo(system).Length;
        var clock = Stopwatch.StartNew();
        var stats = new ReadStats();
        for (var i = 0; i < 5; i++) _ = new EvtxFileReader().ReadAll(system, [Queries.KdcWarnings, Queries.KdcEtypeErrors], CancellationToken.None, null, stats).Count();
        var mbs = size * 5 / 1048576.0 / clock.Elapsed.TotalSeconds;
        output.WriteLine($"{mbs:0} MB/s on one thread, {stats.Records / 5:N0} records per pass");
        clock.Restart();
        var all = EvtxFileReader.ReadEverything(system).Count();
        output.WriteLine($"full decode of {all:N0} records: {all / clock.Elapsed.TotalSeconds:N0} records/s");
    }
}
