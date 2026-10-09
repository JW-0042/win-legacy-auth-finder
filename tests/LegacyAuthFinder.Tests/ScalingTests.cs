using System.Diagnostics;
using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

/// <summary>Many files with many hits, scanned with few and many threads. Guards against lock contention.</summary>
public sealed class ScalingTests(ITestOutputHelper output)
{
    private sealed class BusyReader(int eventsPerFile) : IEvtxReader
    {
        public LogFileInfo Inspect(string path) => throw new NotSupportedException();

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null)
        {
            if (query != Queries.Kerberos) yield break;
            var start = new DateTime(2026, 9, 1);
            for (var i = 0; i < eventsPerFile; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return new RawEvent(4769, Providers.SecurityAuditing, start.AddSeconds(i), "DC01.lab.local", i + 1,
                    new Dictionary<string, string>
                    {
                        ["TargetUserName"] = $"user{i % 500}@LAB.LOCAL",
                        ["TargetDomainName"] = "LAB.LOCAL",
                        ["ServiceName"] = $"HTTP/app{i % 40}.lab.local",
                        ["IpAddress"] = $"::ffff:10.0.{i % 200}.{i % 250}",
                        ["IpPort"] = (49152 + i % 16000).ToString(),
                        ["TicketEncryptionType"] = "0x17",
                        ["SessionKeyEncryptionType"] = "0x17",
                        ["TicketOptions"] = "0x40810000",
                        ["Status"] = "0x0",
                    });
            }
        }
    }

    [Fact]
    public void Sixteen_threads_are_not_slower_than_two()
    {
        const int files = 19, perFile = 60_000;
        var list = Enumerable.Range(0, files).Select(i => new LogFileInfo($"f{i}.evtx", 1, "Security", "DC01", perFile, 1, null, null)).ToList();

        double Run(int threads)
        {
            var clock = Stopwatch.StartNew();
            var r = Scanner.Scan(new BusyReader(perFile), list, "perf", new ScanOptions(Threads: threads));
            clock.Stop();
            Assert.Equal((long)files * perFile, r.TotalHits);
            Assert.All(list, f => Assert.Equal(FileState.Done, r.FileResults[f.Path].State));
            return clock.Elapsed.TotalSeconds;
        }

        Run(2); // warm up
        var two = Run(2);
        var sixteen = Run(16);
        output.WriteLine($"{files} files x {perFile:N0} events: 2 threads {two:0.00} s, 16 threads {sixteen:0.00} s, memory {GC.GetTotalMemory(false) / 1048576} MB");
        Assert.True(sixteen <= two * 1.5, $"16 threads took {sixteen:0.00} s, 2 threads {two:0.00} s");
    }
}
