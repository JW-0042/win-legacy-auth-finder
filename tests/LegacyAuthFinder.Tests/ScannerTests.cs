using System.Diagnostics.Eventing.Reader;
using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

internal sealed class FakeReader : IEvtxReader
{
    public Dictionary<string, List<RawEvent>> Events { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Exception> Throws { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string Path, string Query)> Calls { get; } = [];

    public LogFileInfo Inspect(string path) => throw new NotSupportedException();

    public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken)
    {
        lock (Calls) Calls.Add((path, query.Name));
        if (Throws.TryGetValue(path, out var ex)) throw ex;
        foreach (var e in Events.GetValueOrDefault(path) ?? [])
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DemoData.QueryOf(e) == query) yield return e;
        }
    }
}

public class ScannerTests
{
    private static LogFileInfo File(string path, string channel, string? error = null) =>
        new(path, 1000, channel, "SRV", 100, 1, null, null, error);

    private static RawEvent Rc4(string user, string client, int minute, long record = 1) =>
        new(4769, Providers.SecurityAuditing, new DateTime(2026, 9, 1, 10, minute, 0), "DC01", record,
            new Dictionary<string, string> { ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = user, ["IpAddress"] = client, ["ServiceName"] = "HTTP/app" });

    private static RawEvent Ntlm(string user, int minute) =>
        new(4624, Providers.SecurityAuditing, new DateTime(2026, 9, 1, 9, minute, 0), "FS01", 1,
            new Dictionary<string, string> { ["LmPackageName"] = "NTLM V1", ["TargetUserName"] = user, ["IpAddress"] = "10.0.0.7" });

    [Fact]
    public void Only_security_system_and_directory_service_logs_are_scanned()
    {
        var reader = new FakeReader();
        LogFileInfo[] files =
        [
            File("a.evtx", "Security"), File("b.evtx", "System"), File("e.evtx", "Directory Service"),
            File("c.evtx", "Application"), File("d.evtx", "", "broken"),
        ];
        var r = Scanner.Scan(reader, files, "test", new ScanOptions());
        Assert.Equal(FileState.Skipped, r.FileResults["c.evtx"].State);
        Assert.Equal(FileState.Error, r.FileResults["d.evtx"].State);
        Assert.Equal(["NTLMv1 logons", "RC4 and DES Kerberos tickets", "Kerberos encryption type failures"],
            reader.Calls.Where(c => c.Path == "a.evtx").Select(c => c.Query));
        Assert.Equal(["KDC RC4 warnings", "KDC encryption type errors"], reader.Calls.Where(c => c.Path == "b.evtx").Select(c => c.Query));
        Assert.Equal(["LDAP signing and channel binding"], reader.Calls.Where(c => c.Path == "e.evtx").Select(c => c.Query));
    }

    [Fact]
    public void Many_files_can_be_scanned_at_once()
    {
        var reader = new FakeReader();
        var files = Enumerable.Range(0, 20).Select(i => File($"f{i}.evtx", "Security")).ToList();
        foreach (var f in files) reader.Events[f.Path] = [Rc4("svc", "10.0.0.1", 1)];
        var r = Scanner.Scan(reader, files, "test", new ScanOptions(Threads: 16));
        Assert.Equal(20, r.TotalHits);
        Assert.All(files, f => Assert.Equal(FileState.Done, r.FileResults[f.Path].State));
    }

    [Fact]
    public void Summary_groups_by_kind_account_client_and_service()
    {
        var reader = new FakeReader();
        reader.Events["a.evtx"] = [Rc4("svc", "10.0.0.1", 1), Rc4("SVC", "10.0.0.1", 5), Rc4("svc", "10.0.0.2", 3), Ntlm("bob", 1)];
        var r = Scanner.Scan(reader, [File("a.evtx", "Security")], "test", new ScanOptions());

        Assert.Equal(4, r.TotalHits);
        Assert.Equal(3, r.Summary.Count);
        Assert.Equal(LegacyKind.Ntlmv1, r.Summary[0].Kind);
        var top = r.Summary.Single(s => s.Kind == LegacyKind.Rc4 && s.Client == "10.0.0.1");
        Assert.Equal(2, top.Count);
        Assert.Equal(new DateTime(2026, 9, 1, 10, 1, 0), top.FirstSeen);
        Assert.Equal(new DateTime(2026, 9, 1, 10, 5, 0), top.LastSeen);
        Assert.Equal(["DC01"], top.Computers);
        // Events come back sorted by time.
        Assert.True(r.Events.Zip(r.Events.Skip(1)).All(p => p.First.Time <= p.Second.Time));
    }

    [Fact]
    public void Event_list_is_capped_but_the_summary_counts_everything()
    {
        var reader = new FakeReader();
        reader.Events["a.evtx"] = Enumerable.Range(0, 50).Select(i => Rc4("svc", "10.0.0.1", i % 60)).ToList();
        var r = Scanner.Scan(reader, [File("a.evtx", "Security")], "test", new ScanOptions(MaxEvents: 10));
        Assert.Equal(10, r.Events.Count);
        Assert.True(r.Truncated);
        Assert.Equal(50, r.TotalHits);
        Assert.Equal(50, r.Summary.Single().Count);
    }

    [Fact]
    public void A_broken_file_does_not_stop_the_others()
    {
        var reader = new FakeReader();
        reader.Throws["bad.evtx"] = new EventLogException("The event log file is corrupted.");
        reader.Events["good.evtx"] = [Rc4("svc", "10.0.0.1", 1)];
        var r = Scanner.Scan(reader, [File("bad.evtx", "Security"), File("good.evtx", "Security")], "test", new ScanOptions(Threads: 2));
        Assert.Equal(FileState.Error, r.FileResults["bad.evtx"].State);
        Assert.False(string.IsNullOrWhiteSpace(r.FileResults["bad.evtx"].Message));
        Assert.Equal(FileState.Done, r.FileResults["good.evtx"].State);
        Assert.Equal(1, r.TotalHits);
    }

    [Fact]
    public void Cancelling_returns_partial_results()
    {
        var reader = new FakeReader();
        reader.Events["a.evtx"] = [Rc4("svc", "10.0.0.1", 1)];
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var r = Scanner.Scan(reader, [File("a.evtx", "Security")], "test", new ScanOptions(), cancellationToken: cts.Token);
        Assert.True(r.Cancelled);
        Assert.Equal(FileState.Cancelled, r.FileResults["a.evtx"].State);
    }

    [Fact]
    public void Progress_is_estimated_from_the_record_number()
    {
        var file = new LogFileInfo("a.evtx", 1, "Security", "", 1000, 501, null, null);
        Assert.Equal(0.5, Scanner.Percent(file, 1000));
        Assert.Null(Scanner.Percent(file with { RecordCount = 0 }, 10));
    }

    [Fact]
    public void Demo_covers_every_kind_and_file_state()
    {
        var r = DemoData.Create(DateTime.Now);
        Assert.All(Enum.GetValues<LegacyKind>(), k => Assert.True(r.Count(k) > 0));
        var states = r.FileResults.Values.Select(p => p.State).ToHashSet();
        Assert.Contains(FileState.Done, states);
        Assert.Contains(FileState.Skipped, states);
        Assert.Contains(FileState.Error, states);
        // The AES events in the demo must not show up.
        Assert.DoesNotContain(r.Events, e => e.Service == "cifs/fs01.contoso.local");
    }

    [Fact]
    public void Xpath_queries_cover_the_weak_etypes()
    {
        foreach (var t in new[] { "0x17", "0x18", "0x1", "0x3" })
        {
            Assert.Contains($"Data[@Name='TicketEncryptionType']='{t}'", Queries.Kerberos.XPath);
            Assert.Contains($"Data[@Name='SessionKeyEncryptionType']='{t}'", Queries.Kerberos.XPath);
        }
        Assert.Contains("'NTLM V1'", Queries.Ntlmv1.XPath);
    }
}

public class ReportTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("=cmd|' /c calc'!A1", "'=cmd|' /c calc'!A1")]
    [InlineData("-2+3", "'-2+3")]
    public void Csv_fields_are_quoted_and_formulas_defused(string input, string expected) => Assert.Equal(expected, Reports.Csv(input));

    [Fact]
    public void Csv_exports_have_a_header_and_one_line_per_row()
    {
        var r = DemoData.Create(DateTime.Now);
        using var events = new StringWriter();
        Reports.WriteEventsCsv(events, r.Events);
        Assert.Equal(r.Events.Count + 1, events.ToString().TrimEnd().Split('\n').Length);
        using var summary = new StringWriter();
        Reports.WriteSummaryCsv(summary, r.Summary);
        Assert.StartsWith("Type,Account,Client", summary.ToString());
    }

    [Fact]
    public void Html_report_is_encoded()
    {
        var r = DemoData.Create(DateTime.Now) with { Scope = "<script>x</script>" };
        var html = Reports.ToHtml(r);
        Assert.DoesNotContain("<script>x", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Json_report_has_totals()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(Reports.ToJson(DemoData.Create(DateTime.Now)));
        Assert.True(doc.RootElement.GetProperty("totals").GetProperty("des").GetInt64() > 0);
    }

    [Fact]
    public void Guidance_follows_the_house_style()
    {
        var texts = Guidance.All.Values.SelectMany(g => new[] { g.What, g.Risk, g.Fix });
        Assert.All(texts, t =>
        {
            Assert.DoesNotContain("—", t);
            Assert.DoesNotContain("; ", t);
        });
    }
}
