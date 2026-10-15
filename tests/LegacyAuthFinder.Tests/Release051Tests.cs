using System.Diagnostics;
using System.Text.RegularExpressions;
using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// Version 0.5.1: the retention estimate per log file, the HTML report with the events behind each fix, and the
/// logging check on Windows Server 2016.
/// </summary>
[Collection(SerialCollection.Name)]
public sealed class Release051Tests
{
    private static readonly DateTime T0 = new(2026, 10, 1, 8, 0, 0);

    private static LogFileInfo File(long size, long records, TimeSpan covered, string? error = null) =>
        new("a.evtx", size, Channels.Security, "DC01", records, 1, T0, T0 + covered, error);

    // ---------------- Retention estimate ----------------

    [Fact]
    public void Days_at_each_size_follow_the_load_of_the_file()
    {
        // 4 MB of events over 2 days: 32 MB holds 16 days, 1 GB about 512 days.
        var e = Retention.For(File(EvtxFileReader.HeaderSize + (4L << 20), 10_000, TimeSpan.FromDays(2)))!;
        Assert.Equal(5_000, e.EventsPerDay, 3);
        Assert.Equal([16.0, 50.0, 125.0, 512.0], e.At.Select(a => Math.Round(a.Days, 3)));
        Assert.Equal([32L << 20, 100L << 20, 250L << 20, 1L << 30], e.At.Select(a => a.Size));
        Assert.False(e.Rough);
        Assert.Equal("16 d · 50 d · 125 d · 512 d", e.DaysText);
    }

    [Fact]
    public void A_busy_log_shows_hours()
    {
        // A 4 GB Security log that covers 20 hours, like a busy domain controller.
        var e = Retention.For(File(EvtxFileReader.HeaderSize + (4L << 30), 9_000_000, TimeSpan.FromHours(20)))!;
        Assert.True(e.Rough);
        Assert.Equal("about 9 min · 29 min · 1 h · 5 h", e.DaysText);
        Assert.Equal("10.8M", e.EventsPerDayText);
    }

    [Fact]
    public void No_estimate_without_enough_data()
    {
        Assert.Null(Retention.For(File(1 << 20, 50, TimeSpan.FromDays(3))));
        Assert.Null(Retention.For(File(1 << 20, 5_000, TimeSpan.FromMinutes(30))));
        Assert.Null(Retention.For(File(1 << 20, 5_000, TimeSpan.FromDays(3), error: "broken")));
        Assert.Null(Retention.For(new LogFileInfo("b.evtx", 1 << 20, Channels.Security, "DC01", 5_000, 1, null, null)));
    }

    [Theory]
    [InlineData(0.01, "14 min")]
    [InlineData(0.5, "12 h")]
    [InlineData(2.54, "2.5 d")]
    [InlineData(38.4, "38 d")]
    [InlineData(1000, "2.7 y")]
    public void Days_are_written_in_a_readable_unit(double days, string text) => Assert.Equal(text, Retention.DaysText(days));

    // ---------------- HTML report ----------------

    [Fact]
    public void Every_fix_opens_to_its_steps_and_events()
    {
        var r = DemoData.Create(T0);
        var html = Reports.ToHtml(r);
        Assert.Equal(r.Fixes.Count, Regex.Matches(html, "<details class=\"fix\" id=\"fix-\\d+\">").Count);
        var first = Block(html, 1);
        Assert.Contains("What to do:", first);
        Assert.Contains(System.Net.WebUtility.HtmlEncode(r.Fixes[0].Action), first);
        Assert.Contains("<table class=\"ev\">", first);
        Assert.Contains("<a href=\"https://", first);
        // Every summary row links to its fix.
        Assert.Contains("<a href=\"#fix-1\">1</a>", html);
        Assert.Contains($"Days at {Retention.SizesText}", html);
    }

    /// <summary>The HTML of one fix block.</summary>
    private static string Block(string html, int rank)
    {
        var start = html.IndexOf($"id=\"fix-{rank}\"", StringComparison.Ordinal);
        Assert.True(start > 0);
        return html[start..html.IndexOf("</div></details>", start, StringComparison.Ordinal)];
    }

    [Fact]
    public void A_fix_lists_its_own_newest_events_only()
    {
        var r = DemoData.Create(T0);
        var shown = Reports.EventsByFix(r.Fixes, r.Events, Reports.HtmlEventsPerFix);
        foreach (var f in r.Fixes)
        {
            var list = shown[f];
            Assert.True(list.Count <= Reports.HtmlEventsPerFix);
            Assert.True(list.Count == Math.Min(Reports.HtmlEventsPerFix, f.Events), $"fix {f.Rank}: {list.Count} of {f.Events}");
            var keys = f.SourceRows.Select(x => x.Key).ToHashSet(SummaryKey.Comparer);
            Assert.All(list, e => Assert.Contains(SummaryKey.Of(e), keys));
            // Newest first, and nothing newer of this fix left out.
            Assert.Equal(list.OrderByDescending(e => e.Time).Select(e => e.Time), list.Select(e => e.Time));
            var newestLeftOut = r.Events.Where(e => keys.Contains(SummaryKey.Of(e))).Except(list).Select(e => e.Time).DefaultIfEmpty(DateTime.MinValue).Max();
            Assert.True(list.Count == 0 || newestLeftOut <= list[^1].Time);
        }
    }

    [Fact]
    public void Event_text_is_encoded_in_the_report()
    {
        // Account and workstation names come from the logs, an attacker can choose them.
        var evil = "<script>alert(1)</script>";
        var reader = new FakeReader();
        reader.Events["a.evtx"] =
        [
            new(4624, Providers.SecurityAuditing, T0, "FS01", 1, new Dictionary<string, string>
            {
                ["LmPackageName"] = "NTLM V1", ["TargetUserName"] = evil, ["WorkstationName"] = "<img src=x onerror=alert(2)>", ["IpAddress"] = "10.0.0.7",
                ["ProcessName"] = "\"><b>x</b>",
            }),
        ];
        var r = Scanner.Scan(reader, [new LogFileInfo("a.evtx", 1000, Channels.Security, "FS01", 1, 1, T0, T0)], "<scope>", new ScanOptions());
        var html = Reports.ToHtml(r);
        Assert.DoesNotContain(evil, html);
        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain("<b>x</b>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", Block(html, 1));
    }

    [Fact]
    public void A_big_result_stays_within_the_event_limit()
    {
        var r = DemoData.Create(T0);
        var html = Reports.ToHtml(r);
        var rows = Regex.Matches(html, "<table class=\"ev\">.*?</table>", RegexOptions.Singleline).Sum(m => Regex.Matches(m.Value, "<tr><td>").Count);
        Assert.InRange(rows, 1, Reports.HtmlEventsTotal);
    }

    // ---------------- Logging check on Windows Server 2016 ----------------

    private static string Simulate2016(bool restrictOn)
    {
        var t = LoggingCheck.Script
            .Replace("$isDc = $cs.DomainRole -ge 4", "$isDc = $true")
            .Replace("$is2016 = [int]$os.BuildNumber -lt 17763", "$is2016 = $true")
            .Replace("$ntlmEnhanced = HasEvent 'Microsoft-Windows-NTLM' 4020", "$ntlmEnhanced = $false")
            .Replace("HasEvent 'Microsoft-Windows-Security-Netlogon' 4030", "$false")
            .Replace("$restrictOn = ((Reg $msv 'AuditReceivingNTLMTraffic') -eq 2) -and ((Reg $msv 'RestrictSendingNTLMTraffic') -in 1, 2)", $"$restrictOn = ${restrictOn}".ToLowerInvariant())
            .Replace("'AuditNTLMInDomain') -eq 7\r\n", $"'AuditNTLMInDomain') -eq 7 -or ${restrictOn}\r\n".Replace("True", "true").Replace("False", "false"));
        var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(start)!;
        p.StandardInput.Write(t);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEndAsync();
        var errors = p.StandardError.ReadToEndAsync();
        Assert.True(p.WaitForExit(180_000));
        return output.Result + errors.Result;
    }

    [Fact]
    public void On_server_2016_the_check_does_not_ask_for_an_update_that_does_not_exist()
    {
        var on = Simulate2016(restrictOn: true);
        Assert.Contains("[INFO   ] Enhanced NTLM events 4020 to 4023: not available on Windows Server 2016", on);
        Assert.Contains("[INFO   ] Domain controller NTLM events 4030 to 4033: not available on Windows Server 2016", on);
        Assert.DoesNotContain("Install the latest cumulative update", on.Split("KDC RC4")[0]);
        var off = Simulate2016(restrictOn: false);
        Assert.Contains("[WARN   ] Enhanced NTLM events 4020 to 4023: not available on Windows Server 2016", off);
        Assert.Contains("[WARN   ] Domain controller NTLM events 4030 to 4033: not available on Windows Server 2016", off);
    }
}
