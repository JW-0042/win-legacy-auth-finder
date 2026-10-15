using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LegacyAuthFinder.Core;

public static class Reports
{
    private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

    /// <summary>Rows listed in the HTML report. The CSV export always has everything.</summary>
    public const int HtmlSummaryRows = 1000;

    /// <summary>Events listed under one fix in the HTML report, the newest ones. Fewer when there are many fixes.</summary>
    public const int HtmlEventsPerFix = 50;

    /// <summary>Events listed in the whole HTML report, so it stays small enough to open and send.</summary>
    public const int HtmlEventsTotal = 20_000;

    /// <summary>
    /// The newest events behind each fix: the events of the summary rows the fix was built from, matched the same
    /// way as "Show these events" in the app.
    /// </summary>
    internal static Dictionary<FixItem, List<AuthEvent>> EventsByFix(IReadOnlyList<FixItem> fixes, IEnumerable<AuthEvent> events, int perFix)
    {
        var byKey = new Dictionary<SummaryKey, FixItem>(SummaryKey.Comparer);
        foreach (var f in fixes)
        {
            foreach (var row in f.SourceRows) byKey[row.Key] = f;
        }
        // FixItem and SummaryRow compare by reference, each item is its own key.
        var result = fixes.ToDictionary(f => f, _ => new List<AuthEvent>());
        var open = fixes.Count;
        foreach (var e in events.OrderByDescending(e => e.Time))
        {
            if (!byKey.TryGetValue(SummaryKey.Of(e), out var fix)) continue;
            var list = result[fix];
            if (list.Count >= perFix) continue;
            list.Add(e);
            if (list.Count == perFix && --open == 0) break;
        }
        return result;
    }

    /// <summary>Excel opens UTF-8 CSV correctly only with a byte order mark.</summary>
    public static readonly Encoding CsvEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    /// <param name="separator">',' by default. Excel in many European locales expects ';' (the Windows list separator).</param>
    public static void WriteEventsCsv(TextWriter w, IEnumerable<AuthEvent> events, char separator = ',')
    {
        string C(string v) => Csv(v, separator);
        w.WriteLine(string.Join(separator, "Time", "Type", "Detail", "Computer", "EventId", "Event", "Account", "Domain", "Client", "Service",
            "TicketEncryption", "SessionKeyEncryption", "File", "RecordId"));
        foreach (var e in events)
        {
            w.WriteLine(string.Join(separator,
                e.Time.ToString(TimeFormat, CultureInfo.InvariantCulture), e.KindLabel, C(e.Variant), C(e.Computer),
                e.EventId.ToString(CultureInfo.InvariantCulture), C(e.What), C(e.Account), C(e.Domain), C(e.Client),
                C(e.Service), C(e.TicketEncryption), C(e.SessionEncryption), C(e.File), e.RecordId.ToString(CultureInfo.InvariantCulture)));
        }
    }

    public static void WriteSummaryCsv(TextWriter w, IEnumerable<SummaryRow> rows, char separator = ',')
    {
        string C(string v) => Csv(v, separator);
        w.WriteLine(string.Join(separator, "Type", "Account", "Domains", "Client", "Service", "Count", "FirstSeen", "LastSeen", "Computers", "Details"));
        foreach (var r in rows)
        {
            w.WriteLine(string.Join(separator,
                r.KindLabel, C(r.Account), C(r.DomainsText), C(r.Client), C(r.Service), r.Count.ToString(CultureInfo.InvariantCulture),
                r.FirstSeen.ToString(TimeFormat, CultureInfo.InvariantCulture), r.LastSeen.ToString(TimeFormat, CultureInfo.InvariantCulture),
                C(r.ComputersText), C(r.VariantsText)));
        }
    }

    public static void WriteFixesCsv(TextWriter w, IEnumerable<FixItem> items, char separator = ',')
    {
        string C(string v) => Csv(v, separator);
        w.WriteLine(string.Join(separator, "Rank", "Type", "FixOn", "Target", "Problem", "Action", "Events", "FirstSeen", "LastSeen",
            "Accounts", "Clients", "Services", "LoggedOn"));
        foreach (var f in items)
        {
            w.WriteLine(string.Join(separator,
                f.Rank.ToString(CultureInfo.InvariantCulture), f.KindLabel, C(f.TargetTypeText), C(f.Target), C(f.Problem), C(f.Action),
                f.Events.ToString(CultureInfo.InvariantCulture), f.FirstSeen.ToString(TimeFormat, CultureInfo.InvariantCulture),
                f.LastSeen.ToString(TimeFormat, CultureInfo.InvariantCulture), C(string.Join(" ", f.Accounts)), C(string.Join(" ", f.Clients)),
                C(string.Join(" ", f.Services)), C(string.Join(" ", f.Computers))));
        }
    }

    /// <summary>Quotes a CSV field when needed and defuses values that spreadsheet apps would run as formulas.</summary>
    public static string Csv(string value, char separator = ',')
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([separator, ',', ';', '"', '\n', '\r']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string ToJson(ScanResult r) => JsonSerializer.Serialize(JsonModel(r), JsonOptions);

    /// <summary>Streams the JSON report to a file instead of building one big string.</summary>
    public static void WriteJson(Stream stream, ScanResult r) => JsonSerializer.Serialize(stream, JsonModel(r), JsonOptions);

    public static string Version => typeof(Reports).Assembly.GetName().Version?.ToString(3) ?? "?";

    private static object JsonModel(ScanResult r) => new
    {
        tool = "Legacy Auth Finder",
        version = Version,
        scope = r.Scope,
        durationSeconds = Math.Round(r.Duration.TotalSeconds, 1),
        cancelled = r.Cancelled,
        incomplete = r.Incomplete,
        failedFiles = r.FailedFiles,
        duplicatesSkipped = r.Duplicates,
        totals = new
        {
            ntlmv1 = r.Count(LegacyKind.Ntlmv1),
            rc4 = r.Count(LegacyKind.Rc4),
            des = r.Count(LegacyKind.Des),
            ldapUnsigned = r.Count(LegacyKind.LdapSigning),
            ldapChannelBinding = r.Count(LegacyKind.LdapChannelBinding),
            etypeErrors = r.Count(LegacyKind.EtypeFailure),
            smb1 = r.Count(LegacyKind.Smb1),
            ntlm = r.Count(LegacyKind.Ntlm),
            noPreAuth = r.Count(LegacyKind.NoPreAuth),
            all = r.TotalHits,
        },
        files = r.Files.Select(f => new
        {
            path = f.Path,
            size = f.Size,
            log = f.Channel,
            computer = f.Computer,
            records = f.RecordCount,
            first = f.First,
            last = f.Last,
            state = r.FileResults.TryGetValue(f.Path, out var p) ? p.State.ToString() : "",
            found = p?.Hits ?? 0,
            message = p?.Message ?? f.Error,
            eventsPerDay = Retention.For(f)?.EventsPerDay,
            // Days a log of 32 MB, 100 MB, 250 MB and 1 GB would hold at this file's load. Null when it cannot be estimated.
            daysAtSize = Retention.For(f) is { } estimate ? estimate.At.ToDictionary(a => SizeText(a.Size).Replace(".0 ", " ", StringComparison.Ordinal), a => Math.Round(a.Days, 2)) : null,
            estimateRough = Retention.For(f)?.Rough,
        }),
        fixes = r.Fixes.Select(f => new
        {
            rank = f.Rank,
            type = f.KindLabel,
            fixOn = f.TargetTypeText,
            target = f.Target,
            problem = f.Problem,
            action = f.Action,
            events = f.Events,
            firstSeen = f.FirstSeen,
            lastSeen = f.LastSeen,
            accounts = f.Accounts,
            clients = f.Clients,
            services = f.Services,
            computers = f.Computers,
        }),
        summary = r.Summary.Select(s => new
        {
            type = s.KindLabel,
            account = s.Account,
            domains = s.Domains.Order(StringComparer.OrdinalIgnoreCase),
            client = s.Client,
            service = s.Service,
            count = s.Count,
            firstSeen = s.FirstSeen,
            lastSeen = s.LastSeen,
            computers = s.Computers.Order(StringComparer.OrdinalIgnoreCase),
            details = s.Variants.Order(StringComparer.Ordinal),
        }),
    };

    public static string ToHtml(ScanResult r)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>Legacy authentication report</title><style>");
        sb.Append("body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}.wrap{max-width:1200px;margin:0 auto;padding:32px 20px}");
        sb.Append("h1{margin:0 0 4px}.meta{color:#5b6470;margin:0 0 24px}.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}");
        sb.Append(".tile{background:#fff;border:1px solid #e1e4e8;border-radius:10px;padding:12px 16px;min-width:130px}.tile b{display:block;font-size:24px}");
        sb.Append("table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e1e4e8;margin-bottom:24px;font-size:13px}td,th{text-align:left;padding:5px 8px;border-bottom:1px solid #eef0f2;vertical-align:top}");
        sb.Append("th{background:#f1f3f5}.k{font-weight:600}.Des{color:#b0124f}.Ntlmv1{color:#d93025}.Rc4{color:#c25e00}.LdapSigning{color:#7c3aed}.LdapChannelBinding{color:#0e7490}.EtypeFailure{color:#2f6fd6}.Smb1{color:#9a3412}.Ntlm{color:#4b5b6e}.NoPreAuth{color:#a21caf}.Rc4{color:#a84f00}.g{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:12px 16px;margin-bottom:12px}a{color:#0b62c4}"
            + "details.fix{background:#fff;border:1px solid #e1e4e8;border-radius:8px;margin-bottom:6px}details.fix>summary{cursor:pointer;padding:8px 12px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}"
            + "details.fix[open]>summary{border-bottom:1px solid #eef0f2}.rank{color:#5b6470;min-width:28px}.what{flex:1;min-width:280px}.n{color:#5b6470;font-size:13px}.body{padding:8px 14px 4px}"
            + "dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;font-size:13px}dt{color:#5b6470}dd{margin:0}details.why{margin:6px 0 10px}details.why>summary{cursor:pointer;color:#0b62c4}"
            + "table.ev{font-size:12px}td.more{color:#3b4450;word-break:break-word}button{font:inherit;padding:2px 10px;border-radius:6px;border:1px solid #c9ced6;background:#fff;cursor:pointer}"
            + "@media print{button{display:none}}</style></head><body><div class=\"wrap\">");
        sb.Append($"<h1>Legacy authentication report</h1><p class=\"meta\">{E(r.Scope)} · {r.Files.Count} files · {r.Duration.TotalMinutes:0.#} minutes · Legacy Auth Finder {Version}"
            + $"{(r.Cancelled ? " · scan was cancelled, results are incomplete" : "")}{(r.FailedFiles > 0 ? $" · {r.FailedFiles} {(r.FailedFiles == 1 ? "file" : "files")} had read errors" : "")}"
            + $"{(r.Duplicates > 0 ? $" · {r.Duplicates:N0} duplicate records from overlapping files counted once" : "")}</p>");
        sb.Append("<div class=\"tiles\">");
        foreach (var kind in Guidance.Order)
        {
            sb.Append($"<div class=\"tile\">{Guidance.Label(kind)} events<b>{r.Count(kind):N0}</b></div>");
        }
        sb.Append("</div>");

        foreach (var kind in Guidance.Order.Where(k => r.Count(k) > 0))
        {
            var g = Guidance.For(kind);
            sb.Append($"<div class=\"g\"><b class=\"{kind}\">{E(g.Label)}</b><p>{E(g.Risk)}</p><p><b>What to do:</b> {E(g.Fix)}</p></div>");
        }

        // What to fix: one block per fix that opens to the steps, the background and the events behind it.
        var fixes = r.Fixes.Take(HtmlSummaryRows).ToList();
        var rankOf = new Dictionary<SummaryRow, int>();
        foreach (var f in r.Fixes)
        {
            foreach (var row in f.SourceRows) rankOf[row] = f.Rank;
        }
        if (fixes.Count > 0)
        {
            var perFix = Math.Clamp(HtmlEventsTotal / fixes.Count, 10, HtmlEventsPerFix);
            var eventsOf = EventsByFix(fixes, r.Events, perFix);
            sb.Append("<h2>What to fix first</h2><p class=\"meta\">Click a line for the steps, the background and the events behind it. "
                + "<button type=\"button\" onclick=\"all(true)\">Open all</button> <button type=\"button\" onclick=\"all(false)\">Close all</button></p>");
            foreach (var f in fixes)
            {
                var g = Guidance.For(f.Kind);
                sb.Append($"<details class=\"fix\" id=\"fix-{f.Rank}\"><summary><span class=\"rank\">{f.Rank}</span><span class=\"k {f.Kind}\">{f.KindLabel}</span>"
                    + $"<span class=\"what\"><b>{E(f.TargetTypeText)} {E(f.Target)}</b>: {E(f.Problem)}</span>"
                    + $"<span class=\"n\">{f.Events:N0} events · last {f.LastSeen:yyyy-MM-dd HH:mm}</span></summary><div class=\"body\">");
                sb.Append($"<p><b>What to do:</b> {E(f.Action)}</p><dl>");
                void Fact(string label, string value)
                {
                    if (value.Length > 0) sb.Append($"<dt>{label}</dt><dd>{E(value)}</dd>");
                }
                Fact("Accounts", f.AccountsText);
                Fact("Clients", f.ClientsText);
                Fact("Services", f.ServicesText);
                Fact("Logged on", f.ComputersText);
                Fact("Seen", $"{f.FirstSeen:yyyy-MM-dd HH:mm} to {f.LastSeen:yyyy-MM-dd HH:mm}");
                sb.Append("</dl>");
                sb.Append($"<details class=\"why\"><summary>What {E(g.Label)} is and why it matters</summary><p>{E(g.What)}</p><p>{E(g.Risk)}</p><p>{E(g.Fix)}</p><p>");
                sb.Append(string.Join(" · ", g.References.Select(x => $"<a href=\"{E(x.Url)}\">{E(x.Label)}</a>")));
                sb.Append("</p></details>");
                var shown = eventsOf[f];
                if (shown.Count > 0)
                {
                    sb.Append("<table class=\"ev\"><tr><th>Time</th><th>Logged on</th><th>Event</th><th>Detail</th><th>Account</th><th>Client</th><th>Service</th><th>Encryption</th><th>More</th><th>File, record</th></tr>");
                    foreach (var e in shown)
                    {
                        var account = e.Domain.Length > 0 && e.Account.Length > 0 ? $"{e.Domain}\\{e.Account}" : e.Account;
                        var crypto = string.Join(", ", new[] { e.TicketEncryption.Length > 0 ? $"ticket {e.TicketEncryption}" : "", e.SessionEncryption.Length > 0 ? $"session {e.SessionEncryption}" : "" }.Where(x => x.Length > 0));
                        var more = string.Join("<br>", e.Fields.Select(x => $"{E(x.Key)}: {E(x.Value)}"));
                        sb.Append($"<tr><td>{e.Time:yyyy-MM-dd HH:mm:ss}</td><td>{E(e.Computer)}</td><td>{e.EventId} {E(e.What)}</td><td>{E(e.Variant)}</td><td>{E(account)}</td>"
                            + $"<td>{E(e.Client)}</td><td>{E(e.Service)}</td><td>{E(crypto)}</td><td class=\"more\">{more}</td><td>{E(e.File)}<br>{(e.RecordId > 0 ? $"record {e.RecordId}" : "")}</td></tr>");
                    }
                    sb.Append("</table>");
                }
                var note = shown.Count == 0
                    ? "The single events are not in the event list (it keeps the newest events only). The summary below counts them."
                    : shown.Count < f.Events
                        ? $"The newest {shown.Count:N0} of {f.Events:N0} events. All of them: the events CSV (in the app: Show these events on this fix, then Events as CSV)."
                        : $"All {shown.Count:N0} events.";
                sb.Append($"<p class=\"meta\">{note}</p></div></details>");
            }
            if (r.Fixes.Count > HtmlSummaryRows) sb.Append($"<p class=\"meta\">Showing {HtmlSummaryRows} of {r.Fixes.Count} items. The fix list CSV has all of them (in the app: with no search or type filter).</p>");
        }

        sb.Append($"<h2>Who still uses it</h2><table><tr><th>Type</th><th>Account</th><th>Client</th><th>Service</th><th>Count</th><th>First seen</th><th>Last seen</th><th>Logged on</th><th>Fix</th></tr>");
        foreach (var s in r.Summary.Take(HtmlSummaryRows))
        {
            var fix = rankOf.TryGetValue(s, out var rank) ? $"<a href=\"#fix-{rank}\">{rank}</a>" : "";
            sb.Append($"<tr><td class=\"k {s.Kind}\">{s.KindLabel}</td><td>{E(s.Account)}</td><td>{E(s.Client)}</td><td>{E(s.Service)}</td><td>{s.Count:N0}</td><td>{s.FirstSeen:yyyy-MM-dd HH:mm}</td><td>{s.LastSeen:yyyy-MM-dd HH:mm}</td><td>{E(s.ComputersText)}</td><td>{fix}</td></tr>");
        }
        sb.Append("</table>");
        if (r.Summary.Count > HtmlSummaryRows) sb.Append($"<p class=\"meta\">Showing {HtmlSummaryRows} of {r.Summary.Count} rows. The summary CSV has all of them (in the app: with no search or type filter).</p>");

        sb.Append($"<h2>Files</h2><p class=\"meta\">Events per day and how many days a log of {Retention.SizesText} would hold at the load each file shows. An estimate: the busier the server, the bigger its log must be.</p>");
        sb.Append($"<table><tr><th>File</th><th>Log</th><th>Computer</th><th>Size</th><th>From</th><th>To</th><th>Events per day</th><th>Days at {Retention.SizesText}</th><th>Result</th></tr>");
        foreach (var f in r.Files)
        {
            var result = r.FileResults.TryGetValue(f.Path, out var p) ? p.Message : f.Error ?? "";
            var estimate = Retention.For(f);
            sb.Append($"<tr><td>{E(f.Path)}</td><td>{E(f.Channel)}</td><td>{E(f.Computer)}</td><td>{SizeText(f.Size)}</td><td>{f.First:yyyy-MM-dd HH:mm}</td><td>{f.Last:yyyy-MM-dd HH:mm}</td>"
                + $"<td>{estimate?.EventsPerDayText}</td><td>{estimate?.DaysText}</td><td>{E(result)}</td></tr>");
        }
        sb.Append("</table><p class=\"meta\">Generated by Legacy Auth Finder (read-only, nothing was changed). https://github.com/JW-0042/win-legacy-auth-finder</p></div>");
        // Opens the fix a link points to, and every block before printing.
        sb.Append("<script>function all(o){document.querySelectorAll('details').forEach(function(d){d.open=o;});}"
            + "function hash(){var d=document.getElementById(location.hash.slice(1));if(d){d.open=true;}}"
            + "window.addEventListener('hashchange',hash);window.addEventListener('beforeprint',function(){all(true);});hash();</script></body></html>");
        return sb.ToString();
    }

    public static string SizeText(long bytes) => bytes switch
    {
        >= 1L << 30 => (bytes / (double)(1L << 30)).ToString("0.0", CultureInfo.InvariantCulture) + " GB",
        >= 1L << 20 => (bytes / (double)(1L << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MB",
        >= 1L << 10 => (bytes / 1024.0).ToString("0", CultureInfo.InvariantCulture) + " KB",
        _ => $"{bytes} B",
    };
}
