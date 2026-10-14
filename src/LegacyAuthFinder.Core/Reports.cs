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
        sb.Append("th{background:#f1f3f5}.k{font-weight:600}.Des{color:#b0124f}.Ntlmv1{color:#d93025}.Rc4{color:#c25e00}.LdapSigning{color:#7c3aed}.LdapChannelBinding{color:#0e7490}.EtypeFailure{color:#2f6fd6}.Smb1{color:#9a3412}.Ntlm{color:#4b5b6e}.NoPreAuth{color:#a21caf}.Rc4{color:#a84f00}.g{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:12px 16px;margin-bottom:12px}a{color:#0b62c4}</style></head><body><div class=\"wrap\">");
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

        if (r.Fixes.Count > 0)
        {
            sb.Append("<h2>What to fix first</h2><table><tr><th>#</th><th>Type</th><th>Fix on</th><th>Target</th><th>Problem</th><th>What to do</th><th>Events</th><th>Last seen</th></tr>");
            foreach (var f in r.Fixes.Take(HtmlSummaryRows))
            {
                sb.Append($"<tr><td>{f.Rank}</td><td class=\"k {f.Kind}\">{f.KindLabel}</td><td>{E(f.TargetTypeText)}</td><td>{E(f.Target)}</td><td>{E(f.Problem)}</td><td>{E(f.Action)}</td><td>{f.Events:N0}</td><td>{f.LastSeen:yyyy-MM-dd HH:mm}</td></tr>");
            }
            sb.Append("</table>");
            if (r.Fixes.Count > HtmlSummaryRows) sb.Append($"<p class=\"meta\">Showing {HtmlSummaryRows} of {r.Fixes.Count} items. The fix list CSV has all of them (in the app: with no search or type filter).</p>");
        }

        sb.Append($"<h2>Who still uses it</h2><table><tr><th>Type</th><th>Account</th><th>Client</th><th>Service</th><th>Count</th><th>First seen</th><th>Last seen</th><th>Logged on</th></tr>");
        foreach (var s in r.Summary.Take(HtmlSummaryRows))
        {
            sb.Append($"<tr><td class=\"k {s.Kind}\">{s.KindLabel}</td><td>{E(s.Account)}</td><td>{E(s.Client)}</td><td>{E(s.Service)}</td><td>{s.Count:N0}</td><td>{s.FirstSeen:yyyy-MM-dd HH:mm}</td><td>{s.LastSeen:yyyy-MM-dd HH:mm}</td><td>{E(s.ComputersText)}</td></tr>");
        }
        sb.Append("</table>");
        if (r.Summary.Count > HtmlSummaryRows) sb.Append($"<p class=\"meta\">Showing {HtmlSummaryRows} of {r.Summary.Count} rows. The summary CSV has all of them (in the app: with no search or type filter).</p>");

        sb.Append("<h2>Files</h2><table><tr><th>File</th><th>Log</th><th>Computer</th><th>Size</th><th>From</th><th>To</th><th>Result</th></tr>");
        foreach (var f in r.Files)
        {
            var result = r.FileResults.TryGetValue(f.Path, out var p) ? p.Message : f.Error ?? "";
            sb.Append($"<tr><td>{E(f.Path)}</td><td>{E(f.Channel)}</td><td>{E(f.Computer)}</td><td>{SizeText(f.Size)}</td><td>{f.First:yyyy-MM-dd HH:mm}</td><td>{f.Last:yyyy-MM-dd HH:mm}</td><td>{E(result)}</td></tr>");
        }
        sb.Append("</table><p class=\"meta\">Generated by Legacy Auth Finder (read-only, nothing was changed). https://github.com/JW-0042/win-legacy-auth-finder</p></div></body></html>");
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
