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

    public static void WriteEventsCsv(TextWriter w, IEnumerable<AuthEvent> events)
    {
        w.WriteLine("Time,Type,Detail,Computer,EventId,Event,Account,Domain,Client,Service,TicketEncryption,SessionKeyEncryption,File,RecordId");
        foreach (var e in events)
        {
            w.WriteLine(string.Join(',',
                e.Time.ToString(TimeFormat, CultureInfo.InvariantCulture), e.KindLabel, Csv(e.Variant), Csv(e.Computer),
                e.EventId.ToString(CultureInfo.InvariantCulture), Csv(e.What), Csv(e.Account), Csv(e.Domain), Csv(e.Client),
                Csv(e.Service), Csv(e.TicketEncryption), Csv(e.SessionEncryption), Csv(e.File), e.RecordId.ToString(CultureInfo.InvariantCulture)));
        }
    }

    public static void WriteSummaryCsv(TextWriter w, IEnumerable<SummaryRow> rows)
    {
        w.WriteLine("Type,Account,Client,Service,Count,FirstSeen,LastSeen,Computers,Details");
        foreach (var r in rows)
        {
            w.WriteLine(string.Join(',',
                r.KindLabel, Csv(r.Account), Csv(r.Client), Csv(r.Service), r.Count.ToString(CultureInfo.InvariantCulture),
                r.FirstSeen.ToString(TimeFormat, CultureInfo.InvariantCulture), r.LastSeen.ToString(TimeFormat, CultureInfo.InvariantCulture),
                Csv(r.ComputersText), Csv(r.VariantsText)));
        }
    }

    /// <summary>Quotes a CSV field when needed and defuses values that spreadsheet apps would run as formulas.</summary>
    public static string Csv(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string ToJson(ScanResult r) => JsonSerializer.Serialize(new
    {
        tool = "Legacy Auth Finder",
        version = typeof(Reports).Assembly.GetName().Version?.ToString(3),
        scope = r.Scope,
        durationSeconds = Math.Round(r.Duration.TotalSeconds, 1),
        cancelled = r.Cancelled,
        totals = new
        {
            ntlmv1 = r.Count(LegacyKind.Ntlmv1),
            rc4 = r.Count(LegacyKind.Rc4),
            des = r.Count(LegacyKind.Des),
            ldapUnsigned = r.Count(LegacyKind.LdapSigning),
            ldapChannelBinding = r.Count(LegacyKind.LdapChannelBinding),
            etypeErrors = r.Count(LegacyKind.EtypeFailure),
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
        summary = r.Summary.Select(s => new
        {
            type = s.KindLabel,
            account = s.Account,
            client = s.Client,
            service = s.Service,
            count = s.Count,
            firstSeen = s.FirstSeen,
            lastSeen = s.LastSeen,
            computers = s.Computers,
            details = s.Variants,
        }),
    }, JsonOptions);

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
        sb.Append("th{background:#f1f3f5}.k{font-weight:600}.Des{color:#b0124f}.Ntlmv1{color:#d93025}.Rc4{color:#c25e00}.LdapSigning{color:#7c3aed}.LdapChannelBinding{color:#0e7490}.EtypeFailure{color:#2f6fd6}.g{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:12px 16px;margin-bottom:12px}a{color:#0b62c4}</style></head><body><div class=\"wrap\">");
        sb.Append($"<h1>Legacy authentication report</h1><p class=\"meta\">{E(r.Scope)} · {r.Files.Count} files · {r.Duration.TotalMinutes:0.#} minutes{(r.Cancelled ? " · scan was cancelled, results are incomplete" : "")}</p>");
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

        sb.Append($"<h2>Who still uses it</h2><table><tr><th>Type</th><th>Account</th><th>Client</th><th>Service</th><th>Count</th><th>First seen</th><th>Last seen</th><th>Logged on</th></tr>");
        foreach (var s in r.Summary.Take(HtmlSummaryRows))
        {
            sb.Append($"<tr><td class=\"k {s.Kind}\">{s.KindLabel}</td><td>{E(s.Account)}</td><td>{E(s.Client)}</td><td>{E(s.Service)}</td><td>{s.Count:N0}</td><td>{s.FirstSeen:yyyy-MM-dd HH:mm}</td><td>{s.LastSeen:yyyy-MM-dd HH:mm}</td><td>{E(s.ComputersText)}</td></tr>");
        }
        sb.Append("</table>");
        if (r.Summary.Count > HtmlSummaryRows) sb.Append($"<p class=\"meta\">Showing {HtmlSummaryRows} of {r.Summary.Count} rows. Export the summary as CSV for the full list.</p>");

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
