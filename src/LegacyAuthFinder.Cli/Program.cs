using LegacyAuthFinder.Core;

// legacy-auth-scan <folder> [--no-recurse] [--threads n] [--events-csv f] [--summary-csv f] [--fix-csv f] [--json f] [--html f] [--log f | --no-log] [--windows-api] [--quiet]
// Exit codes: 0 = nothing found, 1 = NTLMv1, RC4 or DES found, 2 = invalid arguments, 3 = no readable log files.

Console.OutputEncoding = System.Text.Encoding.UTF8;
System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("en-US");

const string Usage = "Usage: legacy-auth-scan <folder> [--no-recurse] [--threads <n>] [--events-csv <file>] [--summary-csv <file>] [--fix-csv <file>] [--json <file>] [--html <file>] [--log <file> | --no-log] [--windows-api] [--quiet]";

string? folder = null, eventsCsv = null, summaryCsv = null, fixCsv = null, jsonPath = null, htmlPath = null, logPath = null;
bool recurse = true, quiet = false, demo = false, noLog = false, windowsApi = false;
int? threads = null;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--no-recurse": recurse = false; break;
        case "--threads" when i + 1 < args.Length && int.TryParse(args[i + 1], out var t) && t is > 0 and <= 16: threads = t; i++; break;
        case "--events-csv" when i + 1 < args.Length: eventsCsv = args[++i]; break;
        case "--summary-csv" when i + 1 < args.Length: summaryCsv = args[++i]; break;
        case "--fix-csv" when i + 1 < args.Length: fixCsv = args[++i]; break;
        case "--log" when i + 1 < args.Length: logPath = args[++i]; break;
        case "--no-log": noLog = true; break;
        case "--windows-api": windowsApi = true; break;
        case "--json" when i + 1 < args.Length: jsonPath = args[++i]; break;
        case "--html" when i + 1 < args.Length: htmlPath = args[++i]; break;
        case "--quiet": quiet = true; break;
        case "--demo": demo = true; break;
        case "-h" or "--help" or "/?":
            Console.WriteLine("Legacy Auth Finder: finds NTLM, NTLMv1, RC4, DES, SMBv1, unsigned LDAP and Kerberos encryption type errors in archived Windows event logs (.evtx).");
            Console.WriteLine(Usage);
            Console.WriteLine("Every .evtx file in the folder is checked. Security, System, Directory Service, NTLM Operational and SMBServer Audit logs are scanned, other logs are skipped.");
            Console.WriteLine($"A diagnostic log (timings, no event content) is written to {DiagLog.DefaultFolder} unless --no-log is given.");
            Console.WriteLine("Exit code 0 = nothing found, 1 = legacy authentication found, 3 = no readable log files.");
            return 0;
        default:
            if (folder is null && !args[i].StartsWith('-')) { folder = args[i]; break; }
            Console.Error.WriteLine($"Unknown argument: {args[i]}. {Usage}");
            return 2;
    }
}

ScanResult result;
using var log = noLog || demo ? null : DiagLog.Create("CLI " + string.Join(' ', args), logPath);
if (demo)
{
    result = DemoData.Create(DateTime.Now);
}
else
{
    if (folder is null || !Directory.Exists(folder))
    {
        Console.Error.WriteLine(folder is null ? Usage : $"Folder not found: {folder}");
        return 2;
    }

    var windows = new WindowsEvtxReader { Log = log };
    IEvtxReader reader = windowsApi ? windows : new EvtxFileReader(windows) { Log = log };
    var storage = Storage.Detect(folder);
    log?.Write("FOLDER", $"{Path.GetFullPath(folder)}: storage {storage}, {Storage.Explain(folder)}");
    threads ??= Storage.RecommendedThreads(storage);
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    var files = Scanner.Inventory(reader, folder, recurse, cancellationToken: cts.Token, log: log);
    if (!quiet)
    {
        Console.WriteLine($"Legacy Auth Finder · {Path.GetFullPath(folder)} · {files.Count} .evtx files");
        Console.WriteLine($"{Storage.Describe(storage)} Scanning {threads} at once.");
        foreach (var f in files)
        {
            Console.WriteLine($"  {f.Name,-48} {(f.Error is null ? Channels.Short(f.Channel) : "unreadable"),-12} {Reports.SizeText(f.Size),10}  {f.Computer}");
        }
        Console.WriteLine();
    }
    if (!files.Any(f => f.IsRelevant))
    {
        Console.Error.WriteLine("No readable Security, System, Directory Service, NTLM Operational or SMBServer Audit logs found.");
        return 3;
    }

    var progress = quiet ? null : new Progress<FileProgress>(p =>
    {
        if (p.State is FileState.Done or FileState.Error or FileState.Cancelled)
        {
            Console.WriteLine($"  {Path.GetFileName(p.Path),-48} {p.State,-10} {p.Message}");
        }
    });
    result = Scanner.Scan(reader, files, Path.GetFullPath(folder), new ScanOptions(threads.Value, Log: log), progress, cts.Token);
}

if (!quiet)
{
    Console.WriteLine();
    Console.WriteLine($"Found {result.TotalHits:N0} events in {result.Duration.TotalSeconds:0.#} s: "
        + string.Join(", ", Guidance.Order.Select(k => $"{Guidance.Label(k)} {result.Count(k):N0}")) + ".");
    if (result.Cancelled) Console.WriteLine("The scan was cancelled. Results are incomplete.");
    foreach (var s in result.Summary.Take(25))
    {
        Console.WriteLine($"  {s.KindLabel,-13} {s.Count,10:N0}  {s.Account,-32} {s.Client,-20} {s.Service}");
    }
    if (result.Summary.Count > 25) Console.WriteLine($"  … {result.Summary.Count - 25} more rows. Use --summary-csv for the full list.");
    if (result.Fixes.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("What to fix first:");
        foreach (var f in result.Fixes.Take(15))
        {
            Console.WriteLine($"  {f.Rank,3}. {f.KindLabel,-12} {f.TargetTypeText,-18} {f.Target,-32} {f.Problem}");
        }
        if (result.Fixes.Count > 15) Console.WriteLine($"  … {result.Fixes.Count - 15} more. Use --fix-csv for the full list with the steps.");
    }
    if (log is { IsEnabled: true }) Console.WriteLine($"Diagnostic log: {log.Path}");
}

if (eventsCsv is not null)
{
    using var w = new StreamWriter(eventsCsv, false, Reports.CsvEncoding);
    Reports.WriteEventsCsv(w, result.Events);
}
if (summaryCsv is not null)
{
    using var w = new StreamWriter(summaryCsv, false, Reports.CsvEncoding);
    Reports.WriteSummaryCsv(w, result.Summary);
}
if (fixCsv is not null)
{
    using var w = new StreamWriter(fixCsv, false, Reports.CsvEncoding);
    Reports.WriteFixesCsv(w, result.Fixes);
}
if (jsonPath is not null) File.WriteAllText(jsonPath, Reports.ToJson(result));
if (htmlPath is not null) File.WriteAllText(htmlPath, Reports.ToHtml(result));

return result.TotalHits > 0 ? 1 : 0;
