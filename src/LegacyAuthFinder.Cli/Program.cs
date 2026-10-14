using LegacyAuthFinder.Core;

// legacy-auth-scan <folder> [--no-recurse] [--threads n] [--events-csv f] [--summary-csv f] [--fix-csv f] [--json f] [--html f]
//                  [--csv-separator c] [--log f | --no-log] [--windows-api] [--quiet]
// Exit codes: 0 = nothing found, 1 = legacy authentication found, 2 = invalid arguments, 3 = no readable log files,
//             4 = incomplete (cancelled, or files with read errors), 5 = an export could not be written.

Console.OutputEncoding = System.Text.Encoding.UTF8;
System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("en-US");

const string Usage = "Usage: legacy-auth-scan <folder> [--no-recurse] [--threads <1-64>] [--events-csv <file>] [--summary-csv <file>] [--fix-csv <file>] "
    + "[--json <file>] [--html <file>] [--csv-separator <char>] [--log <file> | --no-log] [--windows-api] [--quiet]";
const int Incomplete = 4, ExportFailed = 5;

string? folder = null, eventsCsv = null, summaryCsv = null, fixCsv = null, jsonPath = null, htmlPath = null, logPath = null;
bool recurse = true, quiet = false, demo = false, noLog = false, windowsApi = false;
var separator = ',';
int? threads = null;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--no-recurse": recurse = false; break;
        case "--threads" when i + 1 < args.Length:
            if (!int.TryParse(args[++i], out var t) || t is < 1 or > 64)
            {
                Console.Error.WriteLine($"--threads must be a number from 1 to 64, not '{args[i]}'.");
                return 2;
            }
            threads = t;
            break;
        case "--events-csv" when i + 1 < args.Length: eventsCsv = args[++i]; break;
        case "--summary-csv" when i + 1 < args.Length: summaryCsv = args[++i]; break;
        case "--fix-csv" when i + 1 < args.Length: fixCsv = args[++i]; break;
        case "--csv-separator" when i + 1 < args.Length:
            var sep = args[++i] is "tab" or "\\t" ? "\t" : args[i];
            if (sep.Length != 1 || sep[0] is '"' or '\r' or '\n')
            {
                Console.Error.WriteLine("--csv-separator must be one character, for example ; or , or tab.");
                return 2;
            }
            separator = sep[0];
            break;
        case "--log" when i + 1 < args.Length: logPath = args[++i]; break;
        case "--no-log": noLog = true; break;
        case "--windows-api": windowsApi = true; break;
        case "--json" when i + 1 < args.Length: jsonPath = args[++i]; break;
        case "--html" when i + 1 < args.Length: htmlPath = args[++i]; break;
        case "--quiet": quiet = true; break;
        case "--demo": demo = true; break;
        case "-h" or "--help" or "/?":
            Console.WriteLine($"Legacy Auth Finder {Reports.Version}: finds NTLM, NTLMv1, RC4, DES, SMBv1, unsigned LDAP, accounts without Kerberos pre-authentication "
                + "and Kerberos encryption type errors in archived Windows event logs (.evtx).");
            Console.WriteLine(Usage);
            Console.WriteLine("Every .evtx file in the folder is checked. Security, System, Directory Service, NTLM Operational and SMBServer Audit logs are scanned, other logs are skipped.");
            Console.WriteLine($"A diagnostic log (timings, no event content) is written to {DiagLog.DefaultFolder} unless --no-log is given.");
            Console.WriteLine("Exit codes: 0 nothing found, 1 legacy authentication found, 2 invalid arguments, 3 no readable log files,");
            Console.WriteLine("            4 incomplete (cancelled, or files with read errors), 5 an export could not be written.");
            return 0;
        default:
            if (folder is null && !args[i].StartsWith('-')) { folder = args[i]; break; }
            Console.Error.WriteLine($"Unknown or incomplete argument: {args[i]}. {Usage}");
            return 2;
    }
}

// Check the export paths before a scan that can take hours, not after it.
foreach (var path in new[] { eventsCsv, summaryCsv, fixCsv, jsonPath, htmlPath, logPath }.OfType<string>())
{
    if (CheckWritable(path) is { } problem)
    {
        Console.Error.WriteLine($"Cannot write {path}: {problem}");
        return 2;
    }
}

ScanResult result;
// Only the option names go to the log, not the paths: they can contain user or server names.
using var log = noLog || demo ? null : DiagLog.Create("CLI " + string.Join(' ', args.Where(a => a.StartsWith("--", StringComparison.Ordinal))), logPath);
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
    log?.Write("FOLDER", $"storage {storage}, {Storage.Explain(folder)}");
    threads ??= Storage.RecommendedThreads(storage);
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    IReadOnlyList<LogFileInfo> files;
    try
    {
        files = Scanner.Inventory(reader, folder, recurse, cancellationToken: cts.Token, log: log);
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("Cancelled while reading the folder. Nothing was scanned.");
        return Incomplete;
    }
    if (!quiet)
    {
        Console.WriteLine($"Legacy Auth Finder {Reports.Version} · {Path.GetFullPath(folder)} · {files.Count} .evtx files");
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

    // Written right away and in order: Progress<T> would post to the thread pool and mix up the lines.
    var progress = quiet ? null : new LineProgress(p =>
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
    if (result.Duplicates > 0) Console.WriteLine($"{result.Duplicates:N0} records from overlapping files were counted once.");
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
if (result.Incomplete)
{
    Console.Error.WriteLine(result.Cancelled
        ? "The scan was cancelled. Results and exports are incomplete."
        : $"{result.FailedFiles} {(result.FailedFiles == 1 ? "file" : "files")} had read errors. Results and exports are incomplete.");
}

var exportFailed = false;
void Export(string? path, Action<string> write)
{
    if (path is null) return;
    try
    {
        write(path);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
    {
        Console.Error.WriteLine($"Could not write {path}: {ex.Message}");
        exportFailed = true;
    }
}

void Csv(string path, Action<StreamWriter> write)
{
    using var w = new StreamWriter(path, false, Reports.CsvEncoding, 1 << 16);
    write(w);
}

Export(eventsCsv, p => Csv(p, w => Reports.WriteEventsCsv(w, result.Events, separator)));
Export(summaryCsv, p => Csv(p, w => Reports.WriteSummaryCsv(w, result.Summary, separator)));
Export(fixCsv, p => Csv(p, w => Reports.WriteFixesCsv(w, result.Fixes, separator)));
Export(jsonPath, p =>
{
    using var stream = new FileStream(p, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16);
    Reports.WriteJson(stream, result);
});
Export(htmlPath, p => File.WriteAllText(p, Reports.ToHtml(result)));

if (exportFailed) return ExportFailed;
if (result.Incomplete) return Incomplete;
return result.TotalHits > 0 ? 1 : 0;

// The folder must exist and accept a new file.
static string? CheckWritable(string path)
{
    try
    {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (dir is null || !Directory.Exists(dir)) return "the folder does not exist";
        if (Directory.Exists(full)) return "it is a folder";
        var probe = Path.Combine(dir, $".legacy-auth-scan-{Environment.ProcessId}.tmp");
        File.WriteAllText(probe, "");
        File.Delete(probe);
        return null;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
    {
        return ex.Message;
    }
}

/// <summary>Reports synchronously under a lock, so console lines come out whole and in order.</summary>
internal sealed class LineProgress(Action<FileProgress> write) : IProgress<FileProgress>
{
    private readonly Lock _gate = new();

    public void Report(FileProgress value)
    {
        lock (_gate)
        {
            write(value);
        }
    }
}
