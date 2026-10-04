using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.App;

public sealed record DetailRow(string Label, string Value);

/// <summary>One file in the folder, updated live while it is scanned.</summary>
public sealed class FileRow(LogFileInfo info, string root) : INotifyPropertyChanged
{
    private FileState _state = info.IsRelevant ? FileState.Queued : info.Error is null ? FileState.Skipped : FileState.Error;
    private string _status = info.Error ?? (info.IsRelevant ? "Waiting" : "Skipped: not a Security or System log");
    private long _hits;
    private double _percent;

    public event PropertyChangedEventHandler? PropertyChanged;

    public LogFileInfo Info { get; } = info;
    public string Name => Path.GetRelativePath(root, Info.Path);
    public string Log => Info.Error is null ? Info.Channel : "unreadable";
    public string Computer => Info.Computer;
    public string SizeText => Reports.SizeText(Info.Size);
    public long Size => Info.Size;
    public string RecordsText => Info.RecordCount > 0 ? Info.RecordCount.ToString("N0") : "";
    public string RangeText => Info.First is { } f && Info.Last is { } l ? $"{f:yyyy-MM-dd HH:mm} to {l:yyyy-MM-dd HH:mm}" : "";

    public FileState State { get => _state; private set { _state = value; OnChanged(); OnChanged(nameof(IsScanning)); } }
    public bool IsScanning => _state == FileState.Scanning;
    public string Status { get => _status; private set { _status = value; OnChanged(); } }
    public long Hits { get => _hits; private set { _hits = value; OnChanged(); } }
    public double Percent { get => _percent; private set { _percent = value; OnChanged(); } }

    public void Update(FileProgress p)
    {
        State = p.State;
        Status = p.Message;
        Hits = p.Hits;
        Percent = p.State == FileState.Done ? 100 : (p.Percent ?? 0) * 100;
    }

    private void OnChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly IEvtxReader _reader = new WindowsEvtxReader();
    private readonly DispatcherTimer _searchTimer;
    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _searchCts;
    private ScanResult? _result;
    private string _folder = "";
    private bool _recurse = true;
    private int _threads = 2;
    private bool _isBusy;
    private string _statusText = "";
    private double _overall;
    private string _kindFilter = "All";
    private string _search = "";
    private IReadOnlyList<AuthEvent> _events = [];
    private IReadOnlyList<SummaryRow> _summary = [];
    private int _tab;
    private object? _selection;

    public MainViewModel()
    {
        _searchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
        _searchTimer.Tick += async (_, _) =>
        {
            _searchTimer.Stop();
            await ApplyFilterAsync();
        };
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<FileRow> Files { get; } = [];
    public IReadOnlyList<string> KindFilters { get; } = ["All", "DES", "NTLMv1", "RC4"];
    public IReadOnlyList<int> ThreadChoices { get; } = [1, 2, 3, 4];

    public string Folder { get => _folder; private set { _folder = value; OnChanged(); OnChanged(nameof(HasFolder)); } }
    public bool HasFolder => _folder.Length > 0;
    public bool Recurse { get => _recurse; set { _recurse = value; OnChanged(); } }
    public int Threads { get => _threads; set { _threads = value; OnChanged(); } }

    public bool IsBusy { get => _isBusy; private set { _isBusy = value; OnChanged(); OnChanged(nameof(CanAct)); } }
    public bool CanAct => !_isBusy;
    public string StatusText { get => _statusText; private set { _statusText = value; OnChanged(); } }
    public double OverallProgress { get => _overall; private set { _overall = value; OnChanged(); } }

    public ScanResult? Result
    {
        get => _result;
        private set
        {
            _result = value;
            foreach (var n in new[] { nameof(Result), nameof(HasResult), nameof(DesCount), nameof(NtlmCount), nameof(Rc4Count), nameof(HeadlineText), nameof(TruncatedText), nameof(IsTruncated), nameof(ScopeText) })
            {
                OnChanged(n);
            }
        }
    }

    public bool HasResult => _result is not null;
    public string DesCount => Compact(_result?.Count(LegacyKind.Des) ?? 0);
    public string NtlmCount => Compact(_result?.Count(LegacyKind.Ntlmv1) ?? 0);
    public string Rc4Count => Compact(_result?.Count(LegacyKind.Rc4) ?? 0);

    /// <summary>Short numbers for the tiles: 950, 13.1k, 4.2M. The exact count is in the summary.</summary>
    public static string Compact(long n) => n switch
    {
        < 10_000 => n.ToString("N0"),
        < 1_000_000 => $"{n / 1000.0:0.#}k",
        _ => $"{n / 1_000_000.0:0.#}M",
    };
    public string ScopeText => _result?.Scope ?? "";
    public string HeadlineText => _result switch
    {
        null => "Open a folder with archived .evtx files from your servers. The tool finds the Security and System logs and scans them.",
        { Cancelled: true } => $"Scan cancelled. {_result.TotalHits:N0} events found so far.",
        { TotalHits: 0 } => _result.Files.Count(f => f.IsRelevant) is var n && n == 1
            ? "No NTLMv1, RC4 or DES found in 1 log."
            : $"No NTLMv1, RC4 or DES found in {_result.Files.Count(f => f.IsRelevant)} logs.",
        _ => $"{_result.TotalHits:N0} events from {_result.Summary.Count:N0} account and client pairs, scanned in {(_result.Duration.TotalSeconds < 10 ? _result.Duration.TotalSeconds.ToString("0.#") : _result.Duration.TotalSeconds.ToString("0"))} s",
    };
    public bool IsTruncated => _result?.Truncated == true;
    public string TruncatedText => _result is { Truncated: true }
        ? $"The event list shows the first {Scanner.DefaultMaxEvents:N0} events. The summary and the totals include all of them."
        : "";

    public string KindFilter { get => _kindFilter; set { _kindFilter = value; OnChanged(); _ = ApplyFilterAsync(); } }
    public string Search { get => _search; set { _search = value; OnChanged(); _searchTimer.Stop(); _searchTimer.Start(); } }

    public IReadOnlyList<AuthEvent> Events { get => _events; private set { _events = value; OnChanged(); OnChanged(nameof(EventsHeader)); } }
    public IReadOnlyList<SummaryRow> Summary { get => _summary; private set { _summary = value; OnChanged(); OnChanged(nameof(SummaryHeader)); } }
    public string EventsHeader => _result is null ? "Events" : $"Events ({_events.Count:N0})";
    public string SummaryHeader => _result is null ? "Who uses it" : $"Who uses it ({_summary.Count:N0})";
    public string FilesHeader => $"Files ({Files.Count})";
    public int SelectedTab { get => _tab; set { _tab = value; OnChanged(); } }

    /// <summary>The selected event or summary row, shown in the detail pane.</summary>
    public object? Selection
    {
        get => _selection;
        set
        {
            _selection = value;
            foreach (var n in new[] { nameof(Selection), nameof(HasSelection), nameof(DetailTitle), nameof(DetailRows), nameof(Guide), nameof(DetailKind), nameof(CanShowEvents) })
            {
                OnChanged(n);
            }
        }
    }

    public bool HasSelection => _selection is AuthEvent or SummaryRow;
    public bool CanShowEvents => _selection is SummaryRow;
    public LegacyKind? DetailKind => _selection switch { AuthEvent e => e.Kind, SummaryRow s => s.Kind, _ => null };
    public KindGuidance? Guide => DetailKind is { } k ? Guidance.For(k) : null;

    public string DetailTitle => _selection switch
    {
        AuthEvent e => $"{e.KindLabel} · {e.What}",
        SummaryRow s => $"{s.KindLabel} · {s.Count:N0} events",
        _ => "",
    };

    public IReadOnlyList<DetailRow> DetailRows => _selection switch
    {
        AuthEvent e => Rows(
            ("Time", e.Time.ToString("yyyy-MM-dd HH:mm:ss")), ("Logged on", e.Computer), ("Event ID", e.EventId.ToString()),
            ("Detail", e.Variant), ("Account", e.Account), ("Domain", e.Domain), ("Client", e.Client), ("Service", e.Service),
            ("Ticket", e.TicketEncryption), ("Session key", e.SessionEncryption))
            .Concat(e.Fields.Select(f => new DetailRow(f.Key, f.Value)))
            .Concat(Rows(("File", e.File), ("Record ID", e.RecordId > 0 ? e.RecordId.ToString() : "")))
            .ToList(),
        SummaryRow s => Rows(
            ("Account", s.Account), ("Client", s.Client), ("Service", s.Service), ("Events", s.Count.ToString("N0")),
            ("First seen", s.FirstSeen.ToString("yyyy-MM-dd HH:mm")), ("Last seen", s.LastSeen.ToString("yyyy-MM-dd HH:mm")),
            ("Logged on", s.ComputersText), ("Details", s.VariantsText)).ToList(),
        _ => [],
    };

    private static IEnumerable<DetailRow> Rows(params (string Label, string Value)[] rows) =>
        rows.Where(r => r.Value.Length > 0).Select(r => new DetailRow(r.Label, r.Value));

    public async Task OpenFolderAsync(string folder)
    {
        Folder = folder;
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;
        IsBusy = true;
        Result = null;
        Selection = null;
        Events = [];
        Summary = [];
        Files.Clear();
        OnChanged(nameof(FilesHeader));
        SelectedTab = 2;
        try
        {
            StatusText = "Finding .evtx files and checking which log each one is…";
            OverallProgress = 0;
            var recurse = Recurse;
            var inventory = await Task.Run(() => Scanner.Inventory(_reader, folder, recurse, cancellationToken: token), token);
            var rows = inventory.ToDictionary(f => f.Path, f => new FileRow(f, folder), StringComparer.OrdinalIgnoreCase);
            foreach (var row in rows.Values) Files.Add(row);
            OnChanged(nameof(FilesHeader));

            var relevant = inventory.Where(f => f.IsRelevant).ToList();
            if (relevant.Count == 0)
            {
                StatusText = inventory.Count == 0 ? "No .evtx files in this folder." : "No readable Security or System logs in this folder.";
                Result = new ScanResult(inventory, [], [], new Dictionary<string, FileProgress>(), 0, false, false, TimeSpan.Zero, folder);
                return;
            }

            var totalBytes = Math.Max(1, relevant.Sum(f => f.Size));
            var progress = new Progress<FileProgress>(p =>
            {
                if (rows.TryGetValue(p.Path, out var row)) row.Update(p);
                var done = relevant.Sum(f => rows[f.Path] is var r && r.State is FileState.Done or FileState.Error or FileState.Cancelled
                    ? f.Size
                    : (long)(f.Size * rows[f.Path].Percent / 100));
                OverallProgress = 100.0 * done / totalBytes;
                var finished = relevant.Count(f => rows[f.Path].State is FileState.Done or FileState.Error);
                StatusText = $"Scanning {finished} of {relevant.Count} logs done · {Reports.SizeText(done)} of {Reports.SizeText(totalBytes)} · {rows.Values.Sum(r => r.Hits):N0} found";
            });
            var options = new ScanOptions(Threads);
            var result = await Task.Run(() => Scanner.Scan(_reader, inventory, folder, options, progress, token));
            Show(result);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Cancelled.";
        }
        finally
        {
            IsBusy = false;
            StatusText = "";
        }
    }

    public void Cancel() => _scanCts?.Cancel();

    public async Task LoadDemoAsync()
    {
        IsBusy = true;
        try
        {
            var result = await Task.Run(() => DemoData.Create(DateTime.Now));
            Folder = result.Scope;
            Files.Clear();
            foreach (var f in result.Files)
            {
                var row = new FileRow(f, @"D:\Logs\contoso-archive");
                if (result.FileResults.TryGetValue(f.Path, out var p)) row.Update(p);
                Files.Add(row);
            }
            OnChanged(nameof(FilesHeader));
            Show(result);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void Show(ScanResult result)
    {
        Result = result;
        Events = result.Events;
        Summary = result.Summary;
        SelectedTab = 0;
        Selection = result.Summary.FirstOrDefault();
        if (_search.Length > 0 || _kindFilter != "All") _ = ApplyFilterAsync();
    }

    /// <summary>Shows the events behind a summary row by searching for its account and client.</summary>
    public void ShowEventsFor(SummaryRow row)
    {
        _kindFilter = row.KindLabel;
        OnChanged(nameof(KindFilter));
        _search = string.Join(' ', new[] { row.Account, row.Client, row.Service }.Where(x => x.Length > 0 && !x.Contains(' ')));
        OnChanged(nameof(Search));
        SelectedTab = 1;
        _ = ApplyFilterAsync();
    }

    private async Task ApplyFilterAsync()
    {
        if (_result is null) return;
        _searchCts?.Cancel();
        var cts = _searchCts = new CancellationTokenSource();
        var terms = _search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        LegacyKind? kind = _kindFilter switch { "DES" => LegacyKind.Des, "NTLMv1" => LegacyKind.Ntlmv1, "RC4" => LegacyKind.Rc4, _ => null };
        var source = _result;
        try
        {
            var (events, summary) = await Task.Run(() =>
            {
                var ev = source.Events.AsParallel().AsOrdered().WithCancellation(cts.Token)
                    .Where(e => (kind is null || e.Kind == kind) && (terms.Length == 0 || e.Matches(terms))).ToList();
                var sm = source.Summary.Where(s => (kind is null || s.Kind == kind) && (terms.Length == 0 || s.Matches(terms))).ToList();
                return (ev, sm);
            }, cts.Token);
            if (cts.IsCancellationRequested) return;
            Events = events;
            Summary = summary;
        }
        catch (OperationCanceledException)
        {
            // A newer search replaced this one.
        }
    }

    private void OnChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
