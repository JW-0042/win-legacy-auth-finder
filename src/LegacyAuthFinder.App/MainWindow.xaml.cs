using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Navigation;
using LegacyAuthFinder.Core;
using Microsoft.Win32;

namespace LegacyAuthFinder.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainViewModel Vm => (MainViewModel)DataContext;

    /// <summary>The window is bigger than many laptop screens at 150 % scaling. Fit it into the work area.</summary>
    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        var area = SystemParameters.WorkArea;
        if (Width > area.Width) Width = area.Width;
        if (Height > area.Height) Height = area.Height;
        if (MinWidth > area.Width) MinWidth = area.Width;
        if (MinHeight > area.Height) MinHeight = area.Height;
        Left = area.Left + Math.Max(0, (area.Width - Width) / 2);
        Top = area.Top + Math.Max(0, (area.Height - Height) / 2);
    }

    /// <summary>Ctrl+F jumps to the search box.</summary>
    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
        }
    }

    private async void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Folder with archived event logs (.evtx)" };
        if (dialog.ShowDialog(this) != true) return;
        await Guard(() => Vm.OpenFolderAsync(dialog.FolderName));
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (!Vm.CanAct || e.Data.GetData(DataFormats.FileDrop) is not string[] { Length: > 0 } paths) return;
        var folder = Directory.Exists(paths[0]) ? paths[0] : Path.GetDirectoryName(paths[0]);
        if (folder is not null) await Guard(() => Vm.OpenFolderAsync(folder));
    }

    private async void Demo_Click(object sender, RoutedEventArgs e) => await Guard(Vm.LoadDemoAsync);

    private async void StartScan_Click(object sender, RoutedEventArgs e) => await Guard(Vm.StartScanAsync);

    private void Cancel_Click(object sender, RoutedEventArgs e) => Vm.Cancel();

    private async Task Guard(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Legacy Auth Finder", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid { SelectedItem: { } item }) Vm.Selection = item;
    }

    private void SummaryGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (SummaryGrid.SelectedItem is SummaryRow row) Vm.ShowEventsFor(row);
    }

    private void FixGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FixGrid.SelectedItem is FixItem item) Vm.ShowEventsFor(item);
    }

    private void ShowEvents_Click(object sender, RoutedEventArgs e)
    {
        if (Vm.Selection is SummaryRow row) Vm.ShowEventsFor(row);
        else if (Vm.Selection is FixItem item) Vm.ShowEventsFor(item);
    }

    // CSV uses the list separator of the user's Windows region (';' in Slovak, Czech or German), so Excel splits columns.
    private static char Separator => App.ListSeparator;

    private async void ExportFixes_Click(object sender, RoutedEventArgs e)
    {
        var items = Vm.Fixes;
        await Save("CSV file|*.csv", "legacy-auth-fix-list.csv", path => WriteCsv(path, w => Reports.WriteFixesCsv(w, items, Separator)));
    }

    private async void ExportSummary_Click(object sender, RoutedEventArgs e)
    {
        var rows = Vm.Summary;
        await Save("CSV file|*.csv", "legacy-auth-summary.csv", path => WriteCsv(path, w => Reports.WriteSummaryCsv(w, rows, Separator)));
    }

    private async void ExportEvents_Click(object sender, RoutedEventArgs e)
    {
        var events = Vm.Events;
        await Save("CSV file|*.csv", "legacy-auth-events.csv", path => WriteCsv(path, w => Reports.WriteEventsCsv(w, events, Separator)));
    }

    private async void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        var result = Vm.Result!;
        var saved = await Save("HTML report|*.html", "legacy-auth-report.html", path => File.WriteAllText(path, Reports.ToHtml(result)));
        if (saved is not null) OpenWithShell(saved);
    }

    private async void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        var result = Vm.Result!;
        await Save("JSON file|*.json", "legacy-auth.json", path =>
        {
            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16);
            Reports.WriteJson(stream, result);
        });
    }

    private static void WriteCsv(string path, Action<StreamWriter> write)
    {
        using var w = new StreamWriter(path, false, Reports.CsvEncoding, 1 << 16);
        write(w);
    }

    /// <summary>
    /// Asks for a file name and writes it in the background, so a 2 million row export does not freeze the window.
    /// Any write error is shown, it never closes the app.
    /// </summary>
    private async Task<string?> Save(string filter, string name, Action<string> write)
    {
        if (Vm.Result is null) return null;
        var dialog = new SaveFileDialog { Filter = filter, FileName = name };
        if (dialog.ShowDialog(this) != true) return null;
        var path = dialog.FileName;
        try
        {
            await Vm.RunBusyAsync($"Writing {Path.GetFileName(path)}…", () => Task.Run(() => write(path)));
            return path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or NotSupportedException or ArgumentException)
        {
            MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return null;
        }
    }

    private void OpenLogFolder_Click(object sender, RoutedEventArgs e)
    {
        if (Vm.LogPath.Length == 0) return;
        // Selects the current log file in Explorer, so it is easy to attach.
        Start(new ProcessStartInfo("explorer.exe", $"/select,\"{Vm.LogPath}\"") { UseShellExecute = true });
    }

    private void Link_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        OpenWithShell(e.Uri.AbsoluteUri);
        e.Handled = true;
    }

    private void OpenWithShell(string target) => Start(new ProcessStartInfo(target) { UseShellExecute = true });

    /// <summary>Opening a link or a file can fail (no browser, no file association). That is a message, not a crash.</summary>
    private void Start(ProcessStartInfo info)
    {
        try
        {
            Process.Start(info);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or FileNotFoundException)
        {
            MessageBox.Show(this, ex.Message, "Legacy Auth Finder", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
