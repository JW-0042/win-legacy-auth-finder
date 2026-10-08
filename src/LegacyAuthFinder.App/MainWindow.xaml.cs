using System.Diagnostics;
using System.IO;
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

    private void ShowEvents_Click(object sender, RoutedEventArgs e)
    {
        if (Vm.Selection is SummaryRow row) Vm.ShowEventsFor(row);
    }

    private void ExportSummary_Click(object sender, RoutedEventArgs e) =>
        Save("CSV file|*.csv", "legacy-auth-summary.csv", path =>
        {
            using var w = new StreamWriter(path, false, Reports.CsvEncoding);
            Reports.WriteSummaryCsv(w, Vm.Summary);
        });

    private void ExportEvents_Click(object sender, RoutedEventArgs e) =>
        Save("CSV file|*.csv", "legacy-auth-events.csv", path =>
        {
            using var w = new StreamWriter(path, false, Reports.CsvEncoding);
            Reports.WriteEventsCsv(w, Vm.Events);
        });

    private void ExportHtml_Click(object sender, RoutedEventArgs e) =>
        Save("HTML report|*.html", "legacy-auth-report.html", path =>
        {
            File.WriteAllText(path, Reports.ToHtml(Vm.Result!));
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        });

    private void ExportJson_Click(object sender, RoutedEventArgs e) =>
        Save("JSON file|*.json", "legacy-auth.json", path => File.WriteAllText(path, Reports.ToJson(Vm.Result!)));

    /// <summary>CSV exports follow the current search and type filter, so you can export exactly what you see.</summary>
    private void Save(string filter, string name, Action<string> write)
    {
        if (Vm.Result is null) return;
        var dialog = new SaveFileDialog { Filter = filter, FileName = name };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            write(dialog.FileName);
        }
        catch (IOException ex)
        {
            MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Link_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
