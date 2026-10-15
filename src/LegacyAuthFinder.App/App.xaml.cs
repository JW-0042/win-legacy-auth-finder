using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace LegacyAuthFinder.App;

public partial class App : Application
{
    private Core.DiagLog? _log;

    /// <summary>The list separator of the user's Windows region, captured before the app switches to English. Used for CSV.</summary>
    public static char ListSeparator { get; private set; } = ',';

    // LegacyAuthFinder.exe [--demo | <folder>]
    // LegacyAuthFinder.exe --screenshot <file.png> [--theme light|dark] [--tab summary|events|files]
    // Screenshot mode loads the demo data, renders the main window to a PNG and exits. Used for the README.
    // It never touches real logs, so no real machine names, accounts or scripts can end up in public images.
    protected override async void OnStartup(StartupEventArgs e)
    {
        // Only separators that cannot appear unquoted in a value, like the command line allows.
        var regional = System.Globalization.CultureInfo.CurrentCulture.TextInfo.ListSeparator;
        if (regional is "," or ";" or "|" or "\t") ListSeparator = regional[0];
        // The interface is in English, so numbers and dates follow English formatting everywhere.
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("en-US");
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("en-US");
        var args = e.Args;
        var i = Array.IndexOf(args, "--screenshot");
        base.OnStartup(e);
        if (i < 0 || i + 1 >= args.Length)
        {
            // One diagnostic log per session. Unhandled errors end up there too.
            var log = Core.DiagLog.Create("GUI");
            _log = log;
            var errors = new Queue<DateTime>();
            var showing = false;
            DispatcherUnhandledException += (_, ex) =>
            {
                // Logged and shown, the app keeps running with its results. An error that comes back at once (in layout
                // or rendering) would open one dialog after another, so the third within 10 seconds closes the app.
                log.Error("CRASH", "UI thread", ex.Exception);
                ex.Handled = true;
                var now = DateTime.UtcNow;
                errors.Enqueue(now);
                while (errors.Count > 0 && now - errors.Peek() > TimeSpan.FromSeconds(10)) errors.Dequeue();
                if (errors.Count >= 3)
                {
                    log.Write("CRASH", "The same kind of error keeps coming back, closing the app");
                    Shutdown(1);
                    return;
                }
                if (showing) return;
                showing = true;
                try
                {
                    MessageBox.Show(MainWindow, ex.Exception.Message, "Legacy Auth Finder", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    showing = false;
                }
            };
            AppDomain.CurrentDomain.UnhandledException += (_, ex) => { if (ex.ExceptionObject is Exception x) log.Error("CRASH", "unhandled", x); };
            TaskScheduler.UnobservedTaskException += (_, ex) => log.Error("CRASH", "unobserved task", ex.Exception);
            var window = new MainWindow();
            MainWindow = window;
            window.Show();
            var vmStart = (MainViewModel)window.DataContext;
            vmStart.AttachLog(log);
            try
            {
                if (args.Contains("--demo")) await vmStart.LoadDemoAsync();
                else if (args.Length > 0 && Directory.Exists(args[0])) await vmStart.OpenFolderAsync(args[0]);
            }
            catch (Exception ex)
            {
                log.Error("UI", "Startup folder", ex);
                MessageBox.Show(window, ex.Message, "Legacy Auth Finder", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }

        var path = Path.GetFullPath(args[i + 1]);
        try
        {
            await RenderScreenshotAsync(args, path);
            Shutdown(0);
        }
        catch (Exception ex)
        {
            File.WriteAllText(path + ".error.txt", ex.ToString());
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _log?.Write("END", $"Application closed (exit code {e.ApplicationExitCode})");
        _log?.Dispose();
        base.OnExit(e);
    }

    private async Task RenderScreenshotAsync(string[] args, string path)
    {
        var t = Array.IndexOf(args, "--theme");
        if (t >= 0 && t + 1 < args.Length)
        {
            ThemeMode = args[t + 1] == "dark" ? ThemeMode.Dark : ThemeMode.Light;
        }

        var window = new MainWindow { Left = -20000, Top = -20000, ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual };
        window.Show();
        var vm = (MainViewModel)window.DataContext;
        // --folder is for testing the real scan path. README screenshots always use the demo data.
        var folderArg = Array.IndexOf(args, "--folder");
        if (folderArg >= 0 && folderArg + 1 < args.Length)
        {
            await vm.OpenFolderAsync(args[folderArg + 1]);
            // After opening: reading the folder sets the recommended number, the argument wins.
            var threadsArg = Array.IndexOf(args, "--threads");
            if (threadsArg >= 0 && threadsArg + 1 < args.Length && int.TryParse(args[threadsArg + 1], out var threads)) vm.Threads = threads;
            if (!args.Contains("--no-scan")) await vm.StartScanAsync();
        }
        else await vm.LoadDemoAsync();
        var tab = Array.IndexOf(args, "--tab") is var ti && ti >= 0 && ti + 1 < args.Length ? args[ti + 1] : "summary";
        if (tab == "events")
        {
            vm.SelectedTab = 2;
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            var grid = (System.Windows.Controls.DataGrid)window.FindName("EventsGrid");
            grid.SelectedItem = vm.Events.FirstOrDefault(e => e.EventId == 4769 && e.SessionEncryption.Length > 0 && e.Kind == Core.LegacyKind.Rc4);
        }
        else if (tab == "files")
        {
            vm.SelectedTab = 3;
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            // A busy domain controller log, so the image shows the retention estimate.
            var grid = (System.Windows.Controls.DataGrid)window.FindName("FilesGrid");
            grid.SelectedItem = vm.Files.Where(f => f.EventsPerDay > 0).OrderByDescending(f => f.EventsPerDay).FirstOrDefault();
        }
        else if (tab == "fix")
        {
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            var grid = (System.Windows.Controls.DataGrid)window.FindName("FixGrid");
            grid.SelectedItem = vm.Fixes.FirstOrDefault(f => f.TargetType == Core.FixTarget.ServiceAccount) ?? vm.Fixes.FirstOrDefault();
        }
        else
        {
            vm.SelectedTab = 1;
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            // An RC4 service account is the most common real finding, so open on it unless asked for another row.
            var grid = (System.Windows.Controls.DataGrid)window.FindName("SummaryGrid");
            grid.SelectedItem = vm.Summary.FirstOrDefault(s => s.Account.StartsWith("svc-erp")) ?? vm.Summary.FirstOrDefault();
        }
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);

        var content = (FrameworkElement)window.Content;
        var dpi = VisualTreeHelper.GetDpi(window);
        var bmp = new RenderTargetBitmap(
            (int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        var bg = new DrawingVisual();
        using (var dc = bg.RenderOpen())
        {
            dc.DrawRectangle(BackgroundFor(window), null, new Rect(0, 0, content.ActualWidth, content.ActualHeight));
        }
        bmp.Render(bg);
        bmp.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        await using (var fs = File.Create(path))
        {
            encoder.Save(fs);
        }
    }

    // Offscreen rendering skips the window chrome, so paint the theme background ourselves.
    private Brush BackgroundFor(Window window)
    {
        if (window.Background is SolidColorBrush { Color.A: 255 } solid) return solid;
        if (window.TryFindResource("ApplicationBackgroundBrush") is SolidColorBrush { Color.A: 255 } themed) return themed;
        return ThemeMode == ThemeMode.Dark
            ? new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20))
            : new SolidColorBrush(Color.FromRgb(0xF3, 0xF3, 0xF3));
    }

    private static T? FindChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) return match;
            if (FindChild<T>(child) is { } nested) return nested;
        }
        return null;
    }
}
