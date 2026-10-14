using System.Diagnostics;
using System.Globalization;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace LegacyAuthFinder.Core;

/// <summary>
/// Plain text diagnostic log for support. One file per session in %LOCALAPPDATA%\LegacyAuthFinder\Logs, flushed after
/// every line so it survives a hang or a killed process. It records timings, file sizes, thread and service state,
/// never the content of events: no account names, client addresses or service names.
/// </summary>
public sealed class DiagLog : IDisposable
{
    public const int KeepFiles = 20;

    /// <summary>A log never grows past this. Thousands of damaged files would otherwise write a stack trace each.</summary>
    public const long MaxBytes = 200L << 20;

    private readonly Lock _gate = new();
    private readonly StreamWriter? _writer;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private bool _disposed;
    private long _written;
    private bool _full;

    private DiagLog(string path, StreamWriter? writer)
    {
        Path = path;
        _writer = writer;
    }

    public string Path { get; }

    public static string DefaultFolder => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LegacyAuthFinder", "Logs");

    /// <summary>Opens a new log file and writes the header. Never throws: if the file cannot be created, nothing is logged.</summary>
    public static DiagLog Create(string mode, string? path = null)
    {
        path ??= System.IO.Path.Combine(DefaultFolder, $"legacy-auth-finder-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.ProcessId}.log");
        StreamWriter? writer = null;
        try
        {
            var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
            if (dir is not null)
            {
                Directory.CreateDirectory(dir);
                Prune(dir);
            }
            var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            writer = null;
        }
        var log = new DiagLog(path, writer);
        log.Header(mode);
        return log;
    }

    public bool IsEnabled => _writer is not null;

    public void Write(string area, string message)
    {
        if (_writer is null) return;
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} +{_clock.Elapsed.TotalSeconds,8:0.000}s T{Environment.CurrentManagedThreadId,-3} {area,-8} {message}";
        lock (_gate)
        {
            if (_disposed || _full) return;
            try
            {
                // Bytes, not characters: the file is UTF-8 and folder or file names can be outside ASCII.
                _written += System.Text.Encoding.UTF8.GetByteCount(line) + 2;
                if (_written > MaxBytes)
                {
                    _full = true;
                    line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} LIMIT    The log reached {MaxBytes >> 20} MB. Nothing more is written.";
                }
                _writer.WriteLine(line);
            }
            catch (IOException)
            {
                // A full disk must not stop the scan.
            }
        }
    }

    public void Error(string area, string context, Exception ex) =>
        Write(area, $"ERROR {context}: {ex.GetType().FullName}: {ex.Message.Trim()} (HResult 0x{ex.HResult:X8}){Environment.NewLine}{ex}");

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                _writer?.Dispose();
            }
            catch (IOException)
            {
                // The last flush can fail on a full disk. The log is best effort.
            }
        }
    }

    private void Header(string mode)
    {
        var version = typeof(DiagLog).Assembly.GetName().Version?.ToString(3) ?? "?";
        Write("START", $"Legacy Auth Finder {version} diagnostic log ({mode}). Contains timings and file names, no event content.");
        Write("SYSTEM", $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}), process {RuntimeInformation.ProcessArchitecture}, {RuntimeInformation.FrameworkDescription}");
        var mem = SystemProbe.Memory();
        Write("SYSTEM", $"{Environment.ProcessorCount} logical CPUs, memory {mem}, server GC {GCSettings.IsServerGC}, GC latency {GCSettings.LatencyMode}");
        Write("SYSTEM", $"Administrator {IsAdmin()}, culture {CultureInfo.CurrentCulture.Name}, UI culture {CultureInfo.CurrentUICulture.Name}, time zone UTC{TimeZoneInfo.Local.BaseUtcOffset:hh\\:mm}");
        Write("SYSTEM", $"Event Log service: {SystemProbe.EventLogServiceText()}");
        ThreadPool.GetMinThreads(out var minW, out var minIo);
        ThreadPool.GetMaxThreads(out var maxW, out var maxIo);
        Write("SYSTEM", $"Thread pool min {minW}/{minIo}, max {maxW}/{maxIo}");
    }

    private static bool IsAdmin()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is SystemException)
        {
            return false;
        }
    }

    private static void Prune(string dir)
    {
        try
        {
            foreach (var old in new DirectoryInfo(dir).GetFiles("legacy-auth-finder-*.log")
                         .OrderByDescending(f => f.LastWriteTimeUtc).Skip(KeepFiles - 1))
            {
                // A log that another running instance still writes is skipped: opening it exclusively fails.
                try
                {
                    using (new FileStream(old.FullName, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
                    old.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // In use or read-only: skip it, the older ones are still cleaned up.
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Old logs that cannot be deleted stay.
        }
    }
}

/// <summary>Counters of this process and of the Windows Event Log service, which does the actual file reading.</summary>
public static class SystemProbe
{
    public sealed record ProcessSample(DateTime At, TimeSpan Cpu, ulong ReadBytes, ulong ReadOps, long WorkingSet, int Threads, int Handles);

    public static ProcessSample? Self()
    {
        try
        {
            using var p = Process.GetCurrentProcess();
            var io = IoCounters(p.Handle);
            return new ProcessSample(DateTime.UtcNow, p.TotalProcessorTime, io.ReadTransferCount, io.ReadOperationCount, p.WorkingSet64, p.Threads.Count, p.HandleCount);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// The Event Log service (wevtsvc in a svchost) opens and parses the .evtx files for EvtQuery. Its CPU time and
    /// disk reads show whether it is busy or waiting. Needs only limited query rights, so it works without admin.
    /// </summary>
    public static ProcessSample? EventLogService()
    {
        var pid = EventLogServicePid();
        return pid > 0 ? FromSystemList(pid) : null;
    }

    /// <summary>
    /// Reads one process from the system process list (NtQuerySystemInformation, SystemProcessInformation). Unlike
    /// OpenProcess this works for service processes without admin rights. Offsets are the x64 layout of
    /// SYSTEM_PROCESS_INFORMATION, checked against this process in the tests.
    /// </summary>
    internal static ProcessSample? FromSystemList(int pid)
    {
        if (IntPtr.Size != 8) return null;
        var size = 1 << 20;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, out var needed);
                if (status == StatusInfoLengthMismatch)
                {
                    size = Math.Max(size * 2, needed + (64 << 10));
                    continue;
                }
                if (status != 0) return null;
                var offset = 0;
                while (true)
                {
                    var entry = buffer + offset;
                    if (Marshal.ReadIntPtr(entry, 80).ToInt64() == pid)
                    {
                        var threads = Marshal.ReadInt32(entry, 4);
                        var cpu = TimeSpan.FromTicks(Marshal.ReadInt64(entry, 40) + Marshal.ReadInt64(entry, 48));
                        var handles = Marshal.ReadInt32(entry, 96);
                        var workingSet = Marshal.ReadInt64(entry, 144);
                        var readOps = (ulong)Marshal.ReadInt64(entry, 208);
                        var readBytes = (ulong)Marshal.ReadInt64(entry, 232);
                        return new ProcessSample(DateTime.UtcNow, cpu, readBytes, readOps, workingSet, threads, handles);
                    }
                    var next = Marshal.ReadInt32(entry, 0);
                    if (next == 0) return null;
                    offset += next;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return null;
    }

    /// <summary>CPU use in percent of one core and read speed between two samples.</summary>
    public static string Delta(ProcessSample? before, ProcessSample? now)
    {
        if (before is null || now is null) return "n/a";
        var seconds = Math.Max(0.001, (now.At - before.At).TotalSeconds);
        var cpu = (now.Cpu - before.Cpu).TotalSeconds / seconds * 100;
        var mb = (now.ReadBytes - before.ReadBytes) / 1048576.0 / seconds;
        var ops = (now.ReadOps - before.ReadOps) / seconds;
        return $"CPU {cpu:0}% of one core, reads {mb:0.0} MB/s in {ops:0} ops/s";
    }

    public static string Describe(ProcessSample? s) => s is null
        ? "n/a"
        : $"working set {s.WorkingSet / 1048576} MB, {(s.Threads >= 0 ? $"{s.Threads} threads, " : "")}{s.Handles} handles, CPU total {s.Cpu.TotalSeconds:0} s, read total {s.ReadBytes / 1048576} MB";

    public static string ThreadPoolText()
    {
        ThreadPool.GetAvailableThreads(out var availW, out _);
        ThreadPool.GetMaxThreads(out var maxW, out _);
        ThreadPool.GetMinThreads(out var minW, out _);
        return $"pool threads {ThreadPool.ThreadCount} (busy {maxW - availW}, min {minW}), queued work {ThreadPool.PendingWorkItemCount}, completed {ThreadPool.CompletedWorkItemCount}";
    }

    public static string GcText()
    {
        var info = GC.GetGCMemoryInfo();
        return $"managed heap {GC.GetTotalMemory(false) / 1048576} MB, GC gen0/1/2 {GC.CollectionCount(0)}/{GC.CollectionCount(1)}/{GC.CollectionCount(2)}, pause {GC.GetTotalPauseDuration().TotalSeconds:0.0} s, memory load {info.MemoryLoadBytes / 1048576} of {info.TotalAvailableMemoryBytes / 1048576} MB";
    }

    public static string Memory()
    {
        var status = new MemoryStatusEx { dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status)
            ? $"{status.ullTotalPhys / 1048576} MB total, {status.ullAvailPhys / 1048576} MB free ({status.dwMemoryLoad}% used)"
            : "n/a";
    }

    public static string EventLogServiceText()
    {
        var pid = EventLogServicePid();
        if (pid <= 0) return "process id not available";
        return $"PID {pid}, {Describe(EventLogService())}";
    }

    private static int EventLogServicePid()
    {
        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return -1;
        try
        {
            var svc = OpenService(scm, "EventLog", ServiceQueryStatus);
            if (svc == IntPtr.Zero) return -1;
            try
            {
                var buffer = new byte[Marshal.SizeOf<ServiceStatusProcess>()];
                if (!QueryServiceStatusEx(svc, 0, buffer, buffer.Length, out _)) return -1;
                return BitConverter.ToInt32(buffer, 28);
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    private static IoCountersStruct IoCounters(IntPtr process) => GetProcessIoCounters(process, out var io) ? io : default;

    private const int SystemProcessInformation = 5;
    private const uint StatusInfoLengthMismatch = 0xC0000004;
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCountersStruct
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr process, out IoCountersStruct counters);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx status);

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int infoClass, IntPtr buffer, int size, out int needed);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, byte[] buffer, int size, out int needed);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
