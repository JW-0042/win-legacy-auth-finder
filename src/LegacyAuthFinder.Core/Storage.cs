using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LegacyAuthFinder.Core;

public enum StorageKind
{
    Unknown,
    Ssd,
    Hdd,
    Network,
}

/// <summary>
/// Where a folder lives decides how many files should be read at once. Reading many files in parallel from one
/// hard disk makes the disk seek between them and the whole scan gets slower, not faster.
/// </summary>
public static class Storage
{
    public static StorageKind Detect(string folder)
    {
        try
        {
            var volume = Volume(folder, out var network);
            if (network) return StorageKind.Network;
            if (volume is null) return StorageKind.Unknown;
            return SeekPenalty(volume) switch
            {
                true => StorageKind.Hdd,
                false => StorageKind.Ssd,
                null => StorageKind.Unknown,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return StorageKind.Unknown;
        }
    }

    /// <summary>
    /// The volume the folder really lives on, as a device path (\\.\Volume{GUID} or \\.\C:). Follows mount points
    /// and junctions, and understands \\?\ paths. Network paths and mapped network drives set <paramref name="network"/>.
    /// </summary>
    internal static string? Volume(string folder, out bool network)
    {
        network = false;
        var full = Path.GetFullPath(folder);
        if (full.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) || (full.StartsWith(@"\\", StringComparison.Ordinal) && !full.StartsWith(@"\\?\", StringComparison.Ordinal) && !full.StartsWith(@"\\.\", StringComparison.Ordinal)))
        {
            network = true;
            return null;
        }
        // Resolve junctions and symbolic links to the target, then ask which volume mount point holds it.
        var target = FinalPath(full) ?? full;
        if (target.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            network = true;
            return null;
        }
        var mount = new StringBuilder(1024);
        if (!GetVolumePathName(target, mount, mount.Capacity)) return null;
        var root = mount.ToString();
        if (GetDriveType(root) == DriveRemote)
        {
            network = true;
            return null;
        }
        var guid = new StringBuilder(64);
        if (GetVolumeNameForVolumeMountPoint(root, guid, guid.Capacity))
        {
            // \\?\Volume{GUID}\ becomes \\.\Volume{GUID}, the form CreateFile takes for a volume.
            return @"\\.\" + guid.ToString().TrimEnd('\\')[4..];
        }
        var letter = Path.GetPathRoot(target);
        return letter is { Length: >= 2 } && letter[1] == ':' ? @"\\.\" + letter[..2] : null;
    }

    private static string? FinalPath(string path)
    {
        using var handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, BackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid) return null;
        var buffer = new StringBuilder(1024);
        var length = GetFinalPathNameByHandle(handle, buffer, buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) return null;
        var text = buffer.ToString();
        return text.StartsWith(@"\\?\", StringComparison.Ordinal) && !text.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? text[4..] : text;
    }

    /// <summary>Details for the diagnostic log: drive type, file system, free space, the volume and the seek penalty answer.</summary>
    public static string Explain(string folder)
    {
        try
        {
            var volume = Volume(folder, out var network);
            if (network) return "network path or mapped network drive";
            var root = Path.GetPathRoot(Path.GetFullPath(folder)) ?? "";
            var drive = root.Length > 0 && !root.StartsWith(@"\\", StringComparison.Ordinal) ? new DriveInfo(root) : null;
            var penalty = volume is null ? null : SeekPenalty(volume);
            return $"volume {volume ?? "unknown"}, drive {root} {(drive is null ? "" : $"type {drive.DriveType}, {(drive.IsReady ? $"{drive.DriveFormat}, {drive.AvailableFreeSpace / 1073741824} of {drive.TotalSize / 1073741824} GB free" : "not ready")}")}, "
                + $"seek penalty {(penalty is null ? "unknown (query failed)" : penalty.Value ? "yes (hard disk)" : "no (SSD)")}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return $"could not inspect the drive: {ex.Message}";
        }
    }

    public static int RecommendedThreads(StorageKind kind) => kind switch
    {
        StorageKind.Ssd => Math.Clamp(Environment.ProcessorCount, 2, 8),
        StorageKind.Hdd => 2,
        StorageKind.Network => 2,
        // Unknown: some USB bridges and storage pools do not answer the query. Read it like a hard disk to be safe.
        _ => 2,
    };

    public static string Describe(StorageKind kind) => kind switch
    {
        StorageKind.Ssd => "This folder is on an SSD. Up to 8 files at once is fine.",
        StorageKind.Hdd => "This folder is on a hard disk. 2 files at once is fastest, more makes the disk seek between files and the whole scan slower.",
        StorageKind.Network => "This folder is on a network share. Start with 2 files at once and raise it only if the share keeps up.",
        _ => "Could not tell what kind of disk this is, so it is read like a hard disk: 2 files at once. Raise it if the folder is on an SSD.",
    };

    private const uint IoctlVolumeGetDiskExtents = 0x560000;
    private const uint IoctlStorageQueryProperty = 0x2D1400;
    private const int StorageDeviceSeekPenaltyProperty = 7;
    private const uint BackupSemantics = 0x02000000;
    private const uint DriveRemote = 4;

    /// <summary>
    /// True when any disk behind the volume has a seek penalty (a spinning disk). A volume can span several disks,
    /// all of them are checked. Needs no admin rights.
    /// </summary>
    private static bool? SeekPenalty(string volume)
    {
        using var vol = CreateFile(volume, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (vol.IsInvalid) return null;
        const int ExtentsSize = 8 + 24 * 32;
        var extents = Marshal.AllocHGlobal(ExtentsSize);
        var query = Marshal.AllocHGlobal(12);
        var output = Marshal.AllocHGlobal(16);
        try
        {
            if (!DeviceIoControl(vol, IoctlVolumeGetDiskExtents, IntPtr.Zero, 0, extents, ExtentsSize, out _, IntPtr.Zero)) return null;
            var count = Math.Min(Marshal.ReadInt32(extents, 0), 32);
            bool? any = null;
            for (var i = 0; i < count; i++)
            {
                var disk = Marshal.ReadInt32(extents, 8 + i * 24);
                using var drive = CreateFile(@"\\.\PhysicalDrive" + disk, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (drive.IsInvalid) continue;
                Marshal.WriteInt32(query, 0, StorageDeviceSeekPenaltyProperty);
                Marshal.WriteInt32(query, 4, 0);
                Marshal.WriteInt32(query, 8, 0);
                if (!DeviceIoControl(drive, IoctlStorageQueryProperty, query, 12, output, 16, out _, IntPtr.Zero)) continue;
                var penalty = Marshal.ReadByte(output, 8) != 0;
                any = (any ?? false) || penalty;
            }
            return any;
        }
        finally
        {
            Marshal.FreeHGlobal(extents);
            Marshal.FreeHGlobal(query);
            Marshal.FreeHGlobal(output);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, int inputSize, IntPtr output, int outputSize, out int returned, IntPtr overlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(string fileName, StringBuilder volumePathName, int bufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string mountPoint, StringBuilder volumeName, int bufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveType(string rootPathName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, int length, uint flags);
}
