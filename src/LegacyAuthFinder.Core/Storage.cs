using System.Runtime.InteropServices;
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
            var full = Path.GetFullPath(folder);
            if (full.StartsWith(@"\\", StringComparison.Ordinal)) return StorageKind.Network;
            var root = Path.GetPathRoot(full);
            if (root is null || root.Length < 2) return StorageKind.Unknown;
            if (new DriveInfo(root).DriveType == DriveType.Network) return StorageKind.Network;
            return SeekPenalty(root[..2]) switch
            {
                true => StorageKind.Hdd,
                false => StorageKind.Ssd,
                null => StorageKind.Unknown,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return StorageKind.Unknown;
        }
    }

    public static int RecommendedThreads(StorageKind kind) => kind switch
    {
        StorageKind.Ssd => Math.Clamp(Environment.ProcessorCount, 2, 8),
        StorageKind.Hdd => 2,
        StorageKind.Network => 2,
        _ => 4,
    };

    public static string Describe(StorageKind kind) => kind switch
    {
        StorageKind.Ssd => "This folder is on an SSD. Up to 8 files at once is fine.",
        StorageKind.Hdd => "This folder is on a hard disk. 2 files at once is fastest, more makes the disk seek between files and the whole scan slower.",
        StorageKind.Network => "This folder is on a network share. Start with 2 files at once and raise it only if the share keeps up.",
        _ => "Could not tell what kind of disk this is. 4 files at once is a safe start.",
    };

    private const uint IoctlVolumeGetDiskExtents = 0x560000;
    private const uint IoctlStorageQueryProperty = 0x2D1400;
    private const int StorageDeviceSeekPenaltyProperty = 7;

    /// <summary>True when the disk behind the volume has a seek penalty (a spinning disk). Needs no admin rights.</summary>
    private static bool? SeekPenalty(string volume)
    {
        using var vol = CreateFile(@"\\.\" + volume, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (vol.IsInvalid) return null;
        var extents = Marshal.AllocHGlobal(1024);
        var query = Marshal.AllocHGlobal(12);
        var output = Marshal.AllocHGlobal(16);
        try
        {
            if (!DeviceIoControl(vol, IoctlVolumeGetDiskExtents, IntPtr.Zero, 0, extents, 1024, out _, IntPtr.Zero)) return null;
            var disk = Marshal.ReadInt32(extents, 8);
            using var drive = CreateFile(@"\\.\PhysicalDrive" + disk, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (drive.IsInvalid) return null;
            Marshal.WriteInt32(query, 0, StorageDeviceSeekPenaltyProperty);
            Marshal.WriteInt32(query, 4, 0);
            Marshal.WriteInt32(query, 8, 0);
            if (!DeviceIoControl(drive, IoctlStorageQueryProperty, query, 12, output, 16, out _, IntPtr.Zero)) return null;
            return Marshal.ReadByte(output, 8) != 0;
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
}
