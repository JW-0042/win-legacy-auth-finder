namespace LegacyAuthFinder.Core;

/// <summary>
/// A read-only PowerShell check that shows whether a server logs what this tool needs: audit policy, event logs,
/// NTLM, SMBv1, Kerberos and LDAP settings. It runs on Windows Server 2016 and newer with the built-in Windows
/// PowerShell 5.1, also in Constrained Language Mode, and changes nothing. The user pastes it into an elevated
/// PowerShell window on each server.
/// </summary>
public static class LoggingCheck
{
    private const string Resource = "LegacyAuthFinder.Core.LoggingCheck.ps1";

    /// <summary>
    /// The script with this version in it and Windows line endings. It ends with an empty line: the classic console
    /// host (no PSReadLine) and standard input need one to finish a block of several lines, so a paste runs it at once.
    /// </summary>
    public static string Script { get; } = Load();

    private static string Load()
    {
        using var stream = typeof(LoggingCheck).Assembly.GetManifestResourceStream(Resource)
            ?? throw new InvalidOperationException($"Resource {Resource} is missing");
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd().Replace("{{VERSION}}", Reports.Version).ReplaceLineEndings("\r\n");
        return text.TrimEnd() + "\r\n\r\n";
    }
}
