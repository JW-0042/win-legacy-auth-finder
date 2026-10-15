using System.Diagnostics;
using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// The logging check is pasted into PowerShell on production servers. It must only read, run on the built-in Windows
/// PowerShell 5.1 (also in Constrained Language Mode) and survive a paste into a console.
/// </summary>
[Collection(SerialCollection.Name)]
public sealed class LoggingCheckTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-check-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static (int Code, string Output) PowerShell(string arguments, string? input = null)
    {
        var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass " + arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input is not null,
            UseShellExecute = false,
        };
        using var p = Process.Start(start)!;
        if (input is not null)
        {
            p.StandardInput.Write(input);
            p.StandardInput.Close();
        }
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        Assert.True(p.WaitForExit(180_000), "PowerShell did not finish in 3 minutes");
        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    [Fact]
    public void The_script_is_safe_to_paste_into_a_console()
    {
        var s = LoggingCheck.Script;
        // Plain ASCII survives every console code page. A tab would trigger tab completion while pasting.
        Assert.All(s, c => Assert.True(c < 128, $"non-ASCII character U+{(int)c:X4}"));
        Assert.DoesNotContain('\t', s);
        Assert.EndsWith("}\r\n\r\n", s);
        Assert.DoesNotContain("\n", s.Replace("\r\n", ""));
        Assert.Contains(Reports.Version, s);
        Assert.DoesNotContain("{{VERSION}}", s);
        // One script block: nothing stays in the session, and no exit that would close the window.
        Assert.Contains("\r\n& {\r\n", s);
        Assert.DoesNotMatch(@"(?im)^\s*exit\b", s);
    }

    [Fact]
    public void The_script_only_runs_commands_that_read()
    {
        var script = Path.Combine(_dir, "check.ps1");
        File.WriteAllText(script, LoggingCheck.Script);
        var lister = Path.Combine(_dir, "commands.ps1");
        File.WriteAllText(lister, """
            param([string]$Path)
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
            'errors=' + $errors.Count
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object {
                    $name = $_.GetCommandName()
                    $first = $_.CommandElements[0]
                    if (-not $name -and $first -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $name = 'inline script block' }
                    elseif (-not $name) { $name = $first.Extent.Text }
                    'command=' + $name
                } | Sort-Object -Unique
            """);
        var (code, text) = PowerShell($"-File \"{lister}\" -Path \"{script}\"");
        output.WriteLine(text);
        Assert.Equal(0, code);
        Assert.Contains("errors=0", text);
        string[] allowed =
        [
            // Reading Windows: audit policy, registry, event logs, WMI, SMB settings, the current user's groups.
            "auditpol.exe", "whoami.exe", "Get-ItemProperty", "Get-WinEvent", "Get-CimInstance", "Get-SmbServerConfiguration", "Test-Path", "Get-Date",
            // The temp file of auditpol /backup, and the output.
            "Join-Path", "Import-Csv", "ConvertFrom-Csv", "Remove-Item", "Write-Host", "Set-StrictMode",
            "Where-Object", "Select-Object", "Sort-Object", "Measure-Object",
            // The archive files of AutoBackup logs: list them, never touch them.
            "Get-ChildItem", "Split-Path",
            // The script's own helpers, the outer & { } and Check running the script block of one check.
            "Row", "Check", "Reg", "Value", "Size", "Days", "HasEvent", "Audit", "Log", "inline script block", "$Body",
        ];
        var commands = text.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("command=")).Select(l => l["command=".Length..]).ToList();
        Assert.NotEmpty(commands);
        Assert.All(commands, c => Assert.Contains(c, allowed));
        // The only thing it deletes is its own temp file.
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(LoggingCheck.Script, "Remove-Item"));
        Assert.Contains("Remove-Item -LiteralPath $file", LoggingCheck.Script);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_script_runs_on_windows_powershell(bool constrained)
    {
        // Through standard input, the way a paste reaches the console. Constrained Language Mode is what locked-down
        // servers (AppLocker, WDAC) run.
        var input = (constrained ? "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\r\n" : "") + LoggingCheck.Script;
        var (code, text) = PowerShell("-Command -", input);
        output.WriteLine(text);
        Assert.Equal(0, code);
        Assert.Contains($"Legacy Auth Finder {Reports.Version}: logging check", text);
        Assert.Matches(@"missing, \d+ warnings|Everything Legacy Auth Finder needs", text);
        // "could not be read" is what Check writes for an unexpected error in one check.
        Assert.DoesNotContain("could not be read: ", text);
        Assert.DoesNotContain("ParserError", text);
        Assert.DoesNotContain("Exception", text);
        // Elevated (as on the CI runners), the audit policy must be read, not reported as unknown.
        if (text.Contains("elevated: True")) Assert.DoesNotContain("[UNKNOWN] Audit Logon", text);
    }
}
