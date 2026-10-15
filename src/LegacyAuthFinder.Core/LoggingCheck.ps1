# Legacy Auth Finder {{VERSION}}: logging check
# Shows whether this server logs what Legacy Auth Finder needs, and what to turn on where it does not.
# Read-only: it reads the audit policy, registry values and event log settings. It changes nothing.
# Windows Server 2016 or newer, the built-in Windows PowerShell 5.1, nothing to install.
# Paste it into an elevated PowerShell window (Run as administrator) on every server and domain controller
# whose logs you want to scan. https://github.com/JW-0042/win-legacy-auth-finder
& {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $rows = @()

    function Row([string]$Status, [string]$Area, [string]$Check, [string]$Current, [string]$Why = '', [string]$Fix = '') {
        # A hashtable, not [pscustomobject]: Constrained Language Mode allows only core types.
        @{ Status = $Status; Area = $Area; Check = $Check; Current = $Current; Why = $Why; Fix = $Fix }
    }

    # One failing check never stops the others.
    function Check([string]$Area, [string]$Name, [scriptblock]$Body) {
        try { & $Body } catch { Row 'UNKNOWN' $Area $Name ('could not be read: ' + $_.Exception.Message) }
    }

    function Reg([string]$Path, [string]$Name) {
        try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
    }

    function Value($v) { if ($null -eq $v) { 'not set' } else { 'value ' + $v } }

    function Size($bytes) { if ($bytes -ge 1GB) { '{0:0.0} GB' -f ($bytes / 1GB) } else { '{0:0} MB' -f ($bytes / 1MB) } }

    function Days($n) { if ($n -eq 1) { '1 day' } else { [string]$n + ' days' } }

    function HasEvent([string]$Provider, [int]$Id) {
        try {
            $meta = Get-WinEvent -ListProvider $Provider -ErrorAction Stop
            [bool]($meta.Events | Where-Object { $_.Id -eq $Id } | Select-Object -First 1)
        } catch { $false }
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $isDc = $cs.DomainRole -ge 4
    # Windows Server 2016 is build 14393. Microsoft adds the enhanced NTLM events to 2019 (17763) and newer only.
    $is2016 = [int]$os.BuildNumber -lt 17763
    # Native tools run with Continue: in Windows PowerShell 5.1 any text on stderr would otherwise stop the script.
    $elevated = $false
    try {
        $ErrorActionPreference = 'Continue'
        $elevated = [bool]((& whoami.exe /groups /fo csv 2>$null) -match 'S-1-16-12288')
    } catch { } finally { $ErrorActionPreference = 'Stop' }

    # Audit policy. auditpol /backup writes the settings as numbers (0 none, 1 success, 2 failure, 3 both), which
    # do not depend on the language of Windows. The file goes to the temp folder and is deleted right away.
    $audit = @{}
    $auditError = ''
    if ($elevated) {
        $file = Join-Path $env:TEMP ('laf-auditpol-' + $PID + '.csv')
        try {
            $ErrorActionPreference = 'Continue'
            $null = & auditpol.exe /backup ('/file:' + $file) 2>$null
            $code = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
            if ($code -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw ('auditpol /backup ended with code ' + $code) }
            # Columns by position, the header text could be translated: 4th is the subcategory GUID, 7th the setting.
            foreach ($line in Import-Csv -LiteralPath $file -Header 'Machine', 'Target', 'Name', 'Guid', 'Inclusion', 'Exclusion', 'Value') {
                $guid = ([string]$line.Guid).Trim().Trim('{}').ToUpperInvariant()
                $value = ([string]$line.Value).Trim()
                if ($guid -match '^[0-9A-F]{8}-' -and $value -match '^[0-9]+$') { $audit[$guid] = [int]$value }
            }
        } catch {
            $auditError = $_.Exception.Message
        } finally {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        }
        # Fallback: the report of auditpol /get, readable where Windows shows these settings in English.
        if ($audit.Count -eq 0) {
            $ErrorActionPreference = 'Continue'
            $report = @(& auditpol.exe /get /category:* /r 2>$null)
            $ErrorActionPreference = 'Stop'
            $words = @{ 'No Auditing' = 0; 'Success' = 1; 'Failure' = 2; 'Success and Failure' = 3 }
            foreach ($line in ($report | Where-Object { $_ } | ConvertFrom-Csv -Header 'Machine', 'Target', 'Name', 'Guid', 'Inclusion', 'Exclusion')) {
                $guid = ([string]$line.Guid).Trim().Trim('{}').ToUpperInvariant()
                $setting = ([string]$line.Inclusion).Trim()
                if ($guid -match '^[0-9A-F]{8}-' -and $words.ContainsKey($setting)) { $audit[$guid] = $words[$setting] }
            }
            if ($audit.Count -eq 0 -and -not $auditError) { $auditError = 'the output of auditpol could not be read on this system' }
            elseif ($audit.Count -gt 0) { $auditError = '' }
        }
    } else {
        $auditError = 'needs an elevated PowerShell (Run as administrator)'
    }

    function Audit([string]$Area, [string]$Name, [string]$Guid, [int]$Need, [string]$Why) {
        $text = @('No auditing', 'Success', 'Failure', 'Success and Failure')
        $fix = 'Group Policy: Advanced Audit Policy Configuration > Audit ' + $Name + ' = ' + $text[$Need] + '. Locally: auditpol /set /subcategory:"{' + $Guid + '}"'
        if ($Need -band 1) { $fix += ' /success:enable' }
        if ($Need -band 2) { $fix += ' /failure:enable' }
        if ($auditError) { return Row 'UNKNOWN' $Area ('Audit ' + $Name) $auditError $Why $fix }
        $have = 0
        if ($audit.ContainsKey($Guid)) { $have = $audit[$Guid] }
        if (($have -band $Need) -eq $Need) { return Row 'OK' $Area ('Audit ' + $Name) $text[$have] $Why }
        Row 'MISSING' $Area ('Audit ' + $Name) ($text[$have] + ', needs ' + $text[$Need]) $Why $fix
    }

    # A log must be on. A full circular log that holds less than a week loses events before they are archived.
    function Log([string]$Area, [string]$Name, [string]$Why) {
        $log = $null
        try { $log = Get-WinEvent -ListLog $Name -ErrorAction Stop } catch { }
        if (-not $log) { return Row 'UNKNOWN' $Area ('Log ' + $Name) 'cannot be read (run as administrator, or the log does not exist here)' $Why }
        # Casts and properties only, no calls on the Math class: Constrained Language Mode allows methods of core types only.
        $mb = [long]($log.MaximumSizeInBytes / 1MB)
        $current = $(if ($log.IsEnabled) { 'enabled' } else { 'disabled' }) + ', max ' + $mb + ' MB, ' + $log.LogMode
        if (-not $log.IsEnabled) { return Row 'MISSING' $Area ('Log ' + $Name) $current $Why ('wevtutil sl "' + $Name + '" /e:true') }
        $days = $null
        try {
            $oldest = Get-WinEvent -LogName $Name -MaxEvents 1 -Oldest -ErrorAction Stop
            $days = ((Get-Date) - $oldest.TimeCreated).Days
            $current += ', oldest event ' + $oldest.TimeCreated.ToString('yyyy-MM-dd') + ' (' + (Days $days) + ')'
        } catch { }

        # AutoBackup: a full log is saved as Archive-<log>-<time>.evtx next to it and a new one starts. The archives
        # hold the history, and Windows never deletes them, so the free space of that disk matters.
        if ([string]$log.LogMode -eq 'AutoBackup') {
            try {
                $path = ([string]$log.LogFilePath) -replace '%SystemRoot%', $env:SystemRoot -replace '%windir%', $env:windir
                $folder = Split-Path -Path $path -Parent
                $base = (Split-Path -Path $path -Leaf) -replace '\.evtx$', ''
                $archives = @(Get-ChildItem -LiteralPath $folder -Filter ('Archive-' + $base + '-*.evtx') -File -ErrorAction Stop)
                if ($archives.Count -gt 0) {
                    $total = ($archives | Measure-Object -Property Length -Sum).Sum
                    $first = ($archives | Sort-Object -Property LastWriteTime | Select-Object -First 1).LastWriteTime
                    $current += ', ' + $archives.Count + ' archive files next to it (' + (Size $total) + ' since ' + $first.ToString('yyyy-MM-dd') + ')'
                    $hours = ((Get-Date) - $first).TotalHours
                    if ($archives.Count -ge 2 -and $hours -gt 0) { $current += ', a new one about every ' + ('{0:0.#}' -f ($hours / $archives.Count)) + ' h' }
                } else {
                    $current += ', no archive files yet'
                }
                $drive = Split-Path -Path $folder -Qualifier
                $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $drive + "'")
                if ($disk -and $disk.Size -gt 0) {
                    $freeShare = $disk.FreeSpace / $disk.Size
                    $current += ', disk ' + $drive + ' ' + ('{0:0}' -f ($freeShare * 100)) + '% free'
                    if ($freeShare -lt 0.1) {
                        return Row 'WARN' $Area ('Log ' + $Name) $current ($Why + ' Windows never deletes the archive files of an AutoBackup log, and the disk is almost full: copy the archives away for the scan and remove the old ones.') ''
                    }
                }
            } catch { }
        }

        $full = $log.FileSize -ge 0.9 * $log.MaximumSizeInBytes
        if ($full -and $log.LogMode -eq 'Circular' -and $null -ne $days -and $days -lt 7) {
            $bigger = $log.MaximumSizeInBytes * 4
            if ($bigger -gt 4GB - 64KB) { $bigger = 4GB - 64KB }
            return Row 'WARN' $Area ('Log ' + $Name) $current ($Why + ' The log is full and holds less than a week: export or archive it regularly, or make it bigger.') ('wevtutil sl "' + $Name + '" /ms:' + $bigger)
        }
        Row 'OK' $Area ('Log ' + $Name) $current $Why
    }

    # ---------------- Every server ----------------
    $rows += Check 'Logon' 'Audit Logon' { Audit 'Logon' 'Logon' '0CCE9215-69AE-11D9-BED3-505054503030' 1 'Event 4624 shows sign-ins with NTLMv1 or LM (LmPackageName).' }
    $rows += Check 'Logon' 'Log Security' { Log 'Logon' 'Security' 'Holds 4624 on every server, and the Kerberos events on domain controllers.' }
    $rows += Check 'Audit' 'Subcategory settings win' {
        $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
        if ($v -eq 1) { Row 'OK' 'Audit' 'Subcategory settings win' 'Audit: Force audit policy subcategory settings is on' }
        else { Row 'INFO' 'Audit' 'Subcategory settings win' 'not set' 'Without "Audit: Force audit policy subcategory settings to override audit policy category settings", an old category-level audit policy can override the settings above. The values above are what applies now.' }
    }

    $ntlmEnhanced = HasEvent 'Microsoft-Windows-NTLM' 4020
    $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $restrictOn = ((Reg $msv 'AuditReceivingNTLMTraffic') -eq 2) -and ((Reg $msv 'RestrictSendingNTLMTraffic') -in 1, 2)
    $rows += Check 'NTLM' 'Enhanced NTLM events' {
        if ($ntlmEnhanced) {
            Row 'OK' 'NTLM' 'Enhanced NTLM events 4020 to 4023' 'available on this build' 'They name every NTLM sign-in with the reason. On by default, unless Group Policy turns off "NTLM Enhanced Logging" (Administrative Templates > System > NTLM): check with gpresult /h.'
        } elseif ($is2016 -and $restrictOn) {
            Row 'INFO' 'NTLM' 'Enhanced NTLM events 4020 to 4023' 'not available on Windows Server 2016' 'Microsoft adds them to Windows Server 2019 and newer only. Here the Restrict NTLM audit below records NTLM use (events 8001 to 8003), and that is on.'
        } elseif ($is2016) {
            Row 'WARN' 'NTLM' 'Enhanced NTLM events 4020 to 4023' 'not available on Windows Server 2016' 'Microsoft adds them to Windows Server 2019 and newer only. On this server the Restrict NTLM audit below is the only record of NTLM use: turn it on.'
        } else {
            Row 'WARN' 'NTLM' 'Enhanced NTLM events 4020 to 4023' ('not available on build ' + $os.BuildNumber) 'Windows Server 2019 and 2022 get them with the October 2026 updates, Windows Server 2025 has them. On Server 2016 use the Restrict NTLM audit settings below.' 'Install the latest cumulative update.'
        }
    }
    $rows += Check 'NTLM' 'Log NTLM Operational' { Log 'NTLM' 'Microsoft-Windows-NTLM/Operational' 'Holds the NTLM events. Its default size of 1 MB fills up fast on busy servers.' }

    $rows += Check 'NTLM' 'Audit incoming NTLM' {
        $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic'
        $why = 'Event 8003 (NTLM Operational) for every incoming NTLM sign-in.'
        $fix = 'Group Policy: Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all accounts'
        if ($v -eq 2) { Row 'OK' 'NTLM' 'Restrict NTLM: audit incoming' 'all accounts' $why }
        elseif ($ntlmEnhanced) { Row 'INFO' 'NTLM' 'Restrict NTLM: audit incoming' ((Value $v) + ', optional') ($why + ' Optional here: the enhanced events cover it.') $fix }
        else { Row 'MISSING' 'NTLM' 'Restrict NTLM: audit incoming' (Value $v) $why $fix }
    }
    $rows += Check 'NTLM' 'Audit outgoing NTLM' {
        $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic'
        $why = 'Event 8001 (NTLM Operational) for every outgoing NTLM sign-in.'
        $fix = 'Group Policy: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Audit all'
        if ($v -eq 1) { Row 'OK' 'NTLM' 'Restrict NTLM: audit outgoing' 'audit all' $why }
        elseif ($v -eq 2) { Row 'INFO' 'NTLM' 'Restrict NTLM: audit outgoing' 'deny all: outgoing NTLM is already blocked (events 4001)' $why }
        elseif ($ntlmEnhanced) { Row 'INFO' 'NTLM' 'Restrict NTLM: audit outgoing' ((Value $v) + ', optional') ($why + ' Optional here: the enhanced events cover it.') $fix }
        else { Row 'MISSING' 'NTLM' 'Restrict NTLM: audit outgoing' (Value $v) $why $fix }
    }

    $rows += Check 'SMB' 'SMBv1' {
        # The SmbShare module, or the same two settings in the registry where the module cannot be loaded.
        $smb1 = $null
        $auditSmb1 = $null
        try {
            $smb = Get-SmbServerConfiguration -ErrorAction Stop
            $smb1 = [bool]$smb.EnableSMB1Protocol
            $prop = $smb.PSObject.Properties['AuditSmb1Access']
            if ($prop) { $auditSmb1 = [bool]$prop.Value }
        } catch {
            $parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            # SMB1 serves only when its driver (service srv) is installed and not disabled, and SMB1 is not set to 0.
            $driver = 'HKLM:\SYSTEM\CurrentControlSet\Services\srv'
            $smb1 = (Test-Path -LiteralPath $driver) -and ((Reg $driver 'Start') -ne 4) -and ((Reg $parameters 'SMB1') -ne 0)
            $value = Reg $parameters 'AuditSmb1Access'
            if ($null -ne $value) { $auditSmb1 = $value -eq 1 } else { $auditSmb1 = $false }
        }
        if (-not $smb1) {
            Row 'OK' 'SMB' 'SMBv1 server' 'SMB1 is turned off, no client can connect with it' 'Nothing to audit.'
        } else {
            if ($null -eq $auditSmb1) { Row 'WARN' 'SMB' 'Audit SMBv1 access' 'this Windows version has no AuditSmb1Access setting' 'Event 3000 shows each client that connects with SMBv1.' 'Install the latest cumulative update.' }
            elseif ($auditSmb1) { Row 'OK' 'SMB' 'Audit SMBv1 access' 'on' 'Event 3000 shows each client that connects with SMBv1.' }
            else { Row 'MISSING' 'SMB' 'Audit SMBv1 access' 'off, while SMB1 is on' 'Event 3000 shows each client that connects with SMBv1.' 'Set-SmbServerConfiguration -AuditSmb1Access $true -Force' }
            Log 'SMB' 'Microsoft-Windows-SMBServer/Audit' 'Holds the SMBv1 events 3000. Its default size of 1 MB is small.'
        }
    }

    # ---------------- Domain controllers ----------------
    if ($isDc) {
        $rows += Check 'Kerberos' 'Audit Kerberos Authentication Service' { Audit 'Kerberos' 'Kerberos Authentication Service' '0CCE9242-69AE-11D9-BED3-505054503030' 3 'Events 4768 (TGTs: RC4, DES, accounts without pre-authentication) and 4771 (failures with 0xE).' }
        $rows += Check 'Kerberos' 'Audit Kerberos Service Ticket Operations' { Audit 'Kerberos' 'Kerberos Service Ticket Operations' '0CCE9240-69AE-11D9-BED3-505054503030' 3 'Events 4769 and 4770 (service tickets with RC4 or DES, failures with 0xE).' }
        $rows += Check 'NTLM' 'Audit Credential Validation' { Audit 'NTLM' 'Credential Validation' '0CCE923F-69AE-11D9-BED3-505054503030' 1 'Event 4776 shows every NTLM sign-in the domain controller checks.' }

        $rows += Check 'Kerberos' 'KdcExtraLogLevel' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'KdcExtraLogLevel'
            $current = if ($null -eq $v) { '0x2 (not set, default)' } else { '0x{0:x}' -f [int]$v }
            if ($null -eq $v) { $v = 2 }
            $why = 'Flag 0x10 logs 4769 failures with status 0xE (no common encryption type): the requests that break when RC4 or DES is turned off.'
            if ([int]$v -band 0x10) { Row 'OK' 'Kerberos' 'KdcExtraLogLevel 0x10' $current $why }
            else { Row 'WARN' 'Kerberos' 'KdcExtraLogLevel 0x10' $current $why ("Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name KdcExtraLogLevel -Type DWord -Value " + ('0x{0:x}' -f ([int]$v -bor 0x10))) }
        }
        $rows += Check 'Kerberos' 'KDC RC4 warnings' {
            if ((HasEvent 'Microsoft-Windows-Kerberos-Key-Distribution-Center' 201) -or (HasEvent 'KDCSVC' 201)) {
                Row 'OK' 'Kerberos' 'KDC RC4 warning events 201 to 209' 'available' 'Logged by the 2026 updates for the RC4 phase-out (CVE-2026-20833).'
            } else {
                Row 'INFO' 'Kerberos' 'KDC RC4 warning events 201 to 209' 'not found in the event provider' 'Logged by the 2026 updates for the RC4 phase-out (CVE-2026-20833).' 'Install the latest cumulative update.'
            }
        }
        $rows += Check 'Kerberos' 'DefaultDomainSupportedEncTypes' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'DefaultDomainSupportedEncTypes'
            if ($null -eq $v) {
                $current = 'not set (Windows default: AES only since the April 2026 updates)'
            } else {
                # The bits of msDS-SupportedEncryptionTypes.
                $types = @()
                if ([int]$v -band 0x1) { $types += 'DES-CBC-CRC' }
                if ([int]$v -band 0x2) { $types += 'DES-CBC-MD5' }
                if ([int]$v -band 0x4) { $types += 'RC4' }
                if ([int]$v -band 0x8) { $types += 'AES128' }
                if ([int]$v -band 0x10) { $types += 'AES256' }
                if ([int]$v -band 0x20) { $types += 'AES session keys' }
                $verdict = if (([int]$v -band 0x4) -and ([int]$v -band 0x3)) { 'allows RC4 and DES' }
                    elseif ([int]$v -band 0x4) { 'allows RC4' }
                    elseif ([int]$v -band 0x3) { 'allows DES' }
                    else { 'AES only' }
                $current = ('0x{0:x}' -f [int]$v) + ' = ' + ($types -join ', ') + ': ' + $verdict
            }
            Row 'INFO' 'Kerberos' 'DefaultDomainSupportedEncTypes' $current 'Encryption types the domain controller assumes for accounts without msDS-SupportedEncryptionTypes. Event 205 is logged while it allows more than AES. Keep it the same on every domain controller, or the same account gets other encryption depending on which one answers.'
        }
        $rows += Check 'Netlogon' 'Enhanced domain NTLM events' {
            $domainAudit = (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain') -eq 7
            if (HasEvent 'Microsoft-Windows-Security-Netlogon' 4030) {
                Row 'OK' 'NTLM' 'Domain controller NTLM events 4030 to 4033' 'available on this build' 'On by default, unless Group Policy turns off "Log Enhanced Domain-wide NTLM Logs" (Administrative Templates > System > Netlogon).'
            } elseif ($is2016 -and $domainAudit) {
                Row 'INFO' 'NTLM' 'Domain controller NTLM events 4030 to 4033' 'not available on Windows Server 2016' 'Microsoft adds them to Windows Server 2019 and newer only. Here the audit of NTLM in this domain below (event 8004) and event 4776 record NTLM use, and that is on.'
            } elseif ($is2016) {
                Row 'WARN' 'NTLM' 'Domain controller NTLM events 4030 to 4033' 'not available on Windows Server 2016' 'Microsoft adds them to Windows Server 2019 and newer only. On this domain controller turn on the audit of NTLM in this domain below (event 8004), next to event 4776.'
            } else {
                Row 'WARN' 'NTLM' 'Domain controller NTLM events 4030 to 4033' ('not available on build ' + $os.BuildNumber) 'Server 2019 and 2022 get them with the October 2026 updates. Without them, use Audit NTLM authentication in this domain below and event 4776.' 'Install the latest cumulative update.'
            }
        }
        $rows += Check 'NTLM' 'Audit NTLM in this domain' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain'
            $why = 'Event 8004 (NTLM Operational) for every NTLM sign-in this domain controller checks.'
            $fix = 'Group Policy: Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all'
            if ($v -eq 7) { Row 'OK' 'NTLM' 'Restrict NTLM: audit in this domain' 'enable all' $why }
            elseif (HasEvent 'Microsoft-Windows-Security-Netlogon' 4030) { Row 'INFO' 'NTLM' 'Restrict NTLM: audit in this domain' ((Value $v) + ', optional') ($why + ' Optional here: the enhanced events cover it.') $fix }
            else { Row 'MISSING' 'NTLM' 'Restrict NTLM: audit in this domain' (Value $v) $why $fix }
        }

        $rows += Check 'LDAP' 'LDAP Interface Events' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' '16 LDAP Interface Events'
            $why = 'Level 2 makes event 2889 name every client with an unsigned LDAP bind, and allows events 3039, 3074 and 3075. Without it there are only the daily counts 2887, 2888 and 3040.'
            if ($null -ne $v -and [int]$v -ge 2) { Row 'OK' 'LDAP' '16 LDAP Interface Events' ([string]$v) $why }
            else { Row 'MISSING' 'LDAP' '16 LDAP Interface Events' (Value $v) $why "Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -Type DWord -Value 2" }
        }
        $rows += Check 'LDAP' 'LDAP channel binding' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
            $names = @{ 0 = 'Never'; 1 = 'When supported'; 2 = 'Always' }
            $current = if ($null -eq $v) { 'not set (Never)' } elseif ($names.ContainsKey([int]$v)) { $names[[int]$v] } else { 'value ' + $v }
            $why = 'Events 3039, 3074 and 3075 (LDAPS clients without channel binding) are only logged with When supported or Always (Microsoft KB4520412). With Never there is only the daily count 3040.'
            if ($null -ne $v -and [int]$v -ge 1) { Row 'OK' 'LDAP' 'LDAP channel binding policy' $current $why }
            else { Row 'WARN' 'LDAP' 'LDAP channel binding policy' $current ($why + ' When supported is Microsoft''s recommended first step, but it is a change on the domain controller: test it first.') 'Group Policy: Domain controller: LDAP server channel binding token requirements = When supported' }
        }
        $rows += Check 'LDAP' 'LDAP signing' {
            $v = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
            $current = if ($null -eq $v) { 'not set' } elseif ([int]$v -ge 2) { 'require signing' } else { 'none (unsigned binds allowed)' }
            Row 'INFO' 'LDAP' 'LDAP server signing requirement' $current 'With signing required, unsigned binds are rejected and counted in event 2888.'
        }
        $rows += Check 'LDAP' 'Log Directory Service' { Log 'LDAP' 'Directory Service' 'Holds the LDAP signing and channel binding events.' }
    }

    # ---------------- Output ----------------
    $role = if ($isDc) { 'domain controller' } elseif ($cs.DomainRole -ge 2) { 'server' } else { 'workstation' }
    Write-Host ''
    Write-Host 'Legacy Auth Finder {{VERSION}}: logging check' -ForegroundColor White
    Write-Host ($env:COMPUTERNAME + ' | ' + $os.Caption + ' (build ' + $os.BuildNumber + ') | ' + $role + ' | elevated: ' + $elevated)
    if (-not $elevated) { Write-Host 'Not elevated: the audit policy and the Security log cannot be read. Run PowerShell as administrator for the full check.' -ForegroundColor Yellow }
    Write-Host ''
    $colors = @{ OK = 'Green'; MISSING = 'Red'; WARN = 'Yellow'; UNKNOWN = 'Magenta'; INFO = 'Gray' }
    foreach ($r in $rows) {
        Write-Host ('[{0,-7}] ' -f $r.Status) -ForegroundColor $colors[$r.Status] -NoNewline
        Write-Host ('{0}: {1}' -f $r.Check, $r.Current)
        if ($r.Status -ne 'OK' -and $r.Why) { Write-Host ('          ' + $r.Why) -ForegroundColor DarkGray }
        if ($r.Status -ne 'OK' -and $r.Fix) { Write-Host ('          Fix: ' + $r.Fix) -ForegroundColor Cyan }
    }
    $missing = @($rows | Where-Object { $_.Status -eq 'MISSING' }).Count
    $warn = @($rows | Where-Object { $_.Status -eq 'WARN' }).Count
    $unknown = @($rows | Where-Object { $_.Status -eq 'UNKNOWN' }).Count
    Write-Host ''
    if ($missing -eq 0 -and $warn -eq 0 -and $unknown -eq 0) {
        Write-Host 'Everything Legacy Auth Finder needs is logged on this server.' -ForegroundColor Green
    } else {
        Write-Host ('{0} missing, {1} warnings, {2} not readable.' -f $missing, $warn, $unknown) -ForegroundColor Yellow
        Write-Host 'Nothing was changed. Review the Fix lines and apply them, best through Group Policy so every server gets the same settings.'
    }
    if (-not $isDc) { Write-Host 'Run this check on the domain controllers too: the Kerberos, LDAP and domain NTLM events are logged there.' -ForegroundColor DarkGray }
}
