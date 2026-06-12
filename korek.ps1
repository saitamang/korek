# =============================================================================
# Invoke-Korek.ps1 - winPEAS gap filler
# Covers what winPEAS misses - run AFTER winPEAS
# =============================================================================
# Usage:
#   . .\Invoke-Korek.ps1; Invoke-Korek
#   Invoke-Korek -OutputFile C:\Windows\Tasks\recon.txt
# =============================================================================

function Invoke-Korek {
    param([string]$OutputFile = "")

    $out = [System.Collections.ArrayList]@()
    function Log  { param([string]$m,[string]$c="White") ; Write-Host $m -ForegroundColor $c ; if($OutputFile){$out.Add($m)|Out-Null} }
    function Hit  { param([string]$m) ; Log "[+] $m" "Green" }
    function Info { param([string]$m) ; Log "    $m" "Gray" }
    function Sec  { param([string]$m) ; Log "`n[*] === $m ===" "Cyan" }

    function Get-File {
        param([string]$p)
        try { if(Test-Path $p -EA Stop){ $f=Get-Item $p -EA Stop; if($f.Length -gt 0 -and -not $f.PSIsContainer){return $f} } } catch{}
        return $null
    }
    function Get-Content-Safe {
        param([string]$p,[int]$n=30)
        try { return Get-Content $p -EA Stop -TotalCount $n } catch { return $null }
    }
    function Get-Reg {
        param([string]$p,[string]$k)
        try { $v=Get-ItemProperty $p -Name $k -EA Stop; return $v.$k } catch { return $null }
    }

    Log "============================================================" "Cyan"
    Log "  Invoke-Korek - Korek - Custom Recon Tool" "Cyan"
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
        $f = Get-File $_
        if($f){ Hit "$_ ($($f.Length) bytes) - DOWNLOAD AND SECRETSDUMP!" }
    }

    # ------------------------------------------------------------------
    # 2. PowerShell history with credential grep
    # ------------------------------------------------------------------
    Sec "POWERSHELL HISTORY (credential grep)"
    try {
        Get-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } | ForEach-Object {
            Hit "History: $($_.FullName)"
            Get-Content-Safe $_.FullName 100 |
            Where-Object { $_ -match "pass|cred|secret|key|token|user|pwd" -and $_ -notmatch "^#" } |
            ForEach-Object { Info ">> $_" }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 3. PuTTY / WinSCP saved sessions
    # ------------------------------------------------------------------
    Sec "PUTTY / WINSCP SAVED SESSIONS"
    try {
        Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -EA SilentlyContinue | ForEach-Object {
            $h = Get-Reg $_.PSPath "HostName"
            $u = Get-Reg $_.PSPath "UserName"
            if($h){ Hit "PuTTY: $($_.PSChildName) -> $u@$h" }
        }
    } catch {}
    try {
        Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" -EA SilentlyContinue | ForEach-Object {
            $h = Get-Reg $_.PSPath "HostName"
            $u = Get-Reg $_.PSPath "UserName"
            $p = Get-Reg $_.PSPath "Password"
            if($h){ Hit "WinSCP: $($_.PSChildName) -> $u@$h Pass:$p" }
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
            if($key){ Hit "WiFi '$name': $($key.Matches.Groups[1].Value.Trim())" }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 5. SSH private keys
    # ------------------------------------------------------------------
    Sec "SSH PRIVATE KEYS"
    @("C:\Users\*\.ssh\*","C:\Users\*\Documents\*","C:\Users\*\Desktop\*","C:\ProgramData\*") | ForEach-Object {
        try {
            Get-Item $_ -EA SilentlyContinue | Where-Object {
                $_.Name -match "^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.pem$|\.ppk$" -and $_.Length -gt 0
            } | ForEach-Object {
                Hit "SSH Key: $($_.FullName)"
                $c = Get-Content-Safe $_.FullName 3
                if($c -match "PRIVATE"){ Info "  Contains PRIVATE KEY" }
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # 6. KeePass databases
    # ------------------------------------------------------------------
    Sec "KEEPASS / PASSWORD FILES"
    try {
        Get-ChildItem C:\ -Recurse -Depth 6 -EA SilentlyContinue |
        Where-Object { $_.Name -match "\.kdbx$|^pass.*\.txt$|^cred.*\.txt$|^password.*\.txt$" -and $_.Length -gt 0 } |
        ForEach-Object { Hit "Password file: $($_.FullName) ($($_.Length) bytes)" }
    } catch {}

    # ------------------------------------------------------------------
    # 7. Sticky Notes
    # ------------------------------------------------------------------
    Sec "STICKY NOTES"
    try {
        Get-Item "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite" -EA SilentlyContinue |
        Where-Object { $_.Length -gt 0 } |
        ForEach-Object { Hit "Sticky Notes DB: $($_.FullName) - copy and read with SQLite browser" }
    } catch {}

    # ------------------------------------------------------------------
    # 8. GPP passwords in SYSVOL
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
                    $c = Get-Content-Safe $_.FullName 50
                    if($c -match "cpassword"){
                        Hit "GPP cpassword in: $($_.FullName)"
                        $c | Where-Object { $_ -match "cpassword" } | ForEach-Object { Info ">> $_" }
                    }
                }
            }
        }
    } catch {}

    # ------------------------------------------------------------------
    # 9. App configs with credentials (wamp/xampp/inetpub specific)
    # ------------------------------------------------------------------
    Sec "APP CONFIG FILES WITH CREDENTIALS"
    @("C:\wamp","C:\wamp64","C:\xampp","C:\inetpub","C:\tomcat","C:\Users") | ForEach-Object {
        if(Test-Path $_ -EA SilentlyContinue){
            try {
                Get-ChildItem $_ -Recurse -Depth 5 -EA SilentlyContinue |
                Where-Object { $_.Name -match "conn\.php|config\.php|web\.config|wp-config\.php|\.env|database\.yml|appsettings\.json|tomcat-users\.xml" -and $_.Length -gt 0 } |
                ForEach-Object {
                    Hit "Config: $($_.FullName)"
                    Get-Content-Safe $_.FullName 30 |
                    Where-Object { $_ -match "pass|password|pwd|secret|credential|key|token|user" -and $_ -notmatch "^//" -and $_ -notmatch "^#" -and $_ -notmatch "^\s*<!--" } |
                    Select-Object -First 5 | ForEach-Object { Info "  >> $($_.Trim())" }
                }
            } catch {}
        }
    }

    # ------------------------------------------------------------------
    # 10. Services running as domain users (better output than winPEAS)
    # ------------------------------------------------------------------
    Sec "SERVICES RUNNING AS DOMAIN USERS"
    try {
        Get-WmiObject win32_service -EA SilentlyContinue |
        Where-Object {
            $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE" -and
            $_.StartName -ne $null -and $_.StartName -ne ""
        } | ForEach-Object {
            Hit "Service '$($_.Name)' runs as: $($_.StartName)"
            Info "Path: $($_.PathName)"
        }
    } catch {}

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if($OutputFile){
        try { $out | Out-File $OutputFile -Encoding UTF8 ; Hit "Saved to: $OutputFile" }
        catch { Log "[-] Could not save: $_" "Red" }
    }
    Log "`n[+] Done! Review GREEN items above." "Green"
}
