#!/bin/bash
# =============================================================================
# linux-korek.sh - linPEAS Gap Filler v2
# Covers what linPEAS misses based on HackTricks methodology
# Run AFTER linpeas.sh for complete Linux privesc coverage
# Author: korek
# =============================================================================
# Usage:
#   chmod +x linux-korek.sh && ./linux-korek.sh
#   ./linux-korek.sh | tee korek_out.txt
#   ./linux-korek.sh --quick   (skip slow sections)
# =============================================================================

QUICK=0
[ "$1" = "--quick" ] && QUICK=1

R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
C='\033[0;36m'
W='\033[1;37m'
N='\033[0m'

hit()  { echo -e "${G}[+]${N} $1"; }
info() { echo -e "    ${W}>>>${N} $1"; }
sec()  { echo -e "\n${C}[*] ========== $1 ==========${N}"; }
warn() { echo -e "${Y}[!]${N} $1"; }
hot()  { echo -e "${R}[!!]${N} $1"; }

echo -e "${C}============================================================${N}"
echo -e "${C}  linux-korek.sh v2 - linPEAS Gap Filler${N}"
echo -e "${C}  Based on HackTricks Linux Privesc Checklist${N}"
echo -e "${C}  Run AFTER linpeas for complete coverage${N}"
echo -e "${C}  $(date)${N}"
echo -e "${C}============================================================${N}"

# ==========================================================================
# 1. Sudo token hijacking (HackTricks - often missed)
# ==========================================================================
sec "SUDO TOKEN HIJACKING"
# Check if any user recently used sudo (token still valid for 15 min)
if [ -d /proc ]; then
    for pid in /proc/[0-9]*/status; do
        puid=$(grep "^Uid:" "$pid" 2>/dev/null | awk '{print $2}')
        if [ "$puid" = "0" ]; then
            cmdline=$(cat "${pid%status}cmdline" 2>/dev/null | tr '\0' ' ')
            if echo "$cmdline" | grep -q "sudo"; then
                hot "Root sudo process found: $cmdline"
                info "Token hijack may be possible via ptrace"
            fi
        fi
    done
fi

# sudoedit CVE-2023-22809 check
sudo_ver=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')
if [ -n "$sudo_ver" ]; then
    info "Sudo version: $sudo_ver"
    # vulnerable if < 1.9.12p2
    echo "$sudo_ver" | grep -qE "^1\.[0-8]\.|^1\.9\.(0|1|2|3|4|5|6|7|8|9|10|11|12p1)" && \
        hot "Sudo $sudo_ver may be vulnerable to CVE-2023-22809 (sudoedit bypass)!"
fi

# ==========================================================================
# 2. Shell history - credential grep
# ==========================================================================
sec "SHELL HISTORY CREDENTIAL GREP"
for histfile in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.history \
                /home/*/.bash_history /home/*/.zsh_history /root/.bash_history; do
    [ -f "$histfile" ] 2>/dev/null || continue
    hits=$(grep -iE "(pass|passwd|password|pwd|secret|key|token|api|credential|curl.*-u|mysql.*-p|psql.*-U|sshpass|-p )" \
           "$histfile" 2>/dev/null | grep -v "^#")
    if [ -n "$hits" ]; then
        hit "History creds in: $histfile"
        echo "$hits" | head -20 | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 3. Process monitoring - poor man's pspy (HackTricks technique)
# ==========================================================================
sec "PROCESS MONITORING - 60 seconds (poor man's pspy)"
echo "Monitoring for new processes... watch for UID=0"
declare -A seen
while IFS= read -r line; do seen["$line"]=1; done < \
    <(ps -eo pid,user,cmd --no-headers 2>/dev/null)

end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
    while IFS= read -r line; do
        if [ -z "${seen[$line]+_}" ]; then
            user=$(echo "$line" | awk '{print $2}')
            cmd=$(echo "$line" | cut -d' ' -f3-)
            pid=$(echo "$line" | awk '{print $1}')
            if [ "$user" = "root" ] || [ "$user" = "0" ]; then
                hot "NEW ROOT PROCESS [PID:$pid]: $cmd"
            else
                hit "New process [$user PID:$pid]: $cmd"
            fi
            seen["$line"]=1
        fi
    done < <(ps -eo pid,user,cmd --no-headers 2>/dev/null)
    sleep 0.5
done

# ==========================================================================
# 4. Cron jobs - deep check including systemd timers
# ==========================================================================
sec "CRON JOBS & SYSTEMD TIMERS"

# all crontab locations
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* \
          /var/spool/cron/* /etc/anacrontab; do
    [ -f "$f" ] 2>/dev/null || continue
    hit "Crontab: $f"
    cat "$f" 2>/dev/null | grep -v "^#\|^$" | while read line; do
        info "$line"
        # check if binary in cron entry is writable
        for word in $line; do
            if [ -f "$word" ] && [ -w "$word" ]; then
                hot "WRITABLE CRON BINARY: $word"
            fi
        done
    done
done

# systemd timers
echo -e "\n${Y}--- Systemd Timers ---${N}"
systemctl list-timers --all 2>/dev/null | grep -v "^$\|NEXT\|listed" | \
while read line; do info "$line"; done

# writable service files
echo -e "\n${Y}--- Writable Systemd Service Files ---${N}"
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -writable 2>/dev/null | \
while read f; do
    hot "Writable service file: $f"
    grep -E "^Exec" "$f" 2>/dev/null | while read line; do info "$line"; done
done

# ==========================================================================
# 5. Writable PATH directories and binaries
# ==========================================================================
sec "WRITABLE PATH DIRECTORIES & BINARIES"
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" ] 2>/dev/null; then
        hot "WRITABLE PATH directory: $dir - PATH hijacking possible!"
    fi
    find "$dir" -writable -type f 2>/dev/null | while read f; do
        hot "Writable binary in PATH: $f"
    done
done

# ==========================================================================
# 6. Root-owned writable files (key privesc - this box's intended path)
# ==========================================================================
sec "ROOT-OWNED FILES WRITABLE BY CURRENT USER"
find / -user root -writable -type f 2>/dev/null | \
grep -vE "(/proc|/sys|/dev|/tmp|/var/tmp|linux-korek|/run)" | \
while read f; do
    hot "Root-owned writable: $f"
    ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
done

# ==========================================================================
# 7. Custom SUID/SGID binaries not in package manager
# ==========================================================================
sec "CUSTOM SUID/SGID BINARIES"
find / -perm -4000 -o -perm -2000 2>/dev/null | while read f; do
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$f" >/dev/null 2>&1 && continue
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qf "$f" >/dev/null 2>&1 && continue
    fi
    hot "Custom SUID/SGID: $f"
    ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
    [ -w "$f" ] && hot "AND WRITABLE - instant root!"
done

# ==========================================================================
# 8. Capabilities - dangerous ones
# ==========================================================================
sec "DANGEROUS CAPABILITIES"
getcap -r / 2>/dev/null | grep -vE "(ping|mtr-packet)" | \
grep -E "(cap_setuid|cap_net_raw|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_chown|cap_fowner|cap_sys_rawio)" | \
while read line; do
    hot "Dangerous capability: $line"
    bin=$(echo "$line" | awk '{print $1}')
    info "Check GTFOBins: https://gtfobins.github.io/#+$(basename $bin)"
done

# ==========================================================================
# 9. NFS no_root_squash
# ==========================================================================
sec "NFS NO_ROOT_SQUASH"
if [ -r /etc/exports ] 2>/dev/null; then
    grep "no_root_squash" /etc/exports 2>/dev/null | while read line; do
        hot "NFS no_root_squash: $line"
        info "Mount remotely, copy /bin/bash with SUID, get root"
    done
fi
showmount -e localhost 2>/dev/null | grep -v "^Export" | while read line; do
    hit "NFS export: $line"
done

# ==========================================================================
# 10. SAM/SYSTEM backup files (windows.old equivalent on Linux)
# ==========================================================================
sec "SENSITIVE BACKUP FILES"
for p in \
    /etc/shadow- /etc/shadow.bak /etc/passwd- /etc/passwd.bak \
    /var/shadow /backup/shadow /etc/shadow.old; do
    [ -r "$p" ] 2>/dev/null && hot "Readable shadow backup: $p" && cat "$p" 2>/dev/null | head -5
done

# RegBack equivalent - config backups
find / -maxdepth 6 \( \
    -name "*.bak" -o -name "*.old" -o -name "*.backup" -o \
    -name "*.orig" -o -name "*.save" -o -name "*.swp" \
\) -readable -type f 2>/dev/null | \
grep -iE "(pass|secret|shadow|key|config|auth|cred)" | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    hit "Sensitive backup: $f"
    grep -iE "(pass|password|secret|key|token)" "$f" 2>/dev/null | head -3 | \
        while read line; do info "$line"; done
done

# ==========================================================================
# 11. Archive/database files (unusual - likely put there intentionally)
# ==========================================================================
sec "UNUSUAL FILES (Archives & DB dumps)"

# Archives
find / -maxdepth 8 \( \
    -name "*.zip" -o -name "*.tar.gz" -o -name "*.tgz" -o \
    -name "*.tar" -o -name "*.7z" -o -name "*.rar" -o -name "*.gz" \
\) -readable -type f 2>/dev/null | \
grep -vE "(/usr/share/doc|/usr/share/man|/usr/lib|/snap|/proc|linux-korek)" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hot "Archive: $f ($size) - examine contents!"
    case "$f" in
        *.zip) zipinfo -1 "$f" 2>/dev/null | grep -iE "(pass|config|shadow|\.sql|\.conf|\.php|\.key|\.pem)" | \
               head -5 | while read l; do info "  contains: $l"; done ;;
        *.tar*|*.tgz) tar -tf "$f" 2>/dev/null | grep -iE "(pass|config|shadow|\.sql|\.conf|\.php|\.key)" | \
                      head -5 | while read l; do info "  contains: $l"; done ;;
    esac
done

# DB dumps
find / -maxdepth 8 \( \
    -name "*.sql" -o -name "*.dump" -o -name "*.sqlite" -o \
    -name "*.sqlite3" -o -name "*.db" \
\) -readable -type f 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hot "DB file: $f ($size)"
    grep -iE "(INSERT.*pass|password.*=|CREATE USER)" "$f" 2>/dev/null | head -3 | \
        while read line; do info "$line"; done
done

# Files in /opt /srv /backup /data
for sysdir in /opt /srv /backup /data /var/backup /mnt /media; do
    [ -d "$sysdir" ] 2>/dev/null || continue
    files=$(find "$sysdir" -type f -readable 2>/dev/null | grep -v "linux-korek")
    if [ -n "$files" ]; then
        hit "Files in $sysdir:"
        echo "$files" | while read f; do
            size=$(du -sh "$f" 2>/dev/null | cut -f1)
            info "$f ($size)"
        done
    fi
done

# ==========================================================================
# 12. CMS config files (Joomla, WordPress, etc.)
# ==========================================================================
sec "CMS CONFIG FILES"
for f in \
    /var/www/html/configuration.php \
    /var/www/html/cms/configuration.php \
    /var/www/*/configuration.php \
    /var/www/html/wp-config.php \
    /var/www/*/wp-config.php \
    /srv/*/configuration.php \
    /srv/*/wp-config.php \
    /var/www/html/config/config.php \
    /var/www/html/*/config.php; do
    [ -f "$f" ] 2>/dev/null || continue
    hot "CMS config: $f"
    grep -iE "(\\\$db|\\\$user|\\\$pass|password|secret|host|DB_)" "$f" 2>/dev/null | \
        grep -v "^//\|^#\|^/*" | head -10 | while read line; do info "$line"; done
done

# ==========================================================================
# 13. Database credentials
# ==========================================================================
sec "DATABASE CREDENTIALS"
for f in ~/.my.cnf ~/.pgpass /etc/mysql/debian.cnf \
          /root/.my.cnf /home/*/.my.cnf /etc/mysql/my.cnf; do
    [ -f "$f" ] 2>/dev/null && [ -r "$f" ] || continue
    hit "DB config: $f"
    grep -iE "(pass|user|host)" "$f" 2>/dev/null | grep -v "^#" | \
        while read line; do info "$line"; done
done

# ==========================================================================
# 14. SSH private keys everywhere
# ==========================================================================
sec "SSH PRIVATE KEYS"
find / -maxdepth 8 \( \
    -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o \
    -name "id_ed25519" -o -name "*.pem" -o -name "*.ppk" \
\) -readable -type f 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    head -1 "$f" 2>/dev/null | grep -q "PRIVATE" || continue
    hot "SSH Private Key: $f"
    ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
done

# authorized_keys
find / -name "authorized_keys" -readable 2>/dev/null | while read f; do
    hit "authorized_keys: $f"
    cat "$f" 2>/dev/null | while read line; do info "$line"; done
done

# ==========================================================================
# 15. Installed software version check (exploitable services)
# ==========================================================================
sec "INSTALLED SOFTWARE VERSIONS (check for CVEs)"
# common services to check
for svc in apache2 nginx mysql postgresql php python3 ruby perl gcc make; do
    ver=$($svc --version 2>/dev/null | head -1)
    [ -n "$ver" ] && info "$svc: $ver"
done

# check for interesting installed packages
dpkg -l 2>/dev/null | grep -iE "(nmap|gcc|python|perl|ruby|php|mysql|postgres|docker|lxc|snap)" | \
    awk '{print $2, $3}' | while read line; do info "$line"; done

# ==========================================================================
# 16. Docker / LXC / Container checks
# ==========================================================================
sec "CONTAINER ESCAPE CHECKS"

# Docker socket
[ -w /var/run/docker.sock ] 2>/dev/null && \
    hot "DOCKER SOCKET WRITABLE! docker run -v /:/mnt --rm -it alpine chroot /mnt sh"

# In Docker?
[ -f /.dockerenv ] && warn "Running inside Docker container"

# Docker group
id | grep -q docker && hot "User in docker group! docker run -v /:/mnt --rm -it alpine chroot /mnt sh"

# LXC/LXD group
id | grep -q lxd && hot "User in lxd group! LXD privilege escalation possible"
id | grep -q lxc && hot "User in lxc group!"

# cgroup check
grep -qE "docker|lxc|kubepods" /proc/1/cgroup 2>/dev/null && warn "Container detected via cgroup"

# privileged container
if [ -f /.dockerenv ]; then
    cap=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')
    [ "$cap" = "0000003fffffffff" ] && hot "PRIVILEGED DOCKER CONTAINER!"
fi

# ==========================================================================
# 17. Writable cron directories
# ==========================================================================
sec "WRITABLE CRON DIRECTORIES"
for cronpath in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    [ -w "$cronpath" ] 2>/dev/null && hot "WRITABLE cron dir: $cronpath"
done

# ==========================================================================
# 18. Tmux / Screen sessions (lateral movement)
# ==========================================================================
sec "TMUX / SCREEN SESSIONS"
tmux list-sessions 2>/dev/null | while read line; do hit "tmux: $line"; done
find /tmp -name "tmux-*" 2>/dev/null | while read f; do
    hit "tmux socket: $f ($(stat -c '%U %G %a' $f 2>/dev/null))"
done
screen -list 2>/dev/null | grep -v "^$\|Socket\|There\|No " | while read line; do
    hit "screen: $line"
done

# ==========================================================================
# 19. Environment variables with credentials
# ==========================================================================
sec "ENVIRONMENT VARIABLES"
env 2>/dev/null | grep -iE "(pass|secret|key|token|api|cred|aws|azure)" | \
    while read line; do hot "Env var with creds: $line"; done

# check /proc/*/environ for other processes
for f in /proc/*/environ; do
    [ -r "$f" ] 2>/dev/null || continue
    hits=$(cat "$f" 2>/dev/null | tr '\0' '\n' | grep -iE "(pass|secret|key|token|api)")
    [ -n "$hits" ] && hit "Env in $f:" && echo "$hits" | while read l; do info "$l"; done
done

# ==========================================================================
# 20. Exploits in home directories / scripts
# ==========================================================================
sec "SCRIPTS & EXECUTABLES IN HOME DIRS"
find /home /root -maxdepth 4 \( \
    -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o \
    -perm /111 \
\) -readable -type f 2>/dev/null | grep -v "linux-korek" | \
while read f; do
    hit "Script: $f"
    # check for credentials inside
    hits=$(grep -iE "(pass|secret|key|token|user)" "$f" 2>/dev/null | grep -v "^#" | head -3)
    [ -n "$hits" ] && echo "$hits" | while read line; do info "$line"; done
done

# ==========================================================================
# 21. Writable /etc/passwd (add root user directly)
# ==========================================================================
sec "WRITABLE SENSITIVE SYSTEM FILES"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/hosts \
         /etc/ssh/sshd_config /etc/crontab; do
    [ -w "$f" ] 2>/dev/null && hot "WRITABLE: $f"
done

# ==========================================================================
# 22. Mail / Inbox files
# ==========================================================================
sec "MAIL FILES"
for maildir in /var/mail /var/spool/mail /home/*/.mail /root/mail; do
    find "$maildir" -readable -type f 2>/dev/null | while read f; do
        size=$(stat -c%s "$f" 2>/dev/null)
        [ "$size" -gt 0 ] 2>/dev/null || continue
        hit "Mail: $f ($size bytes)"
        grep -iE "(pass|secret|key|cred)" "$f" 2>/dev/null | head -3 | \
            while read line; do info "$line"; done
    done
done

# ==========================================================================
# 23. Readable /etc/shadow or backups
# ==========================================================================
sec "SHADOW FILE ACCESS"
[ -r /etc/shadow ] 2>/dev/null && \
    hot "READABLE /etc/shadow!" && \
    cat /etc/shadow | grep -v "^[^:]*:[!*]" | head -20

# ==========================================================================
# 24. Interesting files in home dirs (flags, notes, creds)
# ==========================================================================
sec "INTERESTING FILES IN HOME DIRECTORIES"
find /home /root -maxdepth 4 \( \
    -name "*.txt" -o -name "note*" -o -name "todo*" -o \
    -name "flag*" -o -name "proof*" -o -name "local*" -o \
    -name "secret*" -o -name "cred*" -o -name "pass*" -o \
    -name "*.kdbx" -o -name ".netrc" \
\) -readable 2>/dev/null | while read f; do
    hit "Interesting: $f"
    file "$f" 2>/dev/null | grep -v "directory" | while read line; do info "$line"; done
done

# ==========================================================================
# 25. Sticky Notes / Browser saved passwords
# ==========================================================================
sec "BROWSER & NOTES DATA"
find /home /root -maxdepth 8 \( \
    -name "plum.sqlite" -o \
    -name "Login Data" -o \
    -name "key4.db" -o \
    -name "logins.json" \
\) -readable 2>/dev/null | while read f; do
    hit "Browser/notes data: $f"
done

# ==========================================================================
# 26. App config files with credentials
# ==========================================================================
sec "APP CONFIG FILES WITH CREDENTIALS"
find /var/www /srv /opt /home -maxdepth 6 \( \
    -name "conn.php" -o -name "config.php" -o -name "web.config" -o \
    -name "wp-config.php" -o -name ".env" -o -name "database.yml" -o \
    -name "appsettings.json" -o -name "tomcat-users.xml" -o \
    -name "settings.py" -o -name "local_settings.py" -o \
    -name "secrets.py" -o -name ".netrc" -o -name ".boto" -o \
    -name "*.s3cfg" \
\) -readable 2>/dev/null | while read f; do
    hits=$(grep -iE "(password|passwd|secret|api_key|token|credential)" \
           "$f" 2>/dev/null | grep -v "^#\|^//\|example\|placeholder" | head -5)
    [ -n "$hits" ] && hot "Creds in: $f" && echo "$hits" | while read line; do info "$line"; done
done

# ==========================================================================
# 27. Local users & empty passwords
# ==========================================================================
sec "LOCAL USERS"
awk -F: '$3 >= 1000 || $3 == 0 {print $1" uid:"$3" shell:"$7}' /etc/passwd | \
    while read line; do info "$line"; done

# check for empty passwords in shadow
while IFS=: read -r user pass rest; do
    [ -z "$pass" ] || [ "$pass" = "" ] && warn "Empty password: $user"
done < /etc/shadow 2>/dev/null

echo -e "\n${G}[+] linux-korek.sh v2 complete!${N}"
echo -e "${R}Review [!!] items first, then ${Y}[!] warnings${N}, then ${G}[+] hits${N}"
