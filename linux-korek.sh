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

# Colors
R='\033[0;31m'   # Red
G='\033[0;32m'   # Green  
Y='\033[0;33m'   # Yellow
B='\033[0;34m'   # Blue
C='\033[0;36m'   # Cyan
W='\033[1;37m'   # White bold
N='\033[0m'      # Reset

hit()  { echo -e "${G}[+]${N} $1"; }
info() { echo -e "    ${W}>>>${N} $1"; }
sec()  { echo -e "\n${C}[*] ========== $1 ==========${N}"; }
warn() { echo -e "${Y}[!]${N} $1"; }

echo -e "${C}============================================================${N}"
echo -e "${C}  korek.sh - linPEAS Gap Filler${N}"
echo -e "${C}  Run this AFTER linpeas for complete coverage${N}"
echo -e "${C}  $(date)${N}"
echo -e "${C}============================================================${N}"

# ==========================================================================
# 1. Shell history - grep for credentials (linPEAS finds file, doesn't grep)
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
# 2. Backup and temp files with sensitive names
# ==========================================================================
sec "BACKUP / OLD / TEMP SENSITIVE FILES"
find / -maxdepth 8 \( \
    -name "*.bak" -o -name "*.old" -o -name "*.backup" -o \
    -name "*.orig" -o -name "*.save" -o -name "*.swp" -o \
    -name "*~" -o -name "*.tmp" \
\) -type f -readable 2>/dev/null | grep -iE "(pass|secret|cred|shadow|key|config|auth)" | while read f; do
    size=$(stat -c%s "$f" 2>/dev/null)
    hit "Backup file: $f ($size bytes)"
    grep -iE "(pass|password|secret|key|token|user)" "$f" 2>/dev/null | head -5 | while read line; do
        info "$line"
    done
done

# ==========================================================================
# 3. Database credential files
# ==========================================================================
sec "DATABASE CREDENTIAL FILES"
for f in ~/.my.cnf ~/.pgpass ~/.dbpass /etc/mysql/debian.cnf \
          /var/www/*/wp-config.php /var/www/*/*/wp-config.php \
          /var/www/*/config/database.php /var/www/*/application/config/database.php \
          /home/*/wp-config.php /srv/*/wp-config.php; do
    [ -f "$f" ] 2>/dev/null || continue
    hit "DB config: $f"
    grep -iE "(pass|password|db_|user|host)" "$f" 2>/dev/null | \
        grep -v "^#\|^//" | head -10 | while read line; do info "$line"; done
done

# Also search common web roots
find /var/www /srv /opt /home -maxdepth 6 -name "*.php" -readable 2>/dev/null | \
xargs grep -lE "(\\\$db_pass|\\\$password|\\\$dbpass|DB_PASSWORD)" 2>/dev/null | \
head -10 | while read f; do
    hit "PHP with DB creds: $f"
    grep -iE "(\\\$db_pass|\\\$password|\\\$dbpass|DB_PASSWORD|DB_USER|DB_HOST)" "$f" 2>/dev/null | \
        grep -v "^//" | head -5 | while read line; do info "$line"; done
done

# ==========================================================================
# 4. Config files with passwords
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

# Generic search for config files
find /etc /opt /var /home -maxdepth 5 -name "*.conf" -o -name "*.cfg" -o \
     -name "*.ini" -o -name "*.env" -o -name ".env" 2>/dev/null | \
     xargs grep -lE "(password|passwd|secret|api_key)" 2>/dev/null | \
     grep -v "linpeas\|korek" | head -15 | while read f; do
    hit "Config with creds: $f"
    grep -iE "(password|passwd|secret|api_key)" "$f" 2>/dev/null | \
        grep -v "^#\|^;" | head -3 | while read line; do info "$line"; done
done

# ==========================================================================
# 5. SSH keys in non-standard locations
# ==========================================================================
sec "SSH PRIVATE KEYS (ALL LOCATIONS)"
find / -maxdepth 8 -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o \
       -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | \
while read f; do
    [ -f "$f" ] 2>/dev/null || continue
    [ -r "$f" ] 2>/dev/null || continue
    if head -1 "$f" 2>/dev/null | grep -q "PRIVATE"; then
        hit "SSH Private Key: $f"
        ls -la "$f" 2>/dev/null | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 6. Recently modified files (last 10 minutes - useful post-exploit)
# ==========================================================================
sec "RECENTLY MODIFIED FILES (last 10 min)"
find / -maxdepth 6 -newer /tmp -type f -readable 2>/dev/null | \
grep -vE "(/proc/|/sys/|/dev/|linpeas|korek)" | head -20 | while read f; do
    hit "Recently modified: $f"
done

# ==========================================================================
# 7. Mail / inbox files
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
# 8. Writable cron directories and files
# ==========================================================================
sec "WRITABLE CRON PATHS"
for cronpath in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    if [ -w "$cronpath" ] 2>/dev/null; then
        warn "WRITABLE cron directory: $cronpath"
    fi
done

# Check writable cron files
find /etc/cron* /var/spool/cron -type f 2>/dev/null | while read f; do
    if [ -w "$f" ] 2>/dev/null; then
        warn "WRITABLE cron file: $f"
        cat "$f" 2>/dev/null | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 9. Tmux / Screen sessions (lateral movement)
# ==========================================================================
sec "TMUX / SCREEN SESSIONS"
# tmux
tmux list-sessions 2>/dev/null | while read line; do
    hit "tmux session: $line"
done

# Check for tmux sockets others own
find /tmp -name "tmux-*" 2>/dev/null | while read f; do
    hit "tmux socket: $f ($(ls -la $f 2>/dev/null | awk '{print $1,$3,$4}'))"
done

# screen
screen -list 2>/dev/null | grep -v "^$\|Sockets\|There is\|There are" | while read line; do
    hit "screen session: $line"
done

# ==========================================================================
# 10. Container escape checks
# ==========================================================================
sec "CONTAINER ESCAPE CHECKS"

# Docker socket
if [ -w /var/run/docker.sock ] 2>/dev/null; then
    warn "DOCKER SOCKET IS WRITABLE - container escape possible!"
    info "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
fi

# In a container?
if [ -f /.dockerenv ]; then
    warn "Running inside a Docker container"
    # Check for privileged
    if cat /proc/self/status 2>/dev/null | grep -q "CapEff.*0000003fffffffff\|CapEff.*ffff"; then
        warn "PRIVILEGED CONTAINER - escape possible!"
        info "mount /dev/sda1 /mnt && chroot /mnt"
    fi
fi

# Check cgroup for container indicators
if grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    warn "Container indicators found in cgroup"
fi

# ==========================================================================
# 11. Python / Ruby / Node credential files
# ==========================================================================
sec "APP CREDENTIAL FILES"
find /home /opt /var/www /srv -maxdepth 6 \( \
    -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o \
    -name "settings.py" -o -name "local_settings.py" -o \
    -name "secrets.py" -o -name "database.yml" -o \
    -name "credentials.yml" -o -name ".netrc" -o \
    -name "*.s3cfg" -o -name ".boto" \
\) -readable 2>/dev/null | while read f; do
    hits=$(grep -iE "(password|passwd|secret|api_key|access_key|token|credential)" \
           "$f" 2>/dev/null | grep -v "^#\|^//\|example\|sample\|placeholder")
    if [ -n "$hits" ]; then
        hit "App creds: $f"
        echo "$hits" | head -5 | while read line; do info "$line"; done
    fi
done

# .netrc specifically (often has plaintext creds)
find /home /root -name ".netrc" -readable 2>/dev/null | while read f; do
    hit ".netrc found: $f"
    cat "$f" 2>/dev/null | while read line; do info "$line"; done
done

# ==========================================================================
# 12. Password spray targets - all local users
# ==========================================================================
sec "LOCAL USERS (for password spray)"
cat /etc/passwd | grep -vE "(nologin|false|sync|halt|shutdown)" | \
    awk -F: '$3 >= 1000 || $3 == 0 {print $1" (uid:"$3" shell:"$7}' | \
    while read line; do info "$line"; done

# Check for users with empty passwords
while IFS=: read -r user pass rest; do
    if [ -z "$pass" ] || [ "$pass" = "" ]; then
        warn "User with empty password: $user"
    fi
done < /etc/shadow 2>/dev/null

# ==========================================================================
# 13. Interesting capabilities (linPEAS shows all, we highlight dangerous ones)
# ==========================================================================
sec "DANGEROUS CAPABILITIES"
getcap -r / 2>/dev/null | grep -E "(cap_setuid|cap_net_raw|cap_dac_override|cap_sys_admin|cap_sys_ptrace)" | \
while read line; do
    warn "Dangerous capability: $line"
done

# ==========================================================================
# 14. Readable /etc/shadow or shadow backups
# ==========================================================================
sec "SHADOW FILE ACCESS"
if [ -r /etc/shadow ] 2>/dev/null; then
    warn "READABLE /etc/shadow!"
    cat /etc/shadow | grep -v "^[^:]*:[!*]" | head -20
fi

for f in /etc/shadow- /etc/shadow.bak /var/shadow /backup/shadow; do
    if [ -r "$f" ] 2>/dev/null; then
        hit "Readable shadow backup: $f"
        cat "$f" 2>/dev/null | head -10 | while read line; do info "$line"; done
    fi
done

# ==========================================================================
# 15. NFS shares with no_root_squash (linPEAS checks but often misses)
# ==========================================================================
sec "NFS NO_ROOT_SQUASH"
if [ -r /etc/exports ] 2>/dev/null; then
    grep "no_root_squash" /etc/exports 2>/dev/null | while read line; do
        warn "NFS no_root_squash: $line"
        info "Mount and copy /bin/bash with SUID to get root"
    done
fi

showmount -e localhost 2>/dev/null | while read line; do
    info "NFS export: $line"
done

echo -e "\n${G}[+] linux-korek.sh complete! Review warnings above.${N}"
