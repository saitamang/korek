#!/usr/bin/env bash
# =============================================================================
# auto_nmap.sh - Automated Nmap Scanner + Enumeration Hint Engine
# Author: korek  (upgraded)
# =============================================================================
# Usage:
#   ./auto_nmap.sh <ip>              # TCP only (default)
#   ./auto_nmap.sh <ip> --udp        # UDP only (when stuck on TCP)
#   ./auto_nmap.sh <ip> --all        # TCP + UDP
#   ./auto_nmap.sh -f ip.txt         # from file, TCP only
#   ./auto_nmap.sh -f ip.txt --all   # from file, TCP + UDP
#   Add T4 anywhere for fast timing (labs only)
# =============================================================================

print_help() {
    cat <<EOF

Usage:
  $0 <ip> [--udp|--all] [T4]
  $0 -f ip.txt [--udp|--all] [T4]

Modes:
  (default)  TCP only - fast, use first
  --udp      UDP only  - use when TCP gives nothing
  --all      TCP + UDP - thorough scan

Options:
  T4         Fast timing (labs only)

Examples:
  $0 192.168.1.10
  $0 192.168.1.10 T4
  $0 192.168.1.10 --udp
  $0 192.168.1.10 --all T4
  $0 -f ip.txt --all T4

EOF
    exit 1
}

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

log()  { echo -e "${C}[*]${N} $1"; }
good() { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
hot()  { echo -e "${R}[!!]${N} $1"; }

# A short curl that never hangs the whole scan on a dead host
CURL="curl -sk --max-time 8"

# =============================================================================
# Dependency check (warn, don't die — script still useful with partial tools)
# =============================================================================
check_deps() {
    local missing=""
    for bin in nmap curl awk sed grep; do
        command -v "$bin" >/dev/null 2>&1 || missing="$missing $bin"
    done
    command -v parallel >/dev/null 2>&1 || warn "GNU parallel not found — file mode (-f) will be slower/serial"
    if [[ -n "$missing" ]]; then
        warn "Missing tools:$missing  (some features degraded)"
    fi
}

# =============================================================================
# Arg parsing
# =============================================================================
if [[ -z "$1" ]]; then print_help; fi

MODE="single"
FILE=""
IP=""
TIMING=""
SCAN_MODE="tcp"  # tcp | udp | all

for arg in "$@"; do
    case "$arg" in
        --udp)     SCAN_MODE="udp" ;;
        --all)     SCAN_MODE="all" ;;
        T4)        TIMING="T4" ;;
        -f)        MODE="file" ;;
        -h|--help) print_help ;;
        *)
            if [[ "$MODE" == "file" && -z "$FILE" ]]; then
                FILE="$arg"
            elif [[ "$MODE" == "single" && -z "$IP" && "$arg" != "-f" ]]; then
                IP="$arg"
            fi
            ;;
    esac
done

if [[ "$TIMING" == "T4" ]]; then
    SPEED="-T4 --min-rate 3000"
else
    SPEED="--min-rate 1000"
fi

# =============================================================================
# Priority leads logger — high-value findings get echoed AND appended to a
# per-host LEADS file so they don't get lost in the scroll.
# =============================================================================
lead() {
    local ip="$1"; shift
    hot "$*"
    echo "[LEAD] $*" >> "scans/$ip/LEADS.txt"
}

# =============================================================================
# SNMP hints
# =============================================================================
snmp_hints() {
    local ip="$1"
    lead "$ip" "SNMP UDP/161 open — often leaks users/processes/creds"
    echo -e "    ${Y}[ENUM]${N} snmp-check $ip"
    echo -e "    ${Y}[ENUM]${N} onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip"
    echo -e "    ${Y}[ENUM]${N} snmpwalk -v2c -c public $ip"
    echo -e "    ${Y}[ENUM]${N} snmpwalk -v2c -c private $ip"
    echo -e "    ${Y}[ENUM]${N} snmpwalk -v1 -c public $ip"
}

# =============================================================================
# Web checks: .git exposure, CMS detection, common files
# =============================================================================
web_check() {
    local ip="$1"; local port="${2:-80}"; local proto="${3:-http}"
    local base="$proto://$ip:$port"

    log "Web checks on $base ..."

    # --- Exposed .git (high value: source + creds in history) ---
    local gitcode
    gitcode=$($CURL -o /dev/null -w "%{http_code}" "$base/.git/HEAD")
    if [[ "$gitcode" == "200" ]]; then
        lead "$ip" "Exposed .git/ at $base/.git/  → dump it, creds live in history"
        echo -e "    ${Y}→ git-dumper $base/.git/ ${ip}-git${N}"
        echo -e "    ${Y}→ cd ${ip}-git && git log --all -p | grep -iE 'pass|key|token|secret'${N}"
    fi

    # --- Other exposed VCS / config ---
    for f in /.svn/entries /.env /.DS_Store /config.php.bak /wp-config.php.bak /backup.zip; do
        local c
        c=$($CURL -o /dev/null -w "%{http_code}" "$base$f")
        [[ "$c" == "200" ]] && lead "$ip" "Exposed file: $base$f"
    done

    # --- CMS detection ---
    $CURL "$base/admin/login/index.php" | grep -qi "subrion" && {
        lead "$ip" "Subrion CMS detected at $base"
        echo -e "    ${Y}→ searchsploit subrion ; default admin:admin${N}"; }
    $CURL "$base/wp-login.php" | grep -qi "wordpress" && {
        lead "$ip" "WordPress detected at $base"
        echo -e "    ${Y}→ wpscan --url $base --enumerate u,p,t${N}"; }
    $CURL "$base/administrator/" | grep -qi "joomla" && {
        lead "$ip" "Joomla detected at $base"
        echo -e "    ${Y}→ joomscan -u $base ; searchsploit joomla${N}"; }
    $CURL "$base/" | grep -qi "drupal" && {
        lead "$ip" "Drupal detected at $base"
        echo -e "    ${Y}→ droopescan scan drupal -u $base${N}"; }
    $CURL "$base/phpmyadmin/" | grep -qi "phpmyadmin" && {
        lead "$ip" "phpMyAdmin detected at $base"
        echo -e "    ${Y}→ try root:(blank) / root:root ; searchsploit phpmyadmin${N}"; }
    $CURL -X OPTIONS "$base/" | grep -qi "DAV:" && {
        lead "$ip" "WebDAV enabled at $base"
        echo -e "    ${Y}→ davtest -url $base ; cadaver $base${N}"; }

    # --- Common files ---
    for path in /robots.txt /changelog.txt /readme.txt /README.md /CHANGELOG.md /install.php /config.php /wp-config.php /.git/config; do
        local code
        code=$($CURL -o /dev/null -w "%{http_code}" "$base$path")
        [[ "$code" == "200" ]] && good "Found: $base$path"
    done

    echo -e "    ${Y}→ gobuster dir -u $base -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html -t 30${N}"
    echo -e "    ${Y}→ feroxbuster -u $base -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html${N}"
    echo -e "    ${Y}→ nikto -h $base${N}"
    echo -e "    ${Y}→ whatweb $base${N}"
}

# =============================================================================
# Active Directory detection + enumeration
# -----------------------------------------------------------------------------
# Detection is signature-based on open ports:
#   88(kerberos) is the near-certain DC tell; 389/636/3268/3269 = LDAP/GC.
# Enumeration prints the full unauth + credentialed command set. The unauth
# probes (null session, anon LDAP, AS-REP without creds) are run if nxc/tools
# exist; credentialed commands are printed ready to paste once you have creds.
# =============================================================================
ad_detect_and_enum() {
    local ip="$1"; local ports_file="$2"
    local has88="" has389="" has445="" has53="" has3268="" has636=""

    grep -qE "^88/tcp.*open"   "$ports_file" && has88=1
    grep -qE "^389/tcp.*open"  "$ports_file" && has389=1
    grep -qE "^3268/tcp.*open" "$ports_file" && has3268=1
    grep -qE "^636/tcp.*open"  "$ports_file" && has636=1
    grep -qE "^445/tcp.*open"  "$ports_file" && has445=1
    grep -qE "^53/tcp.*open"   "$ports_file" && has53=1

    # Decide role
    local role=""
    if [[ -n "$has88" ]]; then
        role="DOMAIN CONTROLLER"
    elif [[ -n "$has389" || -n "$has3268" ]] && [[ -n "$has445" ]]; then
        role="AD-JOINED / LDAP host"
    fi
    [[ -z "$role" ]] && return   # not AD, skip silently

    lead "$ip" "Active Directory detected → $role (88=$has88 389=$has389 3268=$has3268 636=$has636)"

    # --- Try to extract domain + DC hostname from the -sCV output ---
    local domain="" dchost=""
    local svcfile="scans/$ip/${ip}_tcp.nmap"
    if [[ -f "$svcfile" ]]; then
        domain=$(grep -oiE "Domain: [A-Za-z0-9._-]+" "$svcfile" | head -1 | awk '{print $2}' | sed 's/0\.//')
        [[ -z "$domain" ]] && domain=$(grep -oiE "DNS_Domain_Name: [A-Za-z0-9._-]+" "$svcfile" | head -1 | awk '{print $2}')
        dchost=$(grep -oiE "DNS_Computer_Name: [A-Za-z0-9._-]+" "$svcfile" | head -1 | awk '{print $2}')
    fi
    [[ -n "$domain" ]] && good "Domain: $domain"
    [[ -n "$dchost" ]] && good "DC hostname: $dchost"

    # Suggest /etc/hosts so Kerberos-based tools resolve names
    if [[ -n "$domain" || -n "$dchost" ]]; then
        local shortname="${dchost%%.*}"   # strip any FQDN portion
        echo -e "    ${Y}[HOSTS]${N} add to /etc/hosts:  $ip   ${dchost:-$domain} ${shortname:+$shortname.$domain $shortname} $domain"
    fi

    echo ""; hot "===== AD ENUMERATION PLAYBOOK ($ip) ====="
    echo "----------------------------------------"

    local DOM="${domain:-DOMAIN.LOCAL}"

    echo -e "${W}[1] Unauthenticated — no creds needed${N}"
    echo -e "    ${Y}→ nxc smb $ip -u '' -p '' --shares --users --pass-pol${N}"
    echo -e "    ${Y}→ nxc smb $ip -u 'guest' -p '' --shares${N}"
    echo -e "    ${Y}→ enum4linux-ng -A $ip${N}"
    echo -e "    ${Y}→ ldapsearch -x -H ldap://$ip -s base namingcontexts   (anon LDAP base)${N}"
    echo -e "    ${Y}→ ldapsearch -x -H ldap://$ip -b 'DC=${DOM//./,DC=}' '(objectClass=user)'${N}"
    echo -e "    ${Y}→ nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='$DOM' $ip${N}"

    echo ""; echo -e "${W}[2] User-enum → then AS-REP roast (no creds)${N}"
    echo -e "    ${Y}→ kerbrute userenum -d $DOM --dc $ip /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt${N}"
    echo -e "    ${Y}→ impacket-GetNPUsers $DOM/ -dc-ip $ip -no-pass -usersfile users.txt -format hashcat${N}"
    echo -e "    ${Y}→ hashcat -m 18200 asrep.txt rockyou.txt${N}"

    echo ""; echo -e "${W}[3] With ANY valid creds (replace USER/PASS)  [Impacket/nxc — run from Kali]${N}"
    echo -e "    ${Y}→ nxc smb $ip -u USER -p PASS --shares --users --groups${N}"
    echo -e "    ${Y}→ nxc smb $ip -u USER -p PASS --rid-brute${N}"
    echo -e "    ${Y}→ impacket-GetUserSPNs $DOM/USER:PASS -dc-ip $ip -request -format hashcat   (Kerberoast → -m 13100)${N}"
    echo -e "    ${Y}→ impacket-lookupsid $DOM/USER:PASS@$ip          (RID cycle → user list)${N}"
    echo -e "    ${Y}→ nxc ldap $ip -u USER -p PASS --bloodhound --collection All --dns-server $ip${N}"
    echo -e "    ${Y}→ bloodhound-python -u USER -p PASS -d $DOM -ns $ip -c All${N}"

    echo ""; echo -e "${W}[4] Post-cred privesc / domain-takeover  [Impacket — needs creds, some need DA]${N}"
    echo -e "    ${Y}→ nxc smb $ip -u USER -p PASS -M gpp_password -M gpp_autologin${N}"
    echo -e "    ${Y}→ nxc smb TARGETS -u USER -p PASS --local-auth        (password reuse sweep)${N}"
    echo -e "    ${Y}→ impacket-secretsdump $DOM/USER:PASS@$ip -just-dc-ntlm   (REQUIRES DA/replication rights)${N}"
    echo -e "    ${Y}→ impacket-psexec $DOM/USER:PASS@$ip   /  impacket-wmiexec  (REQUIRES local admin on target)${N}"
    echo -e "    ${Y}→ check BloodHound: 'Shortest Path to Domain Admins' + mark owned users${N}"

    echo ""; echo -e "${W}[5] PowerView  [ONLY after you have a shell on a domain-JOINED Windows host]${N}"
    echo -e "    ${C}# not run from Kali — load in your foothold session, you're already a domain user${N}"
    echo -e "    ${Y}→ powershell -ep bypass; Import-Module .\\PowerView.ps1${N}"
    echo -e "    ${Y}→ Get-NetDomain ; Get-NetDomainController${N}"
    echo -e "    ${Y}→ Get-NetUser | select samaccountname,description   (descriptions often hold creds)${N}"
    echo -e "    ${Y}→ Get-NetGroup '*admin*' ; Get-NetGroupMember 'Domain Admins'${N}"
    echo -e "    ${Y}→ Get-NetComputer -FullData | select name,operatingsystem${N}"
    echo -e "    ${Y}→ Find-LocalAdminAccess        (where can current user admin?)${N}"
    echo -e "    ${Y}→ Get-NetUser -SPN | select samaccountname,serviceprincipalname  (Kerberoast targets)${N}"
    echo -e "    ${Y}→ Find-InterestingDomainAcl -ResolveGUIDs   (ACL-based privesc paths)${N}"

    echo ""; echo -e "${W}[6] Pivot reminders (internal DC behind a member box)${N}"
    echo -e "    ${Y}→ ligolo: route_add for the internal subnet, then run the Impacket/nxc lines through the tunnel${N}"
    echo "----------------------------------------"

    # --- Live unauth probes (only if tools present; these touch the target) ---
    if command -v nxc >/dev/null 2>&1; then
        log "Running live unauth SMB probe (null session)..."
        nxc smb "$ip" -u '' -p '' --shares 2>/dev/null | tee -a "scans/$ip/ad_nullsession.txt" | grep -qiE 'READ|WRITE' \
            && lead "$ip" "SMB null session readable — see scans/$ip/ad_nullsession.txt"
        nxc smb "$ip" -u '' -p '' --users 2>/dev/null > "scans/$ip/ad_users_null.txt"
        [[ -s "scans/$ip/ad_users_null.txt" ]] && grep -qiE '\\\\' "scans/$ip/ad_users_null.txt" \
            && lead "$ip" "Domain users enumerable via null session — scans/$ip/ad_users_null.txt"
    else
        warn "nxc (netexec) not installed — skipping live AD probes, commands above still valid"
    fi
}

# =============================================================================
# Service hints
# =============================================================================
service_hints() {
    local ip="$1"; local ports_file="$2"; local proto="$3"
    echo ""; log "Next steps for $ip ($proto):"
    echo "----------------------------------------"

    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        case "$port" in
            21)
                good "FTP → anonymous + version exploits"
                echo -e "    ${Y}→ ftp $ip   (anonymous / blank)${N}"
                echo -e "    ${Y}→ nmap -p21 --script ftp-anon,ftp-syst $ip${N}"
                echo -e "    ${Y}→ hydra -l admin -P rockyou.txt ftp://$ip${N}"
                echo -e "    ${Y}→ searchsploit vsftpd / proftpd${N}" ;;
            22)
                good "SSH → known creds / key auth"
                echo -e "    ${Y}→ hydra -L users.txt -P rockyou.txt ssh://$ip -t 4${N}"
                echo -e "    ${Y}→ if key: ssh2john id_rsa > h ; john h --wordlist=rockyou.txt${N}" ;;
            23) good "Telnet → telnet $ip" ;;
            25|587|2525)
                good "SMTP ($port) → user enum"
                echo -e "    ${Y}→ smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $ip${N}"
                echo -e "    ${Y}→ searchsploit exim / postfix / sendmail${N}" ;;
            53)
                good "DNS → zone transfer"
                echo -e "    ${Y}→ dig axfr DOMAIN @$ip${N}"
                echo -e "    ${Y}→ dnsrecon -d DOMAIN -t axfr -n $ip${N}" ;;
            79)
                good "Finger → user enum"
                echo -e "    ${Y}→ for u in root admin guest; do finger \$u@$ip; done${N}" ;;
            80|8080|8000|8888)
                good "HTTP ($port) → web enum"
                web_check "$ip" "$port" "http" ;;
            443|8443)
                good "HTTPS ($port) → web enum"
                echo -e "    ${Y}→ openssl s_client -connect $ip:$port  (cert hostnames)${N}"
                web_check "$ip" "$port" "https" ;;
            110) good "POP3 → telnet $ip 110 ; hydra pop3://$ip" ;;
            143) good "IMAP → telnet $ip 143 ; hydra imap://$ip" ;;
            139|445)
                good "SMB → enumeration"
                echo -e "    ${Y}→ nxc smb $ip -u '' -p '' --shares${N}"
                echo -e "    ${Y}→ nxc smb $ip -u 'guest' -p '' --shares${N}"
                echo -e "    ${Y}→ enum4linux-ng $ip${N}"
                echo -e "    ${Y}→ smbclient -L //$ip/ -N${N}"
                echo -e "    ${Y}→ nxc smb $ip -u '' -p '' --users --pass-pol${N}"
                echo -e "    ${Y}→ nmap -p445 --script smb-vuln* $ip  (EternalBlue etc)${N}"
                # quick null-session probe → lead
                if command -v nxc >/dev/null 2>&1; then
                    nxc smb "$ip" -u '' -p '' --shares 2>/dev/null | grep -qiE 'READ|WRITE' \
                        && lead "$ip" "SMB null/guest session yields readable shares"
                fi ;;
            1433)
                good "MSSQL → default creds"
                echo -e "    ${Y}→ nxc mssql $ip -u sa -p '' ; impacket-mssqlclient sa@$ip${N}" ;;
            3306)
                good "MySQL → default creds"
                echo -e "    ${Y}→ mysql -u root -h $ip --password=''${N}"
                echo -e "    ${Y}→ nmap -p3306 --script mysql-empty-password,mysql-info $ip${N}" ;;
            3389)
                good "RDP → creds / NLA check"
                echo -e "    ${Y}→ xfreerdp /u:administrator /p:password /v:$ip${N}"
                echo -e "    ${Y}→ nxc rdp $ip -u users.txt -p passwords.txt${N}" ;;
            5432) good "PostgreSQL → psql -h $ip -U postgres" ;;
            5985|5986)
                good "WinRM → evil-winrm"
                echo -e "    ${Y}→ evil-winrm -i $ip -u administrator -p password${N}"
                echo -e "    ${Y}→ evil-winrm -i $ip -u administrator -H NTLMHASH${N}" ;;
            6379) good "Redis → redis-cli -h $ip ; KEYS '*'" ;;
            2049) good "NFS → showmount -e $ip ; mount -t nfs $ip:/ /mnt/ -o nolock" ;;
            111)  good "RPC → rpcinfo -p $ip ; showmount -e $ip" ;;
            161)  snmp_hints "$ip" ;;
            69)   good "TFTP (UDP) → tftp $ip ; get /etc/passwd" ;;
            500)  good "IKE/IPSec → ike-scan -M $ip" ;;
            27017|27018) good "MongoDB → mongosh $ip --eval 'show dbs'" ;;
            8009) good "AJP → searchsploit ghostcat (CVE-2020-1938)" ;;
        esac
    done < <(grep "^[0-9]" "$ports_file" 2>/dev/null | grep "open")

    echo "----------------------------------------"
}

# =============================================================================
# TCP scan
# =============================================================================
do_tcp_scan() {
    local ip="$1"
    log "TCP Stage 1/2: Full port scan..."
    nmap -Pn $SPEED -p- "$ip" --open -oN "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null

    ports=$(grep "^[0-9]" "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null | grep "open" | \
            awk '{split($1,a,"/"); printf "%s,",a[1]}' | sed 's/,$//')

    if [[ -z "$ports" ]]; then warn "No open TCP ports on $ip"; return; fi
    good "Open TCP ports: $ports"

    log "TCP Stage 2/2: Service scan on open ports..."
    nmap -Pn $SPEED -sC -sV -p "$ports" "$ip" -oA "scans/$ip/${ip}_tcp" 2>/dev/null

    service_hints "$ip" "scans/$ip/${ip}_tcp_ports.txt" "tcp"

    # AD detection runs after -sCV so it can mine the domain/DC name from output
    ad_detect_and_enum "$ip" "scans/$ip/${ip}_tcp_ports.txt"

    echo "TCP=$ports" >> "scans/$ip/results.txt"
}

# =============================================================================
# UDP scan
# =============================================================================
do_udp_scan() {
    local ip="$1"
    log "UDP Stage 1/2: Top-100 port scan (requires sudo)..."
    sudo nmap -Pn $SPEED -sU --top-ports 100 "$ip" --open \
        -oN "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null

    # FIX: need grep -E for the alternation to work
    udp_ports=$(grep "^[0-9]" "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null | \
                grep -vE "open\|filtered" | grep "open" | \
                awk '{split($1,a,"/"); printf "%s,",a[1]}' | sed 's/,$//')

    if [[ -z "$udp_ports" ]]; then warn "No open UDP ports on $ip"; return; fi
    good "Open UDP ports: $udp_ports"

    echo "$udp_ports" | grep -q "161" && snmp_hints "$ip"

    log "UDP Stage 2/2: Service scan on open ports..."
    sudo nmap -Pn $SPEED -sC -sV -sU -p "$udp_ports" "$ip" -oA "scans/$ip/${ip}_udp" 2>/dev/null

    service_hints "$ip" "scans/$ip/${ip}_udp_ports.txt" "udp"
    echo "UDP=$udp_ports" >> "scans/$ip/results.txt"
}

# =============================================================================
# Main per-host
# =============================================================================
scan_host() {
    local ip="$1"
    mkdir -p "scans/$ip"
    > "scans/$ip/results.txt"
    > "scans/$ip/LEADS.txt"

    echo ""; echo -e "${C}============================================${N}"
    log "Target: $ip | Mode: $SCAN_MODE | Timing: ${TIMING:-normal}"
    echo -e "${C}============================================${N}"

    case "$SCAN_MODE" in
        tcp) do_tcp_scan "$ip" ;;
        udp) do_udp_scan "$ip" ;;
        all) do_tcp_scan "$ip"; echo ""; do_udp_scan "$ip" ;;
    esac

    echo ""; echo -e "${C}============================================${N}"
    good "SCAN COMPLETE: $ip"
    cat "scans/$ip/results.txt" 2>/dev/null | while read -r l; do good "$l"; done

    # Surface priority leads at the very end so they're impossible to miss
    if [[ -s "scans/$ip/LEADS.txt" ]]; then
        echo ""; hot "PRIORITY LEADS for $ip:"
        sed 's/^/    /' "scans/$ip/LEADS.txt"
    fi
    echo -e "${C}============================================${N}"

    {
        echo "# Scan Summary: $ip"
        echo "Date: $(date)"
        echo "Mode: $SCAN_MODE"
        echo ""
        [[ -s "scans/$ip/LEADS.txt" ]] && { echo "## Priority Leads"; sed 's/^/- /' "scans/$ip/LEADS.txt"; echo ""; }
        [[ -f "scans/$ip/${ip}_tcp_ports.txt" ]] && {
            echo "## TCP Ports"; echo '```'
            grep "^[0-9]" "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null | grep "open"; echo '```'; }
        [[ -f "scans/$ip/${ip}_udp_ports.txt" ]] && {
            echo ""; echo "## UDP Ports"; echo '```'
            grep "^[0-9]" "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null | grep "open"; echo '```'; }
    } > "scans/$ip/SUMMARY.md"

    good "Saved: scans/$ip/SUMMARY.md"
}

export -f scan_host do_tcp_scan do_udp_scan snmp_hints service_hints web_check lead ad_detect_and_enum
export -f log good warn hot
export SPEED SCAN_MODE CURL R G Y C W N

# =============================================================================
# Execute
# =============================================================================
check_deps

if [[ "$MODE" == "file" ]]; then
    if [[ -z "$FILE" || ! -f "$FILE" ]]; then warn "Invalid or missing file: $FILE"; print_help; fi
    log "Scanning from file: $FILE (mode: $SCAN_MODE)"
    if command -v parallel >/dev/null 2>&1; then
        cat "$FILE" | parallel -j 5 scan_host
    else
        while read -r line; do [[ -n "$line" ]] && scan_host "$line"; done < "$FILE"
    fi
elif [[ "$MODE" == "single" ]]; then
    [[ -z "$IP" ]] && print_help
    scan_host "$IP"
else
    print_help
fi
