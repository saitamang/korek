#!/usr/bin/env bash
# =============================================================================
# auto_nmap.sh - Automated Nmap Scanner
# Author: korek
# =============================================================================
# Usage:
#   ./auto_nmap.sh <ip>               # TCP only (default)
#   ./auto_nmap.sh <ip> --udp         # UDP only
#   ./auto_nmap.sh <ip> --all         # TCP + UDP
#   ./auto_nmap.sh -f ip.txt          # from file, TCP only
#   ./auto_nmap.sh -f ip.txt --all    # from file, TCP + UDP
#   Add T4 anywhere for fast timing
# =============================================================================

set -euo pipefail

# =============================================================================
# COLORS & OUTPUT
# =============================================================================
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

log()  { echo -e "${C}[*]${N} $1"; }
good() { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
hot()  { echo -e "${R}[!!]${N} $1"; }
err()  { echo -e "${R}[ERROR]${N} $1" >&2; }

# =============================================================================
# HELP
# =============================================================================
print_help() {
    echo ""
    echo -e "${C}Usage:${N}"
    echo "  $0 <ip> [--udp|--all] [T4]"
    echo "  $0 -f ip.txt [--udp|--all] [T4]"
    echo ""
    echo -e "${C}Modes:${N}"
    echo "  (default)  TCP only  — use first"
    echo "  --udp      UDP only  — use when TCP gives nothing"
    echo "  --all      TCP + UDP — thorough scan"
    echo ""
    echo -e "${C}Options:${N}"
    echo "  T4         Fast timing (labs/exams only)"
    echo "  -f file    Scan multiple IPs from file"
    echo ""
    echo -e "${C}Examples:${N}"
    echo "  $0 192.168.1.10"
    echo "  $0 192.168.1.10 T4"
    echo "  $0 192.168.1.10 --udp"
    echo "  $0 192.168.1.10 --all T4"
    echo "  $0 -f targets.txt --all T4"
    echo ""
    exit 0
}

# =============================================================================
# ARG PARSING
# =============================================================================
if [[ $# -eq 0 ]]; then print_help; fi

MODE="single"
FILE=""
IP=""
TIMING="normal"
SCAN_MODE="tcp"

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
            elif [[ -z "$IP" && "$arg" != "-f" ]]; then
                IP="$arg"
            fi
            ;;
    esac
done

# Build nmap speed flags
if [[ "$TIMING" == "T4" ]]; then
    SPEED="-T4 --min-rate 3000"
else
    SPEED="-T2 --min-rate 1000"
fi

# =============================================================================
# VALIDATION
# =============================================================================

# Check nmap installed
if ! command -v nmap &>/dev/null; then
    err "nmap not found — install with: apt install nmap"
    exit 1
fi

# Validate IP (basic check)
validate_ip() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        err "No IP address provided"
        return 1
    fi
    # Accept IPs and hostnames
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$|^[a-zA-Z0-9.-]+$'; then
        err "Invalid IP/hostname format: $ip"
        return 1
    fi
    return 0
}

# Check if running as root for UDP scans
check_root_for_udp() {
    if [[ "$EUID" -ne 0 ]]; then
        warn "UDP scans require root/sudo — run as root or use sudo"
        return 1
    fi
    return 0
}

# =============================================================================
# SNMP HINTS
# =============================================================================
snmp_hints() {
    local ip="$1"
    hot "SNMP UDP/161 found on $ip!"
    echo -e "    ${Y}[ENUM]${N} snmp-check $ip"
    echo -e "    ${Y}[ENUM]${N} onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $ip"
    echo -e "    ${Y}[ENUM]${N} snmpwalk -v2c -c public $ip"
    echo -e "    ${Y}[ENUM]${N} snmpwalk -v2c -c private $ip"
}

# =============================================================================
# SERVICE HINTS
# =============================================================================
service_hints() {
    local ip="$1"
    local ports_file="$2"
    local proto="$3"

    if [[ ! -f "$ports_file" ]]; then
        warn "Port file not found: $ports_file — skipping hints"
        return
    fi

    echo ""
    log "Next steps for $ip ($proto):"
    echo "----------------------------------------"

    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        case "$port" in
            21)   good "FTP → ftp $ip (try: anonymous / blank)"
                  echo -e "    ${Y}→ lftp -u anonymous, ftp://$ip${N}"
                  echo -e "    ${Y}→ hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$ip${N}" ;;
            22)   good "SSH → ssh user@$ip"
                  echo -e "    ${Y}→ ssh-audit $ip${N}"
                  echo -e "    ${Y}→ hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://$ip${N}" ;;
            23)   good "Telnet → nc $ip 23" ;;
            25|587|2525)
                  good "SMTP ($port) → smtp-user-enum -M VRFY -U users.txt -t $ip"
                  echo -e "    ${Y}→ nxc smtp $ip -u users.txt -p passwords.txt${N}"
                  echo -e "    ${Y}→ searchsploit exim / postfix / sendmail${N}" ;;
            53)   good "DNS → dig axfr DOMAIN @$ip"
                  echo -e "    ${Y}→ dnsrecon -d DOMAIN -t axfr -n $ip${N}"
                  echo -e "    ${Y}→ gobuster dns -d DOMAIN -r $ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt${N}" ;;
            80|8080|8000|8888)
                  good "HTTP ($port) → feroxbuster -u http://$ip:$port -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
                  echo -e "    ${Y}→ gobuster dir -u http://$ip:$port -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html${N}"
                  echo -e "    ${Y}→ nikto -h http://$ip:$port${N}"
                  echo -e "    ${Y}→ whatweb http://$ip:$port${N}" ;;
            443|8443)
                  good "HTTPS ($port) → feroxbuster -u https://$ip:$port -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
                  echo -e "    ${Y}→ gobuster dir -u https://$ip:$port -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt${N}"
                  echo -e "    ${Y}→ nikto -h https://$ip:$port -ssl${N}" ;;
            88)   good "Kerberos → impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $ip"
                  echo -e "    ${Y}→ impacket-GetUserSPNs DOMAIN/user:pass -dc-ip $ip -request${N}"
                  echo -e "    ${Y}→ nxc ldap $ip -u '' -p '' --asreproast asrep.txt${N}" ;;
            110)  good "POP3 → telnet $ip 110"
                  echo -e "    ${Y}→ USER root PASS password${N}" ;;
            111)  good "RPC/NFS → rpcinfo -p $ip"
                  echo -e "    ${Y}→ showmount -e $ip${N}"
                  echo -e "    ${Y}→ mount -t nfs $ip:/ /mnt/${N}" ;;
            139|445)
                  good "SMB → nxc smb $ip -u '' -p '' --shares"
                  echo -e "    ${Y}→ enum4linux-ng $ip${N}"
                  echo -e "    ${Y}→ smbclient -L //$ip/${N}"
                  echo -e "    ${Y}→ nxc smb $ip -u '' -p '' --users --pass-pol${N}" ;;
            143)  good "IMAP → telnet $ip 143" ;;
            389|636|3268|3269)
                  good "LDAP ($port) → ldapsearch -x -H ldap://$ip -b 'DC=domain,DC=com'"
                  echo -e "    ${Y}→ nxc ldap $ip -u '' -p '' --users${N}"
                  echo -e "    ${Y}→ windapsearch.py -d DOMAIN --dc-ip $ip -U${N}" ;;
            1433) good "MSSQL → nxc mssql $ip -u sa -p ''"
                  echo -e "    ${Y}→ impacket-mssqlclient sa@$ip${N}"
                  echo -e "    ${Y}→ sqsh -S $ip -U sa -P ''${N}" ;;
            2049) good "NFS → showmount -e $ip"
                  echo -e "    ${Y}→ mount -t nfs $ip:/ /mnt/${N}"
                  echo -e "    ${Y}→ nmap --script nfs-ls,nfs-showmount $ip${N}" ;;
            3306) good "MySQL → mysql -u root -h $ip"
                  echo -e "    ${Y}→ mysql -u root -h $ip --password=''${N}"
                  echo -e "    ${Y}→ nxc mysql $ip -u root -p ''${N}" ;;
            3389) good "RDP → xfreerdp /u:administrator /p:password /v:$ip"
                  echo -e "    ${Y}→ nxc rdp $ip -u users.txt -p passwords.txt${N}"
                  echo -e "    ${Y}→ rdesktop $ip${N}" ;;
            5432) good "PostgreSQL → psql -h $ip -U postgres"
                  echo -e "    ${Y}→ nxc postgres $ip -u postgres -p ''${N}" ;;
            5985|5986|47001)
                  good "WinRM ($port) → evil-winrm -i $ip -u administrator -p password"
                  echo -e "    ${Y}→ nxc winrm $ip -u users.txt -p passwords.txt${N}" ;;
            6379) good "Redis → redis-cli -h $ip"
                  echo -e "    ${Y}→ redis-cli -h $ip KEYS '*'${N}"
                  echo -e "    ${Y}→ redis-cli -h $ip CONFIG GET requirepass${N}" ;;
            9200|9300)
                  good "Elasticsearch ($port) → curl http://$ip:$port"
                  echo -e "    ${Y}→ curl http://$ip:$port/_cat/indices${N}" ;;
            27017|27018)
                  good "MongoDB ($port) → mongosh $ip"
                  echo -e "    ${Y}→ mongo $ip --eval 'db.adminCommand({listDatabases:1})'${N}" ;;
            # UDP specific
            69)   good "TFTP (UDP) → tftp $ip"
                  echo -e "    ${Y}→ try: get /etc/passwd${N}" ;;
            161)  snmp_hints "$ip" ;;
            500)  good "IKE/IPSec → ike-scan $ip" ;;
        esac
    done < <(grep "^[0-9]" "$ports_file" 2>/dev/null | grep "open")

    echo "----------------------------------------"
}

# =============================================================================
# TCP SCAN
# =============================================================================
do_tcp_scan() {
    local ip="$1"
    local outdir="scans/$ip"

    log "TCP Stage 1/2: Full port scan..."

    # NOTE: --open is intentionally NOT used in stage 1
    # On high-latency/filtered hosts (e.g. 172.16.x.x pivots), --open causes
    # nmap to report nothing because filtered ports get silently dropped.
    # We grep for "open" ourselves from the full output instead.
    # --defeat-rst-ratelimit is critical for slow/filtered hosts to prevent
    # nmap from giving up on ports that don't immediately RST back.
    nmap -Pn $SPEED -p- "$ip" \
        --defeat-rst-ratelimit \
        -oN "$outdir/${ip}_tcp_ports.txt" 2>&1 | tee /tmp/nmap_stage1.txt

    # Show any nmap warnings to help debug
    if grep -qi "warning\|error\|failed\|0 hosts" /tmp/nmap_stage1.txt; then
        warn "nmap reported issues — check output above"
    fi

    # Extract open ports (exclude filtered/closed)
    ports=$(grep "^[0-9]" "$outdir/${ip}_tcp_ports.txt" 2>/dev/null | \
            grep "/tcp" | \
            grep "open" | \
            grep -v "filtered\|closed" | \
            awk '{split($1,a,"/"); printf "%s,",a[1]}' | \
            sed 's/,$//')

    if [[ -z "$ports" ]]; then
        warn "No open TCP ports found on $ip"
        warn "Possible reasons:"
        warn "  1. Host behind firewall — try T4: $0 $ip T4"
        warn "  2. Need pivot/tunnel to reach this subnet"
        warn "  3. Check connectivity: ping $ip / nc -zv $ip 445"
        return 0
    fi

    good "Open TCP ports: $ports"

    log "TCP Stage 2/2: Service scan on open ports..."
    nmap -Pn $SPEED -sC -sV -p "$ports" "$ip" \
        -oA "$outdir/${ip}_tcp" 2>&1

    service_hints "$ip" "$outdir/${ip}_tcp_ports.txt" "tcp"

    echo "TCP=$ports" >> "$outdir/results.txt"
}

# =============================================================================
# UDP SCAN
# =============================================================================
do_udp_scan() {
    local ip="$1"
    local outdir="scans/$ip"

    # UDP needs root
    if ! check_root_for_udp; then
        warn "Skipping UDP scan — re-run as root"
        return 1
    fi

    log "UDP Stage 1/2: Top-100 port scan (requires sudo)..."

    if ! nmap -Pn $SPEED -sU --top-ports 100 "$ip" \
        -oN "$outdir/${ip}_udp_ports.txt" 2>&1 | tee /tmp/nmap_udp.txt; then
        err "UDP scan failed for $ip"
        return 1
    fi

    # FIX: UDP shows "open|filtered" — include those, not just "open"
    # Previous version was accidentally excluding valid UDP ports
    udp_ports=$(grep "^[0-9]" "$outdir/${ip}_udp_ports.txt" 2>/dev/null | \
                grep -E "open[^|]|open\|filtered" | \
                awk '{split($1,a,"/"); printf "%s,",a[1]}' | \
                sed 's/,$//')

    if [[ -z "$udp_ports" ]]; then
        warn "No open UDP ports on $ip"
        return 0
    fi

    good "Open UDP ports: $udp_ports"

    # SNMP special handling
    if echo "$udp_ports" | grep -q "\b161\b"; then
        snmp_hints "$ip"
    fi

    log "UDP Stage 2/2: Service scan on open ports..."
    if ! nmap -Pn $SPEED -sC -sV -sU -p "$udp_ports" "$ip" \
        -oA "$outdir/${ip}_udp" 2>/dev/null; then
        warn "UDP service scan had issues — check output file"
    fi

    service_hints "$ip" "$outdir/${ip}_udp_ports.txt" "udp"

    echo "UDP=$udp_ports" >> "$outdir/results.txt"
}

# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================
scan_host() {
    local ip="$1"

    # Validate IP
    if ! validate_ip "$ip"; then
        return 1
    fi

    local outdir="scans/$ip"
    mkdir -p "$outdir" || {
        err "Cannot create output dir: $outdir"
        return 1
    }
    > "$outdir/results.txt"

    echo ""
    echo -e "${C}============================================${N}"
    log "Target: $ip | Mode: $SCAN_MODE | Timing: ${TIMING}"
    echo -e "${C}============================================${N}"

    case "$SCAN_MODE" in
        tcp)
            do_tcp_scan "$ip"
            ;;
        udp)
            do_udp_scan "$ip"
            ;;
        all)
            do_tcp_scan "$ip"
            echo ""
            do_udp_scan "$ip"
            ;;
        *)
            err "Unknown scan mode: $SCAN_MODE (use tcp, udp, or all)"
            return 1
            ;;
    esac

    # Final summary
    echo ""
    echo -e "${C}============================================${N}"
    good "SCAN COMPLETE: $ip"
    if [[ -f "$outdir/results.txt" ]] && [[ -s "$outdir/results.txt" ]]; then
        while IFS= read -r line; do
            good "$line"
        done < "$outdir/results.txt"
    else
        warn "No results recorded for $ip"
    fi
    echo -e "${C}============================================${N}"

    # Save SUMMARY.md
    {
        echo "# Scan Summary: $ip"
        echo "Date: $(date)"
        echo "Mode: $SCAN_MODE | Timing: $TIMING"
        echo ""

        # Quick reference port list
        if [[ -f "$outdir/results.txt" ]] && [[ -s "$outdir/results.txt" ]]; then
            echo "## Open Ports (Quick Reference)"
            echo ```
            cat "$outdir/results.txt"
            echo ```
            echo ""
        fi

        # TCP port table
        if [[ -f "$outdir/${ip}_tcp_ports.txt" ]]; then
            echo "## TCP Port Scan"
            echo ```
            grep "^[0-9]" "$outdir/${ip}_tcp_ports.txt" 2>/dev/null | grep "open" | grep -v "filtered\|closed" || echo "none"
            echo ```
            echo ""
        fi

        # Full TCP service scan output
        if [[ -f "$outdir/${ip}_tcp.nmap" ]]; then
            echo "## TCP Service Scan (nmap -sC -sV)"
            echo ```
            cat "$outdir/${ip}_tcp.nmap"
            echo ```
            echo ""
        fi

        # UDP port table
        if [[ -f "$outdir/${ip}_udp_ports.txt" ]]; then
            echo "## UDP Port Scan"
            echo ```
            grep "^[0-9]" "$outdir/${ip}_udp_ports.txt" 2>/dev/null | grep "open" || echo "none"
            echo ```
            echo ""
        fi

        # Full UDP service scan output
        if [[ -f "$outdir/${ip}_udp.nmap" ]]; then
            echo "## UDP Service Scan"
            echo ```
            cat "$outdir/${ip}_udp.nmap"
            echo ```
            echo ""
        fi

        # Next steps based on open ports
        echo "## Next Steps"
        echo ```
        if [[ -f "$outdir/${ip}_tcp_ports.txt" ]]; then
            while IFS= read -r line; do
                port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
                case "$port" in
                    21)        echo "FTP($port)      → ftp $ip | lftp -u anonymous, ftp://$ip" ;;
                    22)        echo "SSH($port)      → ssh user@$ip | hydra -l user -P rockyou.txt ssh://$ip" ;;
                    25|587)    echo "SMTP($port)     → smtp-user-enum -M VRFY -U users.txt -t $ip" ;;
                    53)        echo "DNS($port)      → dig axfr DOMAIN @$ip | dnsrecon -d DOMAIN -t axfr -n $ip" ;;
                    80|8080|8000|8888) echo "HTTP($port)     → feroxbuster -u http://$ip:$port -w raft-medium-directories.txt | nikto -h http://$ip:$port" ;;
                    88)        echo "Kerberos($port) → impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip $ip" ;;
                    110)       echo "POP3($port)     → telnet $ip 110" ;;
                    111)       echo "RPC($port)      → rpcinfo -p $ip | showmount -e $ip" ;;
                    139|445)   echo "SMB($port)      → nxc smb $ip -u \'\' -p \'\' --shares | enum4linux-ng $ip | smbclient -L //$ip/" ;;
                    389|636|3268) echo "LDAP($port)  → ldapsearch -x -H ldap://$ip -b DC=domain,DC=com | nxc ldap $ip -u \'\' -p \'\' --users" ;;
                    443|8443)  echo "HTTPS($port)    → feroxbuster -u https://$ip:$port -k -w raft-medium-directories.txt | nikto -h https://$ip:$port -ssl" ;;
                    1433)      echo "MSSQL($port)    → nxc mssql $ip -u sa -p \'\' | impacket-mssqlclient sa@$ip" ;;
                    2049)      echo "NFS($port)      → showmount -e $ip | mount -t nfs $ip:/ /mnt/" ;;
                    3306)      echo "MySQL($port)    → mysql -u root -h $ip | nxc mysql $ip -u root -p \'\'" ;;
                    3389)      echo "RDP($port)      → xfreerdp /u:administrator /p:password /v:$ip | nxc rdp $ip -u users.txt -p passwords.txt" ;;
                    5432)      echo "Postgres($port) → psql -h $ip -U postgres | nxc postgres $ip -u postgres -p \'\'" ;;
                    5985|5986|47001) echo "WinRM($port)→ evil-winrm -i $ip -u administrator -p password | nxc winrm $ip -u user -p pass" ;;
                    6379)      echo "Redis($port)    → redis-cli -h $ip | redis-cli -h $ip KEYS \'*\'" ;;
                    27017)     echo "MongoDB($port)  → mongosh $ip" ;;
                esac
            done < <(grep "^[0-9]" "$outdir/${ip}_tcp_ports.txt" 2>/dev/null | grep "open" | grep -v "filtered\|closed")
        fi
        echo ```

    } > "$outdir/SUMMARY.md" 2>/dev/null

    good "Saved: $outdir/SUMMARY.md"
}

# Export for parallel
export -f scan_host do_tcp_scan do_udp_scan snmp_hints service_hints
export -f log good warn hot err validate_ip check_root_for_udp
export SPEED SCAN_MODE TIMING R G Y C W N

# =============================================================================
# EXECUTE
# =============================================================================
if [[ "$MODE" == "file" ]]; then
    # Validate file
    if [[ -z "$FILE" ]]; then
        err "No file specified after -f"
        print_help
    fi
    if [[ ! -f "$FILE" ]]; then
        err "File not found: $FILE"
        exit 1
    fi
    if [[ ! -s "$FILE" ]]; then
        err "File is empty: $FILE"
        exit 1
    fi

    log "Scanning from file: $FILE (mode: $SCAN_MODE)"
    TARGET_COUNT=$(wc -l < "$FILE")
    log "Total targets: $TARGET_COUNT"

    # FIX: proper parallel fallback — serial mode if parallel not installed
    if command -v parallel &>/dev/null; then
        log "Using GNU parallel (5 concurrent)"
        cat "$FILE" | parallel -j 5 scan_host
    else
        warn "GNU parallel not found — running serial (install with: apt install parallel)"
        while IFS= read -r ip; do
            [[ -z "$ip" || "$ip" == \#* ]] && continue  # skip blank/comment lines
            scan_host "$ip"
        done < "$FILE"
    fi

elif [[ "$MODE" == "single" ]]; then
    if [[ -z "$IP" ]]; then
        err "No IP address provided"
        print_help
    fi
    scan_host "$IP"

else
    err "Unknown mode: $MODE"
    print_help
fi
