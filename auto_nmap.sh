#!/usr/bin/env bash
# =============================================================================
# auto_nmap.sh - Automated Nmap Scanner
# Author: korek
# =============================================================================
# Usage:
#   ./auto_nmap.sh <ip>              # TCP only (default)
#   ./auto_nmap.sh <ip> --udp        # UDP only (when stuck on TCP)
#   ./auto_nmap.sh <ip> --all        # TCP + UDP
#   ./auto_nmap.sh -f ip.txt         # from file, TCP only
#   ./auto_nmap.sh -f ip.txt --all   # from file, TCP + UDP
#   Add T4 anywhere for fast timing
# =============================================================================

print_help() {
    echo ""
    echo "Usage:"
    echo "  $0 <ip> [--udp|--all] [T4]"
    echo "  $0 -f ip.txt [--udp|--all] [T4]"
    echo ""
    echo "Modes:"
    echo "  (default)  TCP only - fast, use first"
    echo "  --udp      UDP only - use when TCP gives nothing"
    echo "  --all      TCP + UDP - thorough scan"
    echo ""
    echo "Options:"
    echo "  T4         Fast timing (labs only)"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.10"
    echo "  $0 192.168.1.10 T4"
    echo "  $0 192.168.1.10 --udp"
    echo "  $0 192.168.1.10 --all T4"
    echo "  $0 -f ip.txt --all T4"
    echo ""
    exit 1
}

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

log()  { echo -e "${C}[*]${N} $1"; }
good() { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
hot()  { echo -e "${R}[!!]${N} $1"; }

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
# SNMP hints
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
# Service hints
# =============================================================================
service_hints() {
    local ip="$1"
    local ports_file="$2"
    local proto="$3"  # tcp or udp

    echo ""
    log "Next steps for $ip ($proto):"
    echo "----------------------------------------"

    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        case "$port" in
            21)   good "FTP → try anonymous login / hydra ftp" ;;
            22)   good "SSH → ssh-audit $ip / hydra -l user -P pass.txt ssh://$ip" ;;
            23)   good "Telnet → nc $ip 23" ;;
            25|587|2525)
                  good "SMTP ($port) → smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $ip"
                  echo -e "    ${Y}→ searchsploit exim / postfix / sendmail${N}" ;;
            53)   good "DNS → dig axfr DOMAIN @$ip"
                  echo -e "    ${Y}→ dnsrecon -d DOMAIN -t axfr -n $ip${N}"
                  echo -e "    ${Y}→ gobuster dns -d DOMAIN -r $ip -w subdomains.txt${N}" ;;
            80|8080|8000|8888)
                  good "HTTP ($port) → gobuster dir -u http://$ip:$port -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html"
                  echo -e "    ${Y}→ nikto -h http://$ip:$port${N}"
                  echo -e "    ${Y}→ whatweb http://$ip:$port${N}" ;;
            443|8443)
                  good "HTTPS ($port) → gobuster dir -u https://$ip:$port -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
                  echo -e "    ${Y}→ nikto -h https://$ip:$port -ssl${N}" ;;
            445)  good "SMB → nxc smb $ip -u '' -p '' --shares"
                  echo -e "    ${Y}→ enum4linux-ng $ip${N}"
                  echo -e "    ${Y}→ smbclient -L //$ip/${N}"
                  echo -e "    ${Y}→ nxc smb $ip --users --pass-pol${N}" ;;
            1433) good "MSSQL → nxc mssql $ip -u sa -p ''"
                  echo -e "    ${Y}→ impacket-mssqlclient sa@$ip${N}" ;;
            3306) good "MySQL → mysql -u root -h $ip"
                  echo -e "    ${Y}→ mysql -u root -h $ip --password=''${N}" ;;
            3389) good "RDP → xfreerdp /u:administrator /p:password /v:$ip"
                  echo -e "    ${Y}→ nxc rdp $ip -u users.txt -p passwords.txt${N}" ;;
            5432) good "PostgreSQL → psql -h $ip -U postgres" ;;
            5985|5986)
                  good "WinRM → evil-winrm -i $ip -u administrator -p password" ;;
            6379) good "Redis → redis-cli -h $ip"
                  echo -e "    ${Y}→ redis-cli -h $ip KEYS '*'${N}" ;;
            2049) good "NFS → showmount -e $ip"
                  echo -e "    ${Y}→ mount -t nfs $ip:/ /mnt/${N}" ;;
            111)  good "RPC/NFS → rpcinfo -p $ip"
                  echo -e "    ${Y}→ showmount -e $ip${N}" ;;
            110)  good "POP3 → telnet $ip 110 / USER root PASS password" ;;
            143)  good "IMAP → telnet $ip 143" ;;
            161)  snmp_hints "$ip" ;;  # UDP
            69)   good "TFTP (UDP) → tftp $ip"
                  echo -e "    ${Y}→ try: get /etc/passwd${N}" ;;
            500)  good "IKE/IPSec → ike-scan $ip" ;;
            27017|27018)
                  good "MongoDB → mongosh $ip" ;;
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
    nmap -Pn $SPEED -p- "$ip" \
        --open \
        -oN "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null

    ports=$(grep "^[0-9]" "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null | \
            grep "open" | \
            awk '{split($1,a,"/"); printf "%s,",a[1]}' | \
            sed 's/,$//')

    if [[ -z "$ports" ]]; then
        warn "No open TCP ports on $ip"
        return
    fi

    good "Open TCP ports: $ports"

    log "TCP Stage 2/2: Service scan on open ports..."
    nmap -Pn $SPEED -sC -sV -p "$ports" "$ip" \
        -oA "scans/$ip/${ip}_tcp" 2>/dev/null

    service_hints "$ip" "scans/$ip/${ip}_tcp_ports.txt" "tcp"

    echo "TCP=$ports" >> "scans/$ip/results.txt"
}

# =============================================================================
# UDP scan
# =============================================================================
do_udp_scan() {
    local ip="$1"
    log "UDP Stage 1/2: Top-100 port scan (requires sudo)..."
    sudo nmap -Pn $SPEED -sU --top-ports 100 "$ip" \
        --open \
        -oN "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null

    udp_ports=$(grep "^[0-9]" "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null | \
                grep -v "open|filtered" | \
                grep "open" | \
                awk '{split($1,a,"/"); printf "%s,",a[1]}' | \
                sed 's/,$//')

    if [[ -z "$udp_ports" ]]; then
        warn "No open UDP ports on $ip"
        return
    fi

    good "Open UDP ports: $udp_ports"

    # SNMP special handling
    echo "$udp_ports" | grep -q "161" && snmp_hints "$ip"

    log "UDP Stage 2/2: Service scan on open ports..."
    sudo nmap -Pn $SPEED -sC -sV -sU -p "$udp_ports" "$ip" \
        -oA "scans/$ip/${ip}_udp" 2>/dev/null

    service_hints "$ip" "scans/$ip/${ip}_udp_ports.txt" "udp"

    echo "UDP=$udp_ports" >> "scans/$ip/results.txt"
}

# =============================================================================
# Main scan function
# =============================================================================
scan_host() {
    local ip="$1"
    mkdir -p "scans/$ip"
    > "scans/$ip/results.txt"

    echo ""
    echo -e "${C}============================================${N}"
    log "Target: $ip | Mode: $SCAN_MODE | Timing: ${TIMING:-normal}"
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
    esac

    # Final summary
    echo ""
    echo -e "${C}============================================${N}"
    good "SCAN COMPLETE: $ip"
    cat "scans/$ip/results.txt" 2>/dev/null | while read line; do
        good "$line"
    done
    echo -e "${C}============================================${N}"

    # Save SUMMARY.md
    {
        echo "# Scan Summary: $ip"
        echo "Date: $(date)"
        echo "Mode: $SCAN_MODE"
        echo ""
        [[ -f "scans/$ip/${ip}_tcp_ports.txt" ]] && {
            echo "## TCP Ports"
            echo '```'
            grep "^[0-9]" "scans/$ip/${ip}_tcp_ports.txt" 2>/dev/null | grep "open"
            echo '```'
        }
        [[ -f "scans/$ip/${ip}_udp_ports.txt" ]] && {
            echo ""
            echo "## UDP Ports"
            echo '```'
            grep "^[0-9]" "scans/$ip/${ip}_udp_ports.txt" 2>/dev/null | grep "open"
            echo '```'
        }
    } > "scans/$ip/SUMMARY.md"

    good "Saved: scans/$ip/SUMMARY.md"
}

export -f scan_host do_tcp_scan do_udp_scan snmp_hints service_hints
export -f log good warn hot
export SPEED SCAN_MODE R G Y C W N

# =============================================================================
# Execute
# =============================================================================
if [[ "$MODE" == "file" ]]; then
    if [[ -z "$FILE" || ! -f "$FILE" ]]; then
        warn "Invalid or missing file: $FILE"
        print_help
    fi
    log "Scanning from file: $FILE (mode: $SCAN_MODE)"
    cat "$FILE" | parallel -j 5 scan_host

elif [[ "$MODE" == "single" ]]; then
    if [[ -z "$IP" ]]; then
        print_help
    fi
    scan_host "$IP"

else
    print_help
fi
