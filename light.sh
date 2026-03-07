#!/bin/bash
#==============================================================================
# LinuxLight - Comprehensive Linux Security Checker
# A defensive security auditing tool for system administrators
# https://github.com/int0x33/LinuxLight
#==============================================================================

VERSION="2.0.0"

#--------------------------------------
# Color & formatting
#--------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

#--------------------------------------
# Globals
#--------------------------------------
REPORT_FILE=""
THOROUGH=0
KEYWORD=""
EXPORT_DIR=""

#--------------------------------------
# Usage
#--------------------------------------
usage() {
    echo -e "${RED}================================================================${NC}"
    echo -e "${YELLOW}  LinuxLight - Linux Security Checker v${VERSION}${NC}"
    echo -e "${RED}================================================================${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -t            Enable thorough/lengthy checks (SUID, world-writable, etc.)"
    echo "  -k <keyword>  Search for keyword in config/log files"
    echo "  -r <file>     Save output to report file"
    echo "  -e <dir>      Export directory for detailed findings"
    echo "  -h            Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                  Quick scan with default checks"
    echo "  $0 -t               Full thorough scan"
    echo "  $0 -k password      Scan and search for 'password' in configs"
    echo "  $0 -r report.txt    Save output to report.txt"
    echo ""
    exit 0
}

#--------------------------------------
# Parse arguments
#--------------------------------------
while getopts "tk:r:e:h" opt; do
    case $opt in
        t) THOROUGH=1 ;;
        k) KEYWORD="$OPTARG" ;;
        r) REPORT_FILE="$OPTARG" ;;
        e) EXPORT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

#--------------------------------------
# Output helpers
#--------------------------------------
banner() {
    echo ""
    echo -e "${RED}================================================================${NC}"
    echo -e "${RED}[*]${NC} ${BOLD}$1${NC}"
    echo -e "${RED}================================================================${NC}"
}

section() {
    echo ""
    echo -e "${YELLOW}[+] $1${NC}"
    echo -e "${YELLOW}--------------------------------------------${NC}"
}

info() {
    echo -e "${CYAN}[i]${NC} $1"
}

warn() {
    echo -e "${RED}[!]${NC} ${RED}$1${NC}"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

run_cmd() {
    local desc="$1"
    shift
    local output
    output=$("$@" 2>/dev/null)
    if [ -n "$output" ]; then
        echo -e "${BLUE}--- $desc ---${NC}"
        echo "$output"
        echo ""
    fi
}

# If report file specified, tee all output
if [ -n "$REPORT_FILE" ]; then
    exec > >(tee -a "$REPORT_FILE") 2>&1
fi

#==============================================================================
# HEADER
#==============================================================================
echo ""
echo -e "${RED}================================================================${NC}"
echo -e "${YELLOW}     LinuxLight - Linux Security Checker v${VERSION}${NC}"
echo -e "${YELLOW}     Comprehensive Security Audit Tool${NC}"
echo -e "${RED}================================================================${NC}"
echo -e "${CYAN}  Scan started: $(date)${NC}"
echo -e "${CYAN}  Running as:   $(whoami)${NC}"
echo -e "${CYAN}  Hostname:     $(hostname 2>/dev/null)${NC}"
if [ "$THOROUGH" -eq 1 ]; then
    info "Thorough mode enabled - this may take a while"
fi
if [ -n "$KEYWORD" ]; then
    info "Searching for keyword: $KEYWORD"
fi

#==============================================================================
# 1. SYSTEM INFORMATION
#==============================================================================
banner "SYSTEM INFORMATION"

section "OS & Kernel"
run_cmd "Kernel version" uname -a
run_cmd "Kernel release" uname -r
cat /proc/version 2>/dev/null
echo ""
for f in /etc/*-release /etc/issue; do
    [ -f "$f" ] && run_cmd "$f" cat "$f"
done
run_cmd "Hostname" hostname
run_cmd "Architecture" uname -m

section "CPU Information"
if [ -f /proc/cpuinfo ]; then
    grep -m1 "model name" /proc/cpuinfo 2>/dev/null
    echo "CPU cores: $(grep -c "^processor" /proc/cpuinfo 2>/dev/null)"
fi

section "Memory & Disk"
run_cmd "Memory usage" free -h
run_cmd "Disk usage" df -h
run_cmd "Mounted filesystems" mount

section "Uptime & Load"
run_cmd "Uptime" uptime

section "Date & Timezone"
run_cmd "Current date" date
run_cmd "Timezone" timedatectl status

section "Virtualization / Container Detection"
if [ -f /.dockerenv ]; then
    warn "Running inside a Docker container"
elif grep -q "docker\|lxc\|containerd" /proc/1/cgroup 2>/dev/null; then
    warn "Running inside a container (detected via cgroup)"
fi
if command -v systemd-detect-virt &>/dev/null; then
    virt=$(systemd-detect-virt 2>/dev/null)
    [ "$virt" != "none" ] && info "Virtualization: $virt"
fi
run_cmd "DMI system product" cat /sys/class/dmi/id/product_name

#==============================================================================
# 2. USER & GROUP INFORMATION
#==============================================================================
banner "USER & GROUP INFORMATION"

section "Current User"
run_cmd "User ID" id
run_cmd "Groups" groups

section "Logged-in Users"
run_cmd "Who is logged in" w
run_cmd "Last logins" last -20

section "All Users"
run_cmd "/etc/passwd" cat /etc/passwd

section "Root / UID-0 Accounts"
echo "Accounts with UID 0:"
awk -F: '($3 == 0) {print " -> " $1}' /etc/passwd 2>/dev/null
echo ""

section "Accounts with No Password"
if [ -r /etc/shadow ]; then
    no_pass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "*") {print " -> " $1 " (" $2 ")"}' /etc/shadow 2>/dev/null)
    if [ -n "$no_pass" ]; then
        warn "Accounts with empty/locked passwords:"
        echo "$no_pass"
    else
        success "No accounts with empty passwords"
    fi
else
    info "/etc/shadow is not readable (run as root for full check)"
fi

section "Shadow File Permissions"
if [ -f /etc/shadow ]; then
    ls -la /etc/shadow 2>/dev/null
    perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
    if [ -n "$perms" ] && [ "$perms" != "640" ] && [ "$perms" != "600" ] && [ "$perms" != "000" ]; then
        warn "/etc/shadow has unusual permissions: $perms (expected 600 or 640)"
    fi
fi

section "Sudo Configuration"
run_cmd "Sudo version" sudo -V
run_cmd "Sudo privileges" sudo -l
if [ -r /etc/sudoers ]; then
    echo "--- /etc/sudoers (non-comment lines) ---"
    grep -v "^#\|^$\|^Defaults" /etc/sudoers 2>/dev/null
    echo ""
fi
if [ -d /etc/sudoers.d ]; then
    echo "--- Files in /etc/sudoers.d/ ---"
    ls -la /etc/sudoers.d/ 2>/dev/null
    echo ""
fi

section "Password Policy"
run_cmd "Login defaults" cat /etc/login.defs
run_cmd "PAM password rules" grep -v "^#\|^$" /etc/pam.d/common-password
run_cmd "Password aging" chage -l "$(whoami)"

section "Groups"
run_cmd "All groups" cat /etc/group
echo "Users in sudo/admin/wheel groups:"
for g in sudo admin wheel; do
    getent group "$g" 2>/dev/null | while IFS=: read -r name _ _ members; do
        [ -n "$members" ] && echo " -> $name: $members"
    done
done
echo ""

#==============================================================================
# 3. PRIVILEGE ESCALATION VECTORS
#==============================================================================
banner "PRIVILEGE ESCALATION VECTORS"

section "SUID Binaries"
info "Searching for SUID binaries..."
find / -perm -4000 -type f 2>/dev/null | while read -r f; do
    echo "  SUID: $f ($(ls -la "$f" 2>/dev/null | awk '{print $1, $3, $4}'))"
done
echo ""

section "SGID Binaries"
info "Searching for SGID binaries..."
find / -perm -2000 -type f 2>/dev/null | while read -r f; do
    echo "  SGID: $f ($(ls -la "$f" 2>/dev/null | awk '{print $1, $3, $4}'))"
done
echo ""

section "Writable /etc/passwd"
if [ -w /etc/passwd ]; then
    warn "/etc/passwd is WRITABLE by current user!"
else
    success "/etc/passwd is not writable"
fi

section "Writable /etc/shadow"
if [ -w /etc/shadow ]; then
    warn "/etc/shadow is WRITABLE by current user!"
else
    success "/etc/shadow is not writable"
fi

section "Capabilities"
info "Files with capabilities set:"
getcap -r / 2>/dev/null | while read -r line; do
    echo "  CAP: $line"
done
echo ""

section "Writable Directories in PATH"
echo "$PATH" | tr ':' '\n' | while read -r dir; do
    if [ -w "$dir" ]; then
        warn "Writable PATH directory: $dir"
    fi
done
echo ""

section "Cron Jobs"
run_cmd "Current user crontab" crontab -l
run_cmd "System crontab" cat /etc/crontab
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$d" ]; then
        echo "--- $d ---"
        ls -la "$d" 2>/dev/null
        echo ""
    fi
done
run_cmd "Cron spool" ls -la /var/spool/cron/crontabs/
run_cmd "Anacron" cat /etc/anacrontab
echo ""
info "Checking for writable cron scripts..."
find /etc/cron* -writable -type f 2>/dev/null | while read -r f; do
    warn "Writable cron file: $f"
done
echo ""

section "Systemd Timers"
run_cmd "Active timers" systemctl list-timers --all --no-pager

section "At Jobs"
run_cmd "At queue" atq
run_cmd "at.allow" cat /etc/at.allow
run_cmd "at.deny" cat /etc/at.deny

section "Writable Service Files"
info "Checking for writable systemd service files..."
find /etc/systemd /lib/systemd /usr/lib/systemd -writable -name "*.service" -type f 2>/dev/null | while read -r f; do
    warn "Writable service file: $f"
done
echo ""

section "Docker Group Membership"
if id -nG 2>/dev/null | grep -qw docker; then
    warn "Current user is in the 'docker' group (potential root escalation)"
fi
if id -nG 2>/dev/null | grep -qw lxd; then
    warn "Current user is in the 'lxd' group (potential root escalation)"
fi

section "NFS Exports"
if [ -f /etc/exports ]; then
    echo "--- /etc/exports ---"
    cat /etc/exports 2>/dev/null
    if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
        warn "no_root_squash found in NFS exports (privilege escalation risk)"
    fi
    echo ""
fi

section "Doas Configuration"
run_cmd "doas.conf" cat /etc/doas.conf

section "Polkit Rules"
if [ -d /etc/polkit-1 ]; then
    info "Polkit rules found:"
    find /etc/polkit-1 /usr/share/polkit-1 -name "*.rules" -o -name "*.pkla" 2>/dev/null | while read -r f; do
        echo "  -> $f"
    done
fi
echo ""

#==============================================================================
# 4. NETWORK SECURITY
#==============================================================================
banner "NETWORK SECURITY"

section "Network Interfaces"
if command -v ip &>/dev/null; then
    run_cmd "IP addresses" ip addr show
    run_cmd "IP routes" ip route show
else
    run_cmd "Network interfaces" ifconfig -a
    run_cmd "Routing table" route -n
fi

section "DNS Configuration"
run_cmd "DNS resolvers" cat /etc/resolv.conf
run_cmd "Hosts file" cat /etc/hosts
run_cmd "nsswitch" cat /etc/nsswitch.conf

section "Listening Services"
if command -v ss &>/dev/null; then
    run_cmd "Listening sockets" ss -tulnp
else
    run_cmd "Listening sockets" netstat -tulnp
fi

section "Established Connections"
if command -v ss &>/dev/null; then
    run_cmd "Established connections" ss -tunp
else
    run_cmd "Established connections" netstat -tunp
fi

section "Firewall Rules"
run_cmd "iptables rules" iptables -L -n -v
run_cmd "iptables NAT" iptables -t nat -L -n -v
run_cmd "ip6tables rules" ip6tables -L -n -v
run_cmd "nftables rules" nft list ruleset
run_cmd "UFW status" ufw status verbose
run_cmd "firewalld status" firewall-cmd --state
run_cmd "firewalld zones" firewall-cmd --list-all

section "ARP Cache"
run_cmd "ARP table" arp -en

section "Network Namespaces"
run_cmd "Network namespaces" ip netns list

section "Open Ports via /proc"
if [ -r /proc/net/tcp ]; then
    info "Open TCP ports from /proc/net/tcp:"
    awk '{print $2}' /proc/net/tcp 2>/dev/null | grep -v "local_address" | while read -r addr; do
        port=$((16#${addr##*:}))
        [ "$port" -gt 0 ] 2>/dev/null && echo "  Port: $port"
    done | sort -t: -k2 -un
fi
echo ""

section "Promiscuous Mode Check"
if ip link show 2>/dev/null | grep -i promisc &>/dev/null; then
    warn "Network interface(s) in PROMISCUOUS mode detected"
else
    success "No interfaces in promiscuous mode"
fi

section "Wireless Interfaces"
run_cmd "Wireless interfaces" iwconfig

#==============================================================================
# 5. SSH SECURITY
#==============================================================================
banner "SSH SECURITY"

section "SSH Server Configuration"
for cfg in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [ -r "$cfg" ]; then
        echo "--- $cfg ---"
        grep -v "^#\|^$" "$cfg" 2>/dev/null
        echo ""
    fi
done

section "SSH Security Issues"
if [ -r /etc/ssh/sshd_config ]; then
    # Check PermitRootLogin
    root_login=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$root_login" = "yes" ]; then
        warn "SSH: PermitRootLogin is set to 'yes'"
    elif [ -n "$root_login" ]; then
        success "SSH: PermitRootLogin = $root_login"
    fi

    # Check PasswordAuthentication
    pass_auth=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$pass_auth" = "yes" ]; then
        warn "SSH: PasswordAuthentication is enabled"
    fi

    # Check PermitEmptyPasswords
    empty_pass=$(grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$empty_pass" = "yes" ]; then
        warn "SSH: PermitEmptyPasswords is enabled!"
    fi

    # Check Protocol
    proto=$(grep -i "^Protocol" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$proto" = "1" ]; then
        warn "SSH: Protocol 1 is enabled (insecure!)"
    fi

    # Check X11Forwarding
    x11=$(grep -i "^X11Forwarding" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$x11" = "yes" ]; then
        info "SSH: X11Forwarding is enabled"
    fi

    # Check MaxAuthTries
    max_auth=$(grep -i "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$max_auth" ] && [ "$max_auth" -gt 6 ] 2>/dev/null; then
        warn "SSH: MaxAuthTries is set high ($max_auth)"
    fi
fi

section "SSH Keys"
info "Authorized keys for current user:"
for f in ~/.ssh/authorized_keys ~/.ssh/authorized_keys2; do
    [ -r "$f" ] && run_cmd "$f" cat "$f"
done

info "SSH private keys for current user:"
for f in ~/.ssh/id_rsa ~/.ssh/id_dsa ~/.ssh/id_ecdsa ~/.ssh/id_ed25519; do
    if [ -r "$f" ]; then
        warn "Readable private key: $f"
        ls -la "$f"
        perms=$(stat -c "%a" "$f" 2>/dev/null)
        if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
            warn "  Insecure permissions on $f: $perms (should be 600 or 400)"
        fi
    fi
done
echo ""

info "SSH host keys:"
ls -la /etc/ssh/ssh_host_*_key 2>/dev/null
echo ""

section "SSH Known Hosts"
run_cmd "Known hosts" cat ~/.ssh/known_hosts
run_cmd "SSH config" cat ~/.ssh/config

section "SSH Agent"
run_cmd "SSH agent keys" ssh-add -l

#==============================================================================
# 6. FILE SYSTEM SECURITY
#==============================================================================
banner "FILE SYSTEM SECURITY"

section "World-Writable Files in Key Directories"
info "Searching for world-writable files..."
find /etc /usr /var -writable -type f 2>/dev/null | head -50 | while read -r f; do
    warn "World-writable: $f"
done
echo ""

section "World-Writable Directories (without sticky bit)"
find / -maxdepth 3 -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | while read -r d; do
    warn "World-writable dir (no sticky): $d"
done
echo ""

section "Files with No Owner"
find / -maxdepth 3 -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -20 | while read -r f; do
    warn "No owner/group: $f"
done
echo ""

section "Sensitive File Permissions"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    if [ -e "$f" ]; then
        echo "  $(ls -la "$f" 2>/dev/null)"
    fi
done
echo ""

section "Unmounted Filesystems"
run_cmd "/etc/fstab" cat /etc/fstab

section "Tmp Directories"
echo "Tmp directory permissions:"
for d in /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] && ls -ld "$d" 2>/dev/null
done
echo ""

if [ "$THOROUGH" -eq 1 ]; then
    section "Recently Modified Files (last 24h)"
    info "Files modified in /etc in the last 24 hours:"
    find /etc -mtime -1 -type f 2>/dev/null | while read -r f; do
        echo "  Modified: $f"
    done
    echo ""

    section "Large Files (>100MB)"
    find / -maxdepth 4 -xdev -type f -size +100M 2>/dev/null | while read -r f; do
        echo "  Large: $f ($(du -h "$f" 2>/dev/null | awk '{print $1}'))"
    done
    echo ""

    section "Hidden Files in /home and /root"
    find /home /root -maxdepth 3 -name ".*" -type f 2>/dev/null | while read -r f; do
        echo "  Hidden: $f"
    done
    echo ""
fi

section "Immutable Files"
if command -v lsattr &>/dev/null; then
    info "Checking for immutable files in /etc..."
    lsattr -R /etc/ 2>/dev/null | grep "\-i\-"
fi

#==============================================================================
# 7. PROCESS & SERVICE SECURITY
#==============================================================================
banner "PROCESS & SERVICE SECURITY"

section "Running Processes"
run_cmd "All processes" ps auxf
run_cmd "Processes running as root" ps aux --no-headers

section "Root Processes"
echo "Processes running as root:"
ps aux 2>/dev/null | awk '$1 == "root" {print "  " $0}'
echo ""

section "Services"
run_cmd "Enabled services" systemctl list-unit-files --type=service --state=enabled --no-pager
run_cmd "Running services" systemctl list-units --type=service --state=running --no-pager
run_cmd "Failed services" systemctl list-units --type=service --state=failed --no-pager

section "Inetd / Xinetd"
run_cmd "inetd config" cat /etc/inetd.conf
run_cmd "xinetd config" cat /etc/xinetd.conf
if [ -d /etc/xinetd.d ]; then
    echo "--- /etc/xinetd.d/ ---"
    ls -la /etc/xinetd.d/ 2>/dev/null
fi

section "Process Capabilities"
if [ "$THOROUGH" -eq 1 ]; then
    info "Checking process capabilities..."
    ps -eo pid,comm 2>/dev/null | while read -r pid comm; do
        caps=$(getpcaps "$pid" 2>/dev/null)
        if [ -n "$caps" ] && ! echo "$caps" | grep -q "=$" 2>/dev/null; then
            echo "  PID $pid ($comm): $caps"
        fi
    done
fi

#==============================================================================
# 8. SOFTWARE & PACKAGE SECURITY
#==============================================================================
banner "SOFTWARE & PACKAGE SECURITY"

section "Package Manager"
if command -v apt &>/dev/null; then
    info "Package manager: apt (Debian/Ubuntu)"
    run_cmd "Upgradable packages" apt list --upgradable
elif command -v yum &>/dev/null; then
    info "Package manager: yum (RedHat/CentOS)"
    run_cmd "Available updates" yum check-update
elif command -v dnf &>/dev/null; then
    info "Package manager: dnf (Fedora)"
    run_cmd "Available updates" dnf check-update
elif command -v pacman &>/dev/null; then
    info "Package manager: pacman (Arch)"
elif command -v apk &>/dev/null; then
    info "Package manager: apk (Alpine)"
fi

section "Installed Compilers & Dev Tools"
for tool in gcc cc g++ make python python3 perl ruby php node go javac gdb strace ltrace; do
    path=$(command -v "$tool" 2>/dev/null)
    [ -n "$path" ] && echo "  Found: $tool -> $path"
done
echo ""

section "File Transfer Tools"
for tool in wget curl netcat nc ncat socat tftp ftp scp rsync; do
    path=$(command -v "$tool" 2>/dev/null)
    [ -n "$path" ] && echo "  Found: $tool -> $path"
done
echo ""

section "Installed Security Tools"
for tool in nmap nikto hydra john hashcat aircrack-ng metasploit msfconsole burpsuite wireshark tcpdump; do
    path=$(command -v "$tool" 2>/dev/null)
    [ -n "$path" ] && info "Security tool found: $tool -> $path"
done
echo ""

section "Web Servers"
run_cmd "Apache version" apache2 -v
run_cmd "Apache version (httpd)" httpd -v
run_cmd "Nginx version" nginx -v
run_cmd "Apache modules" apache2ctl -M
run_cmd "Apache envvars" cat /etc/apache2/envvars

section "Databases"
run_cmd "MySQL version" mysql --version
run_cmd "PostgreSQL version" psql -V
run_cmd "MongoDB version" mongod --version
run_cmd "Redis version" redis-server --version
run_cmd "SQLite version" sqlite3 --version

section "Docker"
run_cmd "Docker version" docker --version
run_cmd "Docker containers" docker ps -a
run_cmd "Docker images" docker images

#==============================================================================
# 9. AUTHENTICATION & ACCESS CONTROL
#==============================================================================
banner "AUTHENTICATION & ACCESS CONTROL"

section "PAM Configuration"
if [ -d /etc/pam.d ]; then
    echo "--- PAM modules ---"
    ls -la /etc/pam.d/ 2>/dev/null
    echo ""
fi

section "Login Configuration"
run_cmd "/etc/login.defs (key settings)" grep -v "^#\|^$" /etc/login.defs
run_cmd "Securetty" cat /etc/securetty
run_cmd "Access control" cat /etc/security/access.conf

section "Failed Login Attempts"
run_cmd "Failed logins (btmp)" lastb -10
run_cmd "Auth log failures" grep -i "failed\|failure\|invalid" /var/log/auth.log

section "Account Lockout Policy"
run_cmd "pam_tally2" pam_tally2
run_cmd "faillock" faillock

section "SELinux"
if command -v getenforce &>/dev/null; then
    status=$(getenforce 2>/dev/null)
    if [ "$status" = "Enforcing" ]; then
        success "SELinux is Enforcing"
    elif [ "$status" = "Permissive" ]; then
        warn "SELinux is Permissive (not enforcing)"
    elif [ "$status" = "Disabled" ]; then
        warn "SELinux is Disabled"
    fi
    run_cmd "SELinux status" sestatus
fi

section "AppArmor"
if command -v apparmor_status &>/dev/null; then
    run_cmd "AppArmor status" apparmor_status
elif command -v aa-status &>/dev/null; then
    run_cmd "AppArmor status" aa-status
fi

section "Seccomp"
if [ -f /proc/self/status ]; then
    seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
    case $seccomp in
        0) info "Seccomp: Disabled" ;;
        1) info "Seccomp: Strict mode" ;;
        2) info "Seccomp: Filter mode" ;;
    esac
fi

#==============================================================================
# 10. CREDENTIAL & SECRET HUNTING
#==============================================================================
banner "CREDENTIAL & SECRET HUNTING"

section "Sensitive Files in Home Directories"
for dir in /root /home/*; do
    [ ! -d "$dir" ] && continue
    for f in .bash_history .mysql_history .psql_history .python_history \
             .lesshst .viminfo .wget-hsts .netrc .my.cnf .pgpass \
             .git-credentials .docker/config.json; do
        if [ -r "$dir/$f" ]; then
            warn "Readable: $dir/$f"
        fi
    done
done
echo ""

section "Configuration Files with Potential Credentials"
info "Searching for passwords in common config files..."
for f in /etc/mysql/my.cnf /etc/mysql/debian.cnf /var/lib/mysql/mysql/user.MYD \
         /etc/apache2/sites-available/*.conf /etc/apache2/htpasswd \
         /var/www/html/wp-config.php /var/www/html/configuration.php \
         /var/www/html/config.php /var/www/html/.env \
         /etc/openvpn/*.conf /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
         /etc/vsftpd.conf /etc/proftpd/proftpd.conf \
         /opt/lampp/etc/httpd.conf /root/anaconda-ks.cfg; do
    if [ -r "$f" ]; then
        warn "Readable config: $f"
    fi
done
echo ""

section "Environment Variables with Secrets"
info "Checking environment for potential secrets..."
env 2>/dev/null | grep -iE "pass|secret|key|token|api|auth|cred" | while read -r line; do
    varname=$(echo "$line" | cut -d= -f1)
    warn "Sensitive env var: $varname=<REDACTED>"
done
echo ""

section ".env Files"
info "Searching for .env files..."
find / -maxdepth 5 -name ".env" -type f 2>/dev/null | while read -r f; do
    warn "Found .env file: $f"
done
echo ""

section "Private Keys"
info "Searching for private key files..."
find / -maxdepth 5 -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | while read -r f; do
    [ -r "$f" ] && warn "Readable key file: $f"
done
echo ""

section "Git Repositories with Credentials"
info "Searching for git credential files..."
find / -maxdepth 5 -name ".git-credentials" -o -name ".gitconfig" 2>/dev/null | while read -r f; do
    [ -r "$f" ] && warn "Found git credential file: $f"
done
echo ""

if [ -n "$KEYWORD" ]; then
    section "Keyword Search: '$KEYWORD'"
    info "Searching for keyword in config/log files..."
    find /etc /var/log -maxdepth 3 -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.log" -o -name "*.php" -o -name "*.xml" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o -name "*.env" -o -name "*.properties" \) 2>/dev/null | while read -r f; do
        matches=$(grep -l "$KEYWORD" "$f" 2>/dev/null)
        [ -n "$matches" ] && echo "  Match in: $f"
    done
    echo ""
fi

#==============================================================================
# 11. LOG & AUDIT SECURITY
#==============================================================================
banner "LOG & AUDIT SECURITY"

section "Log Files"
echo "Available log files:"
ls -la /var/log/ 2>/dev/null
echo ""

section "Syslog Configuration"
run_cmd "rsyslog config" cat /etc/rsyslog.conf
run_cmd "syslog-ng config" cat /etc/syslog-ng/syslog-ng.conf

section "Audit Framework"
if command -v auditctl &>/dev/null; then
    run_cmd "Audit rules" auditctl -l
    run_cmd "Audit status" auditctl -s
else
    info "auditd is not installed"
fi

section "Log Permissions"
info "Checking log file permissions..."
find /var/log -maxdepth 1 -type f -perm -o+w 2>/dev/null | while read -r f; do
    warn "World-writable log: $f"
done
echo ""

section "Recent Auth Events"
run_cmd "Recent auth.log (last 30 lines)" tail -30 /var/log/auth.log
run_cmd "Recent secure log (last 30 lines)" tail -30 /var/log/secure

section "Recent Sudo Usage"
grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -20
grep -i "sudo" /var/log/secure 2>/dev/null | tail -20
echo ""

#==============================================================================
# 12. KERNEL & SYSTEM HARDENING
#==============================================================================
banner "KERNEL & SYSTEM HARDENING"

section "Kernel Modules"
run_cmd "Loaded modules" lsmod

section "Kernel Security Parameters"
info "Checking sysctl security settings..."
declare -A expected_sysctl=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.all.accept_source_route"]="0"
    ["kernel.randomize_va_space"]="2"
    ["kernel.exec-shield"]="1"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="1"
    ["fs.suid_dumpable"]="0"
    ["fs.protected_hardlinks"]="1"
    ["fs.protected_symlinks"]="1"
)

for key in "${!expected_sysctl[@]}"; do
    val=$(sysctl -n "$key" 2>/dev/null)
    expected="${expected_sysctl[$key]}"
    if [ -z "$val" ]; then
        continue
    elif [ "$val" = "$expected" ]; then
        success "$key = $val"
    else
        warn "$key = $val (recommended: $expected)"
    fi
done
echo ""

section "Core Dumps"
core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
if [ -n "$core_pattern" ]; then
    info "Core dump pattern: $core_pattern"
fi
if grep -q "hard.*core.*0" /etc/security/limits.conf 2>/dev/null; then
    success "Core dumps disabled in limits.conf"
else
    warn "Core dumps may not be disabled (check /etc/security/limits.conf)"
fi

section "GRUB Security"
if [ -f /boot/grub/grub.cfg ]; then
    if grep -q "password" /boot/grub/grub.cfg 2>/dev/null; then
        success "GRUB appears to be password protected"
    else
        warn "GRUB does not appear to be password protected"
    fi
fi

section "Compiler Access"
for comp in gcc g++ cc make; do
    if command -v "$comp" &>/dev/null; then
        perms=$(stat -c "%a" "$(command -v "$comp")" 2>/dev/null)
        echo "  $comp permissions: $perms"
    fi
done
echo ""

#==============================================================================
# 13. WEB APPLICATION SECURITY
#==============================================================================
banner "WEB APPLICATION SECURITY"

section "Web Root Directories"
for d in /var/www /srv/www /usr/local/www /opt/lampp/htdocs; do
    if [ -d "$d" ]; then
        echo "--- $d ---"
        ls -alR "$d" 2>/dev/null | head -50
        echo ""
    fi
done

section "Web Config Files"
run_cmd "Apache config" cat /etc/apache2/apache2.conf
run_cmd "Apache sites" ls -la /etc/apache2/sites-enabled/
run_cmd "Nginx config" cat /etc/nginx/nginx.conf
run_cmd "Nginx sites" ls -la /etc/nginx/sites-enabled/
run_cmd "PHP config" php -i
run_cmd "Lighttpd config" cat /etc/lighttpd/lighttpd.conf

section "SSL/TLS Certificates"
info "Looking for SSL certificates..."
find /etc/ssl /etc/pki /etc/letsencrypt -name "*.crt" -o -name "*.pem" -o -name "*.cert" 2>/dev/null | while read -r f; do
    if [ -r "$f" ]; then
        expiry=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | cut -d= -f2)
        if [ -n "$expiry" ]; then
            echo "  Certificate: $f (expires: $expiry)"
        fi
    fi
done
echo ""

#==============================================================================
# 14. CONTAINER & VIRTUALIZATION SECURITY
#==============================================================================
banner "CONTAINER & VIRTUALIZATION SECURITY"

section "Docker Security"
if command -v docker &>/dev/null; then
    run_cmd "Docker info" docker info
    info "Checking Docker socket permissions..."
    if [ -S /var/run/docker.sock ]; then
        ls -la /var/run/docker.sock
        if [ -w /var/run/docker.sock ]; then
            warn "Docker socket is writable by current user (potential root escalation)"
        fi
    fi
    echo ""
    info "Checking for privileged containers..."
    docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
        if docker inspect "$id" 2>/dev/null | grep -q '"Privileged": true'; then
            warn "Privileged container: $name ($id)"
        fi
    done
fi

section "LXC/LXD"
run_cmd "LXC containers" lxc list
run_cmd "LXD info" lxc info

section "Kubernetes"
run_cmd "kubectl config" kubectl config view
run_cmd "Kubernetes pods" kubectl get pods --all-namespaces

#==============================================================================
# 15. BACKUP & RECOVERY
#==============================================================================
banner "BACKUP & RECOVERY ASSESSMENT"

section "Backup Files"
info "Searching for backup files..."
find / -maxdepth 4 -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.orig" \
    -o -name "*.save" -o -name "*.swp" -o -name "*~" 2>/dev/null | head -30 | while read -r f; do
    echo "  Backup: $f"
done
echo ""

section "Database Dumps"
info "Searching for database dumps..."
find / -maxdepth 4 -name "*.sql" -o -name "*.sql.gz" -o -name "*.dump" 2>/dev/null | head -20 | while read -r f; do
    warn "Database dump: $f"
done
echo ""

#==============================================================================
# 16. THOROUGH CHECKS (if enabled)
#==============================================================================
if [ "$THOROUGH" -eq 1 ]; then
    banner "THOROUGH CHECKS"

    section "All Writable Directories"
    find / -maxdepth 4 -writable -type d 2>/dev/null | while read -r d; do
        echo "  Writable dir: $d"
    done
    echo ""

    section "All Executable Directories"
    find / -maxdepth 4 -perm -o+x -type d 2>/dev/null | head -50 | while read -r d; do
        echo "  Executable dir: $d"
    done
    echo ""

    section "Sticky Bit Directories"
    find / -maxdepth 4 -perm -1000 -type d 2>/dev/null | while read -r d; do
        echo "  Sticky bit: $d"
    done
    echo ""

    section "Files Modified in Last 7 Days (outside /proc /sys /run)"
    find / -maxdepth 4 -xdev -mtime -7 -type f \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" \
        -not -path "/var/log/*" -not -path "/tmp/*" 2>/dev/null | head -50 | while read -r f; do
        echo "  Recent: $f ($(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1))"
    done
    echo ""

    section "Installed Packages"
    if command -v dpkg &>/dev/null; then
        run_cmd "Debian/Ubuntu packages" dpkg -l
    elif command -v rpm &>/dev/null; then
        run_cmd "RPM packages" rpm -qa
    elif command -v pacman &>/dev/null; then
        run_cmd "Arch packages" pacman -Q
    elif command -v apk &>/dev/null; then
        run_cmd "Alpine packages" apk list --installed
    fi

    section "Open File Descriptors"
    run_cmd "Open files (lsof summary)" lsof -n
fi

#==============================================================================
# SUMMARY
#==============================================================================
banner "SCAN COMPLETE"
echo ""
echo -e "${CYAN}  Scan finished: $(date)${NC}"
echo -e "${CYAN}  Host:          $(hostname 2>/dev/null)${NC}"
echo -e "${CYAN}  Kernel:        $(uname -r 2>/dev/null)${NC}"
if [ -n "$REPORT_FILE" ]; then
    echo -e "${GREEN}  Report saved:  $REPORT_FILE${NC}"
fi
echo ""
echo -e "${YELLOW}  Review all [!] warnings above for potential security issues.${NC}"
echo -e "${YELLOW}  Run with -t flag for thorough checks if not already done.${NC}"
echo ""
