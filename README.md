# LinuxLight

A comprehensive Linux security auditing tool for system administrators and security professionals. LinuxLight performs a thorough check of your Linux system for potential security issues, misconfigurations, and privilege escalation vectors.

## Features

LinuxLight checks for security issues across 16 categories:

1. **System Information** - OS, kernel, CPU, memory, virtualization detection
2. **User & Group Security** - UID-0 accounts, empty passwords, sudo config, password policy
3. **Privilege Escalation Vectors** - SUID/SGID binaries, capabilities, writable cron jobs, NFS exports, Docker group, writable service files, polkit rules
4. **Network Security** - Listening services, firewall rules, promiscuous mode, open ports
5. **SSH Security** - Config hardening checks, key permissions, PermitRootLogin, empty passwords
6. **File System Security** - World-writable files/dirs, no-owner files, sensitive file permissions, immutable files
7. **Process & Service Security** - Root processes, enabled services, inetd/xinetd
8. **Software & Packages** - Compilers, dev tools, transfer tools, web servers, databases, Docker
9. **Authentication & Access Control** - PAM, SELinux, AppArmor, Seccomp, account lockout
10. **Credential & Secret Hunting** - History files, config credentials, .env files, private keys, env vars
11. **Log & Audit Security** - Log permissions, audit framework, recent auth events
12. **Kernel & System Hardening** - Sysctl security params, core dumps, GRUB protection, ASLR
13. **Web Application Security** - Web roots, configs, SSL certificate expiry
14. **Container & Virtualization** - Docker socket, privileged containers, LXC/LXD, Kubernetes
15. **Backup & Recovery** - Backup files, database dumps
16. **Thorough Checks** - Extended file searches, recent modifications, full package lists

## Usage

```bash
# Quick scan
./light.sh

# Full thorough scan
./light.sh -t

# Scan and search for a keyword in configs
./light.sh -k password

# Save output to a report file
./light.sh -r report.txt

# Combined options
./light.sh -t -k secret -r /tmp/audit.txt
```

### Options

| Flag | Description |
|------|-------------|
| `-t` | Enable thorough/lengthy checks (SUID, world-writable, etc.) |
| `-k <keyword>` | Search for keyword in config/log files |
| `-r <file>` | Save output to report file |
| `-e <dir>` | Export directory for detailed findings |
| `-h` | Show help message |

## Requirements

- Bash 4.0+
- Run as root for complete results (many checks require elevated privileges)
- Standard Linux utilities (ps, find, grep, awk, etc.)

## Output

The script uses color-coded output:
- `[!]` Red warnings for potential security issues
- `[✓]` Green for passing checks
- `[i]` Cyan for informational messages
- `[*]` Section headers
- `[+]` Subsection headers

## Notes

- Running as a non-root user will produce partial results since many security checks require elevated privileges
- The `-t` (thorough) flag enables deeper filesystem searches that may take significantly longer
- This tool is intended for **defensive security auditing** of systems you are authorized to test
