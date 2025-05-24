# 🛡️ Linux Security Investigation Cheat Sheet
> SOC Analysts • Blue Team • Incident Responders  
> 📦 Debian/Ubuntu & RHEL/CentOS | OWASP/MITRE-Aligned

---

## ✅ Sections Included

- Failed Logins
- IP Bans & Network Abuse
- Botnets & Miners
- CPU/RAM Triage
- Privilege Escalation
- Persistence & Cron Implants
- RCE / Webshells
- Exposed Services
- Vulnerability / Patch Management
- File Exfiltration
- 🔍 Rootkit Detection ✅ (new)
- Tool Recommendations

---

## 🧠 1. Investigating Failed Logins

**Debian/Ubuntu:** `/var/log/auth.log`  
**RHEL/CentOS:** `/var/log/secure`

```bash
# View failed SSH logins
grep "Failed password" /var/log/auth.log
lastb

grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head
```

```bash
# For RHEL:
grep "Failed password" /var/log/secure
```

```bash
# Systemd based (generic)
journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed password"
journalctl -u ssh | grep "Failed password" | grep "from"
```

---

## 🌐 2. IP Bans & Network Abuse

```bash
ss -tuna
sudo lsof -i -nP | grep LISTEN
```

### Fail2Ban Manual Control
```bash
sudo fail2ban-client set sshd banip <IP>
sudo fail2ban-client set sshd unbanip <IP>
```

### Manual IP Block (iptables)
```bash
sudo iptables -A INPUT -s <IP> -j DROP
sudo iptables -L --line-numbers
sudo iptables -D INPUT <line_number>
```

---

## 🐍 3. Botnet Infection Detection

```bash
ss -tuap | grep -v "127.0.0.1"
pstree -p | less
find /tmp /dev/shm /var/tmp -type f -executable
grep -riE 'botnet|cnc|stratum|pool' /etc/ /tmp/ /var/
```

---

## ⚙️ 4. High CPU / RAM Usage Triage

```bash
ps aux --sort=-%cpu | head
ps aux --sort=-%mem | head
ps aux | grep -E '/tmp/|\.sh|\.py|watchdog|kdevtmpfsi'
```

---

## 🔐 5. Privilege Escalation Abuse

```bash
grep 'sudo:' /var/log/auth.log
awk -F: '$3 == 0 { print $1 }' /etc/passwd
```

---

## 🔁 6. Persistence & Cron Implants

```bash
crontab -l
cat /etc/crontab
ls /etc/cron.* /var/spool/cron
grep -Ei 'curl|wget|base64' ~/.bashrc /etc/rc.local /etc/profile
```

---

## 💣 7. Remote Code Execution / Webshell Detection

```bash
find /var/www/ -name "*.php" -exec grep -Ei 'base64_decode|eval|system|exec' {} \;
find /var/www/ -type f -ctime -2
find /var/www/ -type d -perm -o+w
```

---

## 🌍 8. Service Exposure (Open Ports / Services)

```bash
sudo systemctl list-units --type=service
sudo lsof -i -P -n | grep LISTEN
sudo nmap -sS -sV -T4 localhost
```

---

## 🧬 9. Vulnerability & Patch Management

**Debian/Ubuntu:**
```bash
sudo apt update && apt list --upgradable
ubuntu-security-status
```

**RHEL/CentOS:**
```bash
sudo yum check-update
```

### Deeper Checks
```bash
sudo apt install lynis
sudo lynis audit system
```

```bash
osqueryi "SELECT * FROM patches;"
```

---

## 📤 10. File Exfiltration & Unauthorized Access

```bash
iftop     # Monitor bandwidth
nethogs   # Per-process network usage
```

```bash
find / -type f -size +100M -exec ls -lh {} \;
find / -type f -perm -o=r ! -path "/proc/*" -ls
```

---

## 🔍 11. Rootkit Detection & Analysis

### Recommended Tools

| Tool          | Purpose                             |
|---------------|--------------------------------------|
| `chkrootkit`  | Detects common rootkits              |
| `rkhunter`    | Hidden files/processes & rootkits    |
| `unhide`      | Hidden ports/users/PIDs              |
| `lynis`       | Suspicious behaviors/configs         |

### Basic Scans
```bash
sudo chkrootkit
sudo rkhunter --update
sudo rkhunter --check --skip-keypress
```

### Spot Hidden Behavior
```bash
unhide quick
ls -1 /proc | grep '^[0-9]' | wc -l
ps -ef | wc -l
```

```bash
netstat -tulpn | grep LISTEN
ps aux | awk '{print $11}' | sort | uniq -c | sort -nr | head
```

### Red Flags
- Processes in `/dev` or `/tmp`
- Mismatch in `/proc` vs `ps`
- `/etc/ld.so.preload` is not empty
- Hidden listeners (no parent PID)

---

## 📦 12. Tools Reference

| Tool         | Function                            |
|--------------|--------------------------------------|
| `chkrootkit` | Scan for known rootkits              |
| `rkhunter`   | Hidden files/processes/rootkits      |
| `unhide`     | Detect hidden users/PIDs/ports       |
| `lynis`      | System audit & config hardening      |
| `iftop`      | Bandwidth monitor                    |
| `fail2ban`   | Brute-force mitigation               |
| `osquery`    | OS as a database for live forensics  |

---

> Built for visibility in dark mode ⬛ with command block formatting and section headers.
> Want a printable PDF version or integration with GitHub Actions for daily checks? Just ask.
