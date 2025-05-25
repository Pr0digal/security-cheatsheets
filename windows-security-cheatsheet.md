# 🛡️ Windows Security Investigation Cheat Sheet

> SOC Analysts • Blue Team • Incident Responders> 🔧 Focused on Windows Server & Enterprise Environments

---

## ✅ Sections Included

- Failed Logons (Event IDs)
- RDP Brute Force / Lateral Movement
- Privilege Escalation & Sudo Equivalents
- Process & Service Anomalies
- Network Connections & Beaconing
- Persistence (Registry / Startup / Sched Tasks)
- Suspicious Binaries / Signed Malware
- Memory Forensics & Dump Checks
- Patch & Vulnerability Status
- Rootkit / AV Evasion
- Toolset Reference

---

## 🧠 1. Investigating Failed Logons

```powershell
# Failed logons: Event ID 4625 (bad password or username)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 |
  Format-Table TimeCreated, Message -AutoSize

# Filter by username
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} |
  Where-Object { $_.Message -like '*USERNAME*' } |
  Format-Table TimeCreated, Message
```

---

## 🌐 2. RDP Brute Force / Lateral Movement

```powershell
# Event ID 4625 with LogonType 10 = RDP failure
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} |
  Where-Object { $_.Message -like '*Logon Type: 10*' }

# Event ID 4624 with LogonType 10 = RDP success
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
  Where-Object { $_.Message -like '*Logon Type: 10*' }

# Check for abnormal logon times/IPs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
  Format-List TimeCreated, Message
```

---

## 🔐 3. Privilege Escalation

```powershell
# Check who is in Administrators group
Get-LocalGroupMember -Group "Administrators"

# Detect UAC bypasses via scheduled tasks or reg
Get-ScheduledTask | Where-Object {$_.TaskPath -like '*\Microsoft\Windows\*'}

# Search for tokens or privilege flags (Sysinternals)
whoami /groups
whoami /priv
```

---

## 🔋 4. High CPU / RAM / Process Abuse

```powershell
# List top CPU consuming processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Find processes with high memory usage
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10

# Suspicious parent-child trees
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId
```

---

## 📀 5. Network Monitoring / C2 / Beaconing

```powershell
# List active network connections
netstat -anob

# Detect long-running connections
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}

# Find unexpected listening ports
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}
```

---

## 🔄 6. Persistence Mechanisms

```powershell
# Registry autoruns
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Scheduled Tasks
schtasks /query /fo LIST /v | findstr /i "User: TaskName:"

# Startup folder
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## 🧰 7. Suspicious Binaries / LOLBins

```powershell
# Search for known living-off-the-land binaries
Get-ChildItem -Recurse -Include *.ps1,*.bat,*.vbs,*.exe -Path C:\Users -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'certutil|mshta|wscript|cscript|bitsadmin' }

# Signed binaries check (if available)
Get-AuthenticodeSignature "C:\Path\To\File.exe"
```

---

## 🔀 8. Memory Dump / Forensics

```powershell
# List loaded modules for suspicious processes
Get-Process | ForEach-Object {
    Write-Output $_.ProcessName
    ($_.Modules | Select-Object ModuleName, FileName)
}

# Capture live memory (3rd party: WinPMEM, FTK Imager, etc.)
```

---

## 🔧 9. Patch Status / Vulnerabilities

```powershell
# View installed updates
Get-HotFix

# Compare against latest KB baselines (manual or WSUS)
# Use MBSA, Nessus, or Qualys for vuln scanning
```

---

## ☠️ 10. Rootkit / AV Evasion

- Use **Sysinternals** tools:

  - `sigcheck` - Verify signature anomalies
  - `autoruns` - Full list of startup items
  - `procmon` - Live system call monitoring
  - `tcpview` - GUI for live connections

- 3rd party:

  - GMER (rootkit scan)
  - Kaspersky TDSSKiller
  - Microsoft Defender Offline Scan

---

## 🔹 Toolset Summary

| Tool            | Purpose                                   |
| --------------- | ----------------------------------------- |
| `eventvwr`      | Event Viewer                              |
| `Get-WinEvent`  | Logon/logoff audit logs                   |
| `netstat`       | Show connections & listeners              |
| `schtasks`      | Scheduled tasks                           |
| `reg query`     | Persistence in registry                   |
| `Sysinternals`  | Process/network/dll/memory investigations |
| `WMIC`, `WMI`   | Deep system interrogation                 |
| `sigcheck`      | Verify digital signatures                 |
| `osquery (win)` | Optional DB-style query system (advanced) |

---

> Optimized for dark mode ⬛ with PowerShell formatting blocks and structured forensic flows.
