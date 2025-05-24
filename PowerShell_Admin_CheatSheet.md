
# ⚡ PowerShell Cheat Sheet for Windows Administrators

A compact and practical guide for IT administrators using PowerShell to manage systems, users, networks, and services in a Windows environment. Designed for quick reference and productivity.

> 🔐 Ideal for Helpdesk, SysAdmins, Security Engineers, and Power Users.

---

## 📁 System Info & Health

```powershell
Get-ComputerInfo                          # Full system details
Get-EventLog -LogName System -Newest 20  # Last 20 system logs
Get-Process                               # List running processes
Get-Service                               # List services and statuses
Get-HotFix                                # View installed updates
systeminfo                                # Legacy system info
```

## 🧑‍💻 Active Directory User & Group Management

> Requires: **RSAT Active Directory Module**

```powershell
Get-ADUser -Filter *                                  # List all AD users
Get-ADGroup -Filter *                                 # List all AD groups
Get-ADUser -Identity jdoe                             # Get user by samAccountName
Get-ADGroupMember "Domain Admins"                     # View group members

New-ADUser -Name "Jane Doe" -SamAccountName "jdoe" `
  -AccountPassword (Read-Host -AsSecureString) `
  -Enabled $true

Add-ADGroupMember -Identity "IT" -Members jdoe        # Add user to group
Remove-ADUser -Identity jdoe                          # Remove AD user
```

## 📂 File & Folder Operations

```powershell
Get-ChildItem "C:\Logs"
Copy-Item "C:\file.txt" "D:\Backup"
Move-Item "C:\file.txt" "D:\Archive"
Remove-Item "C:\temp\*" -Recurse
New-Item -ItemType File "C:\NewFile.txt"
```

## 🔐 Local Users & Groups

```powershell
Get-LocalUser
New-LocalUser "tempadmin" -Password (Read-Host -AsSecureString) -FullName "Temp Admin" -Description "Temp Access"
Add-LocalGroupMember -Group "Administrators" -Member "tempadmin"
Remove-LocalUser "tempadmin"
```

## 🔁 Services & Processes

```powershell
Get-Service "Spooler"
Start-Service "Spooler"
Stop-Service "Spooler"
Restart-Service "Spooler"
Get-Process | Sort-Object CPU -Desc
Stop-Process -Name "notepad" -Force
```

## 🌐 Network Utilities

```powershell
Test-Connection google.com
Get-NetIPAddress
Get-NetAdapter
Get-DnsClientServerAddress
```

## 📦 Software Management

```powershell
Get-Package
Get-WmiObject -Class Win32_Product
Uninstall-Package -Name "AppName"
```

## 📜 Scheduled Tasks

```powershell
Get-ScheduledTask
Register-ScheduledTask
Unregister-ScheduledTask -TaskName "BackupTask" -Confirm:$false
```

## 📊 Disk & Storage

```powershell
Get-PSDrive
Get-Volume
Get-Disk
Get-Partition
```

## 🧪 System Utilities

```powershell
sfc /scannow
chkdsk
```

## 📝 Notes & Tips

- Use `-WhatIf` or `-Confirm` when testing destructive commands.
- Always **Run as Administrator** when managing system-level tasks.
- For AD cmdlets, install **RSAT Tools**:
```powershell
Add-WindowsFeature RSAT-AD-PowerShell
```

## 🔗 Resources

- 📘 [Microsoft Docs – PowerShell](https://docs.microsoft.com/powershell/)
- 🔍 [SS64 PowerShell Reference](https://ss64.com/ps/)
- 🛠️ [PowerShell Gallery](https://www.powershellgallery.com/)

## 🙌 Contribute

Feel free to fork, star ⭐, and improve the cheat sheet. Pull requests welcome!
