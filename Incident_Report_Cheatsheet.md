# 🛡️ Cybersecurity Incident Report – IR-XXXX-YYYY

> Fill in the placeholders as needed. Use checkboxes and code blocks where useful.

---

## ✅ 1. Incident Metadata

| Field              | Value                     |
|--------------------|---------------------------|
| **Incident ID**     | IR-2025-XXXX              |
| **Reported By**     |                           |
| **Detection Time**  | YYYY-MM-DD HH:MM (AEST)   |
| **Detection Source**| e.g., EDR, SIEM, Email    |
| **Severity**        | Low / Medium / High / Critical |
| **Current Status**  | Open / Investigating / Contained / Resolved / Closed |

---

## 🔍 2. Executive Summary

> One-paragraph overview of the incident (who, what, where, when, impact).

---

## 🧠 3. Incident Classification

| Category       | Details                            |
|----------------|-------------------------------------|
| **Type**        | Malware / Phishing / Insider Threat / etc. |
| **Initial Vector** | Email / Web / RDP / USB / etc.     |
| **MITRE ATT&CK**   | e.g., T1059.001 (PowerShell)       |
| **Impacted Assets**| Hostnames, IPs, or device IDs     |
| **Affected Users** | Usernames or service accounts      |

---

## 🧾 4. Technical Details

### 🔁 Timeline of Events

YYYY-MM-DD HH:MM - Alert triggered via EDR
YYYY-MM-DD HH:MM - Analyst begins triage
YYYY-MM-DD HH:MM - Host isolated
YYYY-MM-DD HH:MM - Memory dump collected


### 🧬 Indicators of Compromise (IOCs)
- IP: `x.x.x.x`
- File hash: `abc123...`
- Domain: `malicious[.]site`

### 📄 Relevant Logs
- [ ] EDR logs
- [ ] PowerShell transcripts
- [ ] Event Logs (IDs: 4624, 4688, etc.)
- [ ] PCAP / NetFlow exports

---

## 🛑 5. Containment & Mitigation

| Step               | Action Taken                              |
|--------------------|--------------------------------------------|
| **Host Isolation**  | `hostname` removed from network           |
| **User Actions**    | Reset password for `username`             |
| **Blocking**        | IP/domain blocked at firewall/WAF         |
| **Patching**        | Relevant KBs or updates applied           |

---

## 🧪 6. Root Cause Analysis

- **Entry Point:**  
- **Exploit Mechanism:**  
- **Privilege Escalation / Lateral Movement:**  
- **Security Gaps Identified:**  

---

## 🧼 7. Remediation & Lessons Learned

| Area             | Recommendation / Action Item               |
|------------------|---------------------------------------------|
| Authentication   | Implement MFA for all privileged users      |
| Awareness        | Phishing simulation/training                |
| Logging          | Enable command-line and PowerShell auditing |
| Automation       | Expand SOAR to auto-isolate infected hosts  |

---

## 📎 8. Attachments / Evidence

- [ ] `alert-summary.pdf`
- [ ] `memory-dump.raw`
- [ ] `network-traffic.pcap`
- [ ] `screenshot.png`
- [ ] `hashes.txt`

---

## 🚦 9. Final Status

| Field            | Details                                   |
|------------------|-------------------------------------------|
| **Resolved On**   | YYYY-MM-DD                                |
| **Resolution**    | e.g., Host reimaged, credentials rotated  |
| **Notified Parties** | CISO / Legal / External as required     |
| **Closed By**     | Name, Role                                |

---

## 📚 Appendix

- [MITRE ATT&CK Navigator](https://attack.mitre.org/)
- [VirusTotal](https://www.virustotal.com/)
- [Shodan](https://www.shodan.io/)

