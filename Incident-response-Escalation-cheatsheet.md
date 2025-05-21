# 🛡️ Incident Response Escalation Cheat Sheet

A quick reference guide for common security incidents and their escalation paths within a typical enterprise Security Operations environment.

---

## 🔥 Malware Infection
- **Trigger**: Antivirus/EDR detects suspicious behavior or known malware
- **Escalation Path**:
  - L1 SOC → L2 Analyst (containment & investigation)
  - ➤ IR Team if multiple hosts affected
  - ➤ CISO if APT or targeted attack suspected

---

## 🧑‍💻 Phishing / BEC (Business Email Compromise)
- **Trigger**: User reports suspicious email or credential compromise
- **Escalation Path**:
  - L1 SOC → Email Security Team or L2 IR
  - ➤ IAM Team for password resets & MFA enforcement
  - ➤ Legal/CFO if financial fraud or data loss risk

---

## 📁 Data Exfiltration / Data Leak
- **Trigger**: DLP alerts, large outbound data transfers, or sensitive data sent externally
- **Escalation Path**:
  - L2 IR → Legal / Compliance / Data Privacy Officer
  - ➤ Notify Executives if PII or IP compromised

---

## 🕵️ Insider Threat
- **Trigger**: DLP alert, abnormal user behavior, whistleblower tip
- **Escalation Path**:
  - IR Team → HR + Legal
  - ➤ Internal Audit
  - ➤ CISO / Board if severe

---

## 🌐 Web Server or Application Compromise
- **Trigger**: WAF logs, public researcher report, external scanner
- **Escalation Path**:
  - IR Team → AppSec / DevOps / Cloud Infra Team
  - ➤ CISO + Legal if user data is involved

---

## 🧩 Privilege Escalation / Lateral Movement
- **Trigger**: EDR/UEBA detects abnormal credential use or attack techniques (e.g., Kerberoasting)
- **Escalation Path**:
  - Threat Hunting → IR Team
  - ➤ Directory Services Team
  - ➤ CISO if domain compromise suspected

---

## 🌩️ Ransomware Detected
- **Trigger**: File encryption, ransom note, endpoint alerts
- **Escalation Path**:
  - Immediate → IR Lead + CISO + Exec Leadership
  - ➤ Legal, Comms, PR
  - ➤ Law Enforcement (as per playbook)

---

## 🛑 Denial of Service (DoS / DDoS)
- **Trigger**: Monitoring shows traffic spikes, service outages
- **Escalation Path**:
  - SOC → Network/CloudOps Teams
  - ➤ ISP / Cloud Provider / Law Enforcement if prolonged

---

## 🕸️ Third-Party Vendor Breach
- **Trigger**: Notification from vendor, abnormal third-party behavior
- **Escalation Path**:
  - Vendor Mgmt Team → Legal + IR
  - ➤ Risk Team
  - ➤ Executive Review

---

## 🔒 Unauthorized Access Attempt
- **Trigger**: Brute-force alerts, anomalous login location/times, MFA abuse
- **Escalation Path**:
  - L1 SOC → IAM + L2 IR
  - ➤ Security Engineering if IAM bypassed
  - ➤ CISO if attacker gained internal access

---

## 📌 Notes
- Escalation thresholds depend on:
  - Data sensitivity (PII, PCI, IP)
  - Business impact (availability, reputation, revenue)
  - Compliance implications (GDPR, HIPAA, etc.)

---

## 📚 Recommended Reading
- NIST 800-61 Rev. 2 – Computer Security Incident Handling Guide
- MITRE ATT&CK Framework
- SANS Incident Handler's Handbook

---
