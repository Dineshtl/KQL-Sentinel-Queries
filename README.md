# 🔍 KQL Queries — Microsoft Sentinel

> Collection of KQL queries used for threat detection 
> and investigation in Microsoft Sentinel lab environment.
> Author: Thumma Lakshmikanth Gari Dinesh
> Role: Junior SOC Analyst

---

## 📋 Query Index

| # | Query Name | Use Case |
|---|-----------|----------|
| 1 | Failed Login Detection | Brute Force |
| 2 | Successful Login Monitor | User Activity |
| 3 | Brute Force Detection | Attack Detection |
| 4 | Suspicious PowerShell | Malware Detection |
| 5 | New User Created | Privilege Escalation |
| 6 | User Added to Admin Group | Privilege Escalation |
| 7 | Security Alerts Overview | SOC Monitoring |
| 8 | Incidents by Severity | SOC Dashboard |

---

## 1️⃣ Failed Login Detection (EventID 4625)

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer
| order by FailedAttempts desc
```
**Use Case:** Detects accounts with multiple failed logins
**Threat:** Brute Force / Credential Stuffing
<img width="1433" height="627" alt="Screenshot 2026-04-22 154152" src="https://github.com/user-attachments/assets/c38d8cc0-4766-47b6-bee2-cc18c7ed0fc8" />
### 🔴 Investigation Finding:
- **ADMINISTRATOR** account — 12,624 failed attempts 🔴 Critical
- **ADMIN** account — 5,266 failed attempts 🔴 Critical
- **USER** account — 1,405 failed attempts 🔴 High
- All attempts targeting same machine — **WindowsVM**
- **Verdict: TRUE POSITIVE — Active Brute Force Attack confirmed!**
- **Action: Lock account + Block source IP + Escalate to L2**
---

## 2️⃣ Successful Login Monitor (EventID 4624)

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer, IpAddress, LogonType
| order by TimeGenerated desc
```
**Use Case:** Tracks successful logins across environment
**Threat:** Unauthorized access detection
<img width="1900" height="910" alt="image" src="https://github.com/user-attachments/assets/d6aa2674-6ac7-4286-9daa-27cbd2be2e73" />
### ✅ Investigation Finding:
- **Account:** NT AUTHORITY\SYSTEM
- **Computer:** WIN-5EJCIO9KVIB
- **LogonType:** 5 (Service Logon)
- **Total Events:** 27 in last 24 hours
- **Verdict: FALSE POSITIVE — Normal system service logons**
- **Reason: NT AUTHORITY\SYSTEM service logons every hour is standard Windows behavior**

---

## 3️⃣ Brute Force Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedCount = count() by IpAddress, bin(TimeGenerated, 1h)
| where FailedCount > 5
| order by FailedCount desc
```
**Use Case:** Detects IPs with 5+ failed logins per hour
**Threat:** Brute Force Attack
<img width="1913" height="911" alt="image" src="https://github.com/user-attachments/assets/39e7aab6-80cf-4fdb-87e3-340f8fac1da6" />
### 🚨 Investigation Finding — CRITICAL:
- **Attacking IP:** 154.210.208.228
- **Failed Attempts:** 299 per hour consistently
- **Attack Duration:** 8AM to 4PM — 8+ hours
- **Total Records:** 452 events
- **Pattern:** Automated brute force tool confirmed
- **Verdict: 🔴 TRUE POSITIVE — Critical Brute Force Attack**
- **Action: Block IP immediately + Escalate to L2 + 
  Check for successful logins from same IP**

---

## 4️⃣ Suspicious PowerShell Activity (EventID 4688)

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has "powershell"
| project TimeGenerated, Account, Computer, CommandLine
| order by TimeGenerated desc
```
**Use Case:** Detects suspicious PowerShell execution
**Threat:** Malware, Living off the Land attacks
<img width="1912" height="916" alt="image" src="https://github.com/user-attachments/assets/8e658c7b-412d-4dca-9baf-ccc70d727b0d" />
### ✅ Investigation Finding:
- Query executed successfully
- **No suspicious PowerShell activity detected**
- **No unauthorized process creation found**
- **Verdict: No Threat Detected — Environment Clean**
- This query would detect malware/living-off-the-land 
  attacks in a real environment

---

## 5️⃣ New User Account Created (EventID 4720)

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, Computer, SubjectUserName
| order by TimeGenerated desc
```
**Use Case:** Monitors new user account creation
**Threat:** Insider Threat / Persistence
<img width="1919" height="917" alt="image" src="https://github.com/user-attachments/assets/c754ec32-740c-4624-a038-36279038c9fc" />

### ✅ Investigation Finding:
- Query executed successfully
- **No results found in lab environment**
- **Verdict: No Threat Detected — Environment Clean**

---

## 6️⃣ User Added to Admin Group (EventID 4732)

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, Computer, SubjectUserName
| order by TimeGenerated desc
```
**Use Case:** Detects privilege escalation attempts
**Threat:** Privilege Escalation
<img width="1913" height="899" alt="image" src="https://github.com/user-attachments/assets/2cc1a303-f2ba-45d5-a0aa-48cee606238c" />
### ✅ Investigation Finding:
- Query executed successfully
- **No results found in lab environment**
- **Verdict: No Threat Detected — Environment Clean**
---

## 7️⃣ Security Alerts Overview

```kql
SecurityAlert
| order by TimeGenerated desc
| take 100
```
**Use Case:** Overview of all recent security alerts
**Threat:** General SOC monitoring
<img width="1917" height="908" alt="image" src="https://github.com/user-attachments/assets/1af0d746-c3e7-47bd-b052-63273c5594be" />
### 🚨 Investigation Finding — HIGH Severity:
- **Alert Name:** Malicious Login Detected
- **Severity:** HIGH
- **Total Alerts:** 7 alerts on 21/4/2026
- **Time Range:** 11:00 AM to 7:09 PM
- **Provider:** ASI NRT Alerts (Microsoft Sentinel)
- **Connection:** Directly related to brute force attack found in Query 1 and Query 3
- **Verdict: 🔴 TRUE POSITIVE — Sentinel auto-detected malicious login attempts**
- **Action: Investigate all 7 alerts + Cross-reference with IP 154.210.208.228 + Escalate immediately**
---

## 8️⃣ Incidents by Severity

```kql
SecurityIncident
| summarize Count = count() by Severity
| order by Count desc
```
**Use Case:** Dashboard view of incidents by severity
**Threat:** SOC prioritization
<img width="1915" height="906" alt="image" src="https://github.com/user-attachments/assets/5a58e7f8-713c-4091-912e-c17f6da1a638" />

**Severity Level:🔴 HIGH**
**Total High Severity Incidents: 5**
**Time Range: Last 24 hours**
**Platform: Microsoft Sentinel**
**Observation: All detected incidents fall under HIGH severity**
**Verdict: 🔴 TRUE POSITIVE**
---

## 🛠️ Tools Used
- Microsoft Sentinel
- Azure Log Analytics Workspace
- KQL (Kusto Query Language)

## 📫 Connect With Me
- LinkedIn: linkedin.com/in/dineshtl
- Email: dineshtl821@gmail.com# KQL-Sentinel-Queries
KQL queries for Microsoft Sentinel
