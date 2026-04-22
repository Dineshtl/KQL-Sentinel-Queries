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

---

## 7️⃣ Security Alerts Overview

```kql
SecurityAlert
| order by TimeGenerated desc
| take 100
```
**Use Case:** Overview of all recent security alerts
**Threat:** General SOC monitoring

---

## 8️⃣ Incidents by Severity

```kql
SecurityIncident
| summarize Count = count() by Severity
| order by Count desc
```
**Use Case:** Dashboard view of incidents by severity
**Threat:** SOC prioritization

---

## 🛠️ Tools Used
- Microsoft Sentinel
- Azure Log Analytics Workspace
- KQL (Kusto Query Language)

## 📫 Connect With Me
- LinkedIn: linkedin.com/in/dineshtl
- Email: dineshtl821@gmail.com# KQL-Sentinel-Queries
KQL queries for Microsoft Sentinel
