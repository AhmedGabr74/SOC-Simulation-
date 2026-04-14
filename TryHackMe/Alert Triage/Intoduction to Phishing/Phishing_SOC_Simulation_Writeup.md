# 🛡️ TryHackMe — SOC Simulation: Introduction to Phishing
### Alert Triage & Incident Analysis | Blue Team | SOC L1

---

## 📋 Scenario Overview

| Field | Details |
|---|---|
| **Platform** | TryHackMe |
| **Room** | SOC Simulator — Introduction to Phishing |
| **Role** | SOC Analyst (Level 1) |
| **Date** | 04/14/2026 |
| **Total Alerts** | 4 |
| **True Positives** | 2 |
| **False Positives** | 2 |
| **Escalated** | 1 |

> **Scenario:** Acting as a SOC L1 Analyst, I received 4 security alerts related to potential phishing activity. Each alert was triaged, investigated using threat intelligence and log analysis, and classified as True Positive (TP) or False Positive (FP).

---

## 📊 Alerts Summary

| # | Alert Type | Affected User | Host | Verdict | Escalated |
|---|---|---|---|---|---|
| 1 | Outbound connection to blacklisted URL | Hannah Harris | win-3457 | ✅ TRUE POSITIVE | ❌ No |
| 2 | Inbound email with external link | Julia Garcia | win-3452 | ⚠️ FALSE POSITIVE | ❌ No |
| 3 | Inbound email with external link | Julia Garcia | win-3452 | ⚠️ FALSE POSITIVE | ❌ No |
| 4 | Phishing email — typosquatted domain | Charlotte Allen | win-3463 | 🚨 TRUE POSITIVE | ✅ YES |

---

## 🔍 Alert 1 — Blacklisted URL Access Attempt

**Verdict: ✅ TRUE POSITIVE — Blocked | No Escalation Required**

### Details
| Field | Value |
|---|---|
| Time | 04/14/2026 00:42:06.773 |
| Hostname | win-3457 |
| User | Hannah Harris |
| Source IP | 10.20.2.17 |
| Destination IP | 67.199.248.11 |
| Blocked By | Firewall / Proxy |

### Analysis
The alert fired when win-3457 attempted to reach a URL on the organization's threat intelligence blacklist. The URL was a **bit.ly shortened link** — a common attacker technique to bypass URL-filtering controls by hiding the real destination.

The destination IP `67.199.248.11` was confirmed malicious via **VirusTotal**. The firewall blocked the connection before any data exchange occurred.

### Why True Positive
- Destination IP flagged as malicious on VirusTotal
- URL uses bit.ly shortening — known obfuscation technique
- Domain appears on the organization's threat intelligence blacklist

### Why No Escalation
- Firewall blocked the connection — no data exchanged
- No evidence of successful outbound communication
- No lateral movement or follow-up activity observed

### Recommended Actions
- Provide phishing awareness training to Hannah Harris
- Verify bit.ly destination across additional threat intel feeds
- Review proxy logs for similar bit.ly access patterns from other endpoints

### IOCs
| Type | Value |
|---|---|
| IP Address | `67.199.248.11` |
| URL | `http://bit.ly/3sHkX3da12340` |

---

## 🔍 Alert 2 — Inbound Email with External Link

**Verdict: ⚠️ FALSE POSITIVE — Legitimate Onboarding Email**

### Details
| Field | Value |
|---|---|
| Time | 04/14/2026 04:24:43.565 |
| Hostname | win-3452 |
| User | Julia Garcia |
| Sender | onboarding@hrconnex.thm |
| Recipient | j.garcia@thetrydaily.thm |

### Analysis
Alert triggered by an inbound email from `onboarding@hrconnex.thm` to Julia Garcia. The embedded URL was validated against **VirusTotal** and multiple threat intel platforms — **no malicious indicators found**.

While the email shows some phishing characteristics (external domain, urgency language), these are consistent with legitimate HR onboarding communications. No firewall/proxy logs confirmed user interaction with the URL.

### Why False Positive
- URL clean on all threat intelligence platforms
- Sender domain consistent with a legitimate HR system
- No proxy logs show the user accessing the URL
- No suspicious follow-up activity on win-3452

> **Analyst Note:** Urgency language + external domain are phishing indicators worth monitoring. Flagged for continued watch.

---

## 🔍 Alert 3 — Inbound Email with External Link (Same Sender)

**Verdict: ⚠️ FALSE POSITIVE — Same Legitimate Email Chain**

### Details
| Field | Value |
|---|---|
| Time | 04/14/2026 00:37:39.773 |
| Hostname | win-3452 |
| User | Julia Garcia |
| Sender | onboarding@hrconnex.thm |
| Recipient | j.garcia@thetrydaily.thm |

### Analysis
This alert involves the same sender and recipient as Alert 2 — an earlier email in the same onboarding chain. The URL was again validated and returned no malicious results. Same analysis applies: no user interaction detected, no suspicious follow-up activity.

### Why False Positive
- Same legitimate sender/recipient chain as Alert 2
- URL cleared on VirusTotal and all intel platforms
- No proxy or firewall activity from win-3452 related to this URL

---

## 🚨 Alert 4 — Phishing Email: Microsoft Typosquatting

**Verdict: 🚨 TRUE POSITIVE — ESCALATED | User Clicked Phishing Link**

### Details
| Field | Value |
|---|---|
| Time | 04/14/2026 00:43:10.773 |
| Hostname | win-3463 |
| User | Charlotte Allen |
| Source IP | 10.20.2.25 |
| Sender | no-reply@m1crosoftsupport.co |
| Recipient | c.allen@thetrydaily.thm |
| Phishing URL | https://m1crosoftsupport.co/login |
| Destination IP | 45.148.10.131 |

### Analysis
**This is the most critical alert in the investigation.**

Charlotte Allen received an email from `no-reply@m1crosoftsupport.co` — a **typosquatted domain** impersonating Microsoft Support by replacing the letter `o` with the number `1` (`m1crosoftsupport` vs `microsoftsupport`).

The destination IP `45.148.10.131` was confirmed malicious on VirusTotal. **Firewall and proxy logs confirmed that Charlotte Allen clicked the phishing link** and accessed `https://m1crosoftsupport.co/login` from win-3463.

This is a **confirmed phishing compromise event** with high risk of credential theft and account takeover.

### Why True Positive
- Typosquatted domain: `m1crosoftsupport.co` impersonates Microsoft
- Destination IP confirmed malicious on VirusTotal
- Firewall logs confirm user accessed the phishing login page
- No legitimate Microsoft communication uses this domain

### Why Escalated
- User confirmed to have clicked and accessed the phishing login page
- High risk of credential compromise and account takeover
- Potential for lateral movement using stolen credentials
- Immediate containment required

### Remediation Actions
1. **ISOLATE win-3463** from the network immediately
2. **Full endpoint scan** for malware and credential stealers
3. **Reset Charlotte Allen's credentials** across all systems
4. **Block all IOCs** across firewall, proxy, and DNS
5. **Review Active Directory** for unauthorized login attempts
6. **Phishing awareness training** for Charlotte Allen

### IOCs
| Type | Value |
|---|---|
| Sender Email | `no-reply@m1crosoftsupport.co` |
| Phishing Domain | `m1crosoftsupport.co` |
| Phishing URL | `https://m1crosoftsupport.co/login` |
| Destination IP | `45.148.10.131` |
| Technique | Typosquatting — Microsoft impersonation |
| Affected Host | `win-3463` (Charlotte Allen, `10.20.2.25`) |

---

## 🚩 Master IOC List

| Type | Value | Alert |
|---|---|---|
| IP Address | `67.199.248.11` | Alert 1 (blocked) |
| URL | `http://bit.ly/3sHkX3da12340` | Alert 1 |
| Sender Email | `no-reply@m1crosoftsupport.co` | Alert 4 |
| Domain | `m1crosoftsupport.co` | Alert 4 |
| Phishing URL | `https://m1crosoftsupport.co/login` | Alert 4 |
| IP Address | `45.148.10.131` | Alert 4 (user accessed) |

---

## ✅ Skills Demonstrated

- 🔍 **Alert Triage** — Classified 4 alerts as TP/FP using structured analysis methodology
- 📧 **Phishing Email Analysis** — Identified typosquatting, obfuscated URLs, and sender spoofing
- 🌐 **Threat Intelligence** — Used VirusTotal to validate IPs and URLs
- 🔥 **Firewall & Proxy Log Analysis** — Confirmed blocked vs. successful connections per endpoint
- 🚨 **Incident Escalation** — Identified and escalated credential compromise with full remediation plan
- 📋 **IOC Documentation** — Extracted and catalogued all indicators across the investigation
- 📝 **Case Reporting** — Produced structured case reports with verdict justification for each alert

---

*Completed on TryHackMe | SOC Simulation: Introduction to Phishing | Blue Team / SOC L1*
