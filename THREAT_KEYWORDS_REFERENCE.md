# Threat Detection Keywords Reference

## Quick Reference for Security Analysts

This document lists all keywords detected by the enhanced AI Log Analysis severity scoring system.

---

## CRITICAL SEVERITY KEYWORDS
**Automatic escalation to CRITICAL severity**

### Ransomware & Data Theft
- `ransomware` - Ransomware activity
- `data exfiltration` - Data exfiltration attempt
- `exfiltration` - Possible data theft
- `data breach` - Data breach indicator
- `wiper` - Wiper malware

### Privilege & Access
- `privilege escalation` - Privilege escalation detected
- `remote code execution` - RCE attempt
- `backdoor` - Backdoor installation
- `compromised` - System compromise
- `rootkit` - Rootkit detected

### Command & Control
- `command and control` - C2 communication
- `c2` - C2 communication
- `cobalt strike` - Cobalt Strike C2
- `meterpreter` - Meterpreter payload

---

## HIGH SEVERITY KEYWORDS
**Escalates to HIGH severity (unless already CRITICAL)**

### Malware & Threats
- `malware` - Malware detected
- `botnet` - Botnet activity
- `phishing` - Phishing attempt

### Attacks
- `ddos` - DDoS attack
- `bruteforce` - Brute force attack
- `brute force` - Brute force attack
- `credential stuffing` - Credential stuffing
- `unauthorized access` - Unauthorized access
- `account takeover` - Account takeover
- `exploit` - Exploit attempt
- `vulnerability` - Vulnerability exploitation

### Web Application Attacks
- `sql injection` - SQL injection
- `xss` - Cross-site scripting
- `csrf` - CSRF exploit
- `buffer overflow` - Buffer overflow
- `lfi` - Local file inclusion
- `rfi` - Remote file inclusion

### Admin Activity
- `suspicious admin` - Suspicious admin activity

---

## MEDIUM SEVERITY KEYWORDS
**Escalates to MEDIUM severity (if currently LOW/INFO/UNKNOWN)**

### Authentication
- `multiple failed logins` - Multiple login failures
- `failed login` - Failed login attempt

### Security Violations
- `policy violation` - Policy violation
- `anomaly detected` - Anomaly detected
- `suspicious` - Suspicious activity

### Reconnaissance
- `scan` - Scanning activity
- `port scan` - Port scanning
- `nmap` - Network mapping
- `reconnaissance` - Reconnaissance activity

---

## SOURCE-SPECIFIC BEHAVIOR PATTERNS

### Firewall / pfSense
**Detection Patterns:** `deny`, `denied`, `drop`, `dropped`, `reject`, `blocked`  
**Action:** Escalate severity +1 level  
**Reason:** Firewall blocked traffic

### IDS/IPS (Snort, Suricata)
**Detection Patterns:** `alert`, `sid:`, `classification:`  
**Action:** Escalate severity +1 level  
**Reason:** IDS/IPS alert triggered  
**Indicator:** IDS/IPS rule match

### Email Systems (SMTP, Exchange, O365)
**Risky Attachments:**
- `.exe`, `.js`, `.zip`, `.vbs`, `.bat`, `macro`, `attachment`
- **Action:** Escalate +1 level
- **Reason:** Email with risky attachment/content

**Authentication Failures:**
- `dkim fail`, `spf fail`, `dmarc fail`, `spoof`
- **Action:** Escalate +1 level
- **Reason:** Email authentication failure (spoofing indicator)

### Web Servers (nginx, Apache, IIS)
**Attack Patterns:**
| Pattern | Description | Action |
|---------|-------------|--------|
| `/wp-admin` | WordPress admin probing | +1 severity |
| `wp-login` | WordPress login probing | +1 severity |
| `xmlrpc.php` | WordPress XML-RPC exploit | +1 severity |
| `/phpmyadmin` | phpMyAdmin access attempt | +1 severity |
| `union select` | SQL injection attempt | +1 severity |
| `or 1=1` | SQL injection attempt | +1 severity |
| `../` or `..\` | Path traversal | +1 severity |
| `/etc/passwd` | LFI attempt | +1 severity |
| `%00` | Null byte injection | +1 severity |
| `<script` | XSS attempt | +1 severity |

---

## SQU DOMAIN TRUST POLICY

### Trusted Domains (Severity REDUCTION)
**Domain:** `squ.edu.om`  
**Condition:** Authentication success  
**Action:** Reduce severity by 2 levels  
**Example:** HIGH → LOW

**Success Signals:**
- `authentication success`
- `login success`
- `successfully authenticated`
- `accepted password`
- `succeeded`
- `token issued`
- `granted`
- `authenticated`

**Trust Factor Output:**
```
✅ Trusted SQU domain authentication: user@squ.edu.om
```

### Non-SQU Domains (Severity INCREASE)
**Domains:** Any non-squ.edu.om email domain  
**Action:** Increase severity by 1 level  
**Example:** MEDIUM → HIGH

**Trust Factor Output:**
```
⚠️ Non-SQU email domains: attacker@external.com
```

---

## AUTHENTICATION EVENT CLASSIFICATION

### Failure Signals
**Detection Patterns:**
- `authentication failure`
- `login failed`
- `invalid password`
- `bad credentials`
- `locked`
- `mfa failed`
- `denied`
- `rejected`

**Action:** Escalate severity +1 level  
**Indicator:** Failed authentication attempt

### Source Detection
**Authentication Keywords:** `auth`, `okta`, `azuread`, `adfs`, `ldap`, `sso`, `signin`, `logon`, `login`

---

## SEVERITY NORMALIZATION

### Syslog Level Mapping
| Syslog Level | Canonical Severity |
|--------------|-------------------|
| emergency, emerg | critical |
| alert | high |
| error, err | high |
| severe, major | high |
| warning, warn | medium |
| notice, minor | low |
| debug | info |

### Security Event Mapping
| Event Type | Canonical Severity |
|------------|-------------------|
| authentication success, login success | info |
| authentication failure, failed login | medium |
| multiple failed logins | high |
| phishing | high |
| malware | high |
| ransomware | critical |
| exfiltration | critical |
| c2 | critical |

---

## CONFIDENCE SCORING

Confidence increases based on:
- **SQU authentication success:** +20%
- **Non-SQU domain detected:** +10%
- **Authentication failure:** +15%
- **Critical keyword match:** +30%
- **High keyword match:** +20%
- **Medium keyword match:** +10%
- **Firewall block:** +15%
- **IDS/IPS alert:** +20%
- **Email attachment risk:** +15%
- **Email spoofing:** +20%
- **Web attack pattern:** +15%

**Maximum confidence:** 100%  
**Base confidence:** 50%

---

## THREAT SCORE CALCULATION

```python
base_score = severity_scores[overall_severity]
# critical: 100, high: 75, medium: 50, low: 25, info: 10

threat_count_bonus = min(total_threats * 5, 20)
# Max +20 for multiple threats

confidence_factor = confidence / 100
# Scale by confidence percentage

final_score = min(100, (base_score + threat_count_bonus) * confidence_factor)
```

### Examples:
1. **Critical severity, 5 threats, 80% confidence:**
   - base: 100, bonus: 20, factor: 0.8
   - Score: min(100, 120 * 0.8) = **96/100**

2. **High severity, 2 threats, 60% confidence:**
   - base: 75, bonus: 10, factor: 0.6
   - Score: min(100, 85 * 0.6) = **51/100**

3. **Medium severity, 0 threats, 50% confidence:**
   - base: 50, bonus: 0, factor: 0.5
   - Score: min(100, 50 * 0.5) = **25/100**

---

## TRUST SCORE CALCULATION

```python
trust_score = (squ_auth_count / total_auth_count) * 100
```

### Trust Levels:
- **70-100%:** 🟢 High trust (majority SQU)
- **40-69%:** 🟡 Medium trust (mixed)
- **0-39%:** 🔴 Low trust (majority external)

### Examples:
1. **8 SQU auths, 2 external auths:**
   - trust_score = (8/10) * 100 = **80% (High)**

2. **3 SQU auths, 7 external auths:**
   - trust_score = (3/10) * 100 = **30% (Low)**

3. **No authentication events:**
   - trust_score = **50% (Default/Medium)**

---

## Usage in Analysis

### Reading the Output

**Threat Assessment Display:**
```
Threat Score: 85/100 (🔴 CRITICAL)
Confidence: 75%
Trust Score: 🟢 80%
Threats Detected: 12
```

**Interpretation:**
- **85/100:** Very high threat level
- **🔴 CRITICAL:** Highest severity classification
- **75% confidence:** High confidence in assessment
- **80% trust:** Majority trusted SQU authentication
- **12 threats:** Multiple threat indicators found

**Threat Indicators Example:**
- Ransomware activity
- Data exfiltration attempt
- IDS/IPS rule match
- Firewall blocked traffic
- SQL injection attempt

**Trust Factors Example:**
- ✅ Trusted SQU domain authentication: admin@squ.edu.om
- ⚠️ Non-SQU email domains: attacker@external.com

---

## Best Practices

### For Security Analysts
1. **High trust score + low threat score:** Likely routine internal activity
2. **Low trust score + high threat score:** Priority investigation required
3. **Critical keywords:** Always investigate regardless of other factors
4. **Multiple threat types:** Indicates complex attack or compromised system
5. **SQU authentication failures:** Investigate even with high trust score

### For System Administrators
1. Monitor trust score trends over time
2. Investigate sudden drops in trust score
3. Review non-SQU authentication sources
4. Validate external email domains against known partners
5. Tune firewall/IDS rules based on detected patterns

### For Incident Response
1. **Critical + High Confidence:** Immediate escalation
2. **Critical + Low Confidence:** Validate before escalation
3. **High + Multiple Indicators:** Investigate within 1 hour
4. **Medium + SQU Trusted:** Routine monitoring
5. **Low + External Domain:** Validate authentication source

---

## Updating Keywords

To add new keywords, edit `AI_Log_Analysis.py`:

```python
# In compute_rule_based_severity() function

# Add to critical_keywords dict:
"new_threat": "Description of threat",

# Add to high_keywords dict:
"new_attack": "Description of attack",

# Add to medium_keywords dict:
"new_anomaly": "Description of anomaly",
```

---

## Contact & Support
For questions about threat detection keywords or severity scoring, contact the security team or refer to the full documentation in `AI_ANALYSIS_UPGRADE_SUMMARY.md`.
