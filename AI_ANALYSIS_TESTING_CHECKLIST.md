# AI Log Analysis - Testing Checklist

## Pre-Testing Setup
- [ ] Ensure Ollama server is running (`ollama serve`)
- [ ] Verify Mistral model is installed (`ollama list`)
- [ ] Check GPU acceleration is available (optional but recommended)
- [ ] Database contains sample logs with various severity levels
- [ ] At least one log source has authentication events with squ.edu.om domain

---

## Test 1: SQU Domain Trust (Authentication Success)
**Objective:** Verify SQU domains reduce severity for successful authentications

### Setup
Create test log:
```python
{
    'timestamp': '2024-01-15T10:30:00Z',
    'source': 'azure_ad_auth',
    'sourcetype': 'authentication',
    'severity': 'high',
    'raw_log': 'authentication success for user admin@squ.edu.om from IP 10.0.0.1',
    'host': 'auth-server-01'
}
```

### Expected Results
- [ ] Derived severity: LOW or INFO (reduced from HIGH by 2 levels)
- [ ] Trust factors: "✅ Trusted SQU domain authentication: squ.edu.om"
- [ ] Confidence: 70%+ (base 50% + 20% for SQU trust)
- [ ] Trust score: High if majority of logs are SQU

### Test Steps
1. Navigate to AI Log Analysis page
2. Select "Source Analysis" tab
3. Choose source with SQU authentication logs
4. Click "Fetch and Analyze"
5. Verify Rule-Based Threat Assessment shows reduced severity
6. Check Trust & Authentication Analysis section

---

## Test 2: Non-SQU Domain (External Authentication)
**Objective:** Verify non-SQU domains increase severity

### Setup
Create test log:
```python
{
    'timestamp': '2024-01-15T10:35:00Z',
    'source': 'email_gateway',
    'sourcetype': 'email',
    'severity': 'medium',
    'raw_log': 'email received from attacker@suspicious-domain.com with attachment malware.exe',
    'host': 'mail-relay-02'
}
```

### Expected Results
- [ ] Derived severity: HIGH (escalated from MEDIUM)
- [ ] Trust factors: "⚠️ Non-SQU email domains: suspicious-domain.com"
- [ ] Threat indicators: "Email with risky attachment/content", "Malware detected"
- [ ] Confidence: 75%+ (multiple threat signals)
- [ ] Trust score: Low if majority external

### Test Steps
1. Select source with external email logs
2. Analyze batch
3. Verify severity escalation
4. Check threat indicators include both attachment and domain warnings

---

## Test 3: Critical Keywords Detection
**Objective:** Verify critical keywords trigger CRITICAL severity

### Test Keywords
Test each keyword individually:
- [ ] `ransomware` → CRITICAL
- [ ] `data exfiltration` → CRITICAL  
- [ ] `privilege escalation` → CRITICAL
- [ ] `remote code execution` → CRITICAL
- [ ] `backdoor` → CRITICAL
- [ ] `cobalt strike` → CRITICAL
- [ ] `c2` → CRITICAL

### Setup Example
```python
{
    'raw_log': 'WARNING: Possible ransomware activity detected on endpoint WS-001',
    'severity': 'low',
    'source': 'edr_agent'
}
```

### Expected Results
- [ ] Derived severity: CRITICAL (regardless of original severity)
- [ ] Threat indicators: "Ransomware activity"
- [ ] Confidence: 80%+ (critical keyword = +30%)
- [ ] Threat score: 90-100/100

---

## Test 4: Firewall Block Detection
**Objective:** Verify firewall deny/drop/block actions escalate severity

### Setup
```python
{
    'source': 'pfsense',
    'sourcetype': 'firewall',
    'severity': 'low',
    'raw_log': 'Firewall rule 1234: DENIED connection from 192.168.1.100 to 10.0.0.50 port 3389'
}
```

### Expected Results
- [ ] Derived severity: MEDIUM (escalated from LOW)
- [ ] Reasons: "Firewall blocked traffic"
- [ ] Confidence boost: +15%

---

## Test 5: IDS/IPS Alert Detection
**Objective:** Verify IDS/IPS alerts trigger escalation

### Setup
```python
{
    'source': 'snort',
    'sourcetype': 'ids',
    'severity': 'medium',
    'raw_log': 'ALERT [1:2012647:5] ET TROJAN Possible Cobalt Strike Malleable C2 [Classification: A Network Trojan was detected] [Priority: 1]'
}
```

### Expected Results
- [ ] Derived severity: HIGH or CRITICAL (IDS alert + critical keyword)
- [ ] Threat indicators: "IDS/IPS rule match", "Cobalt Strike C2"
- [ ] Confidence: 90%+ (IDS +20%, critical keyword +30%)
- [ ] Reasons: "IDS/IPS alert triggered", "Critical keyword: cobalt strike"

---

## Test 6: Web Attack Pattern Detection
**Objective:** Verify SQL injection, XSS, path traversal detection

### Test Patterns
- [ ] `union select` → SQL injection
- [ ] `or 1=1` → SQL injection
- [ ] `<script>` → XSS attempt
- [ ] `../` → Path traversal
- [ ] `/etc/passwd` → LFI attempt

### Setup
```python
{
    'source': 'nginx',
    'sourcetype': 'web_access',
    'severity': 'info',
    'raw_log': 'GET /search.php?q=test%27%20union%20select%20*%20from%20users-- HTTP/1.1'
}
```

### Expected Results
- [ ] Derived severity: HIGH (SQL injection = high keyword)
- [ ] Threat indicators: "SQL injection", "Web attack pattern: union select"
- [ ] Confidence: 85%+ (multiple indicators)

---

## Test 7: Email Spoofing Detection
**Objective:** Verify DKIM/SPF/DMARC failures escalate severity

### Setup
```python
{
    'source': 'exchange_server',
    'sourcetype': 'email',
    'severity': 'low',
    'raw_log': 'Email from ceo@company.com failed DKIM verification, SPF: softfail, DMARC: fail'
}
```

### Expected Results
- [ ] Derived severity: MEDIUM (escalated from LOW)
- [ ] Threat indicators: "Email spoofing"
- [ ] Reasons: "Email authentication failure (spoofing indicator)"
- [ ] Confidence: 70%+ (spoofing = +20%)

---

## Test 8: Batch Severity Aggregation
**Objective:** Verify batch analysis aggregates correctly

### Setup
Create mixed severity batch:
- 2 CRITICAL (ransomware, C2)
- 5 HIGH (malware, phishing)
- 10 MEDIUM (failed logins)
- 30 LOW (routine events)
- 50 INFO (successful SQU authentications)

### Expected Results
- [ ] Overall severity: CRITICAL (highest in batch)
- [ ] Total threats: 7 (critical + high count)
- [ ] Severity distribution matches input counts
- [ ] Unique threat types: Deduplicated list
- [ ] Trust score: 70%+ if majority SQU auths
- [ ] Confidence: Average across all logs

---

## Test 9: Display Function (Rule-Based Metrics)
**Objective:** Verify enhanced display shows all new sections

### Expected UI Elements
- [ ] **Rule-Based Threat Assessment header**
- [ ] 4-column metrics: Threat Score, Confidence, Trust Score, Threats Detected
- [ ] Color-coded severity badges (🔴🟠🟡🟢)
- [ ] **Detected Threat Indicators** expandable section (max 15 visible)
- [ ] **Severity Distribution** 5-column metrics
- [ ] **Trust & Authentication Analysis** expandable section
- [ ] ✅ for SQU domains, ⚠️ for non-SQU
- [ ] **AI Validation & Additional Analysis** header
- [ ] Original LLM analysis sections (phishing likelihood, threat summary, etc.)

---

## Test 10: LLM Integration
**Objective:** Verify rule-based data enhances LLM prompt

### Check LLM Prompt Contains
- [ ] Pre-computed threat intelligence summary
- [ ] Overall severity from rule-based analysis
- [ ] Trust score and confidence percentage
- [ ] Severity distribution JSON
- [ ] Threat indicators list
- [ ] Trust factors list
- [ ] Enhanced log summaries with derived severity

### Expected LLM Response
- [ ] Validates rule-based findings
- [ ] Identifies additional threats missed by rules
- [ ] Provides attack narrative
- [ ] Assesses false positive likelihood
- [ ] Recommends immediate and long-term actions

---

## Test 11: Performance & Efficiency
**Objective:** Verify rule-based pre-analysis improves speed

### Timing Comparison
1. **Without rule-based (old):** Full LLM analysis time
2. **With rule-based (new):** Pre-analysis + focused LLM time

### Expected Results
- [ ] Rule-based pre-analysis: <500ms for 50 logs
- [ ] Total analysis time: Similar or faster than old method
- [ ] LLM prompt is shorter/more focused
- [ ] No errors or timeouts

### Metrics to Check
- [ ] `total_logs`: Matches input count
- [ ] `logs_analyzed`: Max 20 (LLM limit)
- [ ] `confidence`: 50-100%
- [ ] `threat_score`: 0-100

---

## Test 12: Edge Cases
**Objective:** Test boundary conditions and error handling

### Test Cases
- [ ] **Empty log batch:** Returns error message
- [ ] **Unknown severity:** Defaults to "unknown", confidence 50%
- [ ] **No authentication events:** Trust score = 50%
- [ ] **All SQU authentications:** Trust score = 100%
- [ ] **No threat keywords:** Base severity only, lower confidence
- [ ] **Multiple critical keywords:** Single CRITICAL, all indicators listed
- [ ] **Very long log (>1000 chars):** Truncated properly in display
- [ ] **Missing fields (no raw_log):** Handles gracefully, uses available data

---

## Test 13: Manual Input Tab
**Objective:** Verify manual analysis still works (uses basic LLM, not rule-based yet)

### Test Steps
1. Navigate to "Manual Input" tab
2. Paste sample log with critical keywords
3. Click "Analyze Logs"
4. Verify LLM response displays

### Expected Results
- [ ] Analysis displays without errors
- [ ] No rule-based metrics shown (not implemented for manual input)
- [ ] Original display_organized_analysis works

---

## Test 14: Analysis History
**Objective:** Verify history display works with enhanced results

### Test Steps
1. Save multiple analyses with different threat scores
2. Navigate to "Analysis History" tab
3. Check recent analyses display

### Expected Results
- [ ] History list shows recent analyses
- [ ] Slider controls display count
- [ ] No errors when displaying enhanced results

---

## Test 15: Integration Testing
**Objective:** Verify consistency with other pages

### Cross-Page Consistency
- [ ] **Live Monitor:** Uses same `derived_severity` from database
- [ ] **Threat Scoring:** Uses same `normalize_severity_label()` logic
- [ ] **Database:** Severity values match across all queries

### Test Steps
1. Analyze logs in AI Log Analysis
2. Check same logs in Live Threat Monitor
3. Verify severity classifications match
4. Check derived_severity in database directly

---

## Regression Testing
**Objective:** Verify old functionality still works

### Test Areas
- [ ] Ollama connection status
- [ ] GPU acceleration toggle
- [ ] Model selection
- [ ] Source selection dropdown
- [ ] Max logs slider
- [ ] Log preview expansion
- [ ] Save analysis to database
- [ ] Navigation bar links

---

## Performance Benchmarks

### Target Metrics
- [ ] Rule-based analysis: <100ms per log
- [ ] Batch aggregation (50 logs): <500ms total
- [ ] LLM inference: 5-30s (GPU) or 20-120s (CPU)
- [ ] Total end-to-end: <35s with GPU
- [ ] UI responsiveness: No freezing during analysis

### Memory Usage
- [ ] Peak memory: <500MB for 100-log batch
- [ ] No memory leaks after multiple analyses

---

## Success Criteria

### Must Pass
- ✅ All SQU authentication events reduce severity correctly
- ✅ Critical keywords trigger CRITICAL severity
- ✅ Source-specific patterns detected (firewall, IDS, email, web)
- ✅ Display shows all new UI sections
- ✅ No Python errors or crashes
- ✅ LLM integration still works

### Should Pass
- ✅ Performance improved or equal to old method
- ✅ Confidence scores correlate with threat complexity
- ✅ Trust scores reflect SQU domain ratio accurately
- ✅ Threat indicators are specific and actionable

### Nice to Have
- ✅ LLM finds additional threats beyond rule-based analysis
- ✅ False positive rate reduced for SQU authentications
- ✅ Analysts find new metrics useful

---

## Bug Reporting Template

If you encounter issues, use this template:

```
**Test Case:** [Number and name]
**Expected:** [What should happen]
**Actual:** [What actually happened]
**Logs/Error:**
[Paste any error messages]

**Environment:**
- Python version:
- Streamlit version:
- Ollama version:
- GPU: Yes/No

**Steps to Reproduce:**
1. 
2. 
3. 

**Screenshots:**
[Attach if applicable]
```

---

## Post-Testing

### Documentation Updates
- [ ] Update README.md with new features
- [ ] Create user guide for new metrics
- [ ] Document keyword customization process

### Training
- [ ] Train security analysts on new threat indicators
- [ ] Explain trust score interpretation
- [ ] Demonstrate SQU domain trust policy

### Monitoring
- [ ] Monitor false positive rates
- [ ] Track analyst feedback
- [ ] Collect threat score accuracy metrics
- [ ] Review LLM validation quality

---

## Rollback Plan

If critical issues are found:

1. **Revert analyze_logs_batch():**
   - Restore old function from git history
   - Remove rule-based pre-analysis

2. **Revert display function:**
   - Remove `rule_based_data` parameter
   - Restore old display logic

3. **Keep helper functions:**
   - `normalize_severity_label()` - No side effects
   - `compute_rule_based_severity()` - Not called if removed from batch analysis

4. **Database:**
   - No rollback needed (no schema changes)

---

## Sign-Off

**Tested By:** ________________  
**Date:** ________________  
**All Tests Passed:** [ ] Yes [ ] No  
**Issues Found:** ________________  
**Approved for Production:** [ ] Yes [ ] No  

**Notes:**
_______________________________
_______________________________
_______________________________
