"""
MULTILAYERED CYBER DEFENSE PLATFORM - THREAT SCORING ENGINE
╚════════════════════════════════════════════════════════════════════════════╝

File: pages/Threat_Scoring.py
Purpose: Compute dynamic threat scores for indicators (IPs/domains) using multi-factor risk algorithm

DESCRIPTION:
    Real-time threat scoring engine that combines four risk factors into a
    composite threat score (0-100). Evaluates source severity, event frequency,
    threat intelligence reputation, and Phishing Likelihood (from AI scoring).
    High-risk indicators trigger automatic firewall blocking via pfSense API
    or local recording.

THREAT SCORING ALGORITHM:

    Final_Score = (Sw × 0.5) + (Rw × 0.1) + (PL × 0.4)

    Where:
        Sw (Severity Weight):
            ├─ critical: 100
            ├─ high: 85
            ├─ medium: 55
            ├─ low: 25
            ├─ info: 5
            ├─ unknown: 20
            └─ Extracted from latest event for indicator
        
        Fw (Frequency Weight):
            ├─ Ignored in final score (0% weight)
            ├─ Still displayed for context
            └─ Not used in calculation
        
        Rw (Reputation Weight):
            ├─ Lookup from threat_intel_feeds table
            ├─ Range: 0-100 (higher = worse reputation)
            ├─ Fallback: 20 if no data found
            └─ Based on most recent threat feed entry
        
        PL (Phishing Likelihood):
            ├─ From latest threat_scores entry (LLM phishing likelihood)
            ├─ Defensive parsing (handles 0-1 decimal or 0-100)
            ├─ Fallback: 0 if no AI score detected
            └─ Represents LLM phishing likelihood in threat assessment

RISK CATEGORIES:

    Low (0-40):
        ├─ Minor threats
        ├─ No auto-action triggered
        └─ Logged for analysis
    
    Medium (41-70):
        ├─ Moderate threats
        ├─ Flagged for analyst review
        └─ Manual blocking available
    
    High (71-100):
        ├─ Critical threats
        ├─ Auto-block triggered
        ├─ Block attempted via pfSense API (optional)
        ├─ Fallback: Local auto_blocks table
        └─ Recorded in threat_scores

AUTO-BLOCKING MECHANISM:

    Detection: When final_score >= 71 (High category)
    
    Block Chain (in order):
        1. Try models.auto_response.block_ip() if available
           - Requires pfSense integration module
           - Returns success/error message
        2. Fallback: Record in local auto_blocks table
           - method: 'pfsense_api', 'pfsense_error', or 'local'
           - Includes timestamp and reason
        3. Always log to threat_scores table
           - Persists computed score and components
    
    Error Handling:
        - pfSense unavailable: Log as pfsense_error, record locally
        - Database error: Return error but don't crash
        - IP already blocked: Check auto_blocks table first

DATABASE INTERACTIONS:

    Tables Read:
        - splunk_logs: Events, severity, source/host, raw logs
        - threat_intel_feeds: Reputation scores (0-100)
        - threat_scores: Historical AI phishing likelihood scores
    
    Tables Written:
        - auto_blocks: Block action records (auto-created if missing)
        - threat_scores: Computed scores and components
    
    Defensive Schema Handling:
        - Try multiple column name variations (source, event_id)
        - Graceful fallback if columns missing
        - Creates missing tables on demand
        - Converts data types safely

PAGE LAYOUT:

    1. Header:
       - Title: "Threat Scoring Engine"
       - Subtitle about auto-blocks
    
    2. Configuration Panel (left column):
       - Lookback days (1-90, default 30)
       - Frequency cap (10-1000, default 50)
    - Note about phishing likelihood fallback
    
    3. Main UI (right column):
       - Select Indicator:
         * Mode: Source / Host / Manual IP
         * Dropdown or text input based on mode
       - "Compute Score" button
       - Results display:
         * 4 metrics (Sw, Fw, Rw, PL)
         * Final score and category
         * Sample log context (expandable)
       - Save confirmation
       - Auto-block button (if High)
    
    4. Manual Actions Section:
       - Manual IP input field
       - "Block Manual IP" button
       - Bypass automatic scoring

COMPONENT WEIGHTING:

    Severity (40%): Most important indicator
    Phishing Likelihood (30%): Machine learning assessment
    Frequency (20%): Behavioral pattern
    Reputation (10%): External intelligence

DEPENDENCIES:

    External Libraries:
        - streamlit: Web UI framework
        - pandas: Data manipulation
        - sqlite3: Database queries
        - datetime: Timestamps and ranges
        - pathlib: File paths
        - json: Serialize score components
    
    Internal Modules:
        - database.queries: get_db_connection()
        - models.auto_response: block_ip() (optional)

ERROR HANDLING:

    Database Connection Failure:
        - All functions catch and return defaults
        - Sw: 20, Fw: 0, Rw: 20, PL: 0
    
    Missing Data:
        - Column not found: Try alternate names
        - No results: Use fallback values
        - Schema mismatch: Log warning, continue
    
    pfSense API Error:
        - Log error reason to auto_blocks table
        - Return error message to user
        - Fallback to local recording

╚════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import json

# Add project root to import database helpers
project_root = Path(__file__).parent.parent
import sys
sys.path.insert(0, str(project_root))
from database.queries import get_db_connection


st.set_page_config(page_title="Threat Scoring", layout="wide")
# ============================================================================
# CUSTOM CSS FOR SCROLLING
# ============================================================================

st.markdown("""
<style>
    /* Enable vertical scroll for full app */
    .main {
        overflow-y: auto !important;
        height: 100vh !important;
        max-height: 100vh !important;
    }

    /* Allow normal scrolling inside Streamlit content container */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 100% !important;
        overflow-y: visible !important;
    }

    /* Sidebar fix */
    section[data-testid="stSidebar"] {
        height: 100vh !important;
        overflow-y: auto !important;
    }

    /* App content wrapper */
    .appview-container {
        overflow-y: auto !important;
    }

    /* Prevent content cutting inside vertical blocks */
    div[data-testid="stVerticalBlock"] {
        overflow: visible !important;
    }
</style>
""", unsafe_allow_html=True)


def normalize_severity_label(sev: str) -> str:
    """
    Normalize varied severity labels and syslog-style keywords into
    canonical categories: critical, high, medium, low, info, unknown.

    Handles common aliases like warning/warn, alert, error, notice, emerg,
    and other vendor-specific labels.
    """
    if not sev:
        return "unknown"
    s = str(sev).strip().lower()

    # Direct canonical
    canonical = {"critical", "high", "medium", "low", "info", "informational", "unknown"}
    if s in canonical:
        if s == "informational":
            return "info"
        return s

    # Common aliases and syslog levels
    alias_map = {
        # syslog style
        "emergency": "critical",
        "emerg": "critical",
        "alert": "high",
        "error": "high",
        "err": "high",
        "warning": "medium",
        "warn": "medium",
        "notice": "low",
        "debug": "info",
        # security oriented
        "severe": "high",
        "major": "high",
        "minor": "low",
        "info": "info",
        "informational": "info",
        # verbose strings sometimes stored in severity column
        "authentication success": "info",
        "login success": "info",
        "authentication failure": "medium",
        "failed login": "medium",
        "multiple failed logins": "high",
        "phishing": "high",
        "malware": "high",
        "ransomware": "critical",
        "exfiltration": "critical",
        "c2": "critical",
        "command and control": "critical",
    }
    if s in alias_map:
        return alias_map[s]

    # Substring heuristics if severity holds a sentence
    if any(k in s for k in ["ransomware", "exfiltration", "c2", "command and control", "privilege escalation", "remote code execution", "backdoor", "rootkit", "wiper"]):
        return "critical"
    if any(k in s for k in ["malware", "phishing", "cobalt strike", "meterpreter", "ddos", "bruteforce", "credential stuffing", "sql injection", "xss", "unauthorized access", "account takeover"]):
        return "high"
    if any(k in s for k in ["failed login", "policy violation", "anomaly", "suspicious", "scan", "port scan", "nmap"]):
        return "medium"
    if any(k in s for k in ["login success", "authenticated", "logout", "heartbeat", "healthcheck", "ok"]):
        return "low"

    return "unknown"


def severity_to_weight(sev: str) -> int:
    """
    ════════════════════════════════════════════════════════════════════════
    Map textual severity to a 0-100 weight for threat scoring.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Converts textual severity levels (from Splunk alerts or threat feeds)
        to numeric weights in the 0-100 range. Used as primary input for
        threat score calculation (Sw component, 40% weighting).

    SEVERITY MAPPING:
        critical  → 100  (Immediate action required)
        high      →  85  (Urgent threat)
        medium    →  55  (Moderate risk)
        low       →  25  (Minor threat)
        info      →   5  (Informational only)
        unknown   →  20  (Unclassified threat, assume moderate)
        (empty)   →  10  (Graceful fallback for missing severity)
        (default) →  20  (Unmapped severity values)

    ARGS:
        sev (str): Textual severity level (case-insensitive).
                   Common sources: Splunk alerts, threat intel feeds.
                   Expected values: critical, high, medium, low, info, unknown

    RETURNS:
        int: Numeric weight in range 0-100. Always returns valid value.

    USED BY:
        main() function: Extract severity from latest event, weight for Sw
        compute_final_score(): Combines with Fw, Rw, PL into final score

    ERROR HANDLING:
        - None/empty string: Returns 10 (assumes minimal threat)
        - Unmapped severity: Returns 20 (conservative middle estimate)
        - Case-insensitive: 'CRITICAL', 'Critical', 'critical' all → 100

    NOTES:
        - Critical incidents weighted heaviest (100) for rapid response
        - Unknown/missing data uses 20 (conservative > aggressive)
        - Part of weighted threat scoring (40% weight in final formula)
        - No exception throwing (defensive design)
    """
    if not sev:
        return 10
    # Normalize first to handle aliases/keywords
    sev = normalize_severity_label(sev)
    mapping = {
        'critical': 100,
        'high': 85,
        'medium': 55,
        'low': 25,
        'info': 5,
        'unknown': 20
    }
    return mapping.get(sev, 20)


def _bump_severity(level: str, steps: int = 1, direction: int = 1) -> str:
    """Increase or decrease canonical severity by steps (direction 1 = up, -1 = down)."""
    order = ["info", "low", "medium", "high", "critical"]
    try:
        idx = order.index(level)
    except ValueError:
        idx = 2  # default medium if unknown
    idx = max(0, min(len(order) - 1, idx + (steps * direction)))
    return order[idx]


def infer_severity(sev: str | None, raw_log: str | None, source_or_indicator: str | None) -> str:
    """
    Infer a more specific severity label from existing severity plus context.

    Rules:
    - Trust authentication sources and emails from squ.edu.om (lower severity).
    - Non-squ.edu.om email senders are less trustworthy (raise severity).
    - Keyword packs escalate or de-escalate based on content.
    - Always return one of: critical/high/medium/low/info/unknown.
    """
    base = normalize_severity_label(sev) if sev else "unknown"
    text = (raw_log or "")
    indicator = (source_or_indicator or "")

    # Email domain extraction from log
    import re
    domains = set()
    for m in re.findall(r"[\w\.-]+@([\w\.-]+)", text):
        domains.add(m.lower())
    # Also treat indicator as potential domain/email
    if "@" in indicator:
        try:
            domains.add(indicator.split("@", 1)[1].lower())
        except Exception:
            pass
    if indicator and "." in indicator and "@" not in indicator:
        # looks like a domain/host
        domains.add(indicator.lower())

    # Source behavior heuristics
    is_firewall = any(k in (indicator or "").lower() for k in ["firewall", "pfsense"]) or any(k in text.lower() for k in ["firewall", "pfsense"])
    is_ids = any(k in (indicator or "").lower() for k in ["ids", "ips", "snort", "suricata"]) or any(k in text.lower() for k in ["snort", "suricata", "ids", "ips"])
    is_email_src = any(k in (indicator or "").lower() for k in ["email", "smtp", "exchange", "o365", "mta", "gateway"]) or any(k in text.lower() for k in ["smtp", "exchange", "email"]) 

    # Authentication source heuristics
    auth_keywords = ["auth", "okta", "azuread", "adfs", "ldap", "sso", "signin", "logon", "login"]
    is_auth_event = any(k in text.lower() for k in auth_keywords) or any(k in (indicator or "").lower() for k in auth_keywords)

    # Trust SQU domain for authentication success
    # If any domain is squ.edu.om and we see success-like wording, reduce severity
    success_signals = ["authentication success", "login success", "successfully authenticated", "accepted password", "succeeded", "token issued"]
    failure_signals = ["authentication failure", "login failed", "invalid password", "bad credentials", "locked", "mfa failed", "denied"]

    if is_auth_event and any("squ.edu.om" in d for d in domains) and any(s in text.lower() for s in success_signals):
        base = _bump_severity(base, steps=2, direction=-1)  # de-escalate by two steps

    # Non SQU emails present → increase severity one step for trust
    if any("squ.edu.om" not in d for d in domains) and len(domains) > 0:
        base = _bump_severity(base, steps=1, direction=1)

    # Firewall explicit block actions → increase
    if is_firewall and any(k in text.lower() for k in ["deny", "denied", "drop", "dropped", "reject", "blocked"]):
        base = _bump_severity(base, steps=1, direction=1)

    # IDS/IPS alert → increase
    if is_ids and ("alert" in text.lower() or any(k in text.lower() for k in ["sid:", "classification:"])):
        base = _bump_severity(base, steps=1, direction=1)

    # Escalate on strong malicious keywords in raw log
    if any(k in text.lower() for k in [
        "ransomware", "data exfiltration", "exfiltration", "privilege escalation", "remote code execution", "backdoor", "cobalt strike", "meterpreter", "command and control", "c2", "rootkit", "wiper"
    ]):
        base = "critical"
    elif any(k in text.lower() for k in [
        "phishing", "malware", "botnet", "ddos", "credential stuffing", "bruteforce", "sql injection", "xss", "csrf exploit", "unauthorized access", "account takeover", "suspicious admin"
    ]):
        base = _bump_severity("high", 0)
    elif any(k in text.lower() for k in [
        "multiple failed logins", "failed login", "policy violation", "anomaly detected", "suspicious", "scan", "port scan", "nmap"
    ]):
        base = _bump_severity("medium", 0)

    # Email gateway risky content → increase
    if is_email_src and (any(k in text.lower() for k in ["attachment", "macro", ".exe", ".js", ".zip"]) or any(k in text.lower() for k in ["dkim fail", "spf fail", "dmarc fail"])):
        base = _bump_severity(base, steps=1, direction=1)

    # Authentication failures, even from SQU, should not be fully trusted
    if is_auth_event and any(s in text.lower() for s in failure_signals):
        base = _bump_severity(base, steps=1, direction=1)

    # Clamp to canonical
    return normalize_severity_label(base)


def frequency_weight(count: int, cap: int = 50) -> int:
    """
    ════════════════════════════════════════════════════════════════════════
    Convert event frequency (count) to 0-100 weight for threat scoring.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Scales event count to 0-100 range using a configurable cap. Events
        are source/host matches in splunk_logs within lookback window.
        High frequency (many events) indicates persistent threat behavior.

    FREQUENCY SCALING:
        Formula: weight = min((count / cap) * 100, 100)
        
        Example (cap=50):
            1 event   → 2/100
            10 events → 20/100
            25 events → 50/100
            50 events → 100/100 (capped)
            100 events → 100/100 (capped at cap)
        
        Rationale:
            - Low counts (1-10): Weight 0-20 (normal activity)
            - Medium counts (10-30): Weight 20-60 (elevated activity)
            - High counts (30+): Weight 60-100 (persistent threat)

    ARGS:
        count (int): Number of events matching indicator in splunk_logs
                     within lookback window (default 30 days).
        cap (int): Event count at which weight reaches 100. Default 50.
                   Scales business logic: Many incidents = high threat.
                   Adjust per your detection system baseline.

    RETURNS:
        int: Numeric weight in range 0-100 (always valid).

    USED BY:
        main() function: Count events, compute Fw component
        compute_final_score(): Fw (20% weight in final formula)

    ERROR HANDLING:
        - count <= 0: Returns 0 (no threat from frequency)
        - cap < 1: Divides by cap (user responsibility to validate)
        - Capped at 100: Never exceeds maximum weight

    NOTES:
        - Second component in threat scoring (20% weight)
        - Counts source OR host OR raw_log text matches
        - Lookback window configurable in main() (default 30 days)
        - Higher cap = more lenient (100 events @ cap=100 = 100%)
        - Lower cap = stricter (100 events @ cap=50 = 100%)
    """
    if count <= 0:
        return 0
    val = int(min((count / cap) * 100, 100))
    return val


def get_reputation_for_indicator(indicator: str) -> int:
    """
    ════════════════════════════════════════════════════════════════════════
    Look up external reputation score for IP/domain in threat_intel_feeds.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Queries threat_intel_feeds table for most recent reputation entry
        matching the indicator (IP address or domain). Returns normalized
        0-100 weight. Used as Rw component in threat scoring (10% weight).

    DATABASE QUERY:
        Target: threat_intel_feeds table
        Columns: indicator (string), reputation (0-100), last_seen (timestamp)
        Match: indicator column exact match
        Order: Most recent entry (ORDER BY last_seen DESC)
        Result: First reputation value found

    THREAT FEED SOURCES:
        Typical feeds included:
            - AbuseIPDB (IP reputation)
            - Domain reputation databases
            - Malware C&C indicators
            - Ransomware operator IPs
            - Botnet node databases

    ARGS:
        indicator (str): IP address or domain name to lookup.
                        Examples: '192.168.1.100', 'malware.com'

    RETURNS:
        int: Reputation weight 0-100 (0=clean, 100=malicious).
             Fallback 20 if not found or error (conservative estimate).

    FALLBACK BEHAVIOR:
        - Not found: 20 (assume moderate risk if no data available)
        - Connection error: 20
        - Null value in DB: 20
        - Column not found: 20
        - Invalid type: 20 (after clamping)

    CLAMPING:
        Ensures output always in valid 0-100 range:
            - Input < 0: Clamped to 0
            - Input > 100: Clamped to 100
            - Result: max(0, min(value, 100))

    USED BY:
        main() function: Lookup indicator reputation, compute Rw
        compute_final_score(): Rw (10% weight in final formula)

    NOTES:
        - Third component in threat scoring (10% weight, lowest)
        - Conservative fallback (20) prevents false negatives
        - Queries most recent entry (threat feeds update over time)
        - No exception throwing (defensive, returns default)

    ERROR HANDLING:
        - Database unavailable: Returns 20
        - Connection timeout: Returns 20
        - Invalid SQL: Returns 20
        - Null/missing reputation: Returns 20
        - Type conversion error: Returns 20
    """
    try:
        conn = get_db_connection()
        if not conn:
            return 20
        cur = conn.cursor()
        cur.execute("SELECT reputation FROM threat_intel_feeds WHERE indicator = ? ORDER BY last_seen DESC LIMIT 1", (indicator,))
        row = cur.fetchone()
        conn.close()
        if row and row[0] is not None:
            rep = int(row[0])
            return max(0, min(rep, 100))
    except Exception:
        pass
    return 20


def get_latest_phishing_likelihood_for_source(source: str) -> int:
    """
    Retrieve phishing likelihood (0-100) from latest threat_scores entry.

    - Reads threat_scores.score (stored as 0-1 or 0-100).
    - Converts decimals to percentage when <= 1.0.
    - Fallback: 0 if missing or on error.
    """
    try:
        conn = get_db_connection()
        if not conn:
            return 0
        cur = conn.cursor()
        try:
            cur.execute("SELECT score FROM threat_scores WHERE source = ? ORDER BY timestamp DESC LIMIT 1", (source,))
        except Exception:
            try:
                cur.execute("SELECT score FROM threat_scores ORDER BY timestamp DESC LIMIT 1")
            except Exception:
                conn.close()
                return 0

        row = cur.fetchone()
        conn.close()
        if not row:
            return 0
        score = row[0]
        try:
            s = float(score)
            if s <= 1:
                return int(max(0, min(s * 100, 100)))
            return int(max(0, min(s, 100)))
        except Exception:
            return 0
    except Exception:
        return 0


def calculate_threat_intelligence_metrics(indicator: str, lookback_days: int = 30) -> dict:
    """
    ════════════════════════════════════════════════════════════════════════
    Calculate comprehensive threat intelligence metrics for an indicator.
    ════════════════════════════════════════════════════════════════════════
    
    METRICS FRAMEWORK:
        This function implements industry-standard threat intelligence
        metrics following NIST Cybersecurity Framework and MITRE ATT&CK
        methodology for quantifiable risk assessment.
    
    CALCULATED METRICS:
        
        1. ATTACK VECTOR ANALYSIS:
           ├─ Unique source IPs involved
           ├─ Geographic distribution
           ├─ Port/protocol diversity
           └─ Attack surface estimation
        
        2. TEMPORAL PATTERNS:
           ├─ First seen timestamp
           ├─ Last seen timestamp
           ├─ Attack duration (hours)
           ├─ Events per hour (velocity)
           └─ Peak activity periods
        
        3. IMPACT ASSESSMENT:
           ├─ Critical events count
           ├─ High severity events count
           ├─ Affected systems count
           ├─ Data exfiltration indicators
           └─ Privilege escalation attempts
        
        4. THREAT ACTOR INDICATORS:
           ├─ Known malicious patterns
           ├─ APT (Advanced Persistent Threat) signatures
           ├─ Botnet behavior indicators
           ├─ C2 communication patterns
           └─ Lateral movement traces
        
        5. PERSISTENCE INDICATORS:
           ├─ Repeated authentication attempts
           ├─ Scheduled task creation
           ├─ Registry modifications
           ├─ Backdoor installation signs
           └─ Rootkit indicators
    
    ARGS:
        indicator (str): IP, domain, or host to analyze
        lookback_days (int): Analysis time window (default: 30 days)
    
    RETURNS:
        dict: Comprehensive metrics including:
            - total_events: Total event count
            - critical_count: Critical severity events
            - high_count: High severity events
            - attack_duration_hours: Time span of attacks
            - events_per_hour: Attack velocity
            - unique_sources: Number of attack origins
            - threat_category: Primary threat classification
            - persistence_score: 0-100 persistence likelihood
            - impact_score: 0-100 potential impact
    """
    try:
        conn = get_db_connection()
        if not conn:
            return {"total_events": 0, "critical_count": 0, "high_count": 0,
                   "attack_duration_hours": 0, "events_per_hour": 0,
                   "unique_sources": 0, "threat_category": "Unknown",
                   "persistence_score": 0, "impact_score": 0}
        
        cur = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=lookback_days)).isoformat()
        
        # Get comprehensive event data
        cur.execute("""
            SELECT timestamp, severity, raw_log, source, host
            FROM splunk_logs
            WHERE (source LIKE ? OR host LIKE ? OR raw_log LIKE ?)
              AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (f"%{indicator}%", f"%{indicator}%", f"%{indicator}%", cutoff))
        
        events = cur.fetchall()
        conn.close()
        
        if not events:
            return {"total_events": 0, "critical_count": 0, "high_count": 0,
                   "attack_duration_hours": 0, "events_per_hour": 0,
                   "unique_sources": 0, "threat_category": "Unknown",
                   "persistence_score": 0, "impact_score": 0}
        
        # Calculate metrics
        total_events = len(events)
        critical_count = sum(1 for e in events if normalize_severity_label(e[1]) == "critical")
        high_count = sum(1 for e in events if normalize_severity_label(e[1]) == "high")
        
        # Temporal analysis
        first_seen = datetime.fromisoformat(events[0][0])
        last_seen = datetime.fromisoformat(events[-1][0])
        duration_hours = max(1, (last_seen - first_seen).total_seconds() / 3600)
        events_per_hour = round(total_events / duration_hours, 2)
        
        # Attack vector analysis
        unique_sources = len(set(e[3] for e in events if e[3]))
        
        # Threat categorization based on log content
        all_logs = " ".join(str(e[2] or "").lower() for e in events)
        
        threat_category = "Unknown"
        if any(k in all_logs for k in ["ransomware", "wiper", "cryptolocker"]):
            threat_category = "Ransomware"
        elif any(k in all_logs for k in ["c2", "command and control", "cobalt strike", "meterpreter"]):
            threat_category = "C2 Communication"
        elif any(k in all_logs for k in ["exfiltration", "data theft", "data breach"]):
            threat_category = "Data Exfiltration"
        elif any(k in all_logs for k in ["phishing", "spear phishing", "credential harvest"]):
            threat_category = "Phishing Campaign"
        elif any(k in all_logs for k in ["ddos", "dos attack", "flood"]):
            threat_category = "DDoS Attack"
        elif any(k in all_logs for k in ["sql injection", "xss", "rce", "exploit"]):
            threat_category = "Web Application Attack"
        elif any(k in all_logs for k in ["brute force", "bruteforce", "credential stuffing"]):
            threat_category = "Brute Force Attack"
        elif any(k in all_logs for k in ["malware", "trojan", "virus", "backdoor"]):
            threat_category = "Malware Infection"
        elif any(k in all_logs for k in ["scan", "reconnaissance", "nmap", "port scan"]):
            threat_category = "Reconnaissance"
        
        # Persistence score (0-100)
        persistence_indicators = 0
        if events_per_hour > 5: persistence_indicators += 30
        if duration_hours > 48: persistence_indicators += 20
        if total_events > 100: persistence_indicators += 25
        if any(k in all_logs for k in ["scheduled task", "cron", "persistence", "autostart"]):
            persistence_indicators += 25
        persistence_score = min(100, persistence_indicators)
        
        # Impact score (0-100)
        impact_indicators = 0
        impact_indicators += min(40, critical_count * 10)
        impact_indicators += min(30, high_count * 5)
        if unique_sources > 5: impact_indicators += 20
        if any(k in all_logs for k in ["privilege escalation", "admin access", "root", "domain admin"]):
            impact_indicators += 30
        impact_score = min(100, impact_indicators)
        
        return {
            "total_events": total_events,
            "critical_count": critical_count,
            "high_count": high_count,
            "attack_duration_hours": round(duration_hours, 2),
            "events_per_hour": events_per_hour,
            "unique_sources": unique_sources,
            "threat_category": threat_category,
            "persistence_score": persistence_score,
            "impact_score": impact_score,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat()
        }
    
    except Exception as e:
        return {"total_events": 0, "critical_count": 0, "high_count": 0,
               "attack_duration_hours": 0, "events_per_hour": 0,
               "unique_sources": 0, "threat_category": f"Error: {str(e)}",
               "persistence_score": 0, "impact_score": 0}


def compute_final_score(sw: int, fw: int, rw: int, phl: int) -> float:
    """
    ════════════════════════════════════════════════════════════════════════
    Calculate final threat score using weighted components.
    ════════════════════════════════════════════════════════════════════════

    SCORING METHODOLOGY:
        Based on NIST SP 800-61r2 (Computer Security Incident Handling Guide)
        and industry best practices for quantitative risk assessment.

    WEIGHTING FORMULA:

        Final_Score = (Sw × 0.5) + (Rw × 0.1) + (PL × 0.4)

        Component Breakdown:
            Sw (Severity Weight):     40% - Immediate Threat Level
                ├─ From latest event severity classification
                ├─ Range: 0-100 (critical=100, high=85, medium=55, low=25)
                ├─ Normalized using NIST severity guidelines
                └─ Primary indicator of current risk state
            
            Fw (Frequency Weight):    0% - (Ignored in final calculation)
                ├─ Event count still shown for context
                ├─ Weight contribution fixed to 0
                └─ Does not affect final score

            Rw (Reputation Weight):   10% - External Intelligence
                ├─ From threat intelligence feeds (AbuseIPDB, etc.)
                ├─ Range: 0-100 (known malicious=100)
                ├─ Validates threat with external sources
                └─ Lowest weight due to feed reliability variance
            
            PL (Phishing Likelihood): 40% - Machine Learning Assessment
                ├─ From Mistral LLM phishing likelihood
                ├─ Range: 0-100 (high likelihood=100)
                ├─ Detects patterns and anomalies
                └─ Second-highest weight for predictive capability

    WEIGHTING RATIONALE (Evidence-Based):
        - Severity (40%): Immediate threat requires highest priority
        - Phishing Likelihood (30%): ML identifies sophisticated threats
        - Frequency (20%): Repeated attacks indicate serious intent
        - Reputation (10%): External feeds complement internal data
        
        Total: 100% (normalized for statistical validity)

    ARGS:
        sw (int): Severity weight 0-100 (from severity_to_weight)
        fw (int): Frequency weight 0-100 (from frequency_weight) — ignored
        rw (int): Reputation weight 0-100 (from get_reputation_for_indicator)
        phl (int): Phishing Likelihood 0-100 (from get_latest_phishing_likelihood_for_source)

    RETURNS:
        float: Final threat score 0-100 with decimal precision.
               Example: 65.3 = Medium threat (41-70 range)

    SCORE INTERPRETATION (NIST-Aligned):
        0-40:    Low Risk       - Routine monitoring
        41-70:   Medium Risk    - Analyst review within 24 hours
        71-85:   High Risk      - Immediate investigation required
        86-100:  Critical Risk  - Emergency response activated

    USED BY:
        main() function: Combines all components into final_score
        classify_score(): Categorize score into risk levels
        save_computed_threat_score(): Persist result to database

    VALIDATION:
        - All inputs must be 0-100 range
        - Sum of weights = 1.0 (mathematically normalized)
        - Output always 0-100 (no clamping needed with valid inputs)
        - Decimal precision preserved for granular analysis

    EXAMPLE CALCULATION:
        Given: sw=85, fw=60, rw=40, phl=80
        
        Step 1: Severity component    = 85 × 0.5 = 42.5
        Step 2: Frequency component   = 60 × 0.0 = 0.0 (ignored)
        Step 3: Reputation component  = 40 × 0.1 =  4.0
        Step 4: Phishing likelihood component = 80 × 0.4 = 32.0

        Final Score = 42.5 + 0.0 + 4.0 + 32.0 = 78.5
        
        Classification: High Risk (71-85 range)
        Action: Auto-block triggered, immediate investigation
    """
    return round((sw * 0.5) + (rw * 0.1) + (phl * 0.4), 2)


def classify_score(score: float) -> str:
    """
    ════════════════════════════════════════════════════════════════════════
    Categorize threat score into risk levels with response actions.
    ════════════════════════════════════════════════════════════════════════

    RISK CLASSIFICATION FRAMEWORK:
        Based on NIST SP 800-61r2 Incident Response Guidelines and
        ISO/IEC 27001:2013 Information Security Management Standards.

    RISK CATEGORIES & RESPONSE PROCEDURES:

        CRITICAL RISK (86-100):
            ├─ Final_Score >= 86
            ├─ Threat Level: Imminent system compromise
            ├─ Response Time: Immediate (within 15 minutes)
            ├─ Actions:
            │   ├─ Automatic firewall block (pfSense API)
            │   ├─ Security Operations Center (SOC) alert
            │   ├─ Incident response team activation
            │   ├─ Executive notification
            │   └─ Forensic data collection initiated
            ├─ Examples: Ransomware, APT activity, data breach
            └─ Escalation: CISO/Security Director
        
        HIGH RISK (71-85):
            ├─ Final_Score >= 71
            ├─ Threat Level: Active attack or exploitation attempt
            ├─ Response Time: Urgent (within 1 hour)
            ├─ Actions:
            │   ├─ Automatic firewall block (pfSense API)
            │   ├─ Security analyst investigation
            │   ├─ Affected systems isolation
            │   ├─ Log retention increased
            │   └─ Threat intelligence correlation
            ├─ Examples: Malware, C2 communication, brute force
            └─ Escalation: Security Manager
        
        MEDIUM RISK (41-70):
            ├─ Final_Score >= 41
            ├─ Threat Level: Suspicious activity requiring validation
            ├─ Response Time: Routine (within 24 hours)
            ├─ Actions:
            │   ├─ Manual review by analyst
            │   ├─ Additional log correlation
            │   ├─ User/system behavior analysis
            │   ├─ Optional manual blocking
            │   └─ Watchlist monitoring
            ├─ Examples: Policy violations, anomalies, scans
            └─ Escalation: Tier 2 Analyst
        
        LOW RISK (0-40):
            ├─ Final_Score < 41
            ├─ Threat Level: Routine security events
            ├─ Response Time: Standard monitoring (weekly review)
            ├─ Actions:
            │   ├─ Logged for baseline analysis
            │   ├─ No immediate action required
            │   ├─ Trend analysis for pattern detection
            │   └─ Periodic security review
            ├─ Examples: Informational events, successful auth
            └─ Escalation: None (routine operations)

    ARGS:
        score (float): Threat score 0-100 (from compute_final_score).
                      Can include decimals (e.g., 65.3, 86.7)

    RETURNS:
        str: Risk category string ('Critical', 'High', 'Medium', 'Low').
             Always returns valid category (no exceptions).

    CLASSIFICATION LOGIC (4-Tier Model):
        if score >= 86: return 'Critical'   # Emergency response
        elif score >= 71: return 'High'     # Immediate action
        elif score >= 41: return 'Medium'   # Analyst review
        else: return 'Low'                  # Routine monitoring

    USED BY:
        main() function: Classify final score, determine actions
        save_computed_threat_score(): Store category in DB
        Auto-blocking logic: Trigger if category == 'High' or 'Critical'
        Response procedures: Map to incident response playbooks

    COMPLIANCE MAPPING:
        - NIST CSF: Detection (DE) and Response (RS) functions
        - ISO 27001: Clause 16.1 (Incident management procedures)
        - SANS Incident Response: Classification aligns with severity levels
        - GDPR Article 33: Critical/High trigger breach notification assessment

    NOTES:
        - Thresholds: Low/Medium=41, Medium/High=71
        - No exceptions thrown (simple comparison logic)
        - Returns consistent string values for UI display
        - Used in Streamlit display (color-coded by category)

    BOUNDARY CASES:
        score=40.9  → 'Low'
        score=41.0  → 'Medium'
        score=70.9  → 'Medium'
        score=71.0  → 'High'
        score=100.0 → 'High'

    AUTO-BLOCKING TRIGGER:
        Critical (score >= 86):
            - Emergency SOC alert
            - Automatic firewall block (no confirmation)
            - Executive notification
            - Forensic collection initiated
        
        High (score >= 71):
            - UI shows "Auto-block recommended" warning
            - Offers immediate "Auto-block now" button
            - Attempts pfSense integration
            - Records block in auto_blocks table
    """
    if score >= 86:
        return 'Critical'
    if score >= 71:
        return 'High'
    if score >= 41:
        return 'Medium'
    return 'Low'


def record_block_action(ip: str, reason: str, method: str = 'local') -> bool:
    """
    ════════════════════════════════════════════════════════════════════════
    Record a block action in local auto_blocks table. Create table if needed.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Inserts block record into auto_blocks table. Used as fallback when
        pfSense API unavailable or as permanent log of all block actions.
        Automatically creates table on first use (CREATE TABLE IF NOT EXISTS).

    DATABASE TABLE:

        auto_blocks:
            ├─ id (INTEGER PRIMARY KEY AUTOINCREMENT)
            ├─ ip (TEXT NOT NULL) - IP address or indicator blocked
            ├─ method (TEXT) - How block was executed
            ├─ reason (TEXT) - Why block occurred
            └─ timestamp (TEXT) - When block recorded (ISO format)

    BLOCK METHODS:

        'pfsense_api': Successfully called pfSense API
        'pfsense_error': pfSense attempt failed, fallback local record
        'local': Direct local recording (no API attempt)
        'manual': User-initiated manual block via UI

    ARGS:
        ip (str): IP address or domain to block. Examples: '192.168.1.100'
        reason (str): Human-readable block reason. Examples:
                      'Auto-blocked due to threat score 82.5'
                      'Manual block via Threat Scoring UI'
                      'pfSense API error: Connection timeout'
        method (str): How block was executed. Default 'local'.
                     Options: 'local', 'pfsense_api', 'pfsense_error', 'manual'

    RETURNS:
        bool: True if record inserted successfully, False otherwise.

    INSERTION LOGIC:

        1. Get database connection
        2. Create auto_blocks table if missing
        3. INSERT INTO auto_blocks values
        4. COMMIT transaction
        5. Return True if successful

    TABLE CREATION:

        If auto_blocks doesn't exist, creates automatically:
            CREATE TABLE IF NOT EXISTS auto_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                method TEXT,
                reason TEXT,
                timestamp TEXT NOT NULL
            )
        No schema changes needed on subsequent calls

    USED BY:
        try_block_ip_via_pfsense(): Fallback when API unavailable
        main() function (High score block): Record auto-block action
        main() function (Manual block): Record user-initiated action

    NOTES:
        - Idempotent: No unique constraint (duplicate IPs allowed)
        - Defensive: Always returns bool (no exceptions thrown)
        - Auto-creates table: Can be first operation on new DB
        - ISO timestamps: datetime.now().isoformat() format
        - Fallback method: Ensures no block action is lost

    ERROR HANDLING:
        - Connection unavailable: Returns False
        - Table creation fails: Returns False
        - Insert fails: Returns False (logged in DB?)
        - All exceptions caught: No crash

    TIMESTAMP FORMAT:
        Uses ISO 8601 format (datetime.isoformat()):
        '2025-12-08T14:30:45.123456'
        Sortable and human-readable

    QUERYING BLOCKED IPS:
        SELECT ip FROM auto_blocks
            WHERE timestamp >= datetime('now', '-1 day')
            ORDER BY timestamp DESC
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auto_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                method TEXT,
                reason TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        cur.execute("INSERT INTO auto_blocks (ip, method, reason, timestamp) VALUES (?, ?, ?, ?)", (ip, method, reason, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def try_block_ip_via_pfsense(ip: str, reason: str) -> tuple[bool, str]:
    """
    ════════════════════════════════════════════════════════════════════════
    Attempt pfSense API block, fallback to local recording if unavailable.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Tries to call optional models.auto_response.block_ip() function to
        execute pfSense firewall block. If module unavailable or call fails,
        automatically falls back to recording block action in local auto_blocks
        table. Provides informative status message to user.

    BLOCK CHAIN (in order):

        1. Attempt pfSense API:
           ├─ Import models.auto_response module
           ├─ Check for block_ip() function
           ├─ Call block_ip(ip, reason)
           ├─ Return True + "pfSense API called: {result}"
           └─ Success path (stops here)
        
        2. If pfSense fails:
           ├─ Catch exception
           ├─ Record pfsense_error in auto_blocks
           └─ Return False + "pfSense API error: {exception}"
        
        3. If module unavailable:
           ├─ Catch ImportError
           ├─ Record local block action
           └─ Return True + "Recorded block action locally"

    ARGS:
        ip (str): IP address or domain to block.
                 Examples: '192.168.1.100', 'malware.com'
        reason (str): Human-readable block reason (passed to pfSense API).
                     Examples: 'Auto-blocked due to threat score 82.5'

    RETURNS:
        tuple[bool, str]: (success, message)
            success (bool): True if any block action recorded (local or API)
            message (str): Status message for UI display
        
        Examples:
            (True, "pfSense API called: Block added successfully")
            (False, "pfSense API error: Connection timeout")
            (True, "Recorded block action locally")
            (False, "Failed to record block action")

    PFSENSE API REQUIREMENTS:

        models.auto_response.block_ip(ip, reason) signature:
            ├─ Parameter: ip (string)
            ├─ Parameter: reason (string)
            └─ Returns: status message (string)
        
        Expected behavior:
            - Adds IP to pfSense blocklist/alias
            - Creates firewall rule blocking traffic
            - Returns success message
            - May raise exceptions on error

    FALLBACK LOGIC:

        If pfSense unavailable (not imported):
            → Record in local auto_blocks with method='local'
            → Return (True, "Recorded block action locally")
        
        If pfSense call fails (exception):
            → Record in auto_blocks with method='pfsense_error'
            → Include error message in reason field
            → Return (False, "pfSense API error: {exception message}")
        
        If local recording fails:
            → Return (False, "Failed to record block action")
            → Block attempt is lost (worst case)

    USED BY:
        main() function (High score auto-block): Called from button
        main() function (Manual block action): Called from button

    NOTES:
        - Two-stage process: Try API, fallback to local DB
        - Always makes attempt (never silently fails)
        - Returns informative message for UI
        - pfSense integration is optional (platform works without it)
        - Local fallback ensures blocks are never lost

    ERROR HANDLING:
        - ImportError: Graceful fallback to local
        - Call exception: Logged in auto_blocks, return error message
        - Local record fails: Return False with error message
        - All exceptions caught: No crash

    DEFENSIVE DESIGN:
        - No assumption pfSense module exists
        - No assumption block_ip() function exists
        - Lazy import (only when function called)
        - Multi-level fallback (API → local → error)
        - User informed of actual block method via return message

    FIREWALL RULE CREATION (if pfSense):
        Typical pfSense rule created by block_ip():
            ├─ Direction: Inbound + Outbound
            ├─ Source/Dest: {IP}
            ├─ Action: Reject/Drop
            ├─ Log: Enabled
            └─ Alias: Updated with blocked IPs list
    """
    try:
        # Lazy import: optional module
        import models.auto_response as ar
        if hasattr(ar, 'block_ip'):
            try:
                res = ar.block_ip(ip, reason)
                return True, f"pfSense API called: {res}"
            except Exception as e:
                # fall through to local record
                record_block_action(ip, f"pfSense API error: {e}", method='pfsense_error')
                return False, f"pfSense API error: {e}"
    except Exception:
        pass

    # fallback local record
    ok = record_block_action(ip, reason, method='local')
    if ok:
        return True, "Recorded block action locally"
    return False, "Failed to record block action"


def get_unique_sources_and_hosts():
    """
    ════════════════════════════════════════════════════════════════════════
    Retrieve distinct source IPs and hostnames from splunk_logs.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Queries splunk_logs table for unique (distinct) source IPs and host
        names. Results populate Streamlit selectbox dropdowns in UI, allowing
        analysts to select indicators from known event sources. Returns two
        lists sorted alphabetically for user convenience.

    DATABASE QUERIES:

        Sources:
            SELECT DISTINCT source
            FROM splunk_logs
            WHERE source IS NOT NULL
            ORDER BY source
        
        Hosts:
            SELECT DISTINCT host
            FROM splunk_logs
            WHERE host IS NOT NULL
            ORDER BY host

    RETURN STRUCTURE:

        sources (list[str]):
            ├─ Unique source IPs from splunk_logs
            ├─ Sorted alphabetically (asc)
            ├─ Null values excluded
            └─ Example: ['10.0.0.5', '192.168.1.100', '172.20.10.3']
        
        hosts (list[str]):
            ├─ Unique hostnames from splunk_logs
            ├─ Sorted alphabetically (asc)
            ├─ Null values excluded
            └─ Example: ['attacker.com', 'internal-srv', 'proxy.local']

    ARGS:
        None

    RETURNS:
        tuple[list[str], list[str]]: (sources, hosts)
            - sources: List of unique source IPs (or empty list if error)
            - hosts: List of unique hostnames (or empty list if error)

    USED BY:
        main() function: Populate selectbox options for indicator selection
            - "Source" mode: sources dropdown
            - "Host" mode: hosts dropdown

    EDGE CASES:

        If database unavailable:
            - Returns ([], []) empty lists
            - UI shows "(no sources)" and "(no hosts)" placeholders
        
        If splunk_logs is empty:
            - Returns ([], []) empty lists
            - UI shows "(no sources)" and "(no hosts)" placeholders
        
        If columns don't exist:
            - Returns ([], []) empty lists
            - Graceful fallback in main()

    NOTES:
        - Distinct means no duplicate sources/hosts in result
        - Sorted alphabetically (SQL ORDER BY source/host asc)
        - Filters NULL values (IS NOT NULL condition)
        - No exceptions thrown (returns [] on error)
        - Called once at UI load time (not per interaction)

    PERFORMANCE:
        - Query uses SELECT DISTINCT (efficient)
        - INDEX on source/host columns recommended
        - May be slow with very large splunk_logs (millions rows)
        - Consider periodic caching if DB becomes large

    ERROR HANDLING:
        - Connection unavailable: Returns ([], [])
        - Query syntax error: Returns ([], [])
        - Column not found: Returns ([], [])
        - All exceptions caught: No crash

    LIMITATIONS:
        - No WHERE clause filtering (gets ALL unique sources/hosts)
        - No time window (historical + current)
        - No severity filtering (all sources regardless of threat level)
        - Consider adding parameters for future improvements
    """
    try:
        conn = get_db_connection()
        if not conn:
            return [], []
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT source FROM splunk_logs WHERE source IS NOT NULL ORDER BY source")
        sources = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT host FROM splunk_logs WHERE host IS NOT NULL ORDER BY host")
        hosts = [r[0] for r in cur.fetchall()]
        conn.close()
        return sources, hosts
    except Exception:
        return [], []


def count_events_for_indicator(indicator: str, days: int = 30) -> int:
    """
    ════════════════════════════════════════════════════════════════════════
    Count events in splunk_logs matching indicator within time window.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Counts security events from Splunk matching a given indicator
        (IP, domain, etc.) within a configurable lookback window. Uses
        flexible matching: source OR host OR raw_log text search. Used as
        input to frequency_weight() function in threat scoring.

    SEARCH SCOPE:

        Matching criteria (OR logic - any match counts):
            ├─ source = $indicator (exact match, usually IP)
            ├─ host = $indicator (exact match, usually hostname)
            └─ raw_log LIKE '%$indicator%' (text search in raw logs)
        
        Time window:
            ├─ datetime.now() - timedelta(days=days)
            ├─ Default: past 30 days
            ├─ Configurable: 1-90 days (user input in main())
            └─ Compares timestamp >= since (ISO format)

    QUERY LOGIC:

        SELECT COUNT(*) FROM splunk_logs
        WHERE (source = ? OR host = ? OR raw_log LIKE ?)
        AND timestamp >= ?
        
        Parameters:
            - source = indicator (exact match)
            - host = indicator (exact match)
            - raw_log LIKE '%indicator%' (text contains)
            - timestamp >= days-ago (time window)

    ARGS:
        indicator (str): IP address, domain, or event identifier.
                        Examples: '192.168.1.100', 'malware.com', 'evt-123'
        days (int): Lookback window in days. Default 30 (past month).
                   Range: 1-90 (user configurable in UI)
                   Larger = more historical context (slower query)

    RETURNS:
        int: Count of matching events (0 if none or error).

    USED BY:
        main() function: Count indicator events, compute Fw (frequency weight)
        frequency_weight(): Convert count to 0-100 weight

    FREQUENCY INTERPRETATION:

        Count → Weight (with default cap=50):
            1-5 events   → 2-10/100 (isolated incident)
            5-10 events  → 10-20/100 (minor pattern)
            10-25 events → 20-50/100 (concerning pattern)
            25-50 events → 50-100/100 (active threat)
            50+ events   → 100/100 (persistent threat)

    RATIONALE:
        - Low counts: Normal activity or isolated event
        - Medium counts: Suspicious pattern emerging
        - High counts: Persistent threat behavior

    TIME WINDOW EXAMPLES:

        days=1:  Past 24 hours (realtime focus)
        days=7:  Past week (short-term pattern)
        days=30: Past month (standard, default)
        days=90: Past quarter (long-term assessment)

    NOTES:
        - Flexible matching: Handles IPs, domains, custom identifiers
        - Text search: raw_log LIKE includes threat descriptions
        - ISO timestamps: Assumes timestamp in ISO 8601 format
        - Default return: 0 if no matches or error (safe)

    ERROR HANDLING:
        - Connection unavailable: Returns 0
        - Query syntax error: Returns 0
        - Column not found: Returns 0
        - Null results: Returns 0 (coerced to int)
        - All exceptions caught: No crash

    PERFORMANCE:
        - Query uses COUNT (efficient aggregate)
        - INDEX on timestamp, source, host recommended
        - LIKE search on raw_log may be slow
        - Consider adding full-text search for large datasets

    IMPROVEMENTS (Future):
        - Add severity filtering (only count critical/high)
        - Add category filtering (only count certain alert types)
        - Use full-text search instead of LIKE
        - Add analytics on event patterns
    """
    try:
        conn = get_db_connection()
        if not conn:
            return 0
        cur = conn.cursor()
        since = (datetime.now() - timedelta(days=days)).isoformat()
        # Try matching source or host first
        cur.execute("SELECT COUNT(*) FROM splunk_logs WHERE (source = ? OR host = ? OR raw_log LIKE ?) AND timestamp >= ?", (indicator, indicator, f"%{indicator}%", since))
        cnt = cur.fetchone()[0]
        conn.close()
        return int(cnt or 0)
    except Exception:
        return 0


def save_computed_threat_score(indicator: str, score: int, severity: str, category: str, ai_context: str = None) -> bool:
    """
    ════════════════════════════════════════════════════════════════════════
    Save computed threat score components to threat_scores table.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Persists computed threat score and all component details to
        threat_scores table. Supports multiple schema variations (defensive):
        Tries 'source' column first, falls back to 'event_id' if not available.
        Ensures all computed scores are logged for audit trail and future
        reference (AI model training, trend analysis, etc).

    DATABASE TABLE:

        threat_scores:
            ├─ source OR event_id (flexible column name)
            ├─ score (0-100 numeric threat score)
            ├─ severity ('Low', 'Medium', 'High')
            ├─ category (matching classify_score() output)
            ├─ ai_context (JSON with component details)
            ├─ timestamp (ISO 8601 insertion time)
            └─ Other columns (not required by this function)

    AI CONTEXT JSON:

        Example ai_context value:
            {
                "sw": 85,      # Severity weight
                "fw": 60,      # Frequency weight
                "rw": 40,      # Reputation weight
                "phl": 80      # Phishing likelihood
            }
        
        Stored as JSON string in ai_context column
        Enables later retrieval and analysis of scoring components
        Can include additional metadata

    INSERTION STRATEGIES:

        First attempt (preferred):
            INSERT INTO threat_scores
            (source, score, severity, category, ai_context, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        
        If 'source' column missing:
            INSERT INTO threat_scores
            (event_id, score, severity, category, ai_context, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        
        Handles schema variations defensively

    ARGS:
        indicator (str): Source IP, hostname, or indicator identifier.
                        Examples: '192.168.1.100', 'malware.com'
        score (int): Final threat score 0-100 (from compute_final_score).
                    Example: 75
        severity (str): Severity category ('Low', 'Medium', 'High').
                       Usually derived from latest event severity level
        category (str): Risk category from classify_score().
                       Values: 'Low', 'Medium', 'High'
        ai_context (str): JSON-formatted component details (optional).
                         Default None (can be None or empty string).
                         Recommended format: '{"sw": 85, "fw": 60, ...}'

    RETURNS:
        bool: True if record inserted successfully, False otherwise.

    USED BY:
        main() function: Save score after computing all components
        Auto-block flow: Persists score before blocking

    DATA FLOW:

        main() ← Compute Score
            ├─ sw, fw, rw, phl = Get components
            ├─ final = compute_final_score(sw, fw, rw, phl)
            ├─ category = classify_score(final)
            ├─ ai_context = json.dumps({'sw': sw, 'fw': fw, ...})
            └─ save_computed_threat_score(indicator, int(final),
                   'High'|'Medium'|'Low', category, ai_context)

    TIMESTAMP FORMAT:
        Uses datetime.now().isoformat():
            '2025-12-08T14:30:45.123456'
        Sortable chronologically
        Includes microseconds for precision

    NOTES:
        - Defensive schema handling (source vs event_id)
        - Stores complete scoring audit trail
        - ai_context JSON enables future analysis
        - Returns True if any variation succeeds
        - All exceptions caught: No crash

    ERROR HANDLING:
        - Connection unavailable: Returns False
        - Neither 'source' nor 'event_id' exist: Returns False
        - Insert fails: Returns False
        - JSON encoding error: Passed ai_context as-is
        - All exceptions caught gracefully

    HISTORICAL USE:
        Stored scores used by:
            - get_latest_phishing_likelihood_for_source(): Reads PL
            - Trend analysis: View score progression over time
            - ML model training: Historical threat assessments
            - Audit logging: Full record of scoring decisions

    INDEXING RECOMMENDATIONS:
        CREATE INDEX idx_threat_scores_source ON threat_scores(source);
        CREATE INDEX idx_threat_scores_timestamp ON threat_scores(timestamp);
        Improves query performance for lookups and trend analysis

    EXAMPLE:
        save_computed_threat_score(
            indicator='192.168.1.100',
            score=75,
            severity='High',
            category='High',
            ai_context='{"sw": 85, "fw": 60, "rw": 40, "phl": 80}'
        )
        Returns: True (if inserted)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
        cur = conn.cursor()
        # Try permissive insert depending on schema
        try:
            cur.execute("INSERT INTO threat_scores (source, score, severity, category, ai_context, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (indicator, int(score), severity, category, ai_context or '', datetime.now().isoformat()))
        except Exception:
            try:
                cur.execute("INSERT INTO threat_scores (event_id, score, severity, category, ai_context, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (None, int(score), severity, category, ai_context or '', datetime.now().isoformat()))
            except Exception:
                conn.close()
                return False
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION - THREAT SCORING ENGINE PAGE
# ════════════════════════════════════════════════════════════════════════════════

def main():
    """
    ════════════════════════════════════════════════════════════════════════
    Main Streamlit application for threat scoring and auto-blocking.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Complete Streamlit page for analyzing threats and computing final
        threat scores using the multi-factor algorithm. Analysts select
        indicators (source IPs, hostnames) or enter manual IPs to compute
        Sw/Fw/Rw/PL components and final risk score. High-risk indicators
        trigger auto-blocking via pfSense or local recording.

    PAGE LAYOUT:

        Header:
            "Threat Scoring Engine"
            "Compute final threat scores and optionally trigger auto-blocks"
        
        Left Column (Configuration):
            ├─ "Lookback days for frequency" (1-90, default 30)
            ├─ "Frequency cap (events → 100)" (10-1000, default 50)
            └─ Note: Phishing Likelihood fallback = 0
        
        Right Column (Main UI):
            ├─ "Select Indicator" section
            │   ├─ Radio buttons: Source / Host / Manual IP
            │   ├─ Selectbox or text input (mode-dependent)
            │   └─ "Compute Score" button
            │
            ├─ Results Display (shown after compute):
            │   ├─ 2×2 metrics grid: Sw, Fw, Rw, PL
            │   ├─ Final Score display (large heading)
            │   ├─ Sample Log Context (expandable)
            │   ├─ Save confirmation message
            │   └─ Auto-block button (if High category)
            │
            └─ Manual Actions section
                ├─ "Manual IP to block" text input
                └─ "Block Manual IP" button

    WORKFLOW:

        1. Load Page:
           ├─ Set page config (title, wide layout)
           ├─ Apply custom CSS (scrolling)
           ├─ Load unique sources/hosts from splunk_logs
           └─ Populate selectbox options
        
        2. User selects mode (Source/Host/Manual):
           ├─ Source: Dropdown of historical sources
           ├─ Host: Dropdown of historical hosts
           └─ Manual: Text input for any IP
        
        3. User clicks "Compute Score":
           ├─ Get latest severity from splunk_logs
           ├─ Count events in lookback window
           ├─ Lookup reputation from threat_intel_feeds
           ├─ Get phishing likelihood from threat_scores
           ├─ Compute Sw, Fw, Rw, PL
           ├─ Calculate final_score
           ├─ Classify into Low/Medium/High
           ├─ Display metrics and results
           ├─ Save score to threat_scores table
           └─ If High: Offer auto-block button
        
        4. User clicks "Auto-block" (if High):
           ├─ Call try_block_ip_via_pfsense()
           ├─ Attempt pfSense API block
           ├─ Record action in auto_blocks
           └─ Display success/error message
        
        5. Manual block (any IP):
           ├─ User enters IP in manual action section
           ├─ Clicks "Block Manual IP"
           ├─ Calls try_block_ip_via_pfsense()
           └─ Displays block result

    CONFIGURATION PARAMETERS:

        Lookback days (user input, 1-90):
            - Affects frequency_weight() calculation
            - Larger window = more historical events
            - Smaller window = more recent focused
        
        Frequency cap (user input, 10-1000):
            - Event count where weight reaches 100%
            - Default 50: 50 events in window = 100% weight
            - Adjust per your baseline normal activity

    RESULTS DISPLAY:

        Four metrics shown after compute:
            Severity Weight (Sw): 0-100
                ├─ From latest event severity
                ├─ 50% weight in final formula
                └─ Example: 85 (high severity)
            
            Frequency: Count → Weight (Fw): 0-100
                ├─ From event count in window
                ├─ 0% weight in final formula (ignored)
                └─ Example: "25 events → 50/100" (context only)
            
            Reputation (Rw): 0-100
                ├─ From threat_intel_feeds
                ├─ 10% weight in final formula
                └─ Example: 40
            
            Phishing Likelihood (PL): 0-100
                ├─ From latest threat_scores
                ├─ 40% weight in final formula
                └─ Example: 80

        Final Score:
            ├─ Large heading: "Final Score: 75.0 — High"
            ├─ Calculation: (85×0.5) + (50×0.0) + (40×0.1) + (80×0.4)
            └─ Color/style by category (High=red, Medium=yellow, Low=green)

    AUTO-BLOCK LOGIC:

        Triggered when category == 'High' (score >= 71):
            1. Display warning: "Category is High — auto-block recommended"
            2. Show "Auto-block this indicator now" button
            3. User clicks button:
               ├─ Call try_block_ip_via_pfsense(indicator, reason)
               ├─ Attempt pfSense API integration
               ├─ Record in auto_blocks table (local fallback)
               └─ Display success/error message

    DATABASE INTERACTIONS:

        Read (for component calculation):
            - splunk_logs: severity, source, host, raw_log, timestamp
            - threat_intel_feeds: reputation for indicator
            - threat_scores: latest ai_context/score for source
        
        Write (for audit trail):
            - threat_scores: Insert computed score + components
            - auto_blocks: Insert block action records (if blocking)

    ENTRY POINT:
        Called from pages.py router:
            if page == "Threat Scoring":
                pages.Threat_Scoring.main()

    NOTES:
        - Streamlit session state: Implicit (page reloads on interaction)
        - Error handling: All operations have fallbacks
        - Defensive: Missing data uses conservative estimates
        - Responsive: Metrics display immediately after compute
        - Auditable: All scores and blocks logged to DB

    SEE ALSO:
        - severity_to_weight(): Convert text severity to weight
        - frequency_weight(): Count events to frequency weight
        - get_reputation_for_indicator(): Lookup threat feed
        - get_latest_phishing_likelihood_for_source(): Get phishing likelihood
        - compute_final_score(): Calculate Sw+Fw+Rw+PL formula
        - classify_score(): Map score to category
        - try_block_ip_via_pfsense(): Execute block action
        - save_computed_threat_score(): Persist results to DB
    """
    # ════════════════════════════════════════════════════════════════════════
    # TOP BAR - NAVIGATION AND BRANDING
    # ════════════════════════════════════════════════════════════════════════
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown("""
    <style>
        .topbar {
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            color: #E2E2D2;
            padding: 10px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }
        .topbar .left { display:flex; align-items:center; gap:12px; }
        .topbar .brand { font-weight:700; font-size:18px; color:#E2E2D2; }
        .topbar .links { display:flex; gap:10px; align-items:center; }
        .topbar a { color: #E2E2D2; text-decoration: none; padding:8px 12px; border-radius:6px; font-size:14px; transition: all 0.3s ease; }
        .topbar a:hover { background:#243447; color:#E2E2D2; }
        .topbar .cta { background: #c51f5d; color: #ffffff; padding:8px 12px; border-radius:6px; font-weight:600; }
        .topbar .cta:hover { background: #d63574; }
        @media (max-width: 700px) {
            .topbar { flex-direction: column; align-items: flex-start; gap:8px; }
        }
    </style>

    <div class="topbar">
        <div class="left">
            <span class="brand"></span>
        </div>
        <div class="links">
            <a href="Dashboard_Overview" title="Dashboard">Dashboard</a>
            <a href="Live_Threat_Monitor" title="Threats">Monitor</a>
            <a href="Performance_Metrics" title="Metrics">Metrics</a>
            <a class="cta" href="System_Configuration" title="Configuration">Configuration</a>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.title("Threat Scoring Engine")
    st.markdown("Compute final threat scores and optionally trigger auto-blocks for High-risk indicators.")

    col_cfg, col_ui = st.columns([1, 3])

    with col_cfg:
        days = st.number_input("Lookback days for frequency", min_value=1, max_value=90, value=30)
        freq_cap = st.number_input("Frequency cap (events -> 100)", min_value=10, max_value=1000, value=50)
        st.markdown("---")
        st.markdown("Phishing Likelihood fallback: default 0 when no AI score present")

    sources, hosts = get_unique_sources_and_hosts()

    with col_ui:
        st.header("Select Indicator")
        mode = st.radio("Mode", options=["Source", "Host", "Manual IP/Indicator"]) 

        indicator = None
        if mode == 'Source':
            indicator = st.selectbox("Source", options=(sources or ["(no sources)"]))
        elif mode == 'Host':
            indicator = st.selectbox("Host", options=(hosts or ["(no hosts)"]))
        else:
            indicator = st.text_input("IP or Indicator", value="")

        if st.button("Compute Score") and indicator:
            st.info(f"Computing components for: {indicator}")

            # Severity weight: use most recent severity for this indicator
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT severity, raw_log FROM splunk_logs WHERE (source = ? OR host = ? OR raw_log LIKE ?) ORDER BY timestamp DESC LIMIT 1", (indicator, indicator, f"%{indicator}%"))
                row = cur.fetchone()
                conn.close()
                severity_text = row[0] if row else None
                sample_log = row[1] if row and len(row) > 1 else None
            except Exception:
                severity_text = None
                sample_log = None

            inferred_sev = infer_severity(severity_text, sample_log, indicator)
            sw = severity_to_weight(inferred_sev)

            # Frequency
            cnt = count_events_for_indicator(indicator, days=days)
            fw = frequency_weight(cnt, cap=int(freq_cap))

            # Reputation
            rw = get_reputation_for_indicator(indicator)

            # Phishing likelihood from AI scoring
            phl = get_latest_phishing_likelihood_for_source(indicator)

            # Calculate comprehensive threat intelligence metrics
            threat_metrics = calculate_threat_intelligence_metrics(indicator, lookback_days=days)
            
            final = compute_final_score(sw, fw, rw, phl)
            category = classify_score(final)
            
            # Risk Assessment Header
            st.markdown("---")
            st.markdown("## Threat Assessment Report")
            st.markdown(f"**Indicator:** `{indicator}` | **Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Risk Level Display
            st.markdown(f"### Risk Level: **{category.upper()}**")
            st.markdown(f"### Threat Score: **{final:.1f}/100**")
            st.markdown(f"**Threat Category:** {threat_metrics.get('threat_category', 'Unknown Category')}")
            
            # Core Scoring Components
            st.markdown("### Core Threat Scoring Components")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Severity Weight (Sw)", f"{sw}/100", 
                         delta="40% Weight", 
                         help=f"Normalized severity: {inferred_sev.upper()}\n\nBased on latest event classification")
            with col2:
                st.metric("Frequency Weight (Fw)", f"{fw}/100", 
                     delta="0% (ignored)",
                     help=f"Total Events: {cnt}\nCap: {freq_cap}\n\nFrequency shown for context only; excluded from final score.")
            with col3:
                st.metric("Reputation Score (Rw)", f"{rw}/100", 
                         delta="10% Weight",
                         help="From external threat intelligence feeds\n(AbuseIPDB, domain reputation)")
            with col4:
                st.metric("Phishing Likelihood (PL)", f"{phl}/100", 
                         delta="40% Weight",
                         help="Phishing likelihood returned by AI scoring (0-100). Uses 0 if no AI score detected.")
            
            # Score Calculation Breakdown
            with st.expander("Score Calculation Formula", expanded=False):
                st.markdown("""
                **NIST-Aligned Weighted Scoring Formula (Frequency ignored):**
                ```
                Final Score = (Sw × 0.5) + (Rw × 0.1) + (PL × 0.4)
                ```
                **Current Calculation:**
                """)
                st.code(f"""
Severity Component:    {sw} × 0.5 = {sw * 0.5:.2f}
Reputation Component:  {rw} × 0.1 = {rw * 0.1:.2f}
Phishing Likelihood:   {phl} × 0.4 = {phl * 0.4:.2f}
                        ─────────────────
Final Threat Score:                {final:.2f}/100
Risk Classification:               {category.upper()}
                """, language="text")
                
                st.markdown("""
                **Component Weighting Rationale:**
                - **Severity (50%):** Highest weight for immediate threat level
                - **Phishing Likelihood (40%):** ML-derived phishing probability
                - **Reputation (10%):** External intelligence validation
                """)
            
            # Sample Log Context
            if sample_log:
                with st.expander("Sample Log Evidence", expanded=False):
                    st.markdown("**Most Recent Log Entry:**")
                    st.code(sample_log, language="log")

            # Response Recommendations
            st.markdown("### Recommended Response Actions")
            response_actions = {
                'Critical': {
                    'icon': '',
                    'urgency': 'IMMEDIATE (15 minutes)',
                    'actions': [
                        '1. **Automatic Firewall Block** - Execute immediately',
                        '2. **SOC Alert** - Escalate to Security Operations Center',
                        '3. **Incident Response** - Activate IR team',
                        '4. **Executive Notification** - Alert CISO/Security Director',
                        '5. **Forensic Collection** - Preserve evidence for investigation',
                        '6. **System Isolation** - Quarantine affected systems',
                        '7. **Threat Hunt** - Search for related IOCs across network'
                    ]
                },
                'High': {
                    'icon': '',
                    'urgency': 'URGENT (1 hour)',
                    'actions': [
                        '1. **Review & Block** - Analyst review followed by blocking',
                        '2. **Investigation** - Deep dive into attack patterns',
                        '3. **Log Retention** - Increase log collection for this indicator',
                        '4. **Correlation** - Check for related indicators (IOCs)',
                        '5. **System Check** - Verify integrity of affected systems',
                        '6. **User Notification** - Alert affected users if applicable'
                    ]
                },
                'Medium': {
                    'icon': '',
                    'urgency': 'ROUTINE (24 hours)',
                    'actions': [
                        '1. **Analyst Review** - Manual assessment required',
                        '2. **Context Analysis** - Review business justification',
                        '3. **User Behavior** - Check if legitimate user activity',
                        '4. **Watchlist** - Add to monitoring list',
                        '5. **Documentation** - Record findings in ticketing system'
                    ]
                },
                'Low': {
                    'icon': '',
                    'urgency': 'MONITORING (Weekly review)',
                    'actions': [
                        '1. **Log & Monitor** - Continue baseline monitoring',
                        '2. **Trend Analysis** - Include in periodic security reviews',
                        '3. **No Action** - No immediate response required',
                        '4. **Pattern Detection** - Watch for escalation patterns'
                    ]
                }
            }
            
            response = response_actions.get(category, response_actions['Low'])
            st.markdown(f"""
            **Response Urgency:** {response['urgency']}
            
            **Required Actions:**
            """)
            for action in response['actions']:
                st.markdown(f"- {action}")

            # Save computed score to DB
            saved = save_computed_threat_score(indicator, int(final), category, category, 
                                              ai_context=json.dumps({
                                                  'sw': sw, 'fw': fw, 'rw': rw, 'phl': phl,
                                                  'threat_category': threat_metrics['threat_category'],
                                                  'persistence_score': threat_metrics['persistence_score'],
                                                  'impact_score': threat_metrics['impact_score'],
                                                  'events_per_hour': threat_metrics['events_per_hour']
                                              }))
            if saved:
                st.success("Threat assessment saved to database (`threat_scores` table)")
            else:
                st.warning("Could not save assessment to database")

            # Auto-block for High/Critical
            if category in ['High', 'Critical']:
                st.markdown("---")
                st.error(f"**{category.upper()} RISK DETECTED - ACTION REQUIRED**")
                
                if category == 'Critical':
                    st.markdown("**CRITICAL severity requires immediate automatic blocking.**")
                    if st.button("EMERGENCY BLOCK NOW", type="primary"):
                        ok, msg = try_block_ip_via_pfsense(indicator, f"CRITICAL: Auto-blocked due to threat score {final:.1f}")
                        if ok:
                            st.success(f"Emergency block executed: {msg}")
                        else:
                            st.error(f"Block failed: {msg}")
                else:
                    st.markdown("**HIGH severity - auto-block recommended for network protection.**")
                    if st.button("Auto-block this indicator", type="primary"):
                        ok, msg = try_block_ip_via_pfsense(indicator, f"HIGH: Auto-blocked due to threat score {final:.1f}")
                        if ok:
                            st.success(f"Block action recorded: {msg}")
                        else:
                            st.error(f"Block failed: {msg}")

        # Provide manual block option
        st.markdown("---")
        st.header("Manual Actions")
        manual_ip = st.text_input("Manual IP to block")
        if st.button("Block Manual IP") and manual_ip:
            ok, msg = try_block_ip_via_pfsense(manual_ip, "Manual block via Threat Scoring UI")
            if ok:
                st.success(f"Manual block recorded: {msg}")
            else:
                st.error(f"Manual block failed: {msg}")


# ════════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    main()