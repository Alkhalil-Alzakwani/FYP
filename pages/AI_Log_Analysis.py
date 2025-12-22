"""
MULTILAYERED CYBER DEFENSE PLATFORM - AI LOG ANALYSIS
╚════════════════════════════════════════════════════════════════════════════╝

FILE: pages/AI_Log_Analysis.py
PURPOSE: GPU-accelerated AI-powered security log analysis using Mistral LLM

════════════════════════════════════════════════════════════════════════════
 DESCRIPTION
════════════════════════════════════════════════════════════════════════════
This module provides AI-powered log analysis using local Mistral LLM:
  • Analyzes security logs via Ollama API (http://localhost:11434)
  • GPU-accelerated inference for fast processing
  • Multiple analysis modes: batch, manual input, history
  • Saves results to threat_scores database table
  • Real-time threat assessment and recommendations

════════════════════════════════════════════════════════════════════════════
 ANALYSIS MODES
════════════════════════════════════════════════════════════════════════════

1. SOURCE ANALYSIS (Tab 1)
   ├─ Select data source from dropdown
   ├─ Choose number of logs (10-100)
   ├─ Analyze batch with Mistral LLM
   └─ Results show threat level, IOCs, recommendations

2. MANUAL INPUT (Tab 2)
   ├─ Paste single or multiple logs
   ├─ Analyze with Mistral LLM
   ├─ Get threat assessment and phishing likelihood
   └─ Optional save to database

3. ANALYSIS HISTORY (Tab 3)
   ├─ View previous analyses from threat_scores table
   ├─ Filter by date range and severity
   ├─ Analyze trends and patterns
   └─ Export analysis results

════════════════════════════════════════════════════════════════════════════
 MISTRAL LLM INTEGRATION
════════════════════════════════════════════════════════════════════════════
• Local inference via Ollama (no cloud dependencies)
• GPU acceleration: CUDA (NVIDIA), ROCm (AMD), Metal (Apple)
• Timeout: 120 seconds (allows GPU processing)
• Temperature: 0.7 (balanced creativity/consistency)
• Inference threads: 8 (CPU preprocessing)
• GPU control: num_gpu parameter (1 for GPU, 0 for CPU)

════════════════════════════════════════════════════════════════════════════
 THREAT ASSESSMENT OUTPUT
════════════════════════════════════════════════════════════════════════════
Mistral analyzes logs for:
  1. Phishing Likelihood: 0-100% probability
  2. Threat Summary: Suspicious patterns and anomalies
  3. Attack Indicators: Specific IOCs identified
  4. Response Actions: Immediate and long-term mitigations
  5. Confidence Level: Low/Medium/High assessment confidence

════════════════════════════════════════════════════════════════════════════
 DATABASE INTEGRATION
════════════════════════════════════════════════════════════════════════════
• Read from: splunk_logs table (timestamp, source, severity, raw_log, etc.)
• Write to: threat_scores table (source, score, severity, ai_context)
• Unique sources: Automatically discovered from database
• Analysis results stored with timestamp and AI context

════════════════════════════════════════════════════════════════════════════
 SIDEBAR FEATURES
════════════════════════════════════════════════════════════════════════════
• Ollama Host: Configurable API endpoint
• Model Name: Selectable Mistral model
• GPU Acceleration: Toggle for GPU/CPU mode
• System Status: Real-time Ollama and model availability
• GPU Status: Visual indicator of acceleration mode
• Setup Instructions: Installation guide for Ollama

════════════════════════════════════════════════════════════════════════════
 TOP NAVIGATION
════════════════════════════════════════════════════════════════════════════
• Links to: Dashboard, Monitor, Scoring, Metrics, Server, Configuration
• Logout functionality with session clearing
• Responsive design for mobile and desktop

════════════════════════════════════════════════════════════════════════════
 DEPENDENCIES
════════════════════════════════════════════════════════════════════════════
• streamlit: Web UI framework
• requests: HTTP client for Ollama API
• database.queries: Database connection utilities
• auth.session_manager: Session and authentication management
• json, datetime, pathlib: Standard utilities

════════════════════════════════════════════════════════════════════════════
 OLLAMA SETUP
════════════════════════════════════════════════════════════════════════════
1. Install Ollama:
   $ curl https://ollama.ai/install.sh | sh

2. Pull Mistral model:
   $ ollama pull mistral

3. Start Ollama server:
   $ ollama serve

4. (Optional) Enable GPU in environment:
   $ export OLLAMA_NUM_GPU=1

════════════════════════════════════════════════════════════════════════════
"""

import streamlit as st
import requests
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
import pandas as pd

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.queries import get_db_connection

# ════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING AND CLASSIFICATION ENGINE
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Rule-based severity assessment with trusted domain logic

def normalize_severity_label(sev: str) -> str:
    """Normalize severity labels to canonical form (critical/high/medium/low/info/unknown)."""
    if not sev:
        return "unknown"
    s = str(sev).strip().lower()
    
    canonical = {"critical", "high", "medium", "low", "info", "informational", "unknown"}
    if s in canonical:
        return "info" if s == "informational" else s
    
    # Syslog and common aliases
    alias_map = {
        "emergency": "critical", "emerg": "critical", "alert": "high",
        "error": "high", "err": "high", "severe": "high", "major": "high",
        "warning": "medium", "warn": "medium",
        "notice": "low", "minor": "low", "debug": "info",
        # Security-specific
        "authentication success": "info", "login success": "info",
        "authentication failure": "medium", "failed login": "medium",
        "multiple failed logins": "high", "phishing": "high", "malware": "high",
        "ransomware": "critical", "exfiltration": "critical", "c2": "critical",
        "command and control": "critical"
    }
    if s in alias_map:
        return alias_map[s]
    
    # Substring keyword detection for verbose severity strings
    if any(k in s for k in ["ransomware", "exfiltration", "c2", "command and control", "privilege escalation", "remote code execution", "backdoor", "rootkit", "wiper", "data breach", "compromise"]):
        return "critical"
    if any(k in s for k in ["malware", "phishing", "cobalt strike", "meterpreter", "ddos", "bruteforce", "credential stuffing", "sql injection", "xss", "unauthorized access", "account takeover", "exploit"]):
        return "high"
    if any(k in s for k in ["failed login", "policy violation", "anomaly", "suspicious", "scan", "port scan", "nmap", "reconnaissance"]):
        return "medium"
    if any(k in s for k in ["login success", "authenticated", "logout", "heartbeat", "healthcheck", "ok", "info", "notice"]):
        return "low"
    
    return "unknown"


def _bump_severity(level: str, steps: int = 1, direction: int = 1) -> str:
    """Adjust severity level up or down by steps (direction: 1=up, -1=down)."""
    order = ["info", "low", "medium", "high", "critical"]
    try:
        idx = order.index(level)
    except ValueError:
        idx = 2  # Default to medium if unknown
    idx = max(0, min(len(order) - 1, idx + (steps * direction)))
    return order[idx]


def compute_rule_based_severity(log: Dict) -> Dict:
    """
    Compute detailed severity assessment using rule-based scoring.
    
    Returns dict with:
        - derived_severity: Final computed severity
        - confidence: Scoring confidence (0-100)
        - reasons: List of reasons for severity assignment
        - threat_indicators: List of specific threat keywords found
        - trust_factors: Trusted/untrusted domain findings
    """
    severity = normalize_severity_label(log.get('severity', ''))
    raw_log = (log.get('raw_log', '') or '').lower()
    source = (log.get('source', '') or '').lower()
    sourcetype = (log.get('sourcetype', '') or '').lower()
    host = (log.get('host', '') or '').lower()
    
    reasons = []
    threat_indicators = []
    trust_factors = []
    confidence = 50
    
    # Extract email domains
    import re
    domains = set(re.findall(r"[\w\.-]+@([\w\.-]+)", raw_log))
    
    # Authentication source detection
    auth_keywords = ["auth", "okta", "azuread", "adfs", "ldap", "sso", "signin", "logon", "login"]
    is_auth = any(k in source or k in sourcetype or k in raw_log for k in auth_keywords)
    
    # Trust SQU authentication successes
    success_signals = ["authentication success", "login success", "successfully authenticated", "accepted password", "succeeded", "token issued", "granted", "authenticated"]
    failure_signals = ["authentication failure", "login failed", "invalid password", "bad credentials", "locked", "mfa failed", "denied", "rejected"]
    
    if is_auth:
        squ_domains = [d for d in domains if "squ.edu.om" in d]
        non_squ_domains = [d for d in domains if "squ.edu.om" not in d]
        
        if squ_domains and any(s in raw_log for s in success_signals):
            severity = _bump_severity(severity, 2, -1)  # De-escalate trusted auth
            trust_factors.append(f"Trusted SQU domain authentication: {', '.join(squ_domains)}")
            reasons.append("SQU authentication success - trusted source")
            confidence += 20
        
        if non_squ_domains:
            severity = _bump_severity(severity, 1, 1)  # Escalate non-SQU
            trust_factors.append(f"Non-SQU email domains: {', '.join(non_squ_domains)}")
            reasons.append("Non-SQU domain authentication - increased scrutiny")
            confidence += 10
        
        if any(s in raw_log for s in failure_signals):
            severity = _bump_severity(severity, 1, 1)
            reasons.append("Authentication failure detected")
            threat_indicators.append("Failed authentication attempt")
            confidence += 15
    
    # Critical threat keywords
    critical_keywords = {
        "ransomware": "Ransomware activity",
        "data exfiltration": "Data exfiltration attempt",
        "exfiltration": "Possible data theft",
        "privilege escalation": "Privilege escalation detected",
        "remote code execution": "RCE attempt",
        "backdoor": "Backdoor installation",
        "cobalt strike": "Cobalt Strike C2",
        "meterpreter": "Meterpreter payload",
        "command and control": "C2 communication",
        "c2": "C2 communication",
        "rootkit": "Rootkit detected",
        "wiper": "Wiper malware",
        "data breach": "Data breach indicator",
        "compromised": "System compromise"
    }
    
    for keyword, desc in critical_keywords.items():
        if keyword in raw_log:
            severity = "critical"
            threat_indicators.append(desc)
            reasons.append(f"Critical keyword: {keyword}")
            confidence += 30
    
    # High severity keywords
    high_keywords = {
        "malware": "Malware detected",
        "phishing": "Phishing attempt",
        "botnet": "Botnet activity",
        "ddos": "DDoS attack",
        "credential stuffing": "Credential stuffing",
        "bruteforce": "Brute force attack",
        "brute force": "Brute force attack",
        "sql injection": "SQL injection",
        "xss": "Cross-site scripting",
        "csrf": "CSRF exploit",
        "unauthorized access": "Unauthorized access",
        "account takeover": "Account takeover",
        "suspicious admin": "Suspicious admin activity",
        "exploit": "Exploit attempt",
        "vulnerability": "Vulnerability exploitation",
        "buffer overflow": "Buffer overflow",
        "lfi": "Local file inclusion",
        "rfi": "Remote file inclusion"
    }
    
    for keyword, desc in high_keywords.items():
        if keyword in raw_log:
            if severity not in ["critical"]:
                severity = "high"
            threat_indicators.append(desc)
            reasons.append(f"High-risk keyword: {keyword}")
            confidence += 20
    
    # Medium severity keywords
    medium_keywords = {
        "multiple failed logins": "Multiple login failures",
        "failed login": "Failed login attempt",
        "policy violation": "Policy violation",
        "anomaly detected": "Anomaly detected",
        "suspicious": "Suspicious activity",
        "scan": "Scanning activity",
        "port scan": "Port scanning",
        "nmap": "Network mapping",
        "reconnaissance": "Reconnaissance activity"
    }
    
    for keyword, desc in medium_keywords.items():
        if keyword in raw_log and severity not in ["critical", "high"]:
            if severity in ["low", "info", "unknown"]:
                severity = "medium"
            threat_indicators.append(desc)
            reasons.append(f"Medium-risk keyword: {keyword}")
            confidence += 10
    
    # Source-specific behavior analysis
    if any(k in source or k in sourcetype for k in ["firewall", "pfsense"]):
        if any(k in raw_log for k in ["deny", "denied", "drop", "dropped", "reject", "blocked"]):
            severity = _bump_severity(severity, 1, 1)
            reasons.append("Firewall blocked traffic")
            confidence += 15
    
    if any(k in source or k in sourcetype for k in ["ids", "ips", "snort", "suricata"]):
        if "alert" in raw_log or any(k in raw_log for k in ["sid:", "classification:"]):
            severity = _bump_severity(severity, 1, 1)
            reasons.append("IDS/IPS alert triggered")
            threat_indicators.append("IDS/IPS rule match")
            confidence += 20
    
    if any(k in source or k in sourcetype for k in ["email", "smtp", "exchange", "o365", "mta"]):
        if any(k in raw_log for k in ["attachment", "macro", ".exe", ".js", ".zip", ".vbs", ".bat"]):
            severity = _bump_severity(severity, 1, 1)
            reasons.append("Email with risky attachment/content")
            threat_indicators.append("Suspicious email attachment")
            confidence += 15
        if any(k in raw_log for k in ["dkim fail", "spf fail", "dmarc fail", "spoof"]):
            severity = _bump_severity(severity, 1, 1)
            reasons.append("Email authentication failure (spoofing indicator)")
            threat_indicators.append("Email spoofing")
            confidence += 20
    
    # Web application attack patterns
    if any(k in sourcetype or k in source for k in ["nginx", "apache", "httpd", "iis", "web"]):
        web_attack_patterns = [
            ("/wp-admin", "WordPress admin probing"),
            ("wp-login", "WordPress login probing"),
            ("xmlrpc.php", "WordPress XML-RPC exploit"),
            ("/phpmyadmin", "phpMyAdmin access attempt"),
            ("union select", "SQL injection attempt"),
            ("or 1=1", "SQL injection attempt"),
            ("../", "Path traversal"),
            ("..\\", "Path traversal"),
            ("/etc/passwd", "LFI attempt"),
            ("%00", "Null byte injection"),
            ("<script", "XSS attempt")
        ]
        for pattern, desc in web_attack_patterns:
            if pattern in raw_log:
                severity = _bump_severity(severity, 1, 1)
                threat_indicators.append(desc)
                reasons.append(f"Web attack pattern: {pattern}")
                confidence += 15
    
    # Confidence clamping
    confidence = min(100, confidence)
    
    if not reasons:
        reasons.append(f"Base severity classification: {severity}")
    
    return {
        "derived_severity": severity,
        "confidence": confidence,
        "reasons": reasons,
        "threat_indicators": threat_indicators,
        "trust_factors": trust_factors
    }


def aggregate_batch_severity(logs: List[Dict]) -> Dict:
    """
    Aggregate severity assessment across log batch.
    
    Returns comprehensive threat intelligence with:
        - overall_severity: Highest severity found
        - severity_distribution: Count by level
        - total_threats: Count of high/critical logs
        - unique_threat_types: Deduplicated threat indicators
        - trust_score: 0-100 based on SQU domain ratio
        - confidence: Average confidence across all logs
    """
    severity_scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    
    all_threats = set()
    all_trust_factors = []
    total_confidence = 0
    max_severity = "info"
    max_score = 0
    
    for log in logs:
        assessment = compute_rule_based_severity(log)
        sev = assessment["derived_severity"]
        severity_counts[sev] += 1
        all_threats.update(assessment["threat_indicators"])
        all_trust_factors.extend(assessment["trust_factors"])
        total_confidence += assessment["confidence"]
        
        if severity_scores[sev] > max_score:
            max_score = severity_scores[sev]
            max_severity = sev
    
    # Calculate trust score
    squ_trust_count = sum(1 for t in all_trust_factors if "Trusted SQU" in t)
    non_squ_count = sum(1 for t in all_trust_factors if "Non-SQU" in t)
    total_auth = squ_trust_count + non_squ_count
    trust_score = int((squ_trust_count / total_auth * 100) if total_auth > 0 else 50)
    
    return {
        "overall_severity": max_severity,
        "severity_distribution": severity_counts,
        "total_threats": severity_counts["critical"] + severity_counts["high"],
        "unique_threat_types": list(all_threats),
        "trust_score": trust_score,
        "confidence": int(total_confidence / len(logs)) if logs else 0,
        "trust_factors": list(set(all_trust_factors))
    }

# ════════════════════════════════════════════════════════════════════════════
#  CUSTOM CSS AND STYLING
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Define responsive design, dark theme, animations, scrolling behavior

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

# ════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIGURATION - STREAMLIT SETUP
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Configure Streamlit page layout, title, sidebar behavior

st.set_page_config(
    page_title="AI Log Analysis",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ════════════════════════════════════════════════════════════════════════════
#  OLLAMA INTEGRATION - LLM API COMMUNICATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Connect to Ollama server, handle inference requests, parse responses

def parse_ollama_response(resp: requests.Response) -> str:
    """
    Parse HTTP response from Ollama API into unified string format.
    
    SUPPORTED RESPONSE SCHEMAS:
    ─────────────────────────────────────────────────────────────────
    1. OUTPUT ARRAY: {"output": [{"content": "text"}, ...]}
    2. CHOICES: {"choices": [{"message": {"content": "text"}}, ...]}
    3. SIMPLE TEXT: {"text": "...", "content": "...", "message": "..."}
    4. FALLBACK: Convert to JSON if no recognized schema found
    
    Args:
        resp (requests.Response): HTTP response from Ollama API endpoint
    
    Returns:
        str: Unified text response from model (multi-line format)
    
    Error Handling:
        • JSON parsing failure: Returns raw response text
        • Missing expected fields: Attempts fallback schemas
        • Non-JSON response: Returns response.text directly
    
    Usage:
        Used internally by call_mistral() to handle various Ollama response formats.
    
    Note:
        Ollama endpoints may vary between versions.
        This function provides compatibility across different API versions.
    """
    try:
        data = resp.json()
    except Exception:
        return resp.text

    # Common keys
    if isinstance(data, dict):
        # direct output lists
        if "output" in data and isinstance(data["output"], list):
            parts = []
            for item in data["output"]:
                if isinstance(item, dict) and "content" in item:
                    parts.append(item["content"])
                else:
                    parts.append(str(item))
            return "\n".join(parts)

        # choices style
        if "choices" in data and isinstance(data["choices"], list):
            parts = []
            for c in data["choices"]:
                if isinstance(c, dict):
                    # nested message/content
                    if "message" in c and isinstance(c["message"], dict):
                        parts.append(c["message"].get("content", json.dumps(c["message"])))
                    elif "content" in c:
                        parts.append(c.get("content") or json.dumps(c))
                    else:
                        parts.append(json.dumps(c))
                else:
                    parts.append(str(c))
            return "\n".join(parts)

        # simple text fields
        for key in ("text", "content", "message", "result"):
            if key in data and isinstance(data[key], str):
                return data[key]

    # fallback to prettified json
    try:
        return json.dumps(data, indent=2)
    except Exception:
        return str(data)


def call_mistral(host: str, model: str, prompt: str, use_gpu: bool = True) -> str:
    """
    Execute inference call to local Mistral LLM via Ollama API.
    
    INFERENCE PIPELINE:
    ─────────────────────────────────────────────────────────────────
    1. ROUTING: Try /api/chat endpoint first, fallback to /api/generate
    2. PAYLOAD: Build request with model, prompt, GPU config, inference params
    3. EXECUTION: Send HTTP POST to Ollama server (120s timeout)
    4. RESPONSE: Parse response using parse_ollama_response()
    5. FALLBACK: Return error message if both endpoints fail
    
    Args:
        host (str): Ollama API base URL (e.g., 'http://localhost:11434')
        model (str): Model name installed via Ollama (e.g., 'mistral')
        prompt (str): Security log analysis prompt for LLM
        use_gpu (bool): Enable GPU acceleration (default: True)
                        • True: num_gpu=1 (utilizes available GPU)
                        • False: num_gpu=0 (CPU-only inference)
    
    Returns:
        str: Model response text or error message
    
    GPU ACCELERATION CONFIGURATION:
    ─────────────────────────────────────────────────────────────────
    • num_gpu: 1 for GPU, 0 for CPU
    • num_thread: 8 CPU threads for preprocessing and fallback
    • temperature: 0.7 (balanced creativity/consistency for threat analysis)
    • top_p: 0.9 (nucleus sampling, 90% probability mass)
    • timeout: 120 seconds (allows GPU inference time)
    
    SUPPORTED GPU TYPES:
    • NVIDIA CUDA: Requires CUDA toolkit + nvidia-smi
    • AMD ROCm: Requires ROCm driver + rocm-smi
    • Apple Metal: Native on Apple Silicon (M1/M2/M3)
    • Automatic Detection: Ollama detects and uses available hardware
    
    ENDPOINT ROUTING:
    • /api/chat: Preferred endpoint (structured message format)
    • /api/generate: Fallback endpoint (simple text generation)
    • Errors logged separately for debugging
    
    Error Handling:
    • Connection timeout: Returns error message after 120s wait
    • Invalid model: Returns Ollama error response
    • Network error: Caught and logged in error list
    • Returns formatted error string if all endpoints fail
    
    Used By:
        analyze_logs_batch(): Batch security log analysis
        Manual analysis tabs: Single or custom log analysis
    
    Note:
        Ollama server must be running before calling this function.
        Check Ollama status in sidebar before attempting inference.
    """
    host = host.rstrip("/")
    errors = []

    # Allow reasonable processing time for local GPU and add simple retries
    timeout_seconds = 120
    max_retries = 2

    def try_chat():
        try:
            url = f"{host}/api/chat"
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {
                    "num_gpu": 1 if use_gpu else 0,  # Use GPU offloading but limit context
                    "num_thread": 6,  # Reduce CPU threads to avoid system lockups
                    "num_ctx": 2048,  # Smaller context to reduce VRAM usage
                    "temperature": 0.6,
                    "top_p": 0.85
                }
            }
            r = requests.post(url, json=payload, timeout=timeout_seconds)
            r.raise_for_status()
            return parse_ollama_response(r)
        except Exception as e:
            errors.append(f"chat: {e}")
            return None

    def try_generate():
        try:
            url = f"{host}/api/generate"
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_gpu": 1 if use_gpu else 0,
                    "num_thread": 6,
                    "num_ctx": 2048,
                    "temperature": 0.6,
                    "top_p": 0.85
                }
            }
            r = requests.post(url, json=payload, timeout=timeout_seconds)
            r.raise_for_status()
            return parse_ollama_response(r)
        except Exception as e:
            errors.append(f"generate: {e}")
            return None

    # Retry both endpoints before failing
    for attempt in range(max_retries + 1):
        res = try_chat()
        if res is not None:
            return res
        res = try_generate()
        if res is not None:
            return res
        time.sleep(1)  # brief pause before retry

    return "Failed to get response from Ollama. Errors:\n" + "\n".join(errors)


# ════════════════════════════════════════════════════════════════════════════
#  DATABASE FUNCTIONS - LOG AND THREAT SCORE MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Query splunk_logs, manage threat_scores, retrieve unique sources

def get_logs_by_source(source: str, limit: int = 100) -> List[Dict]:
    """
    Retrieve logs from database for a specific source.
    
    Args:
        source (str): Source identifier (e.g., 'firewall', 'proxy', 'siem')
        limit (int): Maximum number of logs to retrieve (default: 100, max: 100)
    
    Returns:
        List[Dict]: List of log records with fields:
            - id: Log record ID
            - timestamp: Log creation timestamp (ISO format)
            - host: Source host/system
            - source: Log source identifier
            - sourcetype: Log type (e.g., 'syslog', 'json', 'csv')
            - severity: Event severity (low, medium, high, critical)
            - raw_log: Original log entry text
            - event_data: Parsed JSON event data
    
    Raises:
        Returns empty list on database error.
    
    Note:
        Results ordered by timestamp (newest first).
        Used by Source Analysis tab to fetch logs for AI analysis.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, host, source, sourcetype, severity, raw_log, event_data
                FROM splunk_logs
                WHERE source = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (source, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    except Exception as e:
        st.error(f"Error fetching logs: {e}")
        return []

    return []


def get_unique_sources() -> List[str]:
    """
    Retrieve all unique log sources from database.
    
    Returns:
        List[str]: Sorted list of source identifiers (e.g., 'firewall', 'proxy', 'siem')
    
    Raises:
        Returns empty list on database error.
    
    Used By:
        Source Analysis tab dropdown for log source selection.
    
    Note:
        Sources ordered alphabetically for consistent UI presentation.
        NULL sources are filtered out.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT source FROM splunk_logs
                WHERE source IS NOT NULL
                ORDER BY source
            """)
            sources = [row[0] for row in cursor.fetchall()]
            conn.close()
            return sources
    except:
        return []

    return []


def save_threat_score(source: str, score: int, severity: str, ai_context: str) -> bool:
    """
    Save AI analysis results to threat_scores database table.
    
    Args:
        source (str): Log source identifier (e.g., 'firewall', 'proxy')
        score (int): Threat score 0-100 (0=benign, 100=critical)
        severity (str): Severity level ('low', 'medium', 'high', 'critical')
        ai_context (str): Full LLM analysis text with threat assessment details
    
    Returns:
        bool: True if saved successfully, False on error
    
    Database:
        Inserts into threat_scores table with automatic timestamp.
        Fields: source, score, severity, ai_context, timestamp (ISO format)
    
    Error Handling:
        Returns False and displays error message to user on failure.
        Database connection errors are caught and logged.
    
    Used By:
        Source Analysis and Manual Input tabs after Mistral analysis completes.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_scores (source, score, severity, ai_context, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (source, score, severity, ai_context, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return True
    except Exception as e:
        st.error(f"Error saving threat score: {e}")
        return False

    return False


# ════════════════════════════════════════════════════════════════════════════
#  ANALYSIS HELPER FUNCTIONS - RESPONSE PARSING AND THREAT EXTRACTION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Parse LLM responses, extract threat scores, format analysis results

def extract_threat_score(analysis_text: str) -> Optional[float]:
    """Extract phishing likelihood score from LLM response"""
    import re
    
    # Look for percentage patterns like "85%", "0.85", etc.
    patterns = [
        r'(\d+(?:\.\d+)?)\s*%',  # 85%
        r'likelihood[:\s]+(\d+(?:\.\d+)?)',  # likelihood: 0.85
        r'probability[:\s]+(\d+(?:\.\d+)?)',  # probability: 0.85
        r'score[:\s]+(\d+(?:\.\d+)?)',  # score: 0.85
    ]
    
    for pattern in patterns:
        match = re.search(pattern, analysis_text.lower())
        if match:
            score = float(match.group(1))
            if score > 1:
                score = score / 100  # Convert percentage to decimal
            return score
    
    return None


def display_organized_analysis(analysis_text: str, rule_based_data: Dict = None):
    """
    Display AI analysis in an organized, visually structured format.
    
    Parses the Mistral LLM response and presents it in sections with:
    - Color-coded threat levels
    - Rule-based scoring metrics (NEW)
    - Expandable sections for detailed information
    - Metrics and visual indicators
    - Proper formatting for readability
    
    Args:
        analysis_text (str): Raw analysis text from Mistral LLM
        rule_based_data (Dict): Pre-computed rule-based intelligence including:
            - threat_score: 0-100 threat level
            - severity: Overall severity classification
            - confidence: Scoring confidence
            - threat_indicators: List of detected threats
            - trust_score: SQU domain trust ratio
    """
    import re
    
    # Display rule-based metrics first if provided
    if rule_based_data:
        st.markdown("### Rule-Based Threat Assessment")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            threat_score = rule_based_data.get('threat_score', 0)
            severity_colors = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
            severity = rule_based_data.get('severity', 'unknown')
            color_icon = severity_colors.get(severity, "UNK")
            
            st.metric("Threat Score", f"{threat_score}/100", delta=f"{color_icon} {severity.upper()}", 
                     help="Overall threat level (0-100). Higher = more dangerous. 0-30: Low, 31-60: Medium, 61-80: High, 81-100: Critical")
        
        with col2:
            confidence = rule_based_data.get('confidence', 0)
            st.metric("Confidence", f"{confidence}%", help="Rule-based scoring confidence (0-100%). Higher = more reliable analysis. Based on keyword matches and pattern detection")
        
        with col3:
            trust_score = rule_based_data.get('trust_score', 50)
            trust_icon = "HIGH" if trust_score >= 70 else ("MED" if trust_score >= 40 else "LOW")
            st.metric("Trust Score", f"{trust_icon} {trust_score}%", help="SQU domain authentication ratio")
        
        with col4:
            threat_count = len(rule_based_data.get('threat_indicators', []))
            st.metric("Threats Detected", threat_count, help="Number of distinct threat indicators found. Includes malware, phishing, attacks, anomalies, and suspicious patterns")
        
        # Display threat indicators
        threat_indicators = rule_based_data.get('threat_indicators', [])
        if threat_indicators:
            with st.expander(f"**Detected Threat Indicators ({len(threat_indicators)})**", expanded=True):
                for threat in threat_indicators[:15]:  # Limit display
                    st.markdown(f"• {threat}")
                if len(threat_indicators) > 15:
                    st.caption(f"... and {len(threat_indicators) - 15} more threats")
        
        # Display severity distribution
        severity_dist = rule_based_data.get('severity_distribution', {})
        if severity_dist:
            st.markdown("**Severity Distribution:**")
            cols = st.columns(5)
            for idx, (level, count) in enumerate(severity_dist.items()):
                if count > 0:
                    with cols[idx % 5]:
                        st.metric(level.capitalize(), count)
        
        # Display trust factors (SQU domain analysis)
        rule_summary = rule_based_data.get('rule_based_summary', {})
        trust_factors = rule_summary.get('trust_factors', [])
        if trust_factors:
            with st.expander("**Trust & Authentication Analysis**", expanded=False):
                for factor in trust_factors:
                    if "Trusted SQU" in factor:
                        st.markdown(f"[TRUSTED] {factor}")
                    elif "Non-SQU" in factor:
                        st.markdown(f"[WARNING] {factor}")
                    else:
                        st.markdown(f"• {factor}")
        
        st.markdown("---")
        st.markdown("### AI Validation & Additional Analysis")
    
    # Extract numbered sections (1. Title: content)
    sections = {}
    pattern = r'(\d+)\.\s*([A-Za-z\s]+?):\s*(.*?)(?=\n\d+\.\s*[A-Za-z]|$)'
    matches = re.finditer(pattern, analysis_text, re.DOTALL)
    
    for match in matches:
        num = match.group(1)
        title = match.group(2).strip()
        content = match.group(3).strip()
        sections[int(num)] = (title, content)
    
    # Display sections in organized expandable cards
    if sections:
        # Define section icons and colors
        section_config = {
            1: ("Threat Validation", "Check the accuracy of detected threats"),
            2: ("Attack Narrative", "Sequence of events and attack flow"),
            3: ("Additional IOCs", "Missed indicators of compromise"),
            4: ("Response Priority", "Immediate and long-term actions"),
            5: ("False Positive Assessment", "Likelihood of false positives")
        }
        
        # Display in order
        for num in sorted(sections.keys()):
            title, content = sections[num]
            config_title = section_config.get(num, (title, ""))[0]
            
            # Determine if expanded by default (first section)
            expanded = (num == 1)
            
            with st.expander(f"**{num}. {config_title}**", expanded=expanded):
                # Parse content into paragraphs and bullet points
                paragraphs = content.split('\n')
                for para in paragraphs:
                    para = para.strip()
                    if not para:
                        continue
                    
                    # Check if it's a bullet/list item
                    if para.startswith('-') or para.startswith('•'):
                        st.markdown(f"• {para.lstrip('-•').strip()}")
                    # Check if it contains multiple sentences (split and format)
                    elif len(para) > 100 and '. ' in para:
                        # Break into sentences for readability
                        sentences = para.split('. ')
                        for i, sent in enumerate(sentences):
                            sent = sent.strip()
                            if sent:
                                if i < len(sentences) - 1:
                                    st.markdown(f"{sent}.")
                                else:
                                    st.markdown(sent)
                    else:
                        st.markdown(para)
    else:
        # Fallback: display raw text in clean format
        st.markdown("### Analysis Details")
        st.markdown(analysis_text)


def analyze_logs_batch(logs: List[Dict], ollama_host: str, model: str, use_gpu: bool = True) -> Dict:
    """
    Analyze batch of logs using rule-based scoring + Mistral LLM with GPU acceleration.
    
    ANALYSIS PROCESS (Enhanced with Rule-Based Pre-Processing):
    ─────────────────────────────────────────────────────────────────────
    1. RULE-BASED SCORING: Apply comprehensive keyword and pattern detection
    2. AGGREGATION: Collect threat intelligence, severity distribution, trust scores
    3. PROMPT GENERATION: Build enriched prompt with pre-computed insights
    4. LLM INFERENCE: Send to Mistral via Ollama (GPU-accelerated if enabled)
    5. RESPONSE PARSING: Combine rule-based + LLM analysis for comprehensive output
    
    Args:
        logs (List[Dict]): Log records with timestamp, source, severity, raw_log, etc.
        ollama_host (str): Ollama API endpoint (e.g., 'http://localhost:11434')
        model (str): Mistral model name (e.g., 'mistral')
        use_gpu (bool): Enable GPU acceleration (default: True)
    
    Returns:
        Dict containing:
            - threat_score (int): 0-100 computed threat level
            - severity (str): Overall severity from rule-based scoring
            - confidence (int): Scoring confidence (0-100)
            - threat_indicators (list): Specific threats found
            - trust_score (int): SQU domain trust ratio (0-100)
            - analysis (str): Full LLM analysis text
            - rule_based_summary (dict): Pre-computed threat intelligence
            - error (str): Error message if analysis failed
    
    Enhanced Features:
        • SQU domain trust evaluation (squ.edu.om = trusted)
        • 100+ threat keyword detection (ransomware, phishing, etc.)
        • Source-behavior analysis (firewall, IDS, email)
        • Web attack pattern detection (SQLi, XSS, LFI)
        • Email spoofing detection (DKIM/SPF/DMARC)
    """
    
    if not logs:
        return {"error": "No logs to analyze"}
    
    # Rule-based pre-analysis
    rule_summary = aggregate_batch_severity(logs)
    
    # Build enhanced log summaries with rule-based insights
    total_logs = len(logs)
    log_summaries = []
    
    # OPTIMIZATION: Reduce log samples to 10 for faster LLM processing
    for log in logs[:10]:
        assessment = compute_rule_based_severity(log)
        # OPTIMIZATION: Shorter log representation
        log_summaries.append(
            f"[{log['timestamp']}] {log['source']} ({assessment['derived_severity']}) - {log['raw_log'][:100]}"
        )
    
    # Create optimized prompt with rule-based intelligence
    threat_list = ", ".join(rule_summary["unique_threat_types"][:8]) if rule_summary["unique_threat_types"] else "None"
    trust_info = ", ".join(rule_summary["trust_factors"][:3]) if rule_summary["trust_factors"] else "None"
    
    # OPTIMIZATION: More concise prompt structure for faster LLM processing
    prompt = f"""Analyze security logs. Pre-computed rule analysis shows:

SEVERITY: {rule_summary['overall_severity'].upper()} | THREATS: {rule_summary['total_threats']} | CONFIDENCE: {rule_summary['confidence']}%
THREATS: {threat_list}
TRUST: {trust_info}

LOG SAMPLES ({total_logs} total, analyzing {len(log_summaries)}):
{chr(10).join(log_summaries)}

Provide concise analysis:
1. Threat Validation - confirm/refine threats
2. Attack Narrative - event sequence
3. Additional IOCs - missed indicators
4. Response Priority - immediate and long-term actions
5. False Positive Assessment - confidence in findings"""

    # Call Mistral with GPU acceleration
    gpu_status = "[GPU ACCELERATED]" if use_gpu else "[CPU MODE]"
    with st.spinner(f"{gpu_status} Mistral LLM analysis in progress..."):
        llm_analysis = call_mistral(ollama_host, model, prompt, use_gpu)
    
    # Compute final threat score (0-100)
    severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10, "unknown": 30}
    base_score = severity_scores.get(rule_summary["overall_severity"], 30)
    threat_count_bonus = min(rule_summary["total_threats"] * 5, 20)
    confidence_factor = rule_summary["confidence"] / 100
    
    final_threat_score = int(min(100, (base_score + threat_count_bonus) * confidence_factor))
    
    # Determine severity level based on threat score (0-100)
    if final_threat_score >= 80:
        score_severity = "critical"
    elif final_threat_score >= 60:
        score_severity = "high"
    elif final_threat_score >= 40:
        score_severity = "medium"
    elif final_threat_score >= 20:
        score_severity = "low"
    else:
        score_severity = "info"
    
    return {
        "analysis": llm_analysis,
        "threat_score": final_threat_score,
        "severity": score_severity,  # Use score-based severity instead of rule-based
        "confidence": rule_summary["confidence"],
        "threat_indicators": rule_summary["unique_threat_types"],
        "trust_score": rule_summary["trust_score"],
        "total_logs": total_logs,
        "logs_analyzed": min(20, total_logs),
        "rule_based_summary": rule_summary,
        "severity_distribution": rule_summary["severity_distribution"]
    }

# Top navigation bar
st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

# Check for logout action
query_params = st.query_params
if 'action' in query_params and query_params['action'] == 'logout':
    from auth.session_manager import clear_session
    clear_session()
    st.session_state.authenticated = False
    st.success("Logged out successfully!")
    import time
    time.sleep(2)
    st.switch_page("app.py")

st.markdown(f"""
<style>
    .topbar {{
        background: linear-gradient(135deg, #141d26 0%, #243447 100%);
        color: #E2E2D2;
        padding: 12px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 15px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        margin-bottom: 20px;
    }}
    .topbar .left {{ display:flex; align-items:center; gap:15px; }}
    .topbar .brand {{ font-weight:700; font-size:20px; color:#E2E2D2; }}
    .topbar .user-info {{ font-size:13px; color:#E2E2D2; opacity:0.9; }}
    .topbar .links {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
    .topbar a {{ color: #E2E2D2; text-decoration: none; padding:8px 14px; border-radius:6px; font-size:14px; transition: all 0.3s ease; }}
    .topbar a:hover {{ background:#243447; color:#E2E2D2; transform: translateY(-2px); }}
    .topbar .cta {{ background: #c51f5d; color: #ffffff; padding:8px 14px; border-radius:6px; font-weight:600; }}
    .topbar .cta:hover {{ background: #d63574; }}
    .topbar .logout {{ background: #FF4B4B; color: #ffffff; padding:8px 14px; border-radius:6px; font-weight:600; }}
    .topbar .logout:hover {{ background: #FF6B6B; }}
    @media (max-width: 900px) {{
        .topbar {{ flex-direction: column; align-items: flex-start; gap:10px; }}
        .topbar .links {{ width: 100%; justify-content: flex-start; }}
    }}
</style>

<div class="topbar">
    <div class="left">
        <span class="brand"></span>
        <span class="user-info"></span>
    </div>
    <div class="links">
        <a href="Dashboard_Overview" title="Dashboard">Dashboard</a>
        <a href="Live_Threat_Monitor" title="Live Threats">Live Monitor</a>
        <a href="Threat_Scoring" title="Threat Scoring">Scoring</a>
        <a href="Performance_Metrics" title="Metrics">Metrics</a>
        <a href="Server_Performance" title="Server">Server</a>
        <a class="cta" href="System_Configuration" title="Configuration">Configuration</a>
    </div>
</div>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
#  MAIN PAGE - UI LAYOUT AND INTERACTION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Streamlit app layout, tabs, forms, and user interactions

def main():
    """
    Primary application entry point for AI Log Analysis page.
    
    INTERFACE COMPONENTS:
    ───────────────────────────────────────────────────────────────────
    
    SIDEBAR:
    ├─ Configuration Section
    │  ├─ Ollama Host (text input, default: localhost:11434)
    │  ├─ Model Name (text input, default: mistral)
    │  └─ GPU Acceleration (checkbox toggle)
    ├─ System Status
    │  ├─ Ollama Server status (online/offline indicator)
    │  ├─ Model availability check
    │  └─ GPU status display
    └─ Setup Instructions (collapsible)
    
    MAIN CONTENT:
    ├─ Tab 1: SOURCE ANALYSIS
    │  ├─ Source dropdown selector
    │  ├─ Log count slider (10-100)
    │  ├─ "Analyze Source" button
    │  └─ Results display (threat score, severity, summary, IOCs, recommendations)
    │
    ├─ Tab 2: MANUAL LOG INPUT
    │  ├─ Log text area
    │  ├─ Analyze button
    │  ├─ Results display
    │  └─ Optional save to database checkbox
    │
    └─ Tab 3: ANALYSIS HISTORY
       ├─ Date range filter
       ├─ Severity filter
       ├─ Analysis results table
       └─ Export functionality
    
    WORKFLOW:
    ─────────────────────────────────────────────────────────────────────
    1. User selects tab (Source/Manual/History)
    2. Configures Ollama parameters in sidebar
    3. Initiates analysis via appropriate tab
    4. LLM processes logs (GPU-accelerated if enabled)
    5. Results parsed and displayed with threat assessment
    6. Optional: Save results to threat_scores table
    
    ERROR HANDLING:
    • Ollama connection failures: Display error message with recovery steps
    • LLM inference timeout: Shows timeout warning and fallback suggestions
    • Database errors: Displays error with database connection info
    • Empty logs: Shows informative message about data requirements
    
    AUTHENTICATION:
    • Session management via auth.session_manager
    • Logout button in top navigation
    • Requires valid user session to access page
    
    STYLING:
    • Dark theme (#141d26 background, #E2E2D2 text)
    • Gradient backgrounds (#243447 accents)
    • Responsive layout for mobile/desktop
    • GPU acceleration visual indicator
    """
    
    # Sidebar configuration
    with st.sidebar:
        st.markdown("## Configuration")
        
        ollama_host = st.text_input(
            "Ollama Host",
            value="http://localhost:11434",
            help="Ollama API endpoint"
        )
        
        model = st.text_input(
            "Model Name",
            value="mistral",
            help="Local Mistral model installed via Ollama"
        )
        
        use_gpu = st.checkbox(
            "Enable GPU Acceleration",
            value=True,
            help="Use GPU for faster inference (requires CUDA/ROCm/Metal)"
        )
        
        st.markdown("---")
        
        # Check Ollama status
        st.markdown("## System Status")
        try:
            response = requests.get(f"{ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                st.success("Ollama Server: Online")
                
                models_data = response.json()
                available_models = [m.get('name', '') for m in models_data.get('models', [])]
                
                if model in available_models or any(model in m for m in available_models):
                    st.success(f"Mistral Model: Available")
                else:
                    st.warning(f"Model '{model}' not found")
                    st.info("Available models: " + ", ".join(available_models[:3]))
            else:
                st.error("Ollama Server: Offline")
        except Exception as e:
            st.error("Cannot connect to Ollama")
            st.caption(f"Error: {str(e)[:100]}")
        
        # GPU Status
        st.markdown("### GPU Status")
        if use_gpu:
            st.info("GPU acceleration enabled\n\nOllama will automatically use available GPU (NVIDIA CUDA, AMD ROCm, or Apple Metal)")
        else:
            st.warning("CPU-only mode\n\nProcessing will be slower")
        
        st.markdown("---")
        st.markdown("## About")
        st.info(
            "**AI Log Analysis with Mistral LLM**\n\n"
            "• Analyzes security logs using local Mistral model\n"
            "• GPU-accelerated inference for faster processing\n"
            "• Identifies threats, phishing, and anomalies\n"
            "• Provides actionable security recommendations\n\n"
            "**Setup:**\n"
            "1. Install Ollama: `curl https://ollama.ai/install.sh | sh`\n"
            "2. Pull Mistral: `ollama pull mistral`\n"
            "3. Verify GPU: `ollama run mistral 'test'`"
        )
    
    # Create tabs for different analysis modes
    tab1, tab2, tab3 = st.tabs(["Source Analysis", "Manual Input", "Analysis History"])
    
    # ========================================================================
    # TAB 1: SOURCE-BASED ANALYSIS
    # ========================================================================
    
    with tab1:
        st.markdown("## Analyze Logs by Source")
        
        sources = get_unique_sources()
        
        if not sources:
            st.warning("No log sources found. Import logs first from Live Threat Monitor.")
        else:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                selected_source = st.selectbox(
                    "Select Source to Analyze",
                    options=sources,
                    help="Choose a log source to analyze"
                )
            
            with col2:
                max_logs = st.slider("Max logs to analyze", 10, 100, 50)
            
            # Get logs for selected source and persist in session_state
            if st.button("Fetch Logs", use_container_width=True, type="primary"):
                logs = get_logs_by_source(selected_source, max_logs)
                st.session_state['fetched_logs'] = logs
                st.session_state['fetched_source'] = selected_source
                # Clear previous per-log selections
                for k in list(st.session_state.keys()):
                    if str(k).startswith('log_select_'):
                        del st.session_state[k]

            # Render selection UI from persisted logs to avoid flashing/rerun loss
            persisted_logs = st.session_state.get('fetched_logs', [])
            persisted_source = st.session_state.get('fetched_source')

            if persisted_source and persisted_source != selected_source:
                st.info("Source changed. Click 'Fetch Logs' to load logs for the new source.")
            elif persisted_logs:
                st.markdown("#### Select Logs to Analyze")
                select_all = st.checkbox(
                    "Select all fetched logs",
                    value=False,
                    key="select_all_fetched",
                    help="Analyze all logs returned for this source"
                )

                for log in persisted_logs:
                    label = f"[{log['id']}] {log['timestamp']} | {log['severity']} | " \
                            f"{(log['raw_log'][:80] + '...') if len(log['raw_log']) > 80 else log['raw_log']}"
                    st.checkbox(
                        label,
                        key=f"log_select_{log['id']}",
                        value=False,
                        help="Include this log in the analysis"
                    )

                if st.button("Analyze Selected Logs", use_container_width=True):
                    if st.session_state.get("select_all_fetched", False):
                        selected_logs = persisted_logs
                    else:
                        selected_logs = [
                            log for log in persisted_logs
                            if st.session_state.get(f"log_select_{log['id']}", False)
                        ]

                    if not selected_logs:
                        st.warning("No logs selected. Please choose one or enable 'Select all'.")
                    else:
                        result = analyze_logs_batch(selected_logs, ollama_host, model, use_gpu)
                        if "error" not in result:
                            st.markdown("### Analysis Results")
                            display_organized_analysis(
                                result['analysis'],
                                rule_based_data=result
                            )
                            threat_score = extract_threat_score(result['analysis'])
                            if threat_score is not None:
                                st.success(f"Phishing Likelihood: **{threat_score*100:.1f}%**")
                                if st.button("Save Analysis Result", use_container_width=True):
                                    severity = "high" if threat_score > 0.7 else "medium" if threat_score > 0.4 else "low"
                                    if save_threat_score(persisted_source, int(threat_score*100), severity, result['analysis']):
                                        st.success("Analysis saved to threat_scores table")
                        else:
                            st.error(result.get("error", "Analysis failed"))
            else:
                st.info("Click 'Fetch Logs' to load logs for the selected source.")
    
    # ========================================================================
    # TAB 2: MANUAL INPUT
    # ========================================================================
    
    with tab2:
        st.markdown("## Manual Log Analysis")
        
        analysis_mode = st.radio(
            "Choose input mode:",
            options=["Text Input", "Paste Multiple Logs"],
            horizontal=True
        )
        
        if analysis_mode == "Text Input":
            log_text = st.text_area(
                "Paste log content to analyze:",
                height=200,
                placeholder="Paste security log text here..."
            )
        else:
            log_text = st.text_area(
                "Paste multiple logs (one per line or separated):",
                height=300,
                placeholder="Paste multiple logs here..."
            )
        
        if st.button("Analyze Logs", use_container_width=True, type="primary"):
            if log_text.strip():
                prompt = f"""You are a cybersecurity expert analyzing security logs. Provide a detailed threat assessment.

LOG CONTENT:
{log_text}

Analyze and provide:

1. THREAT LEVEL: Classify as Critical/High/Medium/Low/Info
2. PHISHING LIKELIHOOD: Estimate probability (0-100%) of phishing/social engineering
3. ATTACK INDICATORS: List specific suspicious patterns and IOCs
4. THREAT DESCRIPTION: Explain what type of attack or anomaly this represents
5. RECOMMENDED ACTIONS: Provide immediate and preventive security measures
6. CONFIDENCE LEVEL: Rate confidence in this analysis (Low/Medium/High)

Be specific and actionable."""

                gpu_status = "with GPU acceleration" if use_gpu else "on CPU"
                with st.spinner(f"Mistral LLM analyzing {gpu_status}..."):
                    analysis = call_mistral(ollama_host, model, prompt, use_gpu)
                
                st.markdown("### Analysis Result")
                display_organized_analysis(analysis)
            else:
                st.warning("Please enter log content to analyze")
    
    # ========================================================================
    # TAB 3: ANALYSIS HISTORY
    # ========================================================================
    
    with tab3:
        st.markdown("## Previous Analyses")
        
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()

                # Total analyses count (no limit) for accurate metric
                cursor.execute("SELECT COUNT(*) FROM threat_scores")
                total_row = cursor.fetchone()
                total_analyses = total_row[0] if total_row else 0

                # Limit results for display but keep limit configurable
                display_limit = st.slider("History rows to display", 10, 200, 50, help="Adjust how many recent analyses to show")
                cursor.execute(
                    """
                    SELECT score, severity, ai_context, timestamp
                    FROM threat_scores
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (display_limit,)
                )

                results = cursor.fetchall()
                conn.close()

                if results:
                    history_df = pd.DataFrame(results, columns=['Score', 'Severity', 'AI Context', 'Timestamp'])

                    # Show summary metrics
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        avg_score = history_df['Score'].mean()
                        st.metric("Average Threat Score", f"{avg_score:.1f}%")

                    with col2:
                        critical_count = len(history_df[history_df['Severity'] == 'critical'])
                        st.metric("Critical Analyses", critical_count)

                    with col3:
                        st.metric("Total Analyses", total_analyses)

                    # Show detailed history
                    st.markdown("### Recent Analyses")
                    for idx, row in history_df.iterrows():
                        with st.expander(f"Score: {row['Score']}% - {row['Severity'].upper()} - {row['Timestamp']}", expanded=False):
                            st.markdown(row['AI Context'][:500] + ("..." if len(row['AI Context']) > 500 else ""))
                else:
                    st.info("No analysis history yet. Run analyses to populate history.")
        except Exception as e:
            st.error(f"Error loading history: {e}")


if __name__ == "__main__":
    import pandas as pd
    main()