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
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
import pandas as pd

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.queries import get_db_connection
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

    def try_chat():
        try:
            url = f"{host}/api/chat"
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {
                    "num_gpu": 1 if use_gpu else 0,  # Force GPU usage
                    "num_thread": 8,  # CPU threads for preprocessing
                    "temperature": 0.7,
                    "top_p": 0.9,
                }
            }
            r = requests.post(url, json=payload, timeout=120)  # Increased timeout for GPU processing
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
                    "num_gpu": 1 if use_gpu else 0,  # Force GPU usage
                    "num_thread": 8,
                    "temperature": 0.7,
                    "top_p": 0.9,
                }
            }
            r = requests.post(url, json=payload, timeout=120)
            r.raise_for_status()
            return parse_ollama_response(r)
        except Exception as e:
            errors.append(f"generate: {e}")
            return None

    res = try_chat()
    if res is not None:
        return res
    res = try_generate()
    if res is not None:
        return res

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


def display_organized_analysis(analysis_text: str):
    """
    Display AI analysis in an organized, visually structured format.
    
    Parses the Mistral LLM response and presents it in sections with:
    - Color-coded threat levels
    - Expandable sections for detailed information
    - Metrics and visual indicators
    - Proper formatting for readability
    
    Args:
        analysis_text (str): Raw analysis text from Mistral LLM
    """
    import re
    
    # Extract sections using regex patterns
    sections = {
        'phishing_likelihood': r'(?:1\.\s*)?PHISHING LIKELIHOOD[:\s]+(.*?)(?=(?:\d+\.\s*)?(?:THREAT SUMMARY|THREAT LEVEL|ATTACK INDICATORS|$))',
        'threat_summary': r'(?:2\.\s*)?THREAT (?:SUMMARY|LEVEL)[:\s]+(.*?)(?=(?:\d+\.\s*)?(?:ATTACK INDICATORS|RESPONSE ACTIONS|$))',
        'attack_indicators': r'(?:3\.\s*)?ATTACK INDICATORS[:\s]+(.*?)(?=(?:\d+\.\s*)?(?:RESPONSE ACTIONS|THREAT DESCRIPTION|RECOMMENDED ACTIONS|$))',
        'response_actions': r'(?:4\.\s*)?(?:RESPONSE ACTIONS|RECOMMENDED ACTIONS)[:\s]+(.*?)(?=(?:\d+\.\s*)?(?:CONFIDENCE LEVEL|$))',
        'confidence': r'(?:5\.\s*)?CONFIDENCE LEVEL[:\s]+(.*?)$'
    }
    
    extracted = {}
    for key, pattern in sections.items():
        match = re.search(pattern, analysis_text, re.IGNORECASE | re.DOTALL)
        if match:
            extracted[key] = match.group(1).strip()
    
    # Display Phishing Likelihood with visual indicator
    if 'phishing_likelihood' in extracted:
        phishing_text = extracted['phishing_likelihood']
        percentage_match = re.search(r'(\d+)%', phishing_text)
        
        if percentage_match:
            percentage = int(percentage_match.group(1))
            col1, col2 = st.columns([1, 3])
            
            with col1:
                # Color-code based on threat level
                if percentage >= 80:
                    color = "🔴"
                    level = "CRITICAL"
                elif percentage >= 60:
                    color = "🟠"
                    level = "HIGH"
                elif percentage >= 40:
                    color = "🟡"
                    level = "MEDIUM"
                else:
                    color = "🟢"
                    level = "LOW"
                
                st.metric("Phishing Likelihood", f"{percentage}%", delta=level)
            
            with col2:
                st.markdown(f"**{color} Risk Level: {level}**")
                st.caption(phishing_text)
        else:
            st.info(f"**Phishing Likelihood:** {phishing_text}")
    
    st.markdown("---")
    
    # Threat Summary
    if 'threat_summary' in extracted:
        with st.expander("**Threat Summary**", expanded=True):
            st.markdown(extracted['threat_summary'])
    
    # Attack Indicators
    if 'attack_indicators' in extracted:
        with st.expander("**Attack Indicators (IOCs)**", expanded=True):
            indicators = extracted['attack_indicators']
            # Try to format as bullet points if they contain dashes or newlines
            if '\n -' in indicators or '\n-' in indicators:
                st.markdown(indicators)
            else:
                # Split by common delimiters and format
                lines = [line.strip() for line in indicators.split('\n') if line.strip()]
                for line in lines:
                    st.markdown(f"• {line}")
    
    # Response Actions
    if 'response_actions' in extracted:
        with st.expander("**Recommended Response Actions**", expanded=True):
            actions = extracted['response_actions']
            # Check for "Immediate" and "Long-term" sections
            if 'Immediate' in actions or 'immediate' in actions.lower():
                st.markdown(actions)
            else:
                lines = [line.strip() for line in actions.split('\n') if line.strip()]
                st.markdown("**Recommended Actions:**")
                for line in lines:
                    if line and not line.startswith('-'):
                        st.markdown(f"• {line}")
                    else:
                        st.markdown(line)
    
    # Confidence Level
    if 'confidence' in extracted:
        confidence_text = extracted['confidence'].lower()
        if 'high' in confidence_text:
            conf_icon = "🟢"
            conf_level = "HIGH"
        elif 'medium' in confidence_text:
            conf_icon = "🟡"
            conf_level = "MEDIUM"
        else:
            conf_icon = "🔵"
            conf_level = "LOW"
        
        st.markdown(f"**{conf_icon} Confidence Level: {conf_level}**")
        st.caption(extracted['confidence'])
    
    # If no sections were extracted, display raw text as fallback
    if not extracted:
        st.markdown("### Full Analysis")
        st.markdown(analysis_text)


def analyze_logs_batch(logs: List[Dict], ollama_host: str, model: str, use_gpu: bool = True) -> Dict:
    """
    Analyze batch of logs using Mistral LLM with GPU acceleration.
    
    ANALYSIS PROCESS (5 Steps):
    ─────────────────────────────────────────────────────────────────────
    1. AGGREGATION: Collect logs, count severity levels, create summaries
    2. PROMPT GENERATION: Build detailed threat assessment prompt for LLM
    3. LLM INFERENCE: Send to Mistral via Ollama (GPU-accelerated if enabled)
    4. RESPONSE PARSING: Extract threat score, severity, IOCs, recommendations
    5. RESULT FORMATTING: Prepare structured output with assessments
    
    Args:
        logs (List[Dict]): Log records with timestamp, source, severity, raw_log, etc.
        ollama_host (str): Ollama API endpoint (e.g., 'http://localhost:11434')
        model (str): Mistral model name (e.g., 'mistral')
        use_gpu (bool): Enable GPU acceleration (default: True)
    
    Returns:
        Dict containing:
            - threat_score (int): 0-100 threat level
            - severity (str): 'low', 'medium', 'high', or 'critical'
            - phishing_likelihood (float): 0-1.0 probability
            - summary (str): Threat assessment summary
            - iocs (str): Indicators of compromise found
            - recommendations (str): Recommended actions
            - analysis (str): Full LLM analysis text
            - error (str): Error message if analysis failed
    
    GPU Acceleration:
        • NVIDIA CUDA: Requires CUDA toolkit and nvidia-smi
        • AMD ROCm: Requires ROCm driver installation
        • Apple Metal: Native GPU support on Apple Silicon
        • CPU Fallback: Automatic fallback if GPU unavailable
        • Timeout: 120 seconds allows GPU processing time
    
    Error Handling:
        Returns dict with 'error' key if LLM connection fails.
        Gracefully handles empty log lists.
        API timeouts logged and returned as error.
    
    Used By:
        Source Analysis tab ("Analyze Source" button).
        Batch processing workflow for security monitoring.
    """
    
    if not logs:
        return {"error": "No logs to analyze"}
    
    # Aggregate log data
    total_logs = len(logs)
    severity_counts = {}
    log_summaries = []
    
    for log in logs[:20]:  # Limit to first 20 for analysis
        severity = log.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        log_summaries.append(f"[{log['timestamp']}] {log['source']} - {log['host']}: {log['raw_log'][:200]}")
    
    # Create comprehensive prompt for Mistral
    prompt = f"""You are a cybersecurity expert analyzing security logs. Provide a detailed threat assessment.

LOGS TO ANALYZE ({total_logs} total):
{chr(10).join(log_summaries)}

SEVERITY DISTRIBUTION:
{json.dumps(severity_counts, indent=2)}

Analyze these logs and provide:

1. PHISHING LIKELIHOOD: Estimate probability (0-100%) of phishing/social engineering attacks
2. THREAT SUMMARY: Identify suspicious patterns, anomalies, and potential security risks
3. ATTACK INDICATORS: List specific indicators of compromise (IOCs)
4. RESPONSE ACTIONS: Recommend immediate and long-term security responses
5. CONFIDENCE LEVEL: Rate your confidence in this analysis (Low/Medium/High)

Be specific and actionable in your recommendations."""

    # Call Mistral with GPU acceleration
    gpu_status = "with GPU acceleration" if use_gpu else "on CPU"
    with st.spinner(f"Mistral LLM analyzing logs {gpu_status}..."):
        analysis = call_mistral(ollama_host, model, prompt, use_gpu)
    
    return {
        "analysis": analysis,
        "total_logs": total_logs,
        "logs_analyzed": min(20, total_logs),
        "severity_counts": severity_counts
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
            
            # Get logs for selected source
            if st.button("Fetch and Analyze", use_container_width=True, type="primary"):
                logs = get_logs_by_source(selected_source, max_logs)
                
                if logs:

                    
                    # Show logs preview
                    with st.expander("Preview Logs", expanded=False):
                        logs_preview = pd.DataFrame([
                            {
                                'timestamp': log['timestamp'],
                                'host': log['host'],
                                'severity': log['severity'],
                                'raw_log': log['raw_log'][:100] + "..."
                            }
                            for log in logs[:10]
                        ])
                        st.dataframe(logs_preview, use_container_width=True)
                    
                    # Analyze with Mistral using GPU
                    result = analyze_logs_batch(logs, ollama_host, model, use_gpu)
                    
                    if "error" not in result:
                        st.markdown("### Analysis Results")
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Total Logs Analyzed", result['total_logs'])
                        
                        with col2:
                            st.metric("Logs Processed", result['logs_analyzed'])
                        
                        with col3:
                            critical_count = result['severity_counts'].get('critical', 0)
                            st.metric("Critical Events", critical_count)
                        
                        # Severity distribution
                        st.markdown("#### Severity Breakdown")
                        severity_df = pd.DataFrame(
                            list(result['severity_counts'].items()),
                            columns=['Severity', 'Count']
                        )
                        st.bar_chart(severity_df.set_index('Severity'))
                        
                        # Full analysis
                        st.markdown("### AI Analysis Summary")
                        display_organized_analysis(result['analysis'])
                        
                        # Extract and save threat score
                        threat_score = extract_threat_score(result['analysis'])
                        if threat_score is not None:
                            st.success(f"Phishing Likelihood: **{threat_score*100:.1f}%**")
                            
                            # Save to database
                            if st.button("Save Analysis Result", use_container_width=True):
                                severity = "high" if threat_score > 0.7 else "medium" if threat_score > 0.4 else "low"
                                if save_threat_score(selected_source, int(threat_score*100), severity, result['analysis']):
                                    st.success("Analysis saved to threat_scores table")
                
                else:
                    st.warning(f"No logs found for source: {selected_source}")
    
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