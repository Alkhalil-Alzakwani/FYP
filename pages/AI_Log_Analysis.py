"""
================================================================================
AI LOG ANALYSIS PAGE (pages/AI_Log_Analysis.py)
================================================================================

Purpose: Use Mistral LLM for context-aware log analysis

Features:
    - Analyze logs by source using local Mistral LLM via Ollama
    - Input field for log text or batch upload
    - "Analyze with Mistral" button returns:
        * Phishing likelihood (0–1)
        * Summary of suspicious behavior
        * Suggested response action
    - Results stored in threat_scores
    - Query logs from cyber_defense.db by source

Mathematical Formula:
    Threat_Score = (LLM_Confidence × 0.6) + (Severity_Weight × 0.3) + (Reputation_Penalty × 0.1)

Integration:
    - Uses Ollama API (http://localhost:11434)
    - Mistral model locally installed
    - Reads from splunk_logs table for source analysis

Author: Multilayered Cyber Defense Team
================================================================================
"""

import streamlit as st
import requests
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.queries import get_db_connection

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="AI Log Analysis",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# OLLAMA INTEGRATION
# ============================================================================

def parse_ollama_response(resp: requests.Response) -> str:
    """Try to parse common Ollama response shapes into a single string."""
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


def call_mistral(host: str, model: str, prompt: str) -> str:
    """Call local Ollama Mistral API.

    Args:
        host: base URL like http://localhost:11434
        model: model name (mistral)
        prompt: analysis prompt

    Returns:
        Text response from the model
    """
    host = host.rstrip("/")
    errors = []

    def try_chat():
        try:
            url = f"{host}/api/chat"
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False
            }
            r = requests.post(url, json=payload, timeout=60)
            r.raise_for_status()
            return parse_ollama_response(r)
        except Exception as e:
            errors.append(f"chat: {e}")
            return None

    def try_generate():
        try:
            url = f"{host}/api/generate"
            payload = {"model": model, "prompt": prompt, "stream": False}
            r = requests.post(url, json=payload, timeout=60)
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


# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_logs_by_source(source: str, limit: int = 100) -> List[Dict]:
    """Get all logs for a specific source from database"""
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
    """Get list of unique sources from database"""
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
    """Save analysis result to threat_scores table"""
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


# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

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


def analyze_logs_batch(logs: List[Dict], ollama_host: str, model: str) -> Dict:
    """Analyze a batch of logs using Mistral LLM"""
    
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
    prompt = f"""Analyze these security logs and provide a threat assessment:

LOGS TO ANALYZE ({total_logs} total):
{chr(10).join(log_summaries)}

SEVERITY DISTRIBUTION:
{json.dumps(severity_counts, indent=2)}

Please provide:
1. PHISHING LIKELIHOOD (0-100%): Estimate the probability of phishing/social engineering
2. THREAT SUMMARY: Brief summary of suspicious patterns detected
3. RESPONSE ACTION: Recommended automated response
4. CONFIDENCE LEVEL: How confident are you in this analysis?

Format your response clearly with these sections."""

    # Call Mistral
    with st.spinner("Mistral LLM analyzing logs..."):
        analysis = call_mistral(ollama_host, model, prompt)
    
    return {
        "analysis": analysis,
        "total_logs": total_logs,
        "logs_analyzed": min(20, total_logs),
        "severity_counts": severity_counts
    }


# ============================================================================
# MAIN PAGE
# ============================================================================

def main():
    st.title("AI Log Analysis - Mistral LLM")
    st.markdown("Analyze security logs using local Mistral model via Ollama")
    st.markdown("---")
    
    # Sidebar configuration
    with st.sidebar:
        st.markdown("##Configuration")
        
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
        
        st.markdown("---")
        st.markdown("##About")
        st.info(
            "This page analyzes security logs using Mistral LLM running locally via Ollama. "
            "Ensure Ollama is running and Mistral model is installed."
        )
    
    # Create tabs for different analysis modes
    tab1, tab2, tab3 = st.tabs(["📊 Source Analysis", "📝 Manual Input", "📈 Analysis History"])
    
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
            if st.button("🔍 Fetch and Analyze", use_container_width=True, type="primary"):
                logs = get_logs_by_source(selected_source, max_logs)
                
                if logs:
                    st.success(f"✅ Found {len(logs)} logs from source: **{selected_source}**")
                    
                    # Show logs preview
                    with st.expander("📋 Preview Logs", expanded=False):
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
                    
                    # Analyze with Mistral
                    result = analyze_logs_batch(logs, ollama_host, model)
                    
                    if "error" not in result:
                        st.markdown("### 📊 Analysis Results")
                        
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
                        st.markdown("### 🤖 Mistral AI Analysis")
                        st.markdown(result['analysis'])
                        
                        # Extract and save threat score
                        threat_score = extract_threat_score(result['analysis'])
                        if threat_score is not None:
                            st.success(f"✅ Phishing Likelihood: **{threat_score*100:.1f}%**")
                            
                            # Save to database
                            if st.button("💾 Save Analysis Result", use_container_width=True):
                                severity = "high" if threat_score > 0.7 else "medium" if threat_score > 0.4 else "low"
                                if save_threat_score(selected_source, int(threat_score*100), severity, result['analysis']):
                                    st.success("✅ Analysis saved to threat_scores table")
                
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
        
        if st.button("🔍 Analyze Logs", use_container_width=True, type="primary"):
            if log_text.strip():
                prompt = f"""Analyze this security log and provide a threat assessment:

LOG CONTENT:
{log_text}

Please provide:
1. THREAT LEVEL: Critical/High/Medium/Low/Info
2. PHISHING LIKELIHOOD (0-100%): Estimate probability of phishing/social engineering
3. SUSPICIOUS PATTERNS: What patterns indicate threats?
4. RECOMMENDED ACTIONS: What should be done?
5. CONFIDENCE: How confident is this analysis?

Be concise but thorough."""

                with st.spinner("🤖 Analyzing with Mistral..."):
                    analysis = call_mistral(ollama_host, model, prompt)
                
                st.markdown("### 🤖 Analysis Result")
                st.markdown(analysis)
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
                cursor.execute("""
                    SELECT score, severity, ai_context, timestamp
                    FROM threat_scores
                    ORDER BY timestamp DESC
                    LIMIT 20
                """)
                
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
                        total_analyses = len(history_df)
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