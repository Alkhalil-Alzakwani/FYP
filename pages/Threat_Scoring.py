"""
Threat Scoring (pages/Threat_Scoring.py)

Implements the threat scoring algorithm and a Streamlit UI for analysts.

Algorithm:
    Final_Score = (Sw × 0.4) + (Fw × 0.2) + (Rw × 0.1) + (Aic × 0.3)

Categories:
    Low (0–40), Medium (41–70), High (71–100)

When category == 'High' the page will attempt to auto-block the IP using
an optional `models.auto_response.block_ip` function. If that function is not
available, a local `auto_blocks` table is created and the block is recorded.

This page is defensive about schema differences in `threat_scores` and other
tables and will try to read necessary data from `splunk_logs`, `threat_intel_feeds`,
and `threat_scores`.
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


def severity_to_weight(sev: str) -> int:
    """Map textual severity to a 0-100 weight."""
    if not sev:
        return 10
    sev = sev.lower()
    mapping = {
        'critical': 100,
        'high': 85,
        'medium': 55,
        'low': 25,
        'info': 5,
        'unknown': 20
    }
    return mapping.get(sev, 20)


def frequency_weight(count: int, cap: int = 50) -> int:
    """Convert event frequency to 0-100 weight. Cap scales at `cap` events."""
    if count <= 0:
        return 0
    val = int(min((count / cap) * 100, 100))
    return val


def get_reputation_for_indicator(indicator: str) -> int:
    """Lookup reputation for an IP/domain in `threat_intel_feeds`. Returns 0-100."""
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


def get_latest_ai_confidence_for_source(source: str) -> int:
    """Get AI confidence (Aic) from latest entry in `threat_scores` for a given source.
    The function is defensive about the stored format (0-1 decimals vs 0-100).
    Returns 0-100 integer.
    """
    try:
        conn = get_db_connection()
        if not conn:
            return 50
        cur = conn.cursor()
        # Try common column names: source, event_id
        try:
            cur.execute("SELECT score, ai_context FROM threat_scores WHERE source = ? ORDER BY timestamp DESC LIMIT 1", (source,))
        except Exception:
            try:
                cur.execute("SELECT score, ai_context FROM threat_scores ORDER BY timestamp DESC LIMIT 1")
            except Exception:
                conn.close()
                return 50

        row = cur.fetchone()
        conn.close()
        if not row:
            return 50
        score = row[0]
        # Determine if stored as decimal
        try:
            s = float(score)
            if s <= 1:
                return int(s * 100)
            return int(max(0, min(s, 100)))
        except Exception:
            return 50
    except Exception:
        return 50


def compute_final_score(sw: int, fw: int, rw: int, aic: int) -> float:
    return (sw * 0.4) + (fw * 0.2) + (rw * 0.1) + (aic * 0.3)


def classify_score(score: float) -> str:
    if score >= 71:
        return 'High'
    if score >= 41:
        return 'Medium'
    return 'Low'


def record_block_action(ip: str, reason: str, method: str = 'local') -> bool:
    """Record an auto-block action in a local `auto_blocks` table. Create table if needed."""
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
    """Attempt to call `models.auto_response.block_ip(ip, reason)` if available.
    Returns (success, message). Falls back to local recording if the import or call fails.
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
    """Count events in splunk_logs matching either source or host or containing the indicator in raw_log within given days."""
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


def main():
    st.title("Threat Scoring Engine")
    st.markdown("Compute final threat scores and optionally trigger auto-blocks for High-risk indicators.")

    col_cfg, col_ui = st.columns([1, 3])

    with col_cfg:
        days = st.number_input("Lookback days for frequency", min_value=1, max_value=90, value=30)
        freq_cap = st.number_input("Frequency cap (events -> 100)", min_value=10, max_value=1000, value=50)
        st.markdown("---")
        st.markdown("AI Confidence fallback: default 50 when no AI data present")

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

            sw = severity_to_weight(severity_text)

            # Frequency
            cnt = count_events_for_indicator(indicator, days=days)
            fw = frequency_weight(cnt, cap=int(freq_cap))

            # Reputation
            rw = get_reputation_for_indicator(indicator)

            # AI confidence
            aic = get_latest_ai_confidence_for_source(indicator)

            final = compute_final_score(sw, fw, rw, aic)
            category = classify_score(final)

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Severity Weight (Sw)", f"{sw}/100")
                st.metric("Frequency (events)", f"{cnt} events -> {fw}/100")
            with col2:
                st.metric("Reputation (Rw)", f"{rw}/100")
                st.metric("AI Confidence (Aic)", f"{aic}/100")

            st.markdown(f"### Final Score: **{final:.1f}** — **{category}**")

            if sample_log:
                with st.expander("Sample Log Context"):
                    st.code(sample_log)

            # Save computed score to DB
            saved = save_computed_threat_score(indicator, int(final), 'High' if category == 'High' else ('Medium' if category == 'Medium' else 'Low'), category, ai_context=json.dumps({'sw': sw, 'fw': fw, 'rw': rw, 'aic': aic}))
            if saved:
                st.success("Computed score saved to `threat_scores` table")
            else:
                st.warning("Could not save computed score to DB (schema mismatch?)")

            # Auto-block for High
            if category == 'High':
                st.warning("Category is High — auto-block recommended.")
                if st.button("Auto-block this indicator now"):
                    ok, msg = try_block_ip_via_pfsense(indicator, f"Auto-blocked due to threat score {final:.1f}")
                    if ok:
                        st.success(f"Block action recorded: {msg}")
                    else:
                        st.error(f"Block failed: {msg}")

        # Provide manual block option
        st.markdown("---")
        st.header("Manual Actions")
        manual_ip = st.text_input("Manual IP to block (useful for testing)")
        if st.button("Block Manual IP") and manual_ip:
            ok, msg = try_block_ip_via_pfsense(manual_ip, "Manual block via Threat Scoring UI")
            if ok:
                st.success(f"Manual block recorded: {msg}")
            else:
                st.error(f"Manual block failed: {msg}")


if __name__ == '__main__':
    main()
"""
Threat Scoring (pages/Threat_Scoring.py)

Purpose: Implement the threat scoring engine Algorithm Components:

    Severity Weight (Sw): Based on alert type
    Frequency Weight (Fw): Number of repeated incidents from same IP
    Reputation Weight (Rw): From threat feeds
    AI Confidence (Aic): From Mistral output
    Final Formula:

Final_Score = (Sw × 0.4) + (Fw × 0.2) + (Rw × 0.1) + (Aic × 0.3)

Output Categories:

    Low (0–40)
    Medium (41–70)
    High (71–100)

Automatic blocking is triggered for High category.

"""