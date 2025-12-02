"""
================================================================================
FORENSICS AND REPORTS (pages/Forensics_And_Reports.py)
================================================================================

Purpose: Post-incident forensic analysis and reporting

Features:
    - Generate downloadable incident reports (CSV)
    - Upload and store raw PCAP files and make them downloadable
    - Display Splunk event data related to incidents
    - Visualize timeline of incident events
    - Export performance summaries (CSV)

Linked to: threat_scores, siem_logs, splunk_logs

Notes:
    - PDF export requires an external library (e.g., reportlab or fpdf). CSV is supported out-of-the-box.

Author: Multilayered Cyber Defense Team
================================================================================
"""

import streamlit as st
import pandas as pd
import os
import io
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import plotly.express as px

# Add project root to path and import DB helper
project_root = Path(__file__).parent.parent
import sys
sys.path.insert(0, str(project_root))
from database.queries import get_db_connection

# Page config
st.set_page_config(page_title="Forensics & Reports", layout="wide")

# Ensure pcap storage directory exists
PCAP_DIR = project_root / "data" / "pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Database convenience functions
# ---------------------------------------------------------------------------

def get_incidents(limit: int = 50):
    """Return recent analyses / incidents from threat_scores"""
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            # Try to select commonly used columns; be permissive if schema varies
            try:
                cur.execute("SELECT rowid as id, source, score, severity, ai_context, timestamp FROM threat_scores ORDER BY timestamp DESC LIMIT ?", (limit,))
            except Exception:
                # Fallback: try existing schema columns
                cur.execute("SELECT id, NULL as source, score, severity, ai_context, timestamp FROM threat_scores ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
    except Exception as e:
        st.error(f"Error reading incidents: {e}")
    return []


def get_logs_for_source(source: str, limit: int = 500):
    """Get logs from splunk_logs for a given source"""
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT id, timestamp, host, source, sourcetype, severity, raw_log FROM splunk_logs WHERE source = ? ORDER BY timestamp DESC LIMIT ?", (source, limit))
            rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
    except Exception as e:
        st.error(f"Error fetching logs for source {source}: {e}")
    return []


def get_performance_summary(days: int = 30):
    """Simple performance summary based on performance_metrics and threat_scores"""
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            since = (datetime.now() - timedelta(days=days)).isoformat()
            # Example aggregates: count of threat scores, average score
            try:
                cur.execute("SELECT COUNT(*) as total_analyses, AVG(score) as avg_score FROM threat_scores WHERE timestamp >= ?", (since,))
                row = cur.fetchone()
                total = row[0] or 0
                avg = row[1] or 0
            except Exception:
                total, avg = 0, 0
            # Pull top metrics if present
            try:
                cur.execute("SELECT metric_name, AVG(value) as avg_val FROM performance_metrics WHERE date >= ? GROUP BY metric_name", (since,))
                metrics = cur.fetchall()
            except Exception:
                metrics = []
            conn.close()
            return {
                'total_analyses': total,
                'avg_score': avg,
                'metrics': [{ 'metric_name': m[0], 'avg_val': m[1] } for m in metrics]
            }
    except Exception as e:
        st.error(f"Error building performance summary: {e}")
    return {'total_analyses': 0, 'avg_score': 0, 'metrics': []}

# ---------------------------------------------------------------------------
# Helpers for report generation
# ---------------------------------------------------------------------------

def generate_incident_csv(incident: dict, logs: list) -> bytes:
    """Return CSV bytes combining incident info and logs"""
    buf = io.StringIO()
    # Write incident metadata
    buf.write(f"# Incident Report\n")
    for k in ('id', 'source', 'score', 'severity', 'timestamp'):
        buf.write(f"{k},{incident.get(k, '')}\n")
    buf.write("\n# Logs\n")
    # Convert logs to DataFrame and write CSV
    if logs:
        df = pd.DataFrame(logs)
        df.to_csv(buf, index=False)
    else:
        buf.write("No logs available\n")
    return buf.getvalue().encode('utf-8')

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

def main():
    st.title("Forensics & Reports")
    st.markdown("Post-incident analysis, report generation, and PCAP management")
    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["📄 Incident Reports", "📦 PCAP Manager", "📈 Performance Summary"])

    # ---------------------------
    # Tab 1: Incident Reports
    # ---------------------------
    with tab1:
        st.header("Incident Reports")
        incidents = get_incidents(limit=100)
        if not incidents:
            st.info("No incidents found. Run AI analyses to generate entries in threat_scores.")
        else:
            incident_df = pd.DataFrame(incidents)
            st.dataframe(incident_df[['id','source','score','severity','timestamp']], use_container_width=True)

            selected = st.selectbox("Select incident to generate report", options=[f"{i.get('id')} | {i.get('source')} | {i.get('timestamp')}" for i in incidents])
            sel_id = int(selected.split('|')[0].strip())
            incident = next((i for i in incidents if int(i.get('id')) == sel_id), None)

            col1, col2 = st.columns([3,1])
            with col1:
                max_logs = st.number_input("Max logs to include", min_value=10, max_value=5000, value=500)
            with col2:
                if st.button("🔍 Load Logs for Incident"):
                    if incident and incident.get('source'):
                        logs = get_logs_for_source(incident['source'], limit=max_logs)
                        st.success(f"Loaded {len(logs)} logs for source: {incident['source']}")
                        # Show a preview
                        if logs:
                            preview_df = pd.DataFrame(logs[:20])
                            st.dataframe(preview_df[['timestamp','host','sourcetype','severity','raw_log']].head(20), use_container_width=True)
                        # Keep in session for report generation
                        st.session_state['forensics_current_logs'] = logs
                        st.session_state['forensics_current_incident'] = incident
                    else:
                        st.warning("Selected incident has no source information")

            if st.session_state.get('forensics_current_incident'):
                incident = st.session_state['forensics_current_incident']
                logs = st.session_state.get('forensics_current_logs', [])
                csv_bytes = generate_incident_csv(incident, logs)
                st.download_button("⬇️ Download Incident Report (CSV)", data=csv_bytes, file_name=f"incident_{incident.get('id')}.csv", mime='text/csv')

                st.markdown("**Notes:** PDF generation is not enabled by default. To enable PDF reports, install `reportlab` or `fpdf` and extend this page.")

    # ---------------------------
    # Tab 2: PCAP Manager
    # ---------------------------
    with tab2:
        st.header("PCAP Manager")
        st.markdown("Upload and store raw PCAP files for forensic review. Files are stored in `data/pcaps`.")

        uploaded = st.file_uploader("Upload PCAP file", type=['pcap','pcapng'])
        if uploaded:
            save_path = PCAP_DIR / uploaded.name
            with open(save_path, 'wb') as f:
                f.write(uploaded.getbuffer())
            st.success(f"Saved PCAP: {uploaded.name} ({os.path.getsize(save_path):,} bytes)")
            st.download_button("⬇️ Download PCAP", data=open(save_path,'rb'), file_name=uploaded.name)

        st.markdown("---")
        st.markdown("Existing PCAP files:")
        files = sorted(os.listdir(PCAP_DIR))
        if files:
            for fn in files:
                path = PCAP_DIR / fn
                col1, col2 = st.columns([4,1])
                with col1:
                    st.markdown(f"**{fn}** — {os.path.getsize(path):,} bytes")
                with col2:
                    st.download_button(f"Download {fn}", data=open(path,'rb'), file_name=fn)
        else:
            st.info("No PCAP files uploaded yet.")

    # ---------------------------
    # Tab 3: Performance Summary
    # ---------------------------
    with tab3:
        st.header("Performance Summary")
        days = st.slider("Days to summarize", min_value=1, max_value=90, value=30)
        summary = get_performance_summary(days=days)

        st.metric("Analyses (last N days)", summary['total_analyses'])
        st.metric("Average Threat Score", f"{summary['avg_score']:.1f}")

        if summary['metrics']:
            metrics_df = pd.DataFrame(summary['metrics'])
            st.dataframe(metrics_df, use_container_width=True)

        # Export summary as CSV
        export_df = pd.DataFrame([{
            'days': days,
            'total_analyses': summary['total_analyses'],
            'avg_score': summary['avg_score']
        }])
        csv_buf = io.StringIO()
        export_df.to_csv(csv_buf, index=False)
        st.download_button("⬇️ Download Performance Summary (CSV)", data=csv_buf.getvalue().encode('utf-8'), file_name=f"performance_summary_{days}d.csv", mime='text/csv')

    # Footer
    st.markdown('---')
    st.caption('Forensics & Reports — use exported artifacts for incident tracking and external sharing.')


if __name__ == '__main__':
    main()