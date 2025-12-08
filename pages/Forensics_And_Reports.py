"""
MULTILAYERED CYBER DEFENSE PLATFORM - FORENSICS AND REPORTS
╚════════════════════════════════════════════════════════════════════════════╝

FILE: pages/Forensics_And_Reports.py
PURPOSE: Post-incident forensic analysis, evidence management, and report generation

════════════════════════════════════════════════════════════════════════════
 DESCRIPTION
════════════════════════════════════════════════════════════════════════════
Comprehensive forensic investigation and reporting suite for incident response:
  • Generate downloadable incident reports (CSV format with incident + logs)
  • Upload, store, and manage raw PCAP files for network forensics
  • Query Splunk logs associated with specific security incidents
  • View incident timeline with comprehensive event data
  • Export performance summaries (metrics aggregation over N days)
  • Session-based incident tracking and log correlation

════════════════════════════════════════════════════════════════════════════
 PAGE STRUCTURE (3 Tabs)
════════════════════════════════════════════════════════════════════════════

TAB 1: INCIDENT REPORTS
├─ Section: List all recent incidents from threat_scores table
├─ Display: DataFrame with ID, Source, Score, Severity, Timestamp
├─ Selection: Choose specific incident to generate report
├─ Options: Adjust max logs to include (10-5000, default 500)
├─ Action: Load logs for selected incident source
├─ Preview: Show first 20 matching logs
├─ Export: Download incident + logs as CSV file
└─ Note: PDF requires external library (reportlab/fpdf)

TAB 2: PCAP MANAGER
├─ Upload: Accept .pcap and .pcapng files via file uploader
├─ Storage: Save to data/pcaps directory
├─ Metadata: Display file size in bytes
├─ Download: Individual download button for each file
├─ Listing: Show all existing PCAP files with sizes
└─ Use case: Store and retrieve network capture files for analysis

TAB 3: PERFORMANCE SUMMARY
├─ Time range: Slider for days to summarize (1-90, default 30)
├─ Metrics: Total analyses count, average threat score
├─ Database: Aggregate threat_scores and performance_metrics
├─ Display: DataFrame of metrics (metric_name, avg_val)
└─ Export: Download summary as CSV (date range included)

════════════════════════════════════════════════════════════════════════════
 DATABASE TABLES
════════════════════════════════════════════════════════════════════════════
• threat_scores: Incident metadata (id, source, score, severity, ai_context, timestamp)
• splunk_logs: Associated security event logs (id, timestamp, host, source, sourcetype, severity, raw_log)
• performance_metrics: System metrics (metric_name, date, value)

════════════════════════════════════════════════════════════════════════════
 FILE STORAGE
════════════════════════════════════════════════════════════════════════════
• PCAP directory: project_root/data/pcaps
• Auto-created: If directory doesn't exist, created on startup
• Supported formats: .pcap, .pcapng (network capture files)

════════════════════════════════════════════════════════════════════════════
 SESSION STATE MANAGEMENT
════════════════════════════════════════════════════════════════════════════
• forensics_current_incident: Currently selected incident object
• forensics_current_logs: Associated logs for active incident
• Purpose: Persist across reruns for report generation and export

════════════════════════════════════════════════════════════════════════════
 REPORT GENERATION
════════════════════════════════════════════════════════════════════════════
CSV Format:
├─ Header: "# Incident Report" marker
├─ Metadata: Incident ID, source, score, severity, timestamp
├─ Delimiter: "# Logs" section marker
└─ Data: Logs in CSV format (id, timestamp, host, source, sourcetype, severity, raw_log)

Filename: incident_{incident_id}.csv

════════════════════════════════════════════════════════════════════════════
 DEPENDENCIES
════════════════════════════════════════════════════════════════════════════
• streamlit: Web UI framework with file upload/download
• pandas: DataFrame for data display and CSV export
• plotly: Visualization (imported but not actively used)
• sqlite3: Database connectivity (via database.queries)
• pathlib: Path handling for PCAP directory management
• datetime: Timestamp operations and date range calculations

════════════════════════════════════════════════════════════════════════════
 FUTURE ENHANCEMENTS
════════════════════════════════════════════════════════════════════════════
• PDF report generation (requires reportlab or fpdf library)
• Timeline visualization of incident events
• PCAP analysis integration (tshark/pyshark)
• Bulk report generation
• Custom report templates

════════════════════════════════════════════════════════════════════════════
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

# ════════════════════════════════════════════════════════════════════════════
#  IMPORTS AND DEPENDENCIES
# ════════════════════════════════════════════════════════════════════════════

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

# ════════════════════════════════════════════════════════════════════════════
#  STREAMLIT PAGE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

st.set_page_config(page_title="Forensics & Reports", layout="wide")

# ════════════════════════════════════════════════════════════════════════════
#  FILE STORAGE INITIALIZATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Create PCAP storage directory if it doesn't exist

PCAP_DIR = project_root / "data" / "pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

# ════════════════════════════════════════════════════════════════════════════
#  DATABASE QUERY FUNCTIONS - INCIDENT AND LOG RETRIEVAL
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Query threat_scores, splunk_logs, and performance_metrics tables

def get_incidents(limit: int = 50):
    """
    Retrieve recent security incidents from threat_scores table.
    
    Args:
        limit (int): Maximum number of incidents to retrieve (default: 50)
    
    Returns:
        List[Dict]: Incident records with fields:
            - id: Incident identifier
            - source: Log source associated with incident
            - score: Threat score (0-100)
            - severity: Severity level (Critical, High, Medium, Low, Info)
            - ai_context: AI analysis text/context
            - timestamp: Incident detection timestamp
    
    Database:
        Primary table: threat_scores
        Schema flexibility: Handles both rowid and explicit id columns
        Fallback: If schema varies, returns 0 for missing source field
    
    Ordering:
        Results ordered by timestamp DESC (newest incidents first)
    
    Used By:
        main() for Tab 1 incident list and selection
    
    Error Handling:
        Displays error message if query fails
        Returns empty list on failure
    """
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
    """
    Retrieve security logs for a specific source.
    
    Args:
        source (str): Source identifier (e.g., 'firewall', 'proxy', 'siem')
        limit (int): Maximum number of logs to retrieve (default: 500)
    
    Returns:
        List[Dict]: Log records with fields:
            - id: Log entry identifier
            - timestamp: Log creation timestamp (ISO format)
            - host: Source host/system
            - source: Log source identifier
            - sourcetype: Log type (syslog, json, siem, etc.)
            - severity: Event severity level
            - raw_log: Original log entry text
    
    Database:
        Table: splunk_logs
        Filter: WHERE source = ? (case-sensitive)
    
    Ordering:
        Results ordered by timestamp DESC (newest logs first)
    
    Used By:
        main() to fetch logs for selected incident (Tab 1)
    
    Error Handling:
        Displays error message if query fails
        Returns empty list on failure
    
    Note:
        Used for forensic investigation of specific incidents.
        Default limit prevents excessive memory usage.
    """
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
    """
    Build performance summary aggregating threat and system metrics.
    
    SUMMARY COMPONENTS:
    ────────────────────────────────────────────────────────────────────
    1. THREAT ANALYSIS STATISTICS
       • total_analyses: COUNT(*) FROM threat_scores (time-filtered)
       • avg_score: AVG(score) FROM threat_scores (0-100 scale)
       • Time range: Last N days (parameter: days)
    
    2. SYSTEM METRICS
       • metric_name: Name of metric (e.g., 'detection_rate', 'prevention_rate')
       • avg_val: Average value of metric over time period
       • Table: performance_metrics with date filtering
    
    Args:
        days (int): Number of days to include in summary (default: 30)
    
    Returns:
        Dict containing:
            - total_analyses (int): Count of threat_scores records
            - avg_score (float): Average threat score
            - metrics (List[Dict]): Metric aggregations with metric_name and avg_val
    
    Database:
        Tables: threat_scores, performance_metrics
        Date filter: timestamp/date >= (now - N days)
        ISO format: Uses isoformat() for timestamp comparison
    
    Used By:
        main() for Tab 3 performance metrics display and CSV export
    
    Error Handling:
        Per-query try/except blocks for schema flexibility
        Graceful fallback if metrics table missing
        Returns defaults (0 values) on complete failure
    
    Note:
        Defensive programming: Handles missing tables/columns
        Used for compliance reporting and performance tracking
    """
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

# ════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Format and export incident data as CSV reports

def generate_incident_csv(incident: dict, logs: list) -> bytes:
    """
    Generate CSV report combining incident metadata and associated logs.
    
    CSV FORMAT:
    ────────────────────────────────────────────────────────────────────
    
    # Incident Report
    id,<incident_id>
    source,<source_name>
    score,<threat_score>
    severity,<severity_level>
    timestamp,<incident_timestamp>
    
    # Logs
    id,timestamp,host,source,sourcetype,severity,raw_log
    <log_data_rows...>
    
    Args:
        incident (Dict): Incident metadata from threat_scores
            - id: Incident identifier
            - source: Associated source
            - score: Threat score
            - severity: Severity level
            - timestamp: Incident timestamp
        logs (List[Dict]): Associated log records from splunk_logs
    
    Returns:
        bytes: UTF-8 encoded CSV content (ready for download)
    
    Features:
    • Metadata section with incident details
    • Clear "# Logs" section separator
    • CSV format with headers for easy import
    • Handles missing logs (shows "No logs available")
    
    Used By:
        main() for CSV download button in Tab 1
    
    Export format:
        Standard CSV (comma-separated)
        Can be opened in Excel, CSV viewers, or imported elsewhere
        Includes full raw_log field for forensic review
    """
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

# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION - UI AND INTERACTION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Render forensics page with 3-tab interface

def main():
    """
    Primary application entry point for forensics and reports.
    
    PAGE LAYOUT:
    ────────────────────────────────────────────────────────────────────
    • Title: "Forensics & Reports"
    • Subtitle: "Post-incident analysis, report generation, and PCAP management"
    • Structure: 3 tabs for different forensic workflows
    
    TAB 1: INCIDENT REPORTS
    ├─ List incidents from threat_scores table
    ├─ Show DataFrame: id, source, score, severity, timestamp
    ├─ Selectbox: Choose incident by ID | Source | Timestamp
    ├─ Options:
    │  ├─ Max logs slider (10-5000, default 500)
    │  └─ "Load Logs for Incident" button
    ├─ Preview: Show first 20 loaded logs
    ├─ Session state: Store incident and logs for export
    └─ Download: CSV button with incident + logs
    
    TAB 2: PCAP MANAGER
    ├─ Upload: File uploader for .pcap/.pcapng files
    ├─ Storage: Save to data/pcaps directory
    ├─ Display: File size in bytes
    ├─ Listing: All existing PCAP files
    ├─ Download: Individual download buttons per file
    └─ Use case: Store and retrieve network captures
    
    TAB 3: PERFORMANCE SUMMARY
    ├─ Time filter: Slider for days (1-90, default 30)
    ├─ Metrics: Total analyses, average threat score
    ├─ Display: Aggregated system metrics DataFrame
    ├─ Export: Download summary CSV
    └─ Use case: Compliance reporting and trend analysis
    
    ERROR HANDLING:
    • No incidents found: Info message to run analyses
    • No logs for incident: Warning if source missing
    • No PCAP files: Info message
    • Database errors: Error messages displayed to user
    
    SESSION STATE:
    • forensics_current_incident: Active incident object
    • forensics_current_logs: Associated logs for incident
    • Enables report generation across reruns
    
    FOOTER:
    • Info caption: Purpose and usage notes
    
    Dependencies:
    • get_incidents()
    • get_logs_for_source()
    • get_performance_summary()
    • generate_incident_csv()
    """
    st.title("Forensics & Reports")
    st.markdown("Post-incident analysis, report generation, and PCAP management")
    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["Incident Reports", "PCAP Manager", "Performance Summary"])

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
                if st.button("Load Logs for Incident"):
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
                st.download_button("⬇Download Incident Report (CSV)", data=csv_bytes, file_name=f"incident_{incident.get('id')}.csv", mime='text/csv')

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
            st.download_button("Download PCAP", data=open(save_path,'rb'), file_name=uploaded.name)

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
        st.download_button("Download Performance Summary (CSV)", data=csv_buf.getvalue().encode('utf-8'), file_name=f"performance_summary_{days}d.csv", mime='text/csv')

    # Footer
    st.markdown('---')
    st.caption('Forensics & Reports — use exported artifacts for incident tracking and external sharing.')


if __name__ == '__main__':
    main()