"""
Live Threat Monitor (pages/Live_Threat_Monitor.py)

Purpose: Stream real-time logs from Splunk API and display in database

Features:
    - Fetch logs from last 30 days from Splunk
    - Store logs in database without duplication
    - Auto-refresh to fetch new logs
    - Display logs in a filterable table
    - Color-coded severity badges
    - Search and filter capabilities

Linked to: Splunk REST API (172.20.10.3:8000)
"""

import streamlit as st
import pandas as pd
import sys
from pathlib import Path
from datetime import datetime, timedelta
import time

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from models.splunk_connector import get_splunk_connector
from database.queries import (
    insert_splunk_logs, 
    get_splunk_logs, 
    get_splunk_logs_count,
    get_last_splunk_log_timestamp,
    delete_all_splunk_logs
)

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Live Threat Monitor",
    layout="wide"
)

# ============================================================================
# CUSTOM CSS FOR SCROLLING
# ============================================================================

st.markdown("""
<style>
    /* Enable scrolling for main container */
    .main {
        overflow-y: auto !important;
        height: 100vh !important;
        max-height: 100vh !important;
    }
    
    /* Fix block container */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 100% !important;
        overflow-y: visible !important;
    }
    
    /* Enable scrolling on app view container */
    .appview-container {
        overflow-y: auto !important;
    }
    
    /* Make sure content doesn't get cut off */
    div[data-testid="stVerticalBlock"] {
        overflow: visible !important;
    }
    
    /* Custom scrollbar styling */
    ::-webkit-scrollbar {
        width: 12px;
    }
    
    ::-webkit-scrollbar-track {
        background: #1e1e1e;
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #888;
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #555;
    }
    
    /* For Firefox */
    * {
        scrollbar-width: thin;
        scrollbar-color: #888 #1e1e1e;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

if 'last_fetch_time' not in st.session_state:
    st.session_state.last_fetch_time = None
if 'total_logs' not in st.session_state:
    st.session_state.total_logs = 0
if 'new_logs_count' not in st.session_state:
    st.session_state.new_logs_count = 0
if 'fetch_status' not in st.session_state:
    st.session_state.fetch_status = "Not started"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_severity_badge(severity):
    """Return HTML badge for severity level"""
    colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#17a2b8',
        'info': '#6c757d'
    }
    
    color = colors.get(severity.lower() if severity else 'info', '#6c757d')
    
    return f"""
    <span style="background-color: {color}; 
                 color: white; 
                 padding: 3px 10px; 
                 border-radius: 12px; 
                 font-size: 11px;
                 font-weight: bold;
                 text-transform: uppercase;">
        {severity if severity else 'unknown'}
    </span>
    """

def get_severity_reasons(log):
    """
    Generate organized reasons why a log has its assigned severity level
    
    Args:
        log (dict): Log entry from database
        
    Returns:
        list: Organized reasons for the severity assignment
    """
    reasons = []
    severity = (log.get('severity') or 'info').lower()
    sourcetype = (log.get('sourcetype') or '').lower()
    source = (log.get('source') or '').lower()
    raw_log = (log.get('raw_log') or '').lower()
    
    # Critical severity indicators
    if severity == 'critical':
        reasons.append("**Attack detected** - Confirmed malicious activity")
        if 'exploit' in raw_log:
            reasons.append("Exploit attempt detected in traffic")
        if 'ransomware' in raw_log or 'encryption' in raw_log:
            reasons.append("Ransomware/encryption activity flagged")
        if 'breach' in raw_log or 'compromised' in raw_log:
            reasons.append("System breach or compromise suspected")
        if 'failed' in raw_log and 'attempts' in raw_log:
            reasons.append("Multiple failed access attempts")
        if 'snort' in sourcetype or 'alert' in sourcetype:
            reasons.append("IDS/IPS intrusion alert triggered")
        if not reasons:
            reasons.append("Critical threat level assigned by security system")
    
    # High severity indicators
    elif severity == 'high':
        reasons.append("**Potential threat** - Suspicious activity detected")
        if 'phishing' in raw_log or 'suspicious' in raw_log:
            reasons.append("Phishing or social engineering attempt")
        if 'malware' in raw_log or 'virus' in raw_log:
            reasons.append("Malicious software signature detected")
        if 'unauthorized' in raw_log or 'denied' in raw_log:
            reasons.append("Unauthorized access attempt blocked")
        if 'port scan' in raw_log or 'scanning' in raw_log:
            reasons.append("Network reconnaissance/port scanning detected")
        if 'pfsense' in sourcetype or 'firewall' in source:
            reasons.append("Firewall flagged suspicious traffic pattern")
        if not reasons:
            reasons.append("High risk event classified by threat analysis")
    
    # Medium severity indicators
    elif severity == 'medium':
        reasons.append("**Watch alert** - Unusual activity detected")
        if 'error' in raw_log or 'failed' in raw_log:
            reasons.append("Application/system error or failure")
        if 'login' in raw_log or 'authentication' in raw_log:
            reasons.append("Authentication anomaly detected")
        if 'policy' in raw_log or 'violation' in raw_log:
            reasons.append("Security policy violation detected")
        if 'update' in raw_log or 'patch' in raw_log:
            reasons.append("Unpatched or outdated system flagged")
        if not reasons:
            reasons.append("Moderate risk event requiring monitoring")
    
    # Low severity indicators
    elif severity == 'low':
        reasons.append("**Minor issue** - Non-critical event")
        if 'warning' in raw_log:
            reasons.append("System warning or advisory message")
        if 'temporary' in raw_log or 'transient' in raw_log:
            reasons.append("Temporary connection or service issue")
        if 'cache' in raw_log or 'timeout' in raw_log:
            reasons.append("Cache/timeout issue, likely recoverable")
        if not reasons:
            reasons.append("Low risk event, routine monitoring only")
    
    # Info level (default)
    else:
        reasons.append("**Informational** - Normal activity logged")
        if 'connected' in raw_log or 'started' in raw_log:
            reasons.append("Service/process started successfully")
        if 'completed' in raw_log or 'success' in raw_log:
            reasons.append("Operation completed successfully")
        if 'request' in raw_log or 'response' in raw_log:
            reasons.append("Normal request/response logged")
        if not reasons:
            reasons.append("Informational event for audit logging")
    
    return reasons

def get_unique_hosts():
    """Get list of unique hosts from database"""
    from database.queries import get_db_connection
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT host FROM splunk_logs WHERE host IS NOT NULL ORDER BY host")
            hosts = [row[0] for row in cursor.fetchall()]
            conn.close()
            return hosts
    except:
        return []
    return []

def get_unique_sources():
    """Get list of unique sources from database"""
    from database.queries import get_db_connection
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT source FROM splunk_logs WHERE source IS NOT NULL ORDER BY source")
            sources = [row[0] for row in cursor.fetchall()]
            conn.close()
            return sources
    except:
        return []
    return []

def get_sourcetype_stats():
    """Get count of logs by sourcetype"""
    from database.queries import get_db_connection
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT sourcetype, COUNT(*) as count 
                FROM splunk_logs 
                WHERE sourcetype IS NOT NULL 
                GROUP BY sourcetype 
                ORDER BY count DESC
            """)
            stats = cursor.fetchall()
            conn.close()
            return stats
    except:
        return []
    return []

def fetch_and_store_logs(initial_fetch=False):
    """
    Fetch logs from Splunk and store in database
    
    Args:
        initial_fetch (bool): Whether this is the initial 30-day fetch
        
    Returns:
        tuple: (success: bool, message: str, logs_added: int)
    """
    try:
        connector = get_splunk_connector()
        
        # Connect to Splunk
        if not connector.connect():
            return (False, "Failed to connect to Splunk", 0)
        
        # Fetch logs
        if initial_fetch:
            st.session_state.fetch_status = "Fetching last 30 days of logs..."
            logs = connector.fetch_logs(earliest_time="-19d@d", latest_time="now")
        else:
            # Fetch only new logs since last fetch
            last_timestamp = get_last_splunk_log_timestamp()
            if last_timestamp:
                st.session_state.fetch_status = "Fetching new logs..."
                logs = connector.fetch_logs_since(last_timestamp)
            else:
                st.session_state.fetch_status = "Fetching last 19 days of logs..."
                logs = connector.fetch_logs(earliest_time="-19d@d", latest_time="now")
        
        connector.disconnect()
        
        # Store logs in database
        if logs:
            print(f"Storing {len(logs)} logs in database...")
            st.session_state.fetch_status = f"Storing {len(logs)} logs in database..."
            logs_added = insert_splunk_logs(logs)
            st.session_state.new_logs_count = logs_added
            st.session_state.last_fetch_time = datetime.now()
            
            print(f"Successfully stored {logs_added} new logs (duplicates skipped: {len(logs) - logs_added})")
            return (True, f"Successfully added {logs_added} new logs out of {len(logs)} fetched", logs_added)
        else:
            return (True, "No new logs found", 0)
            
    except Exception as e:
        return (False, f"Error fetching logs: {str(e)}", 0)

# ============================================================================
# MAIN PAGE UI
# ============================================================================

st.title("Live Threat Monitor")
st.markdown("Real-time log monitoring from Splunk")
st.markdown("---")

# ============================================================================
# CONTROL PANEL
# ============================================================================

col1, col2, col3 = st.columns([3, 3, 3])

with col1:
    if st.button("Fetch Initial Logs (30 days)", use_container_width=True):
        with st.spinner("Fetching logs from Splunk..."):
            success, message, count = fetch_and_store_logs(initial_fetch=True)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)

with col2:
    if st.button("Sync New Logs", use_container_width=True):
        with st.spinner("Syncing new logs..."):
            success, message, count = fetch_and_store_logs(initial_fetch=False)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)

with col3:
    if st.button("Delete All Logs", use_container_width=True, type="secondary"):
        # Confirmation dialog
        if 'confirm_delete' not in st.session_state:
            st.session_state.confirm_delete = False
        
        if not st.session_state.confirm_delete:
            st.session_state.confirm_delete = True
            st.warning("Click again to confirm deletion of ALL logs!")
            st.rerun()
        else:
            with st.spinner("Deleting all logs..."):
                success, message, count = delete_all_splunk_logs()
                st.session_state.confirm_delete = False
                if success:
                    st.success(message)
                    st.session_state.new_logs_count = 0
                    st.rerun()
                else:
                    st.error(message)

# Additional options row
col_a, col_b = st.columns([2, 2])

with col_a:
    auto_refresh = st.checkbox("🔄 Auto-refresh (5 min)", value=False)

with col_b:
    if st.session_state.last_fetch_time:
        st.info(f"Last sync: {st.session_state.last_fetch_time.strftime('%H:%M:%S')}")

# Auto-refresh logic
if auto_refresh:
    time.sleep(300)  # 5 minutes
    st.rerun()

# ============================================================================
# STATISTICS
# ============================================================================

st.markdown("Statistics")

col1, col2, col3, col4 = st.columns(4)

total_count = get_splunk_logs_count()

with col1:
    st.metric("Total Logs", f"{total_count:,}")

with col2:
    critical_count = get_splunk_logs_count(severity_filter='critical')
    st.metric("Critical", critical_count)

with col3:
    high_count = get_splunk_logs_count(severity_filter='high')
    st.metric("High Severity", high_count)

with col4:
    if st.session_state.new_logs_count > 0:
        st.metric("New Logs", st.session_state.new_logs_count)
    else:
        st.metric("New Logs", 0)

# Show sourcetype distribution
st.markdown("####Logs by Sourcetype")
sourcetype_stats = get_sourcetype_stats()
if sourcetype_stats:
    stats_df = pd.DataFrame(sourcetype_stats, columns=['Sourcetype', 'Count'])
    stats_df['Percentage'] = (stats_df['Count'] / stats_df['Count'].sum() * 100).round(2)
    st.dataframe(stats_df, use_container_width=True, hide_index=True)

st.markdown("---")

# ============================================================================
# FILTERS
# ============================================================================

st.markdown("Filters")

# Get unique hosts and sources
unique_hosts = get_unique_hosts()
unique_sources = get_unique_sources()

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    severity_options = ["All", "critical", "high", "medium", "low", "info"]
    severity_filter = st.selectbox("Severity", severity_options)

with col2:
    host_options = ["All"] + unique_hosts
    host_filter = st.selectbox("Host", host_options)

with col3:
    source_options = ["All"] + unique_sources
    source_filter_select = st.selectbox("Source", source_options)

with col4:
    search_text = st.text_input("Search in logs", "")

with col5:
    sort_order = st.selectbox(
        "Sort by Severity",
        options=["Highest First", "Lowest First"],
        help="Sort logs by severity level"
    )

# Pagination
logs_per_page = st.slider("Logs per page", min_value=10, max_value=500, value=50, step=10)

st.markdown("---")

# ============================================================================
# LOGS TABLE
# ============================================================================

st.markdown("###Logs")

# Apply filters
severity = None if severity_filter == "All" else severity_filter
host = None if host_filter == "All" else host_filter
source = None if source_filter_select == "All" else source_filter_select
search = search_text if search_text else None

# Get filtered logs with host filter
logs = get_splunk_logs(
    limit=logs_per_page,
    offset=0,
    severity_filter=severity,
    source_filter=source,
    search_text=search
)

# Apply host filter manually (since queries.py doesn't have host_filter parameter)
if host:
    logs = [log for log in logs if log.get('host') == host]

# Sort by severity
if logs:
    severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'unknown': 0, None: 0}
    
    if sort_order == "Highest First":
        logs = sorted(logs, key=lambda x: severity_order.get(x.get('severity', 'unknown'), 0), reverse=True)
    else:  # Lowest First
        logs = sorted(logs, key=lambda x: severity_order.get(x.get('severity', 'unknown'), 0), reverse=False)

if logs:
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    
    # Display count
    if host:
        st.info(f"Showing {len(logs)} logs (filtered by host)")
    else:
        filtered_count = get_splunk_logs_count(
            severity_filter=severity,
            source_filter=source,
            search_text=search
        )
        st.info(f"Showing {len(logs)} of {filtered_count:,} logs")
    
    # Display table with custom formatting
    for idx, log in enumerate(logs):
        with st.expander(
            f"[{log['timestamp']}] {log['host']} - {log['source']} - Severity: {log['severity'] or 'unknown'}",
            expanded=False
        ):
            col1, col2, col3 = st.columns([2, 2, 2])
            
            with col1:
                st.markdown("**Details:**")
                st.markdown(f"**ID:** `{log['id']}`")
                st.markdown(f"**Host:** `{log['host']}`")
                st.markdown(f"**Source:** `{log['source']}`")
                st.markdown(f"**Type:** `{log['sourcetype']}`")
                st.markdown(f"**Severity:** {get_severity_badge(log['severity'])}", unsafe_allow_html=True)
                st.markdown(f"**Timestamp:** `{log['timestamp']}`")
            
            with col2:
                st.markdown("**Raw Log:**")
                st.code(log['raw_log'][:500] + ("..." if len(log['raw_log']) > 500 else ""), language='text')
            
            with col3:
                st.markdown("**Severity Assessment:**")
                severity_reasons = get_severity_reasons(log)
                for reason in severity_reasons:
                    st.markdown(f"• {reason}")
                
                st.markdown("---")
                
                if log['event_data']:
                    st.markdown("**Event Data (JSON):**")
                    st.json(log['event_data'])
                else:
                    st.info("No structured event data available")
                
                st.markdown("---")
                
                # AI Analysis button
                if st.button(
                    f"🤖 Analyze Source: {log['source']}",
                    key=f"analyze_{log['id']}",
                    use_container_width=True,
                    type="primary"
                ):
                    st.switch_page("pages/AI_Log_Analysis.py")
                    # Store source in session for AI page to use
                    st.session_state.selected_source_for_analysis = log['source']
    
else:
    st.warning("No logs found. Click 'Fetch Initial Logs' to retrieve data from Splunk.")

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: gray; font-size: 12px;'>
    <p>Live Threat Monitor - Connected to Splunk at 172.20.10.3:8000</p>
    </div>
    """,
    unsafe_allow_html=True
)