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
import base64
import re
import requests
import pydeck as pdk
import ipaddress

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import authentication and database modules
try:
    from auth.session_manager import check_session_timeout, clear_session
    from database.queries import get_db_connection
except ImportError as e:
    st.error(f"Import Error: {e}")
    st.stop()

from models.splunk_connector import get_splunk_connector
from database.queries import (
    insert_splunk_logs, 
    get_splunk_logs, 
    get_splunk_logs_count,
    get_last_splunk_log_timestamp,
    delete_all_splunk_logs
)

# ============================================================================
# AUTHENTICATION CHECK
# ============================================================================

def check_authentication():
    """Verify user is authenticated before rendering page"""
    import time
    
    if not st.session_state.get('authenticated', False):
        # Set default user info for development/testing
        st.session_state.username = 'admin'
        st.session_state.role = 'administrator'
        st.session_state.authenticated = True

        return
    
    # Check session timeout only if authenticated through proper login
    if st.session_state.get('authenticated') and not check_session_timeout():
        st.warning("Session expired. Please login again.")
        st.session_state.username = 'admin'
        st.session_state.role = 'administrator'
        return

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


# ============================================================================
# GEO HELPERS FOR THREAT MAP
# ============================================================================

def extract_ip_from_text(text):
    """Extract first IPv4 address from a text blob."""
    if not text:
        return None
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    return match.group(0) if match else None


def is_valid_ip(value):
    """Validate IPv4 numeric segments."""
    if not value:
        return False
    match = re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value)
    if not match:
        return False
    parts = value.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def geolocate_ip(ip, cache):
    """Geolocate IP using ipapi.co; cache results to reduce calls."""
    if not ip:
        return None
    if ip in cache:
        return cache[ip]

    # Handle private/local/reserved IPs with an Oman-centered fallback
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
            cache[ip] = {"ip": ip, "lat": 21.5, "lon": 57.0, "country": "Private/Local"}
            return cache[ip]
    except Exception:
        pass
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            lat = data.get("latitude")
            lon = data.get("longitude")
            country = data.get("country_name") or "Unknown"
            if lat is not None and lon is not None:
                cache[ip] = {"ip": ip, "lat": lat, "lon": lon, "country": country}
                return cache[ip]
    except Exception:
        pass
    cache[ip] = None
    return None


def build_attack_points(logs, limit=50):
    """Build map points from logs (limited for performance)."""
    points = []
    cache = {}
    seen = set()
    for log in logs[:limit]:
        # Prefer host field if it's a valid IP; otherwise try raw log
        host_val = log.get("host")
        ip = host_val if is_valid_ip(host_val) else extract_ip_from_text(log.get("raw_log") or "")
        if not ip or ip in seen:
            continue
        geo = geolocate_ip(ip, cache)
        if geo:
            points.append({
                "ip": ip,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "country": geo["country"],
                "source": log.get("source", "unknown"),
                "severity": log.get("severity", "unknown")
            })
            seen.add(ip)
    return points

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

# Check authentication first
check_authentication()

# Top Navigation Bar
st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

st.markdown(f"""
<style>
.topbar {{
    background: linear-gradient(135deg, #141d26, #243447);
    color: #E2E2D2;
    padding: 10px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: 8px;
    gap: 12px;
}}

.topbar .left {{
    display: flex;
    align-items: center;
    gap: 10px;
}}

.topbar .brand {{
    font-weight: 700;
    font-size: 18px;
}}

.topbar .user-info {{
    font-size: 13px;
    color: #E2E2D2;
    opacity: 0.9;
}}

.topbar .links {{
    display: flex;
    gap: 12px;
}}

.topbar a {{
    color: #E2E2D2;
    text-decoration: none;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 14px;
}}

.topbar a:hover {{
    background: #243447;
}}

.topbar .cta {{
    background: #c51f5d;
    color: white;
}}

@media (max-width: 700px) {{
    .topbar {{
        flex-direction: column;
        align-items: flex-start;
    }}
}}
</style>

<div class="topbar">
    <div class="left">
        <span class="user-info">{st.session_state.get('username', 'Unknown')} | {st.session_state.get('role', 'Unknown').upper()}</span>
    </div>
    <div class="links">
        <a href="Dashboard_Overview">Dashboard</a>
        <a href="AI_Log_Analysis">AI Analysis</a>
        <a href="Threat_Scoring">Scoring</a>
        <a href="Performance_Metrics">Metrics</a>
        <a class="cta" href="System_Configuration">Configuration</a>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<h1 style="text-align: center;">Live Threat Monitor</h1>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; color: #888;">Real-time log monitoring from Splunk</p>', unsafe_allow_html=True)

# ============================================================================
# CONTROL PANEL
# ============================================================================

st.markdown("""
<style>
.control-panel-section {
    margin: 20px 0;
}

.control-panel-card {
    border-radius: 12px;
    padding: 20px;
    color: #E2E2D2;
    transition: 0.3s ease;
    text-align: center;
    margin-bottom: 15px;
}

.control-panel-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(101,193,249,0.2);
}

.control-panel-card h4 {
    margin-bottom: 12px;
    font-size: 16px;
    font-weight: 600;
    color: #65c1f9;
}

.control-panel-card p {
    font-size: 13px;
    margin-bottom: 0;
    opacity: 0.8;
    line-height: 1.4;
}

/* Custom button styling */
.stButton > button {
    color: #E2E2D2 !important;
    border: 1px solid #243447 !important;
    border-radius: 8px !important;
    transition: all 0.3s ease !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #243447, #141d26) !important;
    transform: translateY(-2px) !important;
    box-shadow: 0 4px 12px rgba(101, 193, 249, 0.3) !important;
}

.stButton > button:active {
    transform: translateY(0px) !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<h3 style="text-align:center;">Control Panel</h3>', unsafe_allow_html=True)

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
    
    st.markdown("""
    """, unsafe_allow_html=True)

with col2:
    if st.button("Sync New Logs", use_container_width=True):
        with st.spinner("Syncing new logs..."):
            success, message, count = fetch_and_store_logs(initial_fetch=False)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)
    
    st.markdown("""
    """, unsafe_allow_html=True)

with col3:
    if st.button("Delete All Logs", use_container_width=True):
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
    
    st.markdown("""
    """, unsafe_allow_html=True)

# Additional options row
col_a, col_b = st.columns([2, 2])

with col_a:
    auto_refresh = st.checkbox("Auto-refresh (5 min)", value=False)

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
st.markdown("---")

st.markdown("<h3 style='text-align: center;'>System Statistics</h3>", unsafe_allow_html=True)

# Get data
total_count = get_splunk_logs_count()
critical_count = get_splunk_logs_count(severity_filter='critical')
high_count = get_splunk_logs_count(severity_filter='high')
new_logs = st.session_state.new_logs_count if st.session_state.new_logs_count > 0 else 0

st.markdown(f"""
<style>
    .stats-card {{
        border-radius: 12px;
        padding: 30px;
        margin-top: 20px;
        transition: all 0.3s ease;
    }}
    .stats-content {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 20px;
    }}
    .stat-inline {{
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .stat-inline-value {{
        font-size: 28px;
        font-weight: 700;
        color: #65c1f9;
    }}
    .stat-inline-label {{
        font-size: 12px;
        opacity: 0.85;
        line-height: 1.3;
    }}


</style>
<div class="stats-card">
    <div class="stats-content">
        <div class="stat-inline">
            <div>
                <div class="stat-inline-value">{total_count:,}</div>
                <div class="stat-inline-label">Total Logs</div>
            </div>
        </div>
        <div class="stat-inline">
            <div>
                <div class="stat-inline-value">{critical_count:,}</div>
                <div class="stat-inline-label">Critical Events</div>
            </div>
        </div>
        <div class="stat-inline">
            <div>
                <div class="stat-inline-value">{high_count:,}</div>
                <div class="stat-inline-label">High Severity</div>
            </div>
        </div>
        <div class="stat-inline">
            <div>
                <div class="stat-inline-value">{new_logs:,}</div>
                <div class="stat-inline-label">New Logs</div>
            </div>
        </div>
        <div class="stat-inline">
            <div>
                <div class="stat-inline-value">ACTIVE</div>
                <div class="stat-inline-label">Monitor Status</div>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Show sourcetype distribution
st.markdown("---")
st.markdown("<h4 style='text-align: center;'>Logs by Sourcetype</h4>", unsafe_allow_html=True)
sourcetype_stats = get_sourcetype_stats()

# Blue-themed styling for the sourcetype stats table
if sourcetype_stats:
    stats_df = pd.DataFrame(sourcetype_stats, columns=['Sourcetype', 'Count'])
    stats_df['Percentage'] = (stats_df['Count'] / stats_df['Count'].sum() * 100).round(2)
    # Apply blue style using pandas Styler
    def blue_style():
        return [
            {'selector': 'th', 'props': [('background-color', '#243447'), ('color', 'white'), ('font-weight', 'bold')]},
            {'selector': 'td', 'props': [('background-color', '#243447'), ('color', '#243447')]},
            {'selector': 'tr:nth-child(even) td', 'props': [('background-color', '#d0e6f7')]},
        ]
    styled_df = stats_df.style.set_table_styles(blue_style())
    st.markdown("""
        <style>
        .stDataFrame thead tr th {
            background-color: #243447 !important;
            color: white !important;
            font-weight: bold !important;
        }
        .stDataFrame tbody tr td {
            background-color: #eaf3fb !important;
            color: #243447 !important;
        }
        .stDataFrame tbody tr:nth-child(even) td {
            background-color: #d0e6f7 !important;
        }
        </style>
    """, unsafe_allow_html=True)
    st.dataframe(stats_df, use_container_width=True, hide_index=True)

st.markdown("---")

# ============================================================================
# FILTERS
# ============================================================================

st.markdown('<h3 style="text-align:center;">Filters</h3>', unsafe_allow_html=True)

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
st.markdown("""
<style>

</style>
""", unsafe_allow_html=True)
logs_per_page = st.slider("Logs per page", min_value=10, max_value=500, value=50, step=10)


# ============================================================================
# LOGS TABLE
# ============================================================================

st.markdown('<h3 style="text-align:center;">Logs</h3>', unsafe_allow_html=True)

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
    st.markdown("""
    <style>
    .count-bar {
        color: white;
        border-radius: 10px;
        padding: 14px 24px;
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .count-bar .icon {
        font-size: 22px;
        margin-right: 8px;
    }
    </style>
    """, unsafe_allow_html=True)
    if host:
        st.markdown(f'<div class="count-bar"></span>Showing <b>{len(logs)}</b> logs <span style="opacity:0.8;">(filtered by host)</span></div>', unsafe_allow_html=True)
    else:
        filtered_count = get_splunk_logs_count(
            severity_filter=severity,
            source_filter=source,
            search_text=search
        )
        st.markdown(f'<div class="count-bar"></span>Showing <b>{len(logs)}</b> of <b>{filtered_count:,}</b> logs</div>', unsafe_allow_html=True)

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
                    f"Analyze Source: {log['source']}",
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
# THREAT MAP
# ============================================================================

st.markdown("---")
st.markdown('<h3 style="text-align:center;">Threat Map</h3>', unsafe_allow_html=True)

map_points = build_attack_points(logs) if logs else []

if map_points:
    initial_view_state = pdk.ViewState(latitude=21.5, longitude=57.0, zoom=4.8, pitch=30)
    layer = pdk.Layer(
        "ScatterplotLayer",
        data=map_points,
        get_position="[lon, lat]",
        get_color="[255, 99, 71, 200]",
        get_radius=50000,
        pickable=True
    )
    tooltip = {
        "html": "<b>IP:</b> {ip}<br/><b>Country:</b> {country}<br/><b>Source:</b> {source}<br/><b>Severity:</b> {severity}",
        "style": {"color": "white"}
    }
    deck = pdk.Deck(
        map_style=None,
        initial_view_state=initial_view_state,
        layers=[layer],
        tooltip=tooltip
    )
    st.pydeck_chart(deck, use_container_width=True)
else:
    st.info("No geolocated IPs available yet. Fetch logs to populate the threat map.")

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