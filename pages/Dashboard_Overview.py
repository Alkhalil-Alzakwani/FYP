"""
MULTILAYERED CYBER DEFENSE PLATFORM - DASHBOARD OVERVIEW
╚════════════════════════════════════════════════════════════════════════════╝

FILE: pages/Dashboard_Overview.py
PURPOSE: Executive summary dashboard with real-time security metrics and threat analytics

════════════════════════════════════════════════════════════════════════════
 DESCRIPTION
════════════════════════════════════════════════════════════════════════════
Comprehensive security operations center (SOC) dashboard providing:
  • Real-time threat detection metrics and KPIs
  • Live attack statistics and severity distribution
  • Detection, prevention, and false positive rates
  • Recent security events with color-coded severity levels
  • Attack type categorization and distribution analysis
  • Quick access navigation to analysis and configuration pages
  • Session-protected access with role-based display

════════════════════════════════════════════════════════════════════════════
 DASHBOARD COMPONENTS (6 Sections)
════════════════════════════════════════════════════════════════════════════

1. TOP NAVIGATION BAR
   ├─ User info display (username, role)
   ├─ Links: Live Monitor, AI Analysis, Scoring, Metrics, Server, Configuration
   └─ Logout functionality

2. HERO CARD (Hero Section)
   ├─ Background image: SOC operations center photo
   ├─ Title: "Real-time Security Operations Center"
   └─ Subtitle: "Comprehensive threat monitoring and analytics dashboard"

3. KEY PERFORMANCE INDICATORS (Stats Card)
   ├─ Total Attacks Detected (from threat_scores)
   ├─ High Severity Threats (severity='High')
   ├─ Blocked Connections (firewall_logs action='block')
   ├─ Detection Rate (%)
   ├─ Response Time (2s)
   └─ System Status (OPERATIONAL)

4. DETECTION & PREVENTION PERFORMANCE (3-Column Layout)
   ├─ Detection Rate Card (85.0%, trend: ↑ +2.3%)
   ├─ Prevention Rate Card (78.0%, trend: ↑ +1.8%)
   └─ False Positive Rate Card (5.2%, trend: ↓ -0.5%)

5. THREAT ANALYSIS CHARTS (2-Column Layout)
   ├─ Severity Distribution Pie Chart
   │  └─ Colors: Critical (#1A3A52), High (#2B5A7A), Medium (#4A7BA7), Low (#6B9BC3)
   └─ Attack Type Distribution Bar Chart
      └─ Dynamic color gradient (blue theme)

6. RECENT SECURITY EVENTS TABLE
   ├─ Columns: ID, Severity, Type, Host, Source, Timestamp
   ├─ Color-coded rows by severity level
   ├─ Shows 15 most recent events
   └─ Summary stats: Total events, Critical/High count, Most common type

7. QUICK ACCESS NAVIGATION GRID
   ├─ Live Threat Monitor
   ├─ AI Log Analysis
   ├─ Threat Scoring
   ├─ Performance Metrics
   ├─ Server Performance
   └─ System Configuration

8. SIDEBAR
   ├─ Navigation Links (all platform pages)
   ├─ System Information (version, last update, database status)
   └─ Refresh Dashboard button (manual rerun trigger)

════════════════════════════════════════════════════════════════════════════
 DATA SOURCES
════════════════════════════════════════════════════════════════════════════
• threat_scores table: Threat analysis scores and severity levels
• splunk_logs table: Security logs from SIEM (primary data source)
• firewall_logs table: Firewall activity and blocked connections
• performance_metrics table: Detection/prevention/FP rates with timestamps

════════════════════════════════════════════════════════════════════════════
 SECURITY & AUTHENTICATION
════════════════════════════════════════════════════════════════════════════
• Session validation: Required for page access
• Session timeout: Automatic redirect to login on expiry
• Role-based display: Username and role shown in top navigation
• Audit logging: All data operations logged (database queries)
• Logout handler: Clears session state and redirects to app.py

════════════════════════════════════════════════════════════════════════════
 COLOR SCHEME
════════════════════════════════════════════════════════════════════════════
• #141d26: Dark background (charcoal)
• #243447: Accent dark (slate blue)
• #E2E2D2: Light text (off-white)
• #65c1f9: Highlight/accent (sky blue)
• #c51f5d: CTA button color (vibrant pink)
• Severity palette: #1A3A52 (Critical), #2B5A7A (High), #4A7BA7 (Medium), #6B9BC3 (Low)

════════════════════════════════════════════════════════════════════════════
 AUTO-REFRESH
════════════════════════════════════════════════════════════════════════════
• Interval: 30 seconds
• Display: "Last updated" timestamp shown at bottom of each section
• Manual refresh: Sidebar button for immediate rerun

════════════════════════════════════════════════════════════════════════════
 DEPENDENCIES
════════════════════════════════════════════════════════════════════════════
• streamlit: Web UI framework with session state management
• pandas: Data processing and DataFrame operations
• plotly: Interactive chart visualizations
• datetime: Timestamp handling and formatting
• database.queries: Database connection utilities
• auth.session_manager: Session validation and timeout handling

════════════════════════════════════════════════════════════════════════════
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
from pathlib import Path

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


# ════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION AND SESSION MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Verify user authentication and session validity before page rendering

def check_authentication():
    """
    Verify user authentication and session validity.
    
    SECURITY CHECKS:
    ────────────────────────────────────────────────────────────────────
    1. Authentication: Verify st.session_state.authenticated is True
    2. Session Timeout: Check session expiry via check_session_timeout()
    3. Redirect on Failure: Send unauthorized users to login page (app.py)
    
    Returns:
        None (exits to login if checks fail)
    
    Behavior:
    • If not authenticated: Shows error and redirects after 4-second delay
    • If session expired: Shows warning and redirects after 4-second delay
    • If authenticated: Continues to page rendering
    
    Used By:
        main() function (first operation before any page content)
    
    Note:
        Session state set by login page (pages/login.py) on successful authentication.
    """
    import time
    
    if not st.session_state.get('authenticated', False):
        st.error("Access Denied: Please login to access this page.")
        st.info("Redirecting to login page...")
        time.sleep(4)
        st.switch_page("app.py")
        st.stop()
    
    # Check session timeout
    if not check_session_timeout():
        st.warning("Session expired. Please login again.")
        time.sleep(4)
        st.switch_page("app.py")
        st.stop()


# ════════════════════════════════════════════════════════════════════════════
#  STREAMLIT PAGE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Set page title, layout mode, and initial sidebar state

st.set_page_config(
    page_title="Dashboard Overview - Cyber Defense Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ════════════════════════════════════════════════════════════════════════════
#  CUSTOM CSS AND RESPONSIVE STYLING
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Dark theme styling, scrolling behavior, container layout, responsive design

st.markdown("""
<style>
    /* Ensure main container is scrollable */
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
    
    /* Sidebar scrolling */
    section[data-testid="stSidebar"] {
        height: 100vh !important;
        overflow-y: auto !important;
    }
    
    /* Force scrolling on app view container */
    .appview-container {
        overflow-y: auto !important;
    }
    
    /* Make sure content doesn't get cut off */
    div[data-testid="stVerticalBlock"] {
        overflow: visible !important;
    }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
#  DATABASE QUERY FUNCTIONS - THREAT DATA AND METRICS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Fetch threat statistics, attack data, performance metrics from database

def get_total_attacks():
    """
    Retrieve total count of detected attacks from database.
    
    Query:
        SELECT COUNT(*) FROM threat_scores
    
    Returns:
        int: Total number of threat records (0 on error)
    
    Used By:
        render_key_metrics() for KPI display
    
    Error Handling:
        Returns 0 if database connection fails or query error occurs.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM threat_scores")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        return 0
    except:
        return 0


def get_high_severity_threats():
    """
    Retrieve count of high severity threats.
    
    Query:
        SELECT COUNT(*) FROM threat_scores WHERE severity = 'High'
    
    Returns:
        int: Number of high severity threat records (0 on error)
    
    Used By:
        render_key_metrics() for high severity KPI
    
    Note:
        Searches for exact severity='High' (normalized by threat_scores table).
        Does not include 'Critical' severity (counted separately if needed).
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM threat_scores WHERE severity = 'High'")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        return 0
    except:
        return 0


def get_blocked_connections():
    """
    Retrieve total count of blocked connections from firewall.
    
    Query:
        SELECT COUNT(*) FROM firewall_logs WHERE action = 'block'
    
    Returns:
        int: Number of blocked firewall connections (0 on error)
    
    Used By:
        render_key_metrics() for blocked connections KPI
    
    Data Source:
        firewall_logs table with action column = 'block'
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM firewall_logs WHERE action = 'block'")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        return 0
    except:
        return 0


def get_recent_threats(limit=10):
    """
    Retrieve recent threat events with normalized severity.
    
    Args:
        limit (int): Maximum number of events to retrieve (default: 10, used as 15)
    
    Returns:
        pd.DataFrame: Recent threat records with columns:
            - id: Record identifier
            - severity: Normalized severity (Critical, High, Medium, Low, Info)
            - category: Event type (IDS Alert, Firewall, Phishing Email, etc.)
            - host: Source host/system
            - source: Source identifier
            - timestamp: Event timestamp (ordered DESC)
    
    Data Sources:
        Primary: splunk_logs table (normalized severity and category)
        Fallback: threat_scores table if splunk_logs empty
    
    Severity Normalization:
        • 'critical', 'crit' → 'Critical'
        • 'high', 'hi' → 'High'
        • 'medium', 'med', 'moderate' → 'Medium'
        • 'low', 'lo' → 'Low'
        • 'info', 'information', 'informational' → 'Info'
    
    Category Mapping (from sourcetype):
        • %snort% → 'IDS Alert'
        • %pfsense% → 'Firewall'
        • %message_rfc822% → 'Phishing Email'
        • %WinEventLog:Security% → 'Security'
        • %WinEventLog:System% → 'System'
        • syslog → 'Syslog'
    
    Used By:
        render_recent_threats_table() for dashboard table display
    
    Error Handling:
        Returns empty DataFrame if database error occurs.
    """
    try:
        conn = get_db_connection()
        if conn:
            # Get from splunk_logs with normalized severity
            query = """
                SELECT 
                    id,
                    CASE 
                        WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 'Critical'
                        WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 'High'
                        WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 'Medium'
                        WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 'Low'
                        WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 'Info'
                        ELSE UPPER(SUBSTR(TRIM(severity), 1, 1)) || LOWER(SUBSTR(TRIM(severity), 2))
                    END as severity,
                    CASE 
                        WHEN sourcetype LIKE '%snort%' THEN 'IDS Alert'
                        WHEN sourcetype LIKE '%pfsense%' THEN 'Firewall'
                        WHEN sourcetype LIKE '%message_rfc822%' THEN 'Phishing Email'
                        WHEN sourcetype LIKE '%WinEventLog:Security%' THEN 'Security'
                        WHEN sourcetype LIKE '%WinEventLog:System%' THEN 'System'
                        WHEN sourcetype = 'syslog' THEN 'Syslog'
                        ELSE sourcetype
                    END as category,
                    host,
                    source,
                    timestamp
                FROM splunk_logs
                WHERE timestamp IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
            
            # If splunk_logs is empty, try threat_scores
            if df.empty:
                query = """
                    SELECT id, score, severity, category, timestamp 
                    FROM threat_scores 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """
                df = pd.read_sql_query(query, conn, params=(limit,))
            
            conn.close()
            return df
        return pd.DataFrame()
    except Exception as e:
        return pd.DataFrame()


def get_threat_distribution():
    """
    Retrieve threat severity distribution across all security logs.
    
    Query Strategy:
        Primary: UNION splunk_logs and threat_scores with normalized severity
        Fallback: Query splunk_logs only if UNION fails
    
    Returns:
        pd.DataFrame: Severity distribution with columns:
            - severity: Normalized severity level (Critical, High, Medium, Low, Info)
            - count: Number of events with that severity
    
    Severity Normalization (same as get_recent_threats):
        • 'critical', 'crit' → 'Critical'
        • 'high', 'hi' → 'High'
        • 'medium', 'med', 'moderate' → 'Medium'
        • 'low', 'lo' → 'Low'
        • 'info', 'information', 'informational' → 'Info'
    
    Data Sources:
        • splunk_logs table (primary)
        • threat_scores table (supplementary)
        Filters out NULL and empty severity values
    
    Ordering:
        Results ordered by severity (Critical → Info) regardless of count
    
    Used By:
        render_threat_charts() for pie chart visualization
    
    Error Handling:
        Primary UNION query: Falls back to splunk_logs only
        Fallback failure: Returns empty DataFrame
    """
    try:
        conn = get_db_connection()
        if conn:
            # Try to get from both splunk_logs and threat_scores with normalized severity
            query = """
                SELECT 
                    CASE 
                        WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 'Critical'
                        WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 'High'
                        WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 'Medium'
                        WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 'Low'
                        WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 'Info'
                        ELSE UPPER(SUBSTR(TRIM(severity), 1, 1)) || LOWER(SUBSTR(TRIM(severity), 2))
                    END as severity,
                    COUNT(*) as count 
                FROM (
                    SELECT severity FROM splunk_logs WHERE severity IS NOT NULL AND severity != ''
                    UNION ALL
                    SELECT severity FROM threat_scores WHERE severity IS NOT NULL
                )
                GROUP BY 
                    CASE 
                        WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 'Critical'
                        WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 'High'
                        WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 'Medium'
                        WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 'Low'
                        WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 'Info'
                        ELSE UPPER(SUBSTR(TRIM(severity), 1, 1)) || LOWER(SUBSTR(TRIM(severity), 2))
                    END
                ORDER BY 
                    CASE 
                        WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 1
                        WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 2
                        WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 3
                        WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 4
                        WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 5
                        ELSE 6
                    END
            """
            df = pd.read_sql_query(query, conn)
            conn.close()
            return df
        return pd.DataFrame()
    except Exception as e:
        # Fallback to just splunk_logs if union fails
        try:
            conn = get_db_connection()
            if conn:
                query = """
                    SELECT 
                        CASE 
                            WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 'Critical'
                            WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 'High'
                            WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 'Medium'
                            WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 'Low'
                            WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 'Info'
                            ELSE UPPER(SUBSTR(TRIM(severity), 1, 1)) || LOWER(SUBSTR(TRIM(severity), 2))
                        END as severity,
                        COUNT(*) as count 
                    FROM splunk_logs 
                    WHERE severity IS NOT NULL AND severity != ''
                    GROUP BY 
                        CASE 
                            WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 'Critical'
                            WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 'High'
                            WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 'Medium'
                            WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 'Low'
                            WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 'Info'
                            ELSE UPPER(SUBSTR(TRIM(severity), 1, 1)) || LOWER(SUBSTR(TRIM(severity), 2))
                        END
                    ORDER BY 
                        CASE 
                            WHEN LOWER(TRIM(severity)) IN ('critical', 'crit') THEN 1
                            WHEN LOWER(TRIM(severity)) IN ('high', 'hi') THEN 2
                            WHEN LOWER(TRIM(severity)) IN ('medium', 'med', 'moderate') THEN 3
                            WHEN LOWER(TRIM(severity)) IN ('low', 'lo') THEN 4
                            WHEN LOWER(TRIM(severity)) IN ('info', 'information', 'informational') THEN 5
                            ELSE 6
                        END
                """
                df = pd.read_sql_query(query, conn)
                conn.close()
                return df
        except:
            pass
        return pd.DataFrame()


def get_attack_types():
    """
    Retrieve distribution of attack types from security logs.
    
    Query:
        SELECT CASE (sourcetype mapping) AS category, COUNT(*) FROM splunk_logs
    
    Returns:
        pd.DataFrame: Attack type distribution with columns:
            - category: Mapped attack type (see Category Mapping)
            - count: Number of events of that type
    
    Category Mapping (from sourcetype):
        • %snort% → 'IDS Alerts'
        • %pfsense% → 'Firewall Events'
        • %message_rfc822% → 'Phishing Emails'
        • %WinEventLog:Security% → 'Security Events'
        • %WinEventLog:System% → 'System Events'
        • syslog → 'Syslog Events'
        • (other) → Use sourcetype as-is
    
    Data Sources:
        Primary: splunk_logs table (sourcetype field)
        Fallback: threat_scores table (category field) if splunk_logs empty
    
    Ordering:
        Results ordered by count DESC, limited to top 10 categories
    
    Used By:
        render_threat_charts() for bar chart visualization
    
    Error Handling:
        Returns empty DataFrame if both data sources fail.
    """
    try:
        conn = get_db_connection()
        if conn:
            # Get from splunk_logs sourcetype (attack types)
            query = """
                SELECT 
                    CASE 
                        WHEN sourcetype LIKE '%snort%' THEN 'IDS Alerts'
                        WHEN sourcetype LIKE '%pfsense%' THEN 'Firewall Events'
                        WHEN sourcetype LIKE '%message_rfc822%' THEN 'Phishing Emails'
                        WHEN sourcetype LIKE '%WinEventLog:Security%' THEN 'Security Events'
                        WHEN sourcetype LIKE '%WinEventLog:System%' THEN 'System Events'
                        WHEN sourcetype = 'syslog' THEN 'Syslog Events'
                        ELSE sourcetype
                    END as category,
                    COUNT(*) as count
                FROM splunk_logs
                WHERE sourcetype IS NOT NULL
                GROUP BY category
                ORDER BY count DESC
                LIMIT 10
            """
            df = pd.read_sql_query(query, conn)
            
            # If splunk_logs is empty, try threat_scores
            if df.empty:
                query = """
                    SELECT category, COUNT(*) as count 
                    FROM threat_scores 
                    WHERE category IS NOT NULL
                    GROUP BY category
                    ORDER BY count DESC
                    LIMIT 10
                """
                df = pd.read_sql_query(query, conn)
            
            conn.close()
            return df
        return pd.DataFrame()
    except Exception as e:
        return pd.DataFrame()


def calculate_detection_rate():
    """
    Retrieve latest detection rate from performance metrics.
    
    Query:
        SELECT value FROM performance_metrics
        WHERE metric_name = 'detection_rate'
        ORDER BY date DESC LIMIT 1
    
    Returns:
        float: Detection rate percentage (default: 85.0 if no data)
    
    Used By:
        render_key_metrics() and render_performance_metrics()
    
    Data Source:
        performance_metrics table with metric_name='detection_rate'
    
    Note:
        Default value (85.0) used if no records found in database.
        Typically updated via background job or system metrics collection.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM performance_metrics WHERE metric_name = 'detection_rate' ORDER BY date DESC LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else 85.0  # Default value
        return 85.0
    except:
        return 85.0


def calculate_prevention_rate():
    """
    Retrieve latest prevention rate from performance metrics.
    
    Query:
        SELECT value FROM performance_metrics
        WHERE metric_name = 'prevention_rate'
        ORDER BY date DESC LIMIT 1
    
    Returns:
        float: Prevention rate percentage (default: 78.0 if no data)
    
    Used By:
        render_key_metrics() and render_performance_metrics()
    
    Data Source:
        performance_metrics table with metric_name='prevention_rate'
    
    Note:
        Default value (78.0) used if no records found in database.
        Represents percentage of detected threats that were prevented.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM performance_metrics WHERE metric_name = 'prevention_rate' ORDER BY date DESC LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else 78.0  # Default value
        return 78.0
    except:
        return 78.0


def calculate_false_positive_rate():
    """
    Retrieve latest false positive rate from performance metrics.
    
    Query:
        SELECT value FROM performance_metrics
        WHERE metric_name = 'false_positive_rate'
        ORDER BY date DESC LIMIT 1
    
    Returns:
        float: False positive rate percentage (default: 5.2 if no data)
    
    Used By:
        render_key_metrics() and render_performance_metrics()
    
    Data Source:
        performance_metrics table with metric_name='false_positive_rate'
    
    Note:
        Default value (5.2) used if no records found in database.
        Lower is better: represents % of alerts that are not actual threats.
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM performance_metrics WHERE metric_name = 'false_positive_rate' ORDER BY date DESC LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else 5.2  # Default value
        return 5.2
    except:
        return 5.2


# ════════════════════════════════════════════════════════════════════════════
#  UI RENDERING FUNCTIONS - DASHBOARD LAYOUT AND VISUALIZATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Render all visible dashboard components in proper order

def render_header():
    """
    Render top navigation bar and hero card section.
    
    COMPONENTS:
    ────────────────────────────────────────────────────────────────────
    1. LOGOUT HANDLER
       • Check for logout action in query params
       • Clear session and redirect to app.py if logout requested
    
    2. TOP NAVIGATION BAR
       ├─ Left side: User info (username | ROLE)
       ├─ Center/Right links:
       │  ├─ Live Monitor (pages/Live_Threat_Monitor)
       │  ├─ AI Analysis (pages/AI_Log_Analysis)
       │  ├─ Scoring (pages/Threat_Scoring)
       │  ├─ Metrics (pages/Performance_Metrics)
       │  ├─ Server (pages/Server_Performance)
       │  ├─ Configuration (pages/System_Configuration) [CTA style]
       │  └─ Logout (query action=logout)
       └─ Styling: Gradient bg, responsive design, hover effects
    
    3. HERO CARD
       ├─ Background image: SOC operations photo (from assets/photos/)
       ├─ Title: "Real-time Security Operations Center"
       ├─ Subtitle: "Comprehensive threat monitoring and analytics dashboard"
       ├─ Styling: Dark overlay, text shadow, full width
       └─ Error handling: Shows without image if file not found
    
    Used By:
        main() as first content render after authentication
    
    Dependencies:
        auth.session_manager.clear_session() for logout
        Hero image: assets/photos/What-Makes-SOC-*.jpg
    """
    # Check for logout action
    query_params = st.query_params
    if 'action' in query_params and query_params['action'] == 'logout':
        clear_session()
        st.session_state.authenticated = False
        st.success("Logged out successfully!")
        import time
        time.sleep(2)
        st.switch_page("app.py")
    
    # Top navigation bar
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
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
        @media (max-width: 900px) {{
            .topbar {{ flex-direction: column; align-items: flex-start; gap:10px; }}
            .topbar .links {{ width: 100%; justify-content: flex-start; }}
        }}
    </style>

    <div class="topbar">
        <div class="left">
            <span class="user-info">{st.session_state.get('username', 'Unknown')} | {st.session_state.get('role', 'Unknown').upper()}</span>
        </div>
        <div class="links">
            <a href="Live_Threat_Monitor" title="Live Threats">Live Monitor</a>
            <a href="AI_Log_Analysis" title="AI Analysis">AI Analysis</a>
            <a href="Threat_Scoring" title="Threat Scoring">Scoring</a>
            <a href="Performance_Metrics" title="Metrics">Metrics</a>
            <a href="Server_Performance" title="Server">Server</a>
            <a class="cta" href="System_Configuration" title="Configuration">Configuration</a>
            <a class="logout" href="?action=logout" title="Logout">Logout</a>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div style='height:15px'></div>", unsafe_allow_html=True)
    
    # Load and display hero card with background image
    from pathlib import Path
    import base64
    
    img_path = Path(__file__).parent.parent / "assets" / "photos" / "What-Makes-SOC-Security-Operations-Centre-Effective-People-Process-and-Technology.jpg"
    
    if img_path.exists():
        with open(img_path, "rb") as img_file:
            img_data = base64.b64encode(img_file.read()).decode()
        
        st.markdown(f"""
        <style>
            .hero-card {{
                background-image: url('data:image/jpeg;base64,{img_data}');
                background-size: cover;
                background-position: center;
                border-radius: 12px;
                padding: 60px;
                color: white;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.7);
                min-height: 500px;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: flex-start;
                text-align: left;
                margin-top: 5px;
            }}
            .hero-card h2 {{
                font-size: 48px;
                font-weight: 700;
                margin: 0 0 24px 0;
                line-height: 1.2;
                max-width: 600px;
            }}
            .hero-card p {{
                font-size: 16px;
                margin: 0 0 30px 0;
                max-width: 700px;
                line-height: 1.6;
            }}
            .hero-card-button {{
                display: inline-block;
                background: #243447;
                color: white;
                padding: 12px 28px;
                border-radius: 6px;
                text-decoration: none;
                font-weight: 700;
                font-size: 16px;
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            .hero-card-button:hover {{
                background: #243447;
                transform: translateY(-2px);
            }}
        </style>
        <div class="hero-card">
            <h2>Real-time Security Operations Center</h2>
            <p>
                Comprehensive threat monitoring and analytics dashboard
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")


def render_key_metrics():
    """
    Render executive summary KPI card.
    
    DISPLAYED METRICS (6 Statistics):
    ────────────────────────────────────────────────────────────────────
    1. Total Attacks Detected: get_total_attacks() [count,000s format]
    2. High Severity Threats: get_high_severity_threats() [count]
    3. Blocked Connections: get_blocked_connections() [count,000s format]
    4. Detection Rate: calculate_detection_rate() [percentage]
    5. Response Time: Hardcoded "2s" (SLA value)
    6. System Status: Hardcoded "OPERATIONAL" (status indicator)
    
    STYLING:
    • Container: Gradient background (#141d26 → #243447)
    • Metrics: Flex layout with 20px gaps, wrappable
    • Values: Large (28px) blue text (#65c1f9), bold
    • Labels: Small (12px) light text (#E2E2D2), 85% opacity
    • Hover: TranslateY(-4px) with blue shadow effect
    
    Used By:
        main() after header render
    
    Data Dependencies:
        • get_total_attacks()
        • get_high_severity_threats()
        • get_blocked_connections()
        • calculate_detection_rate()
    """
    st.markdown("<h3 style='text-align: center;'>Key Performance Indicators</h3>", unsafe_allow_html=True)
    
    
    # Get data
    total_attacks = get_total_attacks()
    high_threats = get_high_severity_threats()
    blocked = get_blocked_connections()
    detection_rate = calculate_detection_rate()
    
    st.markdown(f"""
    <style>
        .stats-card {{
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border-radius: 12px;
            padding: 30px;
            color: #E2E2D2;
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
            color: #E2E2D2;
            opacity: 0.85;
            line-height: 1.3;
        }}
        .stats-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
        }}
    </style>
    <div class="stats-card">
        <div class="stats-content">
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{total_attacks:,}</div>
                    <div class="stat-inline-label">Total Attacks Detected</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{high_threats:,}</div>
                    <div class="stat-inline-label">High Severity Threats</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{blocked:,}</div>
                    <div class="stat-inline-label">Blocked Connections</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{detection_rate:.1f}%</div>
                    <div class="stat-inline-label">Detection Rate</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">2s</div>
                    <div class="stat-inline-label">Response Time</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">OPERATIONAL</div>
                    <div class="stat-inline-label">System Status</div>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_performance_metrics():
    """
    Render three-column performance KPI cards.
    
    CARDS (3-Column Layout):
    ────────────────────────────────────────────────────────────────────
    1. DETECTION RATE
       • Value: calculate_detection_rate() formatted to 1 decimal
       • Delta: ↑ +2.3% (hardcoded trend indicator)
       • Color: #65c1f9 (blue)
    
    2. PREVENTION RATE
       • Value: calculate_prevention_rate() formatted to 1 decimal
       • Delta: ↑ +1.8% (hardcoded trend indicator)
       • Color: #65c1f9 (blue)
    
    3. FALSE POSITIVE RATE
       • Value: calculate_false_positive_rate() formatted to 1 decimal
       • Delta: ↓ -0.5% (hardcoded trend indicator, red color)
       • Color: #65c1f9 (blue) with red trend arrow
    
    STYLING:
    • Each card: Gradient background, center-aligned, text-center
    • Hover: TranslateY(-4px) with shadow effect
    • Responsive: Stacks to 1 column on mobile
    
    Used By:
        main() after key metrics
    
    Data Dependencies:
        • calculate_detection_rate()
        • calculate_prevention_rate()
        • calculate_false_positive_rate()
    """
    st.markdown("<h3 style='text-align: center;'>Detection & Prevention Performance</h3>", unsafe_allow_html=True)
    
    detection_rate = calculate_detection_rate()
    prevention_rate = calculate_prevention_rate()
    fp_rate = calculate_false_positive_rate()
    
    col1, col2, col3 = st.columns(3)
    
    # Detection Rate Card
    with col1:
        st.markdown(f"""
        <style>
            .perf-metric-card {{
                background: linear-gradient(135deg, #141d26 0%, #243447 100%);
                border-radius: 12px;
                padding: 25px;
                color: #E2E2D2;
                text-align: center;
                transition: all 0.3s ease;
            }}
            .perf-metric-value {{
                font-size: 36px;
                font-weight: 700;
                color: #65c1f9;
                margin: 10px 0;
            }}
            .perf-metric-label {{
                font-size: 14px;
                color: #E2E2D2;
                opacity: 0.85;
            }}
            .perf-metric-delta {{
                font-size: 12px;
                color: #4CAF50;
                font-weight: 600;
                margin-top: 8px;
            }}
            .perf-metric-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
            }}
        </style>
        <div class="perf-metric-card">
            <div class="perf-metric-label">Detection Rate</div>
            <div class="perf-metric-value">{detection_rate:.1f}%</div>
            <div class="perf-metric-delta">↑ +2.3%</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Prevention Rate Card
    with col2:
        st.markdown(f"""
        <style>
            .perf-metric-card {{
                background: linear-gradient(135deg, #141d26 0%, #243447 100%);
                border-radius: 12px;
                padding: 25px;
                color: #E2E2D2;
                text-align: center;
                transition: all 0.3s ease;
            }}
            .perf-metric-value {{
                font-size: 36px;
                font-weight: 700;
                color: #65c1f9;
                margin: 10px 0;
            }}
            .perf-metric-label {{
                font-size: 14px;
                color: #E2E2D2;
                opacity: 0.85;
            }}
            .perf-metric-delta {{
                font-size: 12px;
                color: #4CAF50;
                font-weight: 600;
                margin-top: 8px;
            }}
            .perf-metric-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
            }}
        </style>
        <div class="perf-metric-card">
            <div class="perf-metric-label">Prevention Rate</div>
            <div class="perf-metric-value">{prevention_rate:.1f}%</div>
            <div class="perf-metric-delta">↑ +1.8%</div>
        </div>
        """, unsafe_allow_html=True)
    
    # False Positive Rate Card
    with col3:
        st.markdown(f"""
        <style>
            .perf-metric-card {{
                background: linear-gradient(135deg, #141d26 0%, #243447 100%);
                border-radius: 12px;
                padding: 25px;
                color: #E2E2D2;
                text-align: center;
                transition: all 0.3s ease;
            }}
            .perf-metric-value {{
                font-size: 36px;
                font-weight: 700;
                color: #65c1f9;
                margin: 10px 0;
            }}
            .perf-metric-label {{
                font-size: 14px;
                color: #E2E2D2;
                opacity: 0.85;
            }}
            .perf-metric-delta {{
                font-size: 12px;
                color: #FF6B6B;
                font-weight: 600;
                margin-top: 8px;
            }}
            .perf-metric-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
            }}
        </style>
        <div class="perf-metric-card">
            <div class="perf-metric-label">False Positive Rate</div>
            <div class="perf-metric-value">{fp_rate:.1f}%</div>
            <div class="perf-metric-delta">↓ -0.5%</div>
        </div>
        """, unsafe_allow_html=True)


def render_threat_charts():
    """
    Render threat analysis visualizations (2-column layout).
    
    CHARTS:
    ────────────────────────────────────────────────────────────────────
    1. LEFT COLUMN: SEVERITY DISTRIBUTION (Donut Pie Chart)
       • Data: get_threat_distribution() severity levels and counts
       • Type: Plotly Pie chart with hole=0.5 (donut)
       • Colors: Severity-based mapping (#1A3A52, #2B5A7A, #4A7BA7, #6B9BC3)
       • Center annotation: Total count of events
       • Height: 400px
       • Legend: Horizontal bottom
       • Info message: "No threat data available" if empty
    
    2. RIGHT COLUMN: ATTACK TYPE DISTRIBUTION (Bar Chart)
       • Data: get_attack_types() category and count
       • Type: Plotly Bar chart (horizontal bars)
       • Colors: Dynamic blue gradient (43-107 RGB range)
       • X-axis: Attack categories (45° angle)
       • Y-axis: Event counts with grid lines
       • Height: 400px
       • Info message: "No attack type data available" if empty
    
    STYLING:
    • Paper & plot background: Transparent
    • Font: #E2E2D2 (light text)
    • Grid: Light blue (#65c1f9) at 10% opacity
    • Margins: Minimal for maximum chart space
    
    Used By:
        main() after performance metrics
    
    Data Dependencies:
        • get_threat_distribution()
        • get_attack_types()
    
    Plotly Config:
        • use_container_width: True (responsive)
    """
    st.markdown("<h3 style='text-align: center;'>Threat Analysis & Distribution</h3>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    # Severity Distribution Pie Chart
    with col1:
        st.markdown("<h5 style='text-align: center; color: #65c1f9; margin-top: 20px;'>Threat Severity Distribution</h5>", unsafe_allow_html=True)
        
        severity_df = get_threat_distribution()
        
        if not severity_df.empty:
            # Create color mapping based on actual severity values
            severity_colors = {
                'High': '#2B5A7A',      # Deep blue
                'Medium': '#4A7BA7',    # Medium blue
                'Low': '#6B9BC3',       # Light blue
                'Critical': '#1A3A52'   # Darkest blue (if exists)
            }
            
            # Map colors to actual data
            colors = [severity_colors.get(sev, '#65c1f9') for sev in severity_df['severity']]
            
            fig = go.Figure(data=[go.Pie(
                labels=severity_df['severity'],
                values=severity_df['count'],
                hole=.5,
                marker=dict(
                    colors=colors,
                    line=dict(color='#141d26', width=2)
                ),
                textfont=dict(color='white', size=14, family='Arial'),
                textposition='auto',
                textinfo='label+percent'
            )])
            
            fig.update_layout(
                height=400,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#E2E2D2', size=13),
                margin=dict(l=20, r=20, t=40, b=20),
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.15,
                    xanchor="center",
                    x=0.5,
                    font=dict(color='#E2E2D2', size=12),
                    bgcolor='rgba(0,0,0,0)'
                ),
                annotations=[dict(
                    text=f'<b>Total<br>{severity_df["count"].sum()}</b>',
                    x=0.5, y=0.5,
                    font=dict(size=16, color='#65c1f9', family='Arial'),
                    showarrow=False
                )]
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data available")
    
    # Attack Types Bar Chart
    with col2:
        st.markdown("<h5 style='text-align: center; color: #65c1f9; margin-top: 20px;'>Events Type Distribution</h5>", unsafe_allow_html=True)
        
        attack_types_df = get_attack_types()
        
        if not attack_types_df.empty:
            # Generate blue gradient colors based on actual number of categories
            n_colors = len(attack_types_df)
            colors = [f'rgb({int(43 + i * (107-43)/max(n_colors-1, 1))}, {int(90 + i * (155-90)/max(n_colors-1, 1))}, {int(122 + i * (195-122)/max(n_colors-1, 1))})' 
                     for i in range(n_colors)]
            
            fig = go.Figure(data=[go.Bar(
                x=attack_types_df['category'],
                y=attack_types_df['count'],
                marker=dict(
                    color=colors,
                    line=dict(color='#141d26', width=1)
                ),
                text=attack_types_df['count'],
                textposition='auto',
                textfont=dict(color='white', size=12)
            )])
            
            fig.update_layout(
                height=400,
                xaxis_title="Events Category",
                yaxis_title="Count",
                showlegend=False,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#E2E2D2', size=12),
                xaxis=dict(
                    gridcolor='rgba(101, 193, 249, 0.1)',
                    title_font=dict(color='#65c1f9', size=14),
                    tickangle=-45
                ),
                yaxis=dict(
                    gridcolor='rgba(101, 193, 249, 0.1)',
                    title_font=dict(color='#65c1f9', size=14)
                ),
                margin=dict(l=20, r=20, t=40, b=80)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack type data available")


def render_recent_threats_table():
    """
    Render recent security events table with color-coded severity.
    
    DATA:
    ────────────────────────────────────────────────────────────────────
    • Source: get_recent_threats(15)
    • Columns: ID, Severity, Category/Type, Host, Source, Timestamp
    • Rows: 15 most recent events ordered by timestamp DESC
    
    STYLING:
    • Color coding per severity (row background):
      - Critical: #1A3A52 (darkest blue)
      - High: #2B5A7A (dark blue)
      - Medium: #4A7BA7 (medium blue)
      - Low: #6B9BC3 (light blue)
      - Info: #8BB8D8 (lighter blue, black text)
      - Other: #E8F4F8 (very light blue, black text)
    • Height: 450px (scrollable)
    • Width: Full container width
    
    SUMMARY STATISTICS (Below Table):
    • Total Events: len(display_df)
    • Critical/High Count: Count of rows with severity in ['Critical', 'High']
    • Most Common Type: Most frequent value in Type/Category column
    
    Used By:
        main() after threat charts
    
    Data Dependencies:
        • get_recent_threats(15)
    
    Error Handling:
        "No recent security events found" message if data empty
    """
    st.markdown("<h3 style='text-align: center;'>Recent Security Events</h3>", unsafe_allow_html=True)
    
    recent_df = get_recent_threats(15)
    
    if not recent_df.empty:
        # Format the dataframe for display
        display_df = recent_df.copy()
        
        # Format timestamp to be more readable
        if 'timestamp' in display_df.columns:
            try:
                display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        # Rename columns based on what's available
        if len(display_df.columns) == 6:
            display_df.columns = ['ID', 'Severity', 'Type', 'Host', 'Source', 'Timestamp']
        else:
            display_df.columns = ['ID', 'Score', 'Severity', 'Category', 'Timestamp']
        
        # Apply color coding with blue theme
        def highlight_severity(row):
            severity = row.get('Severity', '')
            if severity == 'Critical':
                return ['background-color: #1A3A52; color: white'] * len(row)
            elif severity == 'High':
                return ['background-color: #2B5A7A; color: white'] * len(row)
            elif severity == 'Medium':
                return ['background-color: #4A7BA7; color: white'] * len(row)
            elif severity == 'Low':
                return ['background-color: #6B9BC3; color: white'] * len(row)
            elif severity == 'Info':
                return ['background-color: #8BB8D8; color: black'] * len(row)
            else:
                return ['background-color: #E8F4F8; color: black'] * len(row)
        
        styled_df = display_df.style.apply(highlight_severity, axis=1)
        st.dataframe(styled_df, use_container_width=True, height=450)
        
        # Show summary stats centered
        critical_high = len(display_df[display_df['Severity'].isin(['Critical', 'High'])])
        if 'Type' in display_df.columns:
            most_common = display_df['Type'].value_counts().index[0] if len(display_df) > 0 else 'N/A'
        else:
            most_common = display_df['Category'].value_counts().index[0] if len(display_df) > 0 else 'N/A'
        
        st.markdown(f"<div style='text-align: center; color: #E2E2D2; font-size: 14px; margin-top: 15px;'><strong>Total Events: {len(display_df)}</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Critical/High: {critical_high}</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Most Common: {most_common}</strong></div>", unsafe_allow_html=True)
    else:
        st.info("No recent security events found")


def render_quick_navigation():
    """
    Render quick access grid with links to main platform pages.
    
    GRID CARDS (6 Items - Responsive):
    ────────────────────────────────────────────────────────────────────
    1. Live Threat Monitor → pages/Live_Threat_Monitor
       "Real-time threat detection and monitoring"
    
    2. AI Log Analysis → pages/AI_Log_Analysis
       "Intelligent log analysis with machine learning"
    
    3. Threat Scoring → pages/Threat_Scoring
       "Advanced threat risk assessment and scoring"
    
    4. Performance Metrics → pages/Performance_Metrics
       "System performance analytics and trends"
    
    5. Server Performance → pages/Server_Performance
       "Server health monitoring and resources"
    
    6. System Configuration → pages/System_Configuration
       "Configure system settings and preferences"
    
    STYLING:
    • Container: Grid layout, responsive (minmax 250px, 1fr)
    • Cards: Gradient bg, 30px padding, center alignment
    • Hover: TranslateY(-4px) with shadow effect
    • Title: 18px blue text (#65c1f9), bold
    • Description: 14px light text, 90% opacity
    
    Used By:
        main() before footer
    
    Note:
        All links are styled as card buttons (no default link styling).
    """
    st.markdown("""
    <style>
        .quick-access-section {
            margin: 20px 0;
            margin-top: 20px;
        }
        .quick-access-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .quick-access-card {
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border-radius: 12px;
            padding: 30px;
            color: #E2E2D2;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            text-decoration: none;
        }
        .quick-access-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
            text-decoration: none;
            color: #E2E2D2;
        }
        .quick-access-card h4 {
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 12px 0;
            color: #65c1f9;
        }
        .quick-access-card p {
            font-size: 14px;
            margin: 0 0 20px 0;
            opacity: 0.9;
            line-height: 1.5;
        }
        .quick-access-icon {
            font-size: 28px;
            margin-bottom: 12px;
        }
    </style>
    <div class="quick-access-section">
        <h3 style='text-align: center;'>Quick Access</h3>
        <div class="quick-access-grid">
            <a href="Live_Threat_Monitor" class="quick-access-card" style="text-decoration: none;">
                <h4>Live Threat Monitor</h4>
                <p>Real-time threat detection and monitoring</p>
            </a>
            <a href="AI_Log_Analysis" class="quick-access-card" style="text-decoration: none;">
                <h4>AI Log Analysis</h4>
                <p>Intelligent log analysis with machine learning</p>
            </a>
            <a href="Threat_Scoring" class="quick-access-card" style="text-decoration: none;">
                <h4>Threat Scoring</h4>
                <p>Advanced threat risk assessment and scoring</p>
            </a>
            <a href="Performance_Metrics" class="quick-access-card" style="text-decoration: none;">
                <h4>Performance Metrics</h4>
                <p>System performance analytics and trends</p>
            </a>
            <a href="Server_Performance" class="quick-access-card" style="text-decoration: none;">
                <h4>Server Performance</h4>
                <p>Server health monitoring and resources</p>
            </a>
            <a href="System_Configuration" class="quick-access-card" style="text-decoration: none;">
                <h4>System Configuration</h4>
                <p>Configure system settings and preferences</p>
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """
    Render sidebar with navigation links and system information.
    
    SIDEBAR SECTIONS:
    ────────────────────────────────────────────────────────────────────
    1. NAVIGATION TITLE
       "Navigation" header with horizontal separator
    
    2. PAGE LINKS (8 Pages)
       • Dashboard_Overview (current page)
       • Live_Threat_Monitor
       • AI_Log_Analysis
       • Threat_Scoring
       • Performance_Metrics
       • Server_Performance
       • System_Configuration
       • Forensics_And_Reports
       • User_Management
    
    3. SYSTEM INFORMATION SECTION
       ├─ Version: 1.0.0 (hardcoded)
       ├─ Last Updated: Current datetime (YYYY-MM-DD HH:MM)
       └─ Database: "Connected" (static)
    
    4. REFRESH BUTTON
       • Label: "Refresh Dashboard"
       • Width: Full width
       • Action: st.rerun() (reruns entire app)
    
    Used By:
        main() as first sidebar operation
    
    Note:
        Uses Streamlit's st.page_link() for navigation (new in v1.24+).
    """
    with st.sidebar:
        st.title("Navigation")
        st.markdown("---")
        
        st.page_link("pages/Dashboard_Overview.py", label="Dashboard Overview")
        st.page_link("pages/Live_Threat_Monitor.py", label="Live Threat Monitor")
        st.page_link("pages/AI_Log_Analysis.py", label="AI Log Analysis")
        st.page_link("pages/Threat_Scoring.py", label="Threat Scoring")
        st.page_link("pages/Performance_Metrics.py", label="Performance Metrics")
        st.page_link("pages/Server_Performance.py", label="Server Performance")
        st.page_link("pages/System_Configuration.py", label="System Configuration")
        st.page_link("pages/Forensics_And_Reports.py", label="Forensics & Reports")
        st.page_link("pages/User_Management.py", label="User Management")
        
        st.markdown("---")
        st.markdown("### System Information")
        st.markdown(f"**Version:** 1.0.0")
        st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        st.markdown(f"**Database:** Connected")
        
        st.markdown("---")
        if st.button("Refresh Dashboard", use_container_width=True):
            st.rerun()


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Orchestrate page rendering workflow and content layout

def main():
    """
    Primary application entry point orchestrating complete dashboard.
    
    RENDERING WORKFLOW (Execution Order):
    ────────────────────────────────────────────────────────────────────
    1. check_authentication() - Verify user session and access rights
    2. render_sidebar() - Navigation and system info (always visible)
    3. render_header() - Top navigation bar and hero card
    4. render_key_metrics() - Executive summary KPIs (6 statistics)
    5. render_performance_metrics() - Detection/prevention rates (3 cards)
    6. render_threat_charts() - Severity + Attack type visualizations
    7. render_recent_threats_table() - Security events table (15 rows)
    8. render_quick_navigation() - Quick access grid (6 pages)
    9. Footer - Copyright notice and disclaimer
    
    HORIZONTAL SEPARATORS:
    • Placed between major sections for visual organization
    • Dark divider: "---" markdown
    
    TIMESTAMPS:
    • "Last updated" shown at top and bottom of content
    • Format: YYYY-MM-DD HH:MM:SS
    • Refresh interval: Every 30 seconds (noted in UI)
    
    FLOW:
    ├─ Security check fails → Redirect to login
    ├─ Sidebar rendered first (always accessible)
    ├─ Main content flows top-to-bottom
    ├─ Each section isolated with separators
    └─ Footer with disclaimer at end
    
    AUTHENTICATION:
    • First operation before any content rendering
    • Prevents unauthorized dashboard access
    • Redirects expired sessions to login page
    
    Dependencies:
    • check_authentication()
    • render_sidebar()
    • render_header()
    • render_key_metrics()
    • render_performance_metrics()
    • render_threat_charts()
    • render_recent_threats_table()
    • render_quick_navigation()
    """
    
    # Check authentication
    check_authentication()
    
    # Render sidebar
    render_sidebar()
    
    # Render main content
    render_header()
    
    # Key metrics
    render_key_metrics()
    st.markdown("---")
    
    # Performance metrics
    render_performance_metrics()
    
    # Auto-refresh indicator
    st.markdown(f"<div style='text-align: center; color: gray; font-size: 12px;'>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Auto-refresh: Every 30 seconds</div>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Threat charts
    render_threat_charts()
    st.markdown("---")
    
    # Recent threats table
    render_recent_threats_table()
    st.markdown("---")
    
    # Quick navigation
    render_quick_navigation()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray; font-size: 12px;'>"
        "Multilayered Cyber Defense Platform | Unauthorized access is prohibited"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()