"""
MULTILAYERED CYBER DEFENSE PLATFORM - PERFORMANCE METRICS & ANALYTICS
╚════════════════════════════════════════════════════════════════════════════╝

File: pages/Performance_Metrics.py
Purpose: Real-time KPI tracking, performance analytics, and defense effectiveness

DESCRIPTION:
    Comprehensive dashboard for monitoring operational effectiveness metrics
    across the cyber defense platform. Displays Key Performance Indicators (KPIs),
    trend analysis, and system performance analytics with interactive Plotly charts.

KEY PERFORMANCE INDICATORS (KPIs) DISPLAYED:
    ├─ Detection Rate: Percentage of threats detected out of total attempts
    ├─ Prevention Rate: Percentage of detected threats successfully blocked
    ├─ False Positive Rate: Percentage of false alerts (medium severity logs)
    ├─ MTTD: Mean Time to Detect (minutes from first occurrence to indexing)
    ├─ MTTR: Mean Time to Respond (minutes from detection to response)
    └─ Auto-Containment Rate: Percentage of incidents auto-contained (70% default)

CHARTS & VISUALIZATIONS:
    1. Detection Rate Trend (Line Chart)
       - Time range: Last 30 days
       - Data source: splunk_logs grouped by date
       - Metrics: Daily detection rate percentage
       - Shows: Detection effectiveness over time period
    
    2. Auto-Containment Effectiveness (Bar Chart)
       - Comparison: Auto-Contained vs Manual Intervention
       - Colors: #65c1f9 (auto), #fd7e14 (manual)
       - Shows: Percentage distribution of containment methods
    
    3. Severity vs Response Time (Scatter Plot)
       - X-axis: Severity level (critical, high, medium, low, info)
       - Y-axis: Response time in minutes
       - Colors: Mapped by severity (red→critical, orange→high, etc.)
       - Shows: Correlation between incident severity and response speed
       - Data source: splunk_logs with timestamp/indexed_at calculations

DATABASE INTERACTIONS:
    Tables Used:
        - splunk_logs: Primary security event data
          * Fields: severity, timestamp, indexed_at, source
          * Queries: Detection rate, prevention rate, FP rate, response times
        - performance_metrics: Historical KPI storage
          * Fields: metric_name, value, date
          * Usage: Long-term trend analysis and reporting
    
    Key Queries:
        • Detection rate: COUNT(severity IN 'critical','high') / COUNT(*)
        • Prevention rate: COUNT(severity='critical') / COUNT(severity IN 'critical','high')
        • MTTD: AVG((julianday(indexed_at) - julianday(timestamp)) * 24 * 60) in minutes
        • Response time: (julianday(indexed_at) - julianday(timestamp)) * 24 * 60
        • Auto-containment: Total_incidents * 0.7 / Total_incidents (demo value)

PAGE LAYOUT COMPONENTS:
    1. Header Section
       - Navigation bar with links (Dashboard, Live Monitor, AI Analysis, etc.)
       - Page title: "Performance Metrics"
       - Subtitle: "Real-time KPI tracking and performance analytics"
    
    2. Key Metrics Cards (6 columns)
       - Cards display: Value (large, #65c1f9) + Label
       - Styling: Dark gradient background, hover elevation effect
       - Responsive: Adapts to screen size (min-width: 200px, max-width: 1fr)
    
    3. Two-Column Chart Section
       - Column 1: Auto-Containment bar chart
       - Column 2: Severity vs Response time scatter plot
    
    4. Full-Width Chart Section
       - Detection Rate Trend line chart spanning 30 days
    
    5. Footer
       - Centered attribution text

STYLING & THEME:
    Color Scheme:
        • Background: Gradient #141d26 → #243447 (dark navy to dark blue)
        • Text: #E2E2D2 (light text)
        • Accent: #65c1f9 (highlight/primary KPI color)
        • Secondary: #fd7e14 (warning/manual intervention)
        • Critical: #dc3545 (danger alerts)
        • Info: #6c757d (informational)
    
    CSS Elements:
        • Cards: Border-radius 12px, gradient background, hover transform
        • Charts: Plotly dark template with dark background
        • Navigation: Responsive with mobile fallback (max-width: 700px)
        • Metrics grid: CSS Grid with auto-fit, min 200px columns

DEPENDENCIES:
    External Libraries:
        - streamlit: Web framework
        - pandas: DataFrames and data manipulation
        - plotly.express: High-level charting API
        - plotly.graph_objects: Low-level chart customization
        - datetime: Timestamp handling
    
    Internal Modules:
        - auth.session_manager: check_session_timeout(), clear_session()
        - database.queries: get_db_connection()

AUTHENTICATION & SESSION:
    • Session state variables: username, role, authenticated
    • Timeout handling: check_session_timeout() validates expiry
    • Development mode: Default user (admin/administrator) for testing
    • Page config: Wide layout, centered content

ERROR HANDLING:
    - Database connection failures: Try-except returns empty DataFrame/0.0
    - Missing data: Info messages displayed ("No X data available")
    - SQL errors: Gracefully handled with default return values
    - Empty datasets: Charts show info message instead of crashing

PERFORMANCE CONSIDERATIONS:
    • Database queries optimized with proper WHERE/GROUP BY clauses
    • Plotly charts configured for performance (dark mode, no animations)
    • Data limited: LIMIT 100 for scatter plot (prevents oversized datasets)
    • CSS optimized: Minimal recalculation, smooth transitions (0.3s)

NAVIGATION FLOW:
    Pages linked in header:
        Dashboard_Overview → Live_Threat_Monitor → AI_Log_Analysis
        → Threat_Scoring → System_Configuration
    
    User roles supported: admin, analyst, viewer
╚════════════════════════════════════════════════════════════════════════════╝
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

# Import modules
try:
    from auth.session_manager import check_session_timeout, clear_session
    from database.queries import get_db_connection
except ImportError as e:
    st.error(f"Import Error: {e}")
    st.stop()

# ════════════════════════════════════════════════════════════════════════════
#  CUSTOM CSS FOR SCROLLING AND THEME APPLICATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Enable smooth scrolling, apply dark theme, optimize layout for performance metrics

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
#  AUTHENTICATION & SESSION MANAGEMENT - USER VERIFICATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Verify user session and enforce access control

def check_authentication():
    """
    Verify user is authenticated before rendering page.
    
    Purpose: Ensure user has valid session before displaying performance metrics.
    If not authenticated, set default dev credentials or prompt re-login.
    
    Session Validation:
        1. Check if st.session_state.authenticated == True
        2. If False: Set development defaults (admin/administrator)
        3. If True: Call check_session_timeout() to validate expiry
        4. If expired: Show warning and reset to defaults
    
    Session State Variables Set:
        - username (str): Authenticated username or 'admin' for dev
        - role (str): User role ('administrator', 'analyst', 'viewer')
        - authenticated (bool): Authentication status
    
    Returns: None (modifies st.session_state in-place)
    
    Used By: main() on page load
    
    Note: Development mode allows testing without full login flow
    """
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


# ════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIGURATION - STREAMLIT PAGE SETUP
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Configure page metadata and layout

st.set_page_config(
    page_title="Performance Metrics - Cyber Defense Platform",
    layout="wide"
)


# ════════════════════════════════════════════════════════════════════════════
#  DATA FETCHING FUNCTIONS - DATABASE QUERIES FOR KPI METRICS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Query database for KPI calculations and trend analysis

def get_detection_rate():
    """
    Calculate detection rate from logs.
    
    Purpose: Measure percentage of threats detected by the system.
    Formula: (Detected Threats / Total Log Events) * 100
    
    Detection Logic:
        - Total: COUNT(*) from splunk_logs (all events)
        - Detected: COUNT(*) where severity IN ('critical', 'high')
        - Calculation: (detected / total) * 100
    
    Returns:
        float: Detection rate percentage (0-100), rounded to 2 decimals
    
    Error Handling:
        - No database connection: Return 0.0
        - Division by zero (total=0): Return 0.0
        - SQL error: Return 0.0
    
    Used By: render_key_metrics()
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            # Total attempts (all logs)
            cursor.execute("SELECT COUNT(*) FROM splunk_logs")
            total = cursor.fetchone()[0]
            
            # Detected threats (high severity and above)
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity IN ('critical', 'high')")
            detected = cursor.fetchone()[0]
            
            conn.close()
            
            if total > 0:
                return round((detected / total) * 100, 2)
            return 0.0
    except:
        return 0.0


def get_prevention_rate():
    """
    Calculate prevention rate from logs.
    
    Purpose: Measure percentage of detected threats that were successfully blocked.
    Formula: (Blocked Threats / Total Threats) * 100
    
    Prevention Logic:
        - Total threats: COUNT(*) where severity IN ('critical', 'high')
        - Blocked: COUNT(*) where severity = 'critical' (assume critical = blocked)
        - Calculation: (blocked / total_threats) * 100
    
    Returns:
        float: Prevention rate percentage (0-100), rounded to 2 decimals
    
    Error Handling:
        - No database connection: Return 0.0
        - Division by zero: Return 0.0
        - SQL error: Return 0.0
    
    Used By: render_key_metrics()
    
    Note: Assumes all critical severity events are auto-blocked
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            # Total threats
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity IN ('critical', 'high')")
            total_threats = cursor.fetchone()[0]
            
            # Blocked (assuming critical are blocked)
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity = 'critical'")
            blocked = cursor.fetchone()[0]
            
            conn.close()
            
            if total_threats > 0:
                return round((blocked / total_threats) * 100, 2)
            return 0.0
    except:
        return 0.0


def get_false_positive_rate():
    """
    Calculate false positive rate.
    
    Purpose: Measure percentage of false alerts from total alerts generated.
    Formula: (False Positives / Total Alerts) * 100
    
    False Positive Logic:
        - Total alerts: COUNT(*) where severity IN ('critical', 'high', 'medium')
        - False positives: COUNT(*) where severity = 'medium' (demo assumption)
        - Calculation: (false_positives / total_alerts) * 100
    
    Returns:
        float: False positive rate percentage (0-100), rounded to 2 decimals
    
    Error Handling:
        - No database connection: Return 0.0
        - Division by zero: Return 0.0
        - SQL error: Return 0.0
    
    Used By: render_key_metrics()
    
    Note: In demo, medium severity events treated as false positives
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            # True positives + False positives (all alerts)
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity IN ('critical', 'high', 'medium')")
            total_alerts = cursor.fetchone()[0]
            
            # Assume false positives are medium severity
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity = 'medium'")
            false_positives = cursor.fetchone()[0]
            
            conn.close()
            
            if total_alerts > 0:
                return round((false_positives / total_alerts) * 100, 2)
            return 0.0
    except:
        return 0.0


def get_mean_time_to_detect():
    """
    Calculate MTTD (Mean Time to Detect).
    
    Purpose: Measure average time from threat occurrence to detection/indexing.
    Formula: AVG((indexed_at - timestamp) * 24 * 60) in minutes
    
    MTTD Calculation:
        - Time difference: (julianday(indexed_at) - julianday(timestamp))
        - Convert to minutes: * 24 * 60
        - Average: AVG across all critical/high severity events
        - Filter: indexed_at and timestamp must not be NULL
    
    Returns:
        float: Mean time to detect in minutes, rounded to 2 decimals, default 2.5 if no data
    
    Error Handling:
        - No database connection: Return 2.5
        - No critical/high events: Return 2.5
        - SQL error: Return 2.5
    
    Used By: render_key_metrics()
    
    Note: Simulated based on log indexing timestamps (not absolute detection time)
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT AVG(
                    CAST((julianday(indexed_at) - julianday(timestamp)) * 24 * 60 AS REAL)
                ) as avg_minutes
                FROM splunk_logs 
                WHERE severity IN ('critical', 'high')
                AND indexed_at IS NOT NULL 
                AND timestamp IS NOT NULL
            """)
            result = cursor.fetchone()[0]
            conn.close()
            
            return round(result if result else 2.5, 2)
    except:
        return 2.5


def get_mean_time_to_respond():
    """
    Calculate MTTR (Mean Time to Respond).
    
    Purpose: Measure average time from detection to response/remediation.
    
    Returns:
        float: Mean time to respond in minutes (simulated value: 5.3)
    
    Used By: render_key_metrics()
    
    Note: Currently returns hardcoded value (5.3 minutes). In production,
    would track from detection timestamp to resolution timestamp in database.
    """
    # In real scenario, this would track from detection to resolution
    return 5.3


def get_auto_containment_rate():
    """
    Calculate auto-containment rate.
    
    Purpose: Measure percentage of incidents automatically contained without manual intervention.
    Formula: (Auto-Contained Incidents / Total Incidents) * 100
    
    Auto-Containment Logic:
        - Total incidents: COUNT(*) where severity = 'critical'
        - Auto-contained: Total_incidents * 0.7 (demo assumption: 70% auto-contained)
        - Calculation: (auto_contained / total_incidents) * 100
    
    Returns:
        float: Auto-containment rate percentage (0-100), rounded to 2 decimals
    
    Error Handling:
        - No database connection: Return 0.0
        - Division by zero: Return 0.0
        - SQL error: Return 0.0
    
    Used By: render_key_metrics(), render_auto_containment_chart()
    
    Note: Demo value (70%) represents system automation level - adjust in production
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            # Total incidents
            cursor.execute("SELECT COUNT(*) FROM splunk_logs WHERE severity = 'critical'")
            total_incidents = cursor.fetchone()[0]
            
            # Auto-contained (assume 70% for demo)
            auto_contained = int(total_incidents * 0.7)
            
            conn.close()
            
            if total_incidents > 0:
                return round((auto_contained / total_incidents) * 100, 2)
            return 0.0
    except:
        return 0.0


def get_detection_rate_over_time():
    """
    Get detection rate trend over last 30 days.
    
    Purpose: Fetch daily detection rates for historical trend analysis and visualization.
    
    Data Retrieval:
        - Time range: Last 30 days (WHERE timestamp >= date('now', '-30 days'))
        - Grouping: By date (DATE(timestamp))
        - Metrics per date:
          * total: COUNT(*) all events
          * detected: COUNT(*) where severity IN ('critical', 'high')
          * detection_rate: (detected / total) * 100
    
    Returns:
        pd.DataFrame: Columns [date, total, detected, detection_rate] or empty DataFrame
    
    DataFrame Structure:
        - date (str): Date in YYYY-MM-DD format
        - total (int): Total log events for that day
        - detected (int): Detected threats for that day
        - detection_rate (float): Calculated detection percentage
    
    Error Handling:
        - No database connection: Return empty DataFrame
        - No data found: Return empty DataFrame
        - SQL error: Return empty DataFrame
    
    Used By: render_detection_rate_chart()
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as total,
                    SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) as detected
                FROM splunk_logs
                WHERE timestamp >= date('now', '-30 days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if rows:
                df = pd.DataFrame(rows, columns=['date', 'total', 'detected'])
                df['detection_rate'] = (df['detected'] / df['total'] * 100).round(2)
                return df
            return pd.DataFrame()
    except:
        return pd.DataFrame()


def get_severity_response_time():
    """
    Get severity vs response time data.
    
    Purpose: Fetch response time metrics by severity level for correlation analysis.
    
    Data Retrieval:
        - Fields: severity, response_minutes (calculated), source
        - Calculation: response_minutes = (indexed_at - timestamp) * 24 * 60
        - Limit: LIMIT 100 (performance optimization to prevent large datasets)
        - Filter: severity, indexed_at, timestamp must not be NULL
    
    Returns:
        pd.DataFrame: Columns [severity, response_minutes, source] or empty DataFrame
    
    DataFrame Structure:
        - severity (str): 'critical', 'high', 'medium', 'low', 'info'
        - response_minutes (float): Time from occurrence to indexing in minutes
        - source (str): Event source (IP, host, application)
    
    Error Handling:
        - No database connection: Return empty DataFrame
        - No data found: Return empty DataFrame
        - SQL error: Return empty DataFrame
    
    Used By: render_severity_response_chart()
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    severity,
                    CAST((julianday(indexed_at) - julianday(timestamp)) * 24 * 60 AS REAL) as response_minutes,
                    source
                FROM splunk_logs 
                WHERE severity IS NOT NULL
                AND indexed_at IS NOT NULL 
                AND timestamp IS NOT NULL
                LIMIT 100
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if rows:
                df = pd.DataFrame(rows, columns=['severity', 'response_minutes', 'source'])
                return df
            return pd.DataFrame()
    except:
        return pd.DataFrame()


def get_performance_metrics_history():
    """
    Get stored performance metrics history.
    
    Purpose: Retrieve historical performance metrics from performance_metrics table.
    
    Data Retrieval:
        - Fields: metric_name, value, date
        - Ordering: ORDER BY date DESC (most recent first)
        - Limit: LIMIT 100 (last 100 records)
    
    Returns:
        pd.DataFrame: Columns [metric_name, value, date] or empty DataFrame
    
    DataFrame Structure:
        - metric_name (str): Name of KPI (e.g., 'detection_rate', 'prevention_rate')
        - value (float): Metric value
        - date (str): Timestamp of metric calculation
    
    Error Handling:
        - No database connection: Return empty DataFrame
        - Table not found: Return empty DataFrame
        - SQL error: Return empty DataFrame
    
    Used By: Future reporting and analytics features
    
    Note: Requires population of performance_metrics table via scheduled jobs
    """
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT metric_name, value, date 
                FROM performance_metrics 
                ORDER BY date DESC 
                LIMIT 100
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            if rows:
                return pd.DataFrame(rows, columns=['metric_name', 'value', 'date'])
            return pd.DataFrame()
    except:
        return pd.DataFrame()


# ════════════════════════════════════════════════════════════════════════════
#  UI RENDERING FUNCTIONS - PAGE COMPONENTS AND VISUALIZATIONS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Render header, metrics cards, and interactive Plotly charts

def render_header():
    """
    Render page header with navigation.
    
    Purpose: Display top navigation bar with username, role, and links to other pages.
    
    Header Components:
        1. Vertical spacing (8px top)
        2. Top navigation bar (gradient background):
           - Left section: Username + Role display
           - Right section: Navigation links
        3. Page title: "Performance Metrics"
        4. Subtitle: "Real-time KPI tracking and performance analytics"
    
    Navigation Links (in header):
        - Dashboard_Overview
        - Live_Threat_Monitor
        - AI_Log_Analysis
        - Threat_Scoring
        - System_Configuration (CTA button styling)
    
    Returns: None (renders to Streamlit page)
    
    Styling:
        - Background: Linear gradient #141d26 → #243447
        - Text: #E2E2D2
        - Responsive: Flex layout with mobile fallback (max-width: 700px)
        - CTA button: #c51f5d background
    
    Used By: main()
    """
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
            <a href="Live_Threat_Monitor">Live Monitor</a>
            <a href="AI_Log_Analysis">AI Analysis</a>
            <a href="Threat_Scoring">Scoring</a>
            <a class="cta" href="System_Configuration">Configuration</a>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('<h1 style="text-align: center;">Performance Metrics</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #888;">Real-time KPI tracking and performance analytics</p>', unsafe_allow_html=True)


def render_key_metrics():
    """
    Render key performance indicators.
    
    Purpose: Display 6 KPI metrics in responsive grid layout with visual cards.
    
    Metrics Displayed (6-column grid):
        1. Detection Rate (%): Threats detected / total attempts
        2. Prevention Rate (%): Threats blocked / total threats
        3. False Positive Rate (%): False alerts / total alerts
        4. MTTD (minutes): Mean time to detect
        5. MTTR (minutes): Mean time to respond
        6. Auto-Containment Rate (%): Incidents auto-contained
    
    Card Styling:
        - Background: Linear gradient #141d26 → #243447
        - Value: Large font (32px), bold, #65c1f9 color
        - Label: Smaller font (13px), #E2E2D2 with 0.85 opacity
        - Grid: CSS Grid with auto-fit, minmax(200px, 1fr)
        - Hover: Translate up 4px, box shadow with #65c1f9
        - Transition: 0.3s ease
    
    Data Source:
        - Calls all KPI functions: get_detection_rate(), get_prevention_rate(), etc.
    
    Returns: None (renders to Streamlit page)
    
    Used By: main()
    """
    st.markdown("---")
    st.markdown("<h3 style='text-align: center;'>Key Performance Indicators</h3>", unsafe_allow_html=True)
    
    # Get metrics
    detection_rate = get_detection_rate()
    prevention_rate = get_prevention_rate()
    fp_rate = get_false_positive_rate()
    mttd = get_mean_time_to_detect()
    mttr = get_mean_time_to_respond()
    auto_containment = get_auto_containment_rate()
    
    # Display in cards
    st.markdown(f"""
    <style>
        .metrics-card {{
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border-radius: 12px;
            padding: 25px;
            color: #E2E2D2;
            margin-top: 20px;
            transition: all 0.3s ease;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .metric-item {{
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.05);
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: 700;
            color: #65c1f9;
            margin-bottom: 8px;
        }}
        .metric-label {{
            font-size: 13px;
            color: #E2E2D2;
            opacity: 0.85;
        }}
        .metrics-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
        }}
    </style>
    <div class="metrics-card">
        <div class="metrics-grid">
            <div class="metric-item">
                <div class="metric-value">{detection_rate}%</div>
                <div class="metric-label">Detection Rate</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{prevention_rate}%</div>
                <div class="metric-label">Prevention Rate</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{fp_rate}%</div>
                <div class="metric-label">False Positive Rate</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{mttd}m</div>
                <div class="metric-label">MTTD (Mean Time to Detect)</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{mttr}m</div>
                <div class="metric-label">MTTR (Mean Time to Respond)</div>
            </div>
            <div class="metric-item">
                <div class="metric-value">{auto_containment}%</div>
                <div class="metric-label">Auto-Containment Rate</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_detection_rate_chart():
    """
    Render detection rate over time line chart.
    
    Purpose: Visualize detection rate trend over 30-day period as interactive line chart.
    
    Chart Characteristics:
        - Type: Line chart with markers (Plotly Express)
        - X-axis: Date (YYYY-MM-DD)
        - Y-axis: Detection rate percentage (0-100%)
        - Data source: get_detection_rate_over_time()
        - Points: Markers at each day
        - Color: #65c1f9 (highlight blue)
        - Line width: 3px
        - Mode: 'lines+markers'
    
    Layout Configuration:
        - Background: Dark rgba(20, 29, 38, 0.8)
        - Font: #E2E2D2
        - Height: 400px
        - Hover: Unified mode (shows all series at x-value)
        - Template: plotly_dark
    
    Error Handling:
        - Empty DataFrame: Show info message "No detection rate data available..."
        - Missing data: Chart not rendered, message displayed
    
    Returns: None (renders Plotly chart or info message)
    
    Used By: main()
    """
    st.markdown("---")
    st.markdown("<h3 style='text-align: center;'>Detection Rate Trend (Last 30 Days)</h3>", unsafe_allow_html=True)
    
    df = get_detection_rate_over_time()
    
    if not df.empty:
        fig = px.line(
            df, 
            x='date', 
            y='detection_rate',
            title='Detection Rate Over Time',
            labels={'date': 'Date', 'detection_rate': 'Detection Rate (%)'},
            template='plotly_dark'
        )
        
        fig.update_traces(
            line_color='#65c1f9',
            line_width=3,
            mode='lines+markers'
        )
        
        fig.update_layout(
            plot_bgcolor='rgba(20, 29, 38, 0.8)',
            paper_bgcolor='rgba(20, 29, 38, 0.8)',
            font=dict(color='#E2E2D2'),
            hovermode='x unified',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No detection rate data available. Logs need to be populated.")


def render_auto_containment_chart():
    """
    Render auto-containment rate bar chart.
    
    Purpose: Compare auto-contained vs manual intervention incidents as bar chart.
    
    Chart Characteristics:
        - Type: Bar chart (Plotly Express)
        - X-axis: Type ['Auto-Contained', 'Manual Intervention']
        - Y-axis: Percentage (0-100%)
        - Data source: get_auto_containment_rate() + calculated manual rate
        - Colors: 
          * Auto-Contained: #65c1f9 (blue highlight)
          * Manual Intervention: #fd7e14 (orange warning)
    
    Data Calculation:
        - auto_rate: get_auto_containment_rate()
        - manual_rate: 100 - auto_rate
    
    Layout Configuration:
        - Background: Dark rgba(20, 29, 38, 0.8)
        - Font: #E2E2D2
        - Height: 400px
        - Legend: Hidden
        - Template: plotly_dark
    
    Returns: None (renders Plotly chart)
    
    Used By: main() (rendered in left column of two-column layout)
    """
    st.markdown("---")
    st.markdown("<h3 style='text-align: center;'>Auto-Containment Effectiveness</h3>", unsafe_allow_html=True)
    
    auto_rate = get_auto_containment_rate()
    manual_rate = 100 - auto_rate
    
    df = pd.DataFrame({
        'Type': ['Auto-Contained', 'Manual Intervention'],
        'Percentage': [auto_rate, manual_rate]
    })
    
    fig = px.bar(
        df,
        x='Type',
        y='Percentage',
        title='Incident Containment Method Distribution',
        labels={'Percentage': 'Percentage (%)'},
        color='Type',
        color_discrete_map={
            'Auto-Contained': '#65c1f9',
            'Manual Intervention': '#fd7e14'
        },
        template='plotly_dark'
    )
    
    fig.update_layout(
        plot_bgcolor='rgba(20, 29, 38, 0.8)',
        paper_bgcolor='rgba(20, 29, 38, 0.8)',
        font=dict(color='#E2E2D2'),
        showlegend=False,
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_severity_response_chart():
    """
    Render severity vs response time scatter plot.
    
    Purpose: Show correlation between incident severity and response time.
    
    Chart Characteristics:
        - Type: Scatter plot (Plotly Express)
        - X-axis: Severity level (categorical)
        - Y-axis: Response time in minutes
        - Data source: get_severity_response_time()
        - Marker size: 10px
        - Marker border: 1px white
        - Hover: Includes source field
    
    Severity Color Mapping:
        - critical: #dc3545 (red - danger)
        - high: #fd7e14 (orange - warning)
        - medium: #ffc107 (yellow - caution)
        - low: #17a2b8 (teal - info)
        - info: #6c757d (gray)
    
    Layout Configuration:
        - Background: Dark rgba(20, 29, 38, 0.8)
        - Font: #E2E2D2
        - Height: 400px
        - Template: plotly_dark
    
    Error Handling:
        - Empty DataFrame: Show info message "No response time data available..."
    
    Returns: None (renders Plotly chart or info message)
    
    Used By: main() (rendered in right column of two-column layout)
    """
    st.markdown("---")
    st.markdown("<h3 style='text-align: center;'>Severity vs Response Time Analysis</h3>", unsafe_allow_html=True)
    
    df = get_severity_response_time()
    
    if not df.empty:
        # Map severity to numeric values for better visualization
        severity_order = {'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
        df['severity_num'] = df['severity'].map(severity_order)
        
        fig = px.scatter(
            df,
            x='severity',
            y='response_minutes',
            title='Response Time by Severity Level',
            labels={'severity': 'Severity Level', 'response_minutes': 'Response Time (minutes)'},
            color='severity',
            color_discrete_map={
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#17a2b8',
                'info': '#6c757d'
            },
            template='plotly_dark',
            hover_data=['source']
        )
        
        fig.update_traces(marker=dict(size=10, line=dict(width=1, color='white')))
        
        fig.update_layout(
            plot_bgcolor='rgba(20, 29, 38, 0.8)',
            paper_bgcolor='rgba(20, 29, 38, 0.8)',
            font=dict(color='#E2E2D2'),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No response time data available. Logs need to be populated.")


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION LOGIC - PAGE ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Orchestrate page rendering with all components

def main():
    """
    Main application entry point.
    
    Purpose: Orchestrate rendering of all page components in correct order.
    
    Execution Flow:
        1. check_authentication() → Verify user session
        2. render_header() → Display navigation and title
        3. render_key_metrics() → Display 6 KPI cards
        4. Two-column layout:
           - Column 1: render_auto_containment_chart()
           - Column 2: render_severity_response_chart()
        5. Full-width: render_detection_rate_chart()
        6. Footer: Attribution text
    
    Page Layout:
        ┌─────────────────────────────────────────────────┐
        │ Header (Navigation + Title)                     │
        ├─────────────────────────────────────────────────┤
        │ Key Metrics (6 cards in grid)                   │
        ├─────────────────────────────────────────────────┤
        │ Chart 1 (50%)        │ Chart 2 (50%)            │
        │ Auto-Containment     │ Severity vs Response     │
        ├─────────────────────────────────────────────────┤
        │ Detection Rate Trend (100% width)               │
        ├─────────────────────────────────────────────────┤
        │ Footer                                          │
        └─────────────────────────────────────────────────┘
    
    Returns: None (orchestrates Streamlit rendering)
    
    Used By: Script entry point (if __name__ == "__main__")
    """
    
    # Check authentication
    check_authentication()
    
    # Render header
    render_header()
    
    # Render key metrics
    render_key_metrics()
    
    # Render charts
    col1, col2 = st.columns(2)
    
    with col1:
        render_auto_containment_chart()
    
    with col2:
        render_severity_response_chart()
    
    # Full width chart
    render_detection_rate_chart()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray; font-size: 12px;'>"
        "Performance Metrics - Real-time KPI Tracking"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()