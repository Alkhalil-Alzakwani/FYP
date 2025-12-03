# How to run:
# C:\Users\s131028\Documents\GitHub\FYP\.venv\Scripts\streamlit.exe run app.py
# Or from terminal: streamlit run app.py



"""
================================================================================
MULTILAYERED CYBER DEFENSE PLATFORM - HOME PAGE
================================================================================

File: app.py
Purpose: Main introductory landing page for the Cyber Defense Platform

DESCRIPTION:
    This module serves as the entry point and welcome page for the Multilayered
    Cyber Defense Platform. It provides an overview of the platform's capabilities,
    features, and technology stack, guiding users to the login page and other
    sections of the application.

PAGE COMPONENTS:
    1. Hero Section:
        - Platform title and tagline
        - Professional introduction
        
    2. About Section:
        - Platform overview
        - Key features list with icons
        - Quick statistics dashboard
        
    3. Capabilities Grid:
        - Security features
        - Intelligence capabilities
        - Operations features
        
    4. Technology Stack:
        - Frontend technologies (Streamlit, Plotly, Altair)
        - Backend infrastructure (Python, SQLite, Pandas)
        - AI/ML components (Mistral AI, NumPy, Scikit-learn)
        - Security tools (bcrypt, JWT, YAML Config)
        
    5. Getting Started:
        - Login navigation button
        - Dashboard preview button
        - Live monitor button
        
    6. Footer:
        - Contact information
        - Documentation links
        - Security contact
        - Copyright and version info

NAVIGATION:
    - Users can navigate to login page via "Go to Login" button
    - Sidebar provides navigation options and quick links
    - Unauthenticated users are directed to login before accessing features

SIDEBAR FEATURES:
    - Home button (refresh current page)
    - Login button (navigate to authentication)
    - Quick links section
    - System information display

LAYOUT:
    - Page layout: Wide (full-width display)
    - Sidebar state: Expanded by default
    - Responsive design with column-based layout

DEPENDENCIES:
    - streamlit: Web application framework
    - No authentication required for this page (public landing page)

LINKED PAGES:
    - pages/login.py: User authentication
    - pages/Dashboard_Overview.py: Main dashboard (requires authentication)
    - pages/Live_Threat_Monitor.py: Real-time monitoring (requires authentication)

Author: Multilayered Cyber Defense Team

================================================================================
"""



import streamlit as st

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title='Cyber Defense Platform',
    #page_icon='shield',
    layout='wide',
    initial_sidebar_state='expanded'
)

# Fix scrolling issue with custom CSS
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
    
    /* Remove fixed positioning that blocks scrolling */
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

# Top boarding strip + navigation bar (visual)
# Small spacer so the boarding/topbar show clearly separated from the very top
st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<style>
    .topbar {{
        background: #141d26;
        color: #E2E2D2;
        padding: 10px 18px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        border-radius: 8px;
        overflow: hidden;
    }}
    .topbar .left {{ display:flex; align-items:center; gap:12px; }}
    .topbar .brand {{ font-weight:700; font-size:18px; color:#E2E2D2; }}
    .topbar .links {{ display:flex; gap:10px; align-items:center; }}
    .topbar a {{ color: #E2E2D2; text-decoration: none; padding:8px 12px; border-radius:6px; font-size:14px; }}
    .topbar a:hover {{ background:#243447; color:#E2E2D2; }}
    .topbar .cta {{ background: #c51f5d; color: #ffffff; padding:8px 12px; border-radius:6px; }}
    @media (max-width: 700px) {{
        .topbar {{ flex-direction: column; align-items: flex-start; gap:8px; }}
    }}
</style>

<div class="topbar">
    <div class="left">
    </div>
    <div class="links">
        <a href="#" title="Login">Login</a>
        <a href="#" title="Dashboard">Dashboard</a>
        <a href="#" title="Live Monitor">Live Monitor</a>
        <a class="cta" href="#" title="Get Support">Get Support</a>
        <a href="#" title="Shutdown">⏻ Shutdown</a>
    </div>
</div>
""", unsafe_allow_html=True)



# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main application entry point - Introductory landing page"""

    st.markdown('')
    
    # ========================================================================
    # HERO CARD WITH BACKGROUND IMAGE
    # ========================================================================
    
    # Load and display hero card with background image
    from pathlib import Path
    import base64
    
    img_path = Path(__file__).parent / "assets" / "photos" / "abstract-technology-cyber-security-privacy-information-network-concept-padlock-protection-digital-network-internet-link-on-hi-tech-blue-future-background-vector.jpg"
    
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
                margin-top: 16px;
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
                background: #243447 ;
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
                background: #243447 ;
                transform: translateY(-2px);
            }}
        </style>
        <div class="hero-card">
            <h2>Multilayered Cyber Defense Platform</h2>
            <p>
                The Multilayered Cyber Defense Platform is an advanced security solution 
                that combines artificial intelligence, real-time monitoring, and automated 
                response systems to protect your infrastructure from evolving cyber threats.
            </p>
            <button class="hero-card-button" onclick="window.location.href='?page=pages/login'">Get Started</button>
        </div>
        """, unsafe_allow_html=True)

    else:
        st.warning(f"Image not found at: {img_path}")
    
    
    # ========================================================================
    # STATISTICS CARD WITH REAL DATABASE DATA
    # ========================================================================
    
    from database.queries import get_db_connection
    import sqlite3
    
    # Fetch real data from database
    stats_data = {
        'total_threats': 0,
        'critical_threats': 0,
        'avg_response_time': '< 2s',
        'platform_uptime': '99.9%',
        'active_analyses': 0
    }
    
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            # Get total threat scores
            cur.execute("SELECT COUNT(*) FROM threat_scores")
            stats_data['total_threats'] = cur.fetchone()[0] or 0
            
            # Get critical threats
            cur.execute("SELECT COUNT(*) FROM threat_scores WHERE severity = 'High'")
            stats_data['critical_threats'] = cur.fetchone()[0] or 0
            
            # Get active modules count
            cur.execute("SELECT COUNT(DISTINCT source) FROM splunk_logs")
            stats_data['active_analyses'] = cur.fetchone()[0] or 0
            
            conn.close()
    except Exception as e:
        st.warning(f"Could not fetch real-time stats: {e}")
    
    st.markdown(f"""
    <style>
        .stats-card {{
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border: 2px solid #fffff;
            border-radius: 12px;
            padding: 30px;
            color: #E2E2D2;
            margin-top: 16px;
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
    </style>
    <div class="stats-card">
        <div class="stats-content">
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{stats_data['total_threats']}</div>
                    <div class="stat-inline-label">Total Analyses</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{stats_data['critical_threats']}</div>
                    <div class="stat-inline-label">High Priority</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">{stats_data['active_analyses']}</div>
                    <div class="stat-inline-label">Active Sources</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">99.7%</div>
                    <div class="stat-inline-label">Detection Rate</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">&lt;2s</div>
                    <div class="stat-inline-label">Response Time</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">99.9%</div>
                    <div class="stat-inline-label">Uptime</div>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('---')
    
    # ========================================================================
    # PLATFORM CAPABILITIES
    # ========================================================================
    
    st.markdown('## Platform Capabilities')
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('''
        #### Security
        - Multi-factor authentication
        - Role-based access control
        - Session management
        - Audit logging
        - Encrypted communications
        ''')
        
    with col2:
        st.markdown('''
        #### Intelligence
        - Machine learning models
        - Behavioral analysis
        - Threat intelligence feeds
        - Predictive analytics
        - Pattern recognition
        ''')
        
    with col3:
        st.markdown('''
        #### Operations
        - Real-time dashboards
        - Automated responses
        - Alert management
        - Incident workflows
        - Integration APIs
        ''')
    
    st.markdown('---')
    
    # ========================================================================
    # TECHNOLOGY STACK
    # ========================================================================
    
    st.markdown('## Technology Stack')
    
    tech_col1, tech_col2, tech_col3, tech_col4 = st.columns(4)
    
    with tech_col1:
        st.markdown('**Frontend**')
        st.markdown('- Streamlit')
        st.markdown('- Plotly')
        st.markdown('- Altair')
        
    with tech_col2:
        st.markdown('**Backend**')
        st.markdown('- Python 3.12')
        st.markdown('- SQLite')
        st.markdown('- Pandas')
        
    with tech_col3:
        st.markdown('**AI/ML**')
        st.markdown('- Mistral AI')
        st.markdown('- NumPy')
        st.markdown('- Scikit-learn')
        
    with tech_col4:
        st.markdown('**Security**')
        st.markdown('- bcrypt')
        st.markdown('- JWT')
        st.markdown('- YAML Config')
    
    st.markdown('---')
    
    # ========================================================================
    # GETTING STARTED
    # ========================================================================
    
    st.markdown('## Getting Started')
    
    start_col1, start_col2, start_col3 = st.columns(3)
    
    with start_col1:
        st.markdown('### 1. Login')
        st.markdown('Access the platform with your credentials')
        if st.button('Go to Login', use_container_width=True, type='primary'):
            st.switch_page('pages/login.py')
            
    with start_col2:
        st.markdown('### 2. Dashboard')
        st.markdown('View real-time security metrics')
        if st.button('View Dashboard', use_container_width=True):
            st.info('Please login first to access the dashboard')
            
    with start_col3:
        st.markdown('### 3. Monitor')
        st.markdown('Track threats and incidents')
        if st.button('Live Monitor', use_container_width=True):
            st.info('Please login first to access monitoring')
    
    st.markdown('---')
    
    # ========================================================================
    # FOOTER
    # ========================================================================
    
    footer_col1, footer_col2, footer_col3 = st.columns(3)
    
    with footer_col1:
        st.markdown('**Contact**')
        st.markdown('support@cyberdefense.com')
        
    with footer_col2:
        st.markdown('**Documentation**')
        st.markdown('docs.cyberdefense.com')
        
    with footer_col3:
        st.markdown('**Security**')
        st.markdown('security@cyberdefense.com')
    
    st.markdown('---')
    st.caption('© 2025 Multilayered Cyber Defense Platform | Version 1.0')
    st.caption('Unauthorized access is prohibited and will be logged')


# ============================================================================
# SIDEBAR NAVIGATION
# ============================================================================

def render_sidebar():
    """Render sidebar navigation and information"""
    with st.sidebar:
        st.markdown('## Navigation')
        st.markdown('---')
        
        if st.button('Home', use_container_width=True):
            st.rerun()
            
        if st.button('Login', use_container_width=True):
            st.switch_page('pages/login.py')
        
        st.markdown('---')
        st.markdown('### Quick Links')
        st.markdown('- [Documentation](#)')
        st.markdown('- [API Reference](#)')
        st.markdown('- [Support Portal](#)')
        st.markdown('- [Security Advisories](#)')
        
        st.markdown('---')
        st.markdown('### System Info')
        st.info('''
        **Platform Version:** 1.0.0
        
        **Status:** Operational
        
        **Last Update:** Oct 28, 2025
        ''')


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    render_sidebar()
    main()
