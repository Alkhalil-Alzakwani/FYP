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
        background: linear-gradient(135deg, #141d26 0%, #243447 100%);
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
        <a href="?nav=login" title="Login">Login</a>
        <a href="#platform-capabilities" title="Capabilities">Capabilities</a>
        <a href="#technology-stack" title="Technology">Technology</a>
        <a class="cta" href="#contact-information" title="Get Support">Get Support</a>
        <a href="#" onclick="window.close(); return false;" title="Shutdown">⏻ Shutdown</a>
    </div>
</div>
""", unsafe_allow_html=True)



# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main application entry point - Introductory landing page"""
    
    # Check for navigation from topbar
    query_params = st.query_params
    if 'nav' in query_params and query_params['nav'] == 'login':
        st.switch_page('pages/login.py')

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
    
    st.markdown(f"""
    <style>
        .capabilities-section {{
            margin: 20px 0;
            margin-top: 20px;

        }}
        .capabilities-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .capability-card {{
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border: 2px solid #fffff;
            border-radius: 12px;
            padding: 30px;
            color: #E2E2D2;
            transition: all 0.3s ease;
        }}
        .capability-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
        }}
        .capability-card h4 {{
            font-size: 20px;
            font-weight: 700;
            margin: 0 0 16px 0;
        }}
        .capability-card ul {{
            margin: 0;
            padding-left: 20px;
            list-style: none;
        }}
        .capability-card li {{
            font-size: 14px;
            margin-bottom: 8px;
            opacity: 0.9;
        }}
        .capability-card li:before {{
            content: "▸ ";
            font-weight: 700;
            margin-right: 8px;
        }}
    </style>
    <div class="capabilities-section" id="platform-capabilities">
        <h2 style="color: #E2E2D2; margin-bottom: 10px;text-align: center;">Platform Capabilities</h2>
        <div class="capabilities-grid">
            <div class="capability-card">
                <h4>Security</h4>
                <ul>
                    <li>Multi-factor authentication</li>
                    <li>Role-based access control</li>
                    <li>Session management</li>
                    <li>Audit logging</li>
                    <li>Encrypted communications</li>
                </ul>
            </div>
            <div class="capability-card">
                <h4>Intelligence</h4>
                <ul>
                    <li>Machine learning models</li>
                    <li>Behavioral analysis</li>
                    <li>Threat intelligence feeds</li>
                    <li>Predictive analytics</li>
                    <li>Pattern recognition</li>
                </ul>
            </div>
            <div class="capability-card">
                <h4>Operations</h4>
                <ul>
                    <li>Real-time dashboards</li>
                    <li>Automated responses</li>
                    <li>Alert management</li>
                    <li>Incident workflows</li>
                    <li>Integration APIs</li>
                </ul>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('---')
    
    # ========================================================================
    # TECHNOLOGY STACK
    # ========================================================================
    
    st.markdown("""
    <h2 id="technology-stack" style="color: #E2E2D2; text-align: center; margin-bottom: 20px;">Technology Stack</h2>
    """, unsafe_allow_html=True)
    
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
    
    st.markdown(f"""
    <style>
        .getting-started-section {{
            margin: 20px 0;
            margin-top: 20px;
        }}
        .getting-started-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .getting-started-card {{
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            border: 2px solid #fffff;
            border-radius: 12px;
            padding: 30px;
            color: #E2E2D2;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }}
        .getting-started-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
        }}
        .getting-started-card h4 {{
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 12px 0;
            color: #65c1f9;
        }}
        .getting-started-card p {{
            font-size: 14px;
            margin: 0 0 20px 0;
            opacity: 0.9;
            line-height: 1.5;
        }}
        .getting-started-button {{
            background: #243447;
            color: white;
            padding: 10px 24px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-weight: 700;
            font-size: 14px;
            transition: all 0.3s ease;
            width: 100%;
        }}
        .getting-started-button:hover {{
            background: #c51f5d;
            transform: translateY(-2px);
        }}
    </style>
    <div class="getting-started-section">
        <h2 style="color: #E2E2D2; text-align: center; margin-bottom: 20px;">Getting Started</h2>
        <div class="getting-started-grid">
            <div class="getting-started-card">
                <h4>Login</h4>
                <p>Access the platform with your credentials</p>
                <button class="getting-started-button" onclick="window.location.href='?page=pages/login'">Go to Login</button>
            </div>
            <div class="getting-started-card">
                <h4>Dashboard</h4>
                <p>View real-time security metrics</p>
                <button class="getting-started-button" onclick="alert('Please login first to access the dashboard')">View Dashboard</button>
            </div>
            <div class="getting-started-card">
                <h4>Monitor</h4>
                <p>Track threats and incidents</p>
                <button class="getting-started-button" onclick="alert('Please login first to access monitoring')">Live Monitor</button>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('---')
    
    # ========================================================================
    # FOOTER
    # ========================================================================
    
    st.markdown(f"""
    <style>
        .footer-section {{
            margin-top: 40px;
            margin-bottom: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}
        .footer-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
            width: 100%;
            max-width: 900px;
        }}
        .footer-card {{
            border: 2px solid #E2E2D2;
            border-radius: 12px;
            padding: 30px;
            color: #fffff;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }}
        .footer-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(101, 193, 249, 0.3);
        }}
        .footer-card h4 {{
            font-size: 16px;
            font-weight: 700;
            margin: 0 0 14px 0;
            color: #65c1f9;
        }}
        .footer-card p {{
            font-size: 14px;
            margin: 8px 0;
            opacity: 0.9;
            line-height: 1.6;
        }}
        .footer-card a {{
            color: #E2E2D2;
            text-decoration: none;
            font-weight: 600;
        }}
        .footer-card a:hover {{
            text-decoration: underline;
            color: #c51f5d;
        }}
        .footer-bottom {{
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid rgba(229, 192, 218, 0.2);
            opacity: 0.8;
            font-size: 12px;
            color: #E2E2D2;
            width: 100%;
        }}
    </style>
    <div class="footer-section" id="contact-information">
        <h2 style="color: #E2E2D2; text-align: center; margin-bottom: 30px;">Contact & Information</h2>
        <div class="footer-grid">
            <div class="footer-card">
                <h4>Email</h4>
                <p><a href="mailto:kh.zakwani1@gmail.com">kh.zakwani1@gmail.com</a></p>
            </div>
            <div class="footer-card">
                <h4>Phone</h4>
                <p>+968 71777979</p>
            </div>
            <div class="footer-card">
                <h4>Institution</h4>
                <p><a href="https://www.squ.edu.om" target="_blank">squ.edu.om</a></p>
            </div>
        </div>
        <div class="footer-bottom">
            <p>© 2025 Multilayered Cyber Defense Platform | Version 1.0</p>
            <p>Unauthorized access is prohibited and will be logged</p>
        </div>
    </div>
    """, unsafe_allow_html=True)


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


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    render_sidebar()
    main()
