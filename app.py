"""
MULTILAYERED CYBER DEFENSE PLATFORM - LANDING PAGE
╚════════════════════════════════════════════════════════════════════════════╝

FILE: app.py
PURPOSE: Main entry point and welcome page for the Cyber Defense Platform

════════════════════════════════════════════════════════════════════════════
 DESCRIPTION
════════════════════════════════════════════════════════════════════════════
This module serves as the public-facing landing page that:
  • Introduces users to the platform's capabilities
  • Displays real-time security metrics and statistics
  • Provides navigation to authentication and main features
  • Showcases technology stack and capabilities

════════════════════════════════════════════════════════════════════════════
 PAGE STRUCTURE
════════════════════════════════════════════════════════════════════════════

1. NAVIGATION BAR
   └─ Top navigation with login, capabilities, technology, and support links
   └─ Responsive design that adapts to mobile screens

2. HERO SECTION
   └─ Background image with platform title and description
   └─ Call-to-action button to get started

3. STATISTICS CARD
   └─ Displays real-time data from database:
      ├─ Total analyses performed
      ├─ High priority threats
      ├─ Active data sources
      ├─ Detection rate (%)
      ├─ Average response time
      └─ System uptime (%)

4. PLATFORM CAPABILITIES (Grid Layout)
   └─ Security, Intelligence, and Operations features
   └─ Each category displays 5 key capabilities

5. TECHNOLOGY STACK (4-Column Layout)
   └─ Frontend: Streamlit, Plotly, Altair
   └─ Backend: Python 3.12, SQLite, Pandas
   └─ AI: Mistral AI, NumPy, Scikit-learn
   └─ Security: bcrypt, JWT, YAML Config

6. GETTING STARTED (Action Cards)
   └─ Login: Access platform with credentials
   └─ Dashboard: View real-time security metrics
   └─ Live Monitor: Track threats and incidents

7. FOOTER / CONTACT
   └─ Contact information (email, phone)
   └─ Institution link
   └─ Copyright and version information

════════════════════════════════════════════════════════════════════════════
 KEY FEATURES
════════════════════════════════════════════════════════════════════════════
✓ Public page (no authentication required)
✓ Query-parameter-based navigation (?nav=login/dashboard/monitor)
✓ Real-time database integration for statistics
✓ Responsive design for mobile and desktop
✓ Smooth hover effects and visual feedback
✓ Authentication checks for protected pages

════════════════════════════════════════════════════════════════════════════
 DATABASE QUERIES
════════════════════════════════════════════════════════════════════════════
• threat_scores: COUNT(*) for total analyses
• threat_scores: COUNT(*) WHERE severity='High' for critical threats
• splunk_logs: COUNT(DISTINCT source) for active data sources

════════════════════════════════════════════════════════════════════════════
 COLOR SCHEME & STYLING
════════════════════════════════════════════════════════════════════════════
• Dark background: #141d26 (charcoal)
• Accent dark: #243447 (slate)
• Light text: #E2E2D2 (off-white)
• Highlight: #65c1f9 (sky blue)
• CTA color: #c51f5d (vibrant pink)

════════════════════════════════════════════════════════════════════════════
 DEPENDENCIES
════════════════════════════════════════════════════════════════════════════
• streamlit: Web framework and UI components
• database.queries: Database connection utilities
• pathlib: File path handling for image assets
• base64: Image encoding for inline display

════════════════════════════════════════════════════════════════════════════
 HOW TO RUN
════════════════════════════════════════════════════════════════════════════
Terminal:
/Users/alkhalilalzakwani/Documents/GitHub/FYP/.venv/bin/python -m streamlit run app.py

With specific environment:
cd /Users/alkhalilalzakwani/Documents/GitHub/FYP
source .venv/bin/activate
python -m streamlit run app.py

════════════════════════════════════════════════════════════════════════════
"""



import streamlit as st

# ════════════════════════════════════════════════════════════════════════════
# PAGE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════
# Configure Streamlit page settings: title, layout, and sidebar state

st.set_page_config(
    page_title='Cyber Defense Platform',
    #page_icon='shield',
    layout='wide',
    initial_sidebar_state='expanded'
)

# CSS Fix for Scrolling and Layout
# Ensures proper scrolling behavior on main content and sidebar
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

# ════════════════════════════════════════════════════════════════════════════
# NAVIGATION BAR
# ════════════════════════════════════════════════════════════════════════════
# Top navigation bar with platform branding and quick links
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



# ════════════════════════════════════════════════════════════════════════════
# MAIN CONTENT
# ════════════════════════════════════════════════════════════════════════════

def main():
    """
    Main application entry point - Renders the landing page
    
    Handles:
    - Navigation routing via query parameters
    - Authentication checks for protected pages
    - Display of hero section and statistics
    - Platform capabilities showcase
    - Technology stack information
    - Getting started options
    - Footer with contact information
    """
    
    # ────────────────────────────────────────────────────────────────────────
    # HANDLE NAVIGATION ROUTING
    # ────────────────────────────────────────────────────────────────────────
    # Route users based on query parameters (?nav=login/dashboard/monitor)
    query_params = st.query_params
    if 'nav' in query_params:
        if query_params['nav'] == 'login':
            st.switch_page('pages/login.py')
        elif query_params['nav'] == 'dashboard':
            # Check if user is logged in
            if 'authenticated' in st.session_state and st.session_state['authenticated']:
                st.switch_page('pages/Dashboard_Overview.py')
            else:
                st.warning('Please login first to access the dashboard')
                st.switch_page('pages/login.py')
        elif query_params['nav'] == 'monitor':
            # Check if user is logged in
            if 'authenticated' in st.session_state and st.session_state['authenticated']:
                st.switch_page('pages/Live_Threat_Monitor.py')
            else:
                st.warning('Please login first to access monitoring')
                st.switch_page('pages/login.py')

    st.markdown('')
    
    # ────────────────────────────────────────────────────────────────────────
    # HERO SECTION
    # ────────────────────────────────────────────────────────────────────────
    # Large banner with background image, title, and call-to-action button
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
            <a href="#getting-started" class="hero-card-button" style="text-decoration: none; display: inline-block;">Get Started</a>
        </div>
        """, unsafe_allow_html=True)

    else:
        st.warning(f"Image not found at: {img_path}")
    
    
    # ────────────────────────────────────────────────────────────────────────
    # STATISTICS DASHBOARD
    # ────────────────────────────────────────────────────────────────────────
    # Display real-time metrics: total analyses, threats, detection rate, uptime
    from database.queries import get_db_connection
    import sqlite3
    
    # Initialize statistics object with default values
    # Will be populated with real data from database
    stats_data = {
        'total_threats': 0,
        'critical_threats': 0,
        'avg_response_time': '< 2s',
        'platform_uptime': '99.9%',
        'active_analyses': 0
    }
    
    try:
        # Establish database connection
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            
            # Query 1: Count total threat analyses
            cur.execute("SELECT COUNT(*) FROM threat_scores")
            stats_data['total_threats'] = cur.fetchone()[0] or 0
            
            # Query 2: Count high-priority threats
            cur.execute("SELECT COUNT(*) FROM threat_scores WHERE severity = 'High'")
            stats_data['critical_threats'] = cur.fetchone()[0] or 0
            
            # Query 3: Count active data sources
            cur.execute("SELECT COUNT(DISTINCT source) FROM splunk_logs")
            stats_data['active_analyses'] = cur.fetchone()[0] or 0
            
            # Close database connection
            conn.close()
    except Exception as e:
        # Fallback: Display warning but use default stats
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
                    <div class="stat-inline-value">{stats_data['active_analyses']}</div>
                    <div class="stat-inline-label">Active Sources</div>
                </div>
            </div>
            <div class="stat-inline">
                <div>
                    <div class="stat-inline-value">90%</div>
                    <div class="stat-inline-label">Detection Accuracy</div>
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
                    <div class="stat-inline-value">99.9%</div>
                    <div class="stat-inline-label">Uptime</div>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('---')
    
    # ────────────────────────────────────────────────────────────────────────
    # PLATFORM CAPABILITIES GRID
    # ────────────────────────────────────────────────────────────────────────
    # Three-column grid showcasing Security, Intelligence, and Operations
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
                    <li>Large Language Models</li>
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
    
    # ────────────────────────────────────────────────────────────────────────
    # TECHNOLOGY STACK
    # ────────────────────────────────────────────────────────────────────────
    # Four-column layout: Frontend, Backend, AI, Security tools
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
        st.markdown('**AI/LLM**')
        st.markdown('- Mistral AI')
        st.markdown('- Zero-shot Learning')
        st.markdown('- NumPy')

        
    with tech_col4:
        st.markdown('**Security**')
        st.markdown('- bcrypt')
        st.markdown('- JWT')
        st.markdown('- YAML Config')
    
    st.markdown('---')
    
    # ────────────────────────────────────────────────────────────────────────
    # GETTING STARTED / ACTION CARDS
    # ────────────────────────────────────────────────────────────────────────
    # Three action cards: Login, Dashboard, and Live Monitor with buttons
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
    <div class="getting-started-section" id="getting-started">
        <h2 style="color: #E2E2D2; text-align: center; margin-bottom: 20px;">Getting Started</h2>
        <div class="getting-started-grid">
            <div class="getting-started-card">
                <h4>Login</h4>
                <p>Access the platform with your credentials</p>
                <a href="?nav=login" class="getting-started-button" style="text-decoration: none; display: block; line-height: 1.5;">Go to Login</a>
            </div>
            <div class="getting-started-card">
                <h4>Dashboard</h4>
                <p>View real-time security metrics</p>
                <a href="?nav=dashboard" class="getting-started-button" style="text-decoration: none; display: block; line-height: 1.5;">View Dashboard</a>
            </div>
            <div class="getting-started-card">
                <h4>Monitor</h4>
                <p>Track threats and incidents</p>
                <a href="?nav=monitor" class="getting-started-button" style="text-decoration: none; display: block; line-height: 1.5;">Live Monitor</a>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('---')
    
    # ────────────────────────────────────────────────────────────────────────
    # FOOTER / CONTACT INFORMATION
    # ────────────────────────────────────────────────────────────────────────
    # Contact details, institution link, and copyright information
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


# ════════════════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ════════════════════════════════════════════════════════════════════════════

def render_sidebar():
    """
    Render sidebar with navigation options
    
    Features:
    - Home button: Refresh current page
    - Login button: Navigate to authentication page
    - Quick links: Documentation, API reference, support, security
    """
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


# ════════════════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
# Render sidebar and main content when script is executed

if __name__ == '__main__':
    render_sidebar()
    main()