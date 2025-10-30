r"""
================================================================================
MULTILAYERED CYBER DEFENSE PLATFORM - HOME PAGE
================================================================================

How to run:
    C:\Users\s131028\Documents\GitHub\FYP\.venv\Scripts\streamlit.exe run app.py

    Or from terminal:
    streamlit run app.py

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
Last Modified: October 28, 2025
Version: 1.0.0
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


# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main application entry point - Introductory landing page"""
    
    # ========================================================================
    # HERO SECTION
    # ========================================================================
    
    # Header with login button
    header_col1, header_col2 = st.columns([4, 1])
    
    with header_col1:
        st.markdown('# Multilayered Cyber Defense Platform')
        st.markdown('### AI-Powered Threat Detection and Response System')
    
    with header_col2:
        st.markdown('')  # Add spacing
        if st.button('Login', use_container_width=True, type='primary'):
            st.switch_page('pages/login.py')
    
    st.markdown('---')
    
    # ========================================================================
    # INTRODUCTION & QUICK STATS
    # ========================================================================
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown('''
        ## About the Platform
        
        The **Multilayered Cyber Defense Platform** is an advanced security solution that combines 
        artificial intelligence, real-time monitoring, and automated response systems to protect 
        your infrastructure from evolving cyber threats.
        
        ### Key Features
        
        - **AI-Powered Log Analysis**: Leverage Mistral AI to analyze security logs and detect anomalies
        - **Real-Time Threat Monitoring**: Live visualization of security events and threats
        - **Automated Response System**: Intelligent threat mitigation and incident response
        - **Performance Metrics**: Comprehensive analytics and reporting dashboard
        - **Forensics & Investigation**: Detailed analysis tools for security incidents
        - **Threat Scoring**: Advanced algorithms to prioritize and classify threats
        - **User Management**: Role-based access control and user administration
        ''')
        
    with col2:
        st.markdown('### Quick Stats')
        
        metric_col1, metric_col2 = st.columns(2)
        with metric_col1:
            st.metric('Threat Detection', '99.7%', '2.1%')
            st.metric('Response Time', '< 2s', '-0.3s')
        with metric_col2:
            st.metric('Uptime', '99.9%', '0.1%')
            st.metric('Active Modules', '7', '+1')
    
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
