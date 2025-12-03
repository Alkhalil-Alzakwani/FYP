"""
================================================================================
MULTILAYERED CYBER DEFENSE PLATFORM - MAIN AUTHENTICATION ENTRY POINT
================================================================================

File: app.py
Purpose: Main Streamlit application entry point with user authentication

DESCRIPTION:
    This module serves as the login gateway for the Multilayered Cyber Defense
    Platform Dashboard. It handles user authentication, session management,
    and redirects authenticated users to the main dashboard.

AUTHENTICATION WORKFLOW:
    1. Check for active session in st.session_state
    2. If no session exists → display login page
    3. User submits credentials (username + password)
    4. Verify credentials against database using auth_manager
    5. On success:
        - Create secure session with session_manager
        - Store user info (id, username, role, login_time) in session state
        - Redirect to Dashboard Overview page
    6. On failure:
        - Display error message
        - Allow retry
    
LOGIN FORM COMPONENTS:
    - Username input field (text)
    - Password input field (masked)
    - Login button (submit)
    - Error message display (conditional)

SESSION MANAGEMENT:
    - Session timeout: 30 minutes (configurable in security.yaml)
    - Session state variables:
        * authenticated: bool
        * user_id: int
        * username: str
        * role: str (admin/analyst/viewer)
        * login_time: datetime
    - Auto-logout on session expiry
    
DATABASE INTEGRATION:
    - Connects to SQL database via config/db_config.yaml
    - Queries 'users' table for authentication
    - Updates 'last_login' timestamp on successful login
    - Creates session record in 'sessions' table

SECURITY FEATURES:
    - Password hashing with bcrypt
    - Session token generation
    - IP address tracking
    - User agent loggin
    - Protection against SQL injection
    - Rate limiting for brute force prevention

DEPENDENCIES:
    - streamlit: UI framework
    - auth.auth_manager: Core authentication logic
    - auth.session_manager: Session state handler
    - database.queries: Database interaction
    - config/security.yaml: Security configurations
    - config/db_config.yaml: Database connection settings

NAVIGATION:
    - Authenticated users → pages/Dashboard_Overview.py
    - Logout → Clear session and return to login

Author: Multilayered Cyber Defense Team
Last Modified: October 28, 2025
================================================================================
"""

import streamlit as st
import yaml
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import authentication modules
try:
    from auth.auth_manager import authenticate_user, validate_session
    from auth.session_manager import create_session, clear_session, check_session_timeout
    from database.queries import get_user_by_username, update_last_login
except ImportError as e:
    st.error(f"Import Error: {e}")
    st.stop()


# ============================================================================
# CONFIGURATION LOADER
# ============================================================================

def load_config(config_file):
    """Load configuration from YAML file"""
    try:
        config_path = project_root / "config" / config_file
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config if config is not None else {}
        else:
            return {}
    except Exception as e:
        st.error(f"Error loading {config_file}: {e}")
        return {}


# Load configurations
security_config = load_config("security.yaml")
db_config = load_config("db_config.yaml")


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Login - Cyber Defense Platform",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# ============================================================================
# CUSTOM CSS FOR STYLING
# ============================================================================

st.markdown("""
<style>
    /* Main container styling */
    .main {
        background: linear-gradient(135deg, #141d26 0%, #243447 100%);
        overflow-y: auto !important;
        height: 100vh !important;
    }
    
    /* Block container */
    .block-container {
        padding-top: 3rem !important;
        padding-bottom: 3rem !important;
        max-width: 500px !important;
        margin: 0 auto !important;
    }
    
    /* Hide sidebar */
    section[data-testid="stSidebar"] {
        display: none;
    }
    
    /* Streamlit elements styling */
    .stTextInput > div > div > input {
        background-color: #243447;
        color: #E2E2D2;
        border: 1px solid #fffff;
        border-radius: 8px;
        padding: 12px;
        font-size: 16px;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #fffff;
        box-shadow: 0 0 0 1px #E2E2D2;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #E2E2D2 0%, #d63574 100%);
        color: #E2E2D2;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-size: 16px;
        font-weight: 600;
        width: 100%;
        transition: all 0.3s ease;
        box-shadow: 0 4px 8px rgba(197, 31, 93, 0.3);
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #d63574 0%, #e74489 100%);
        box-shadow: 0 6px 12px rgba(197, 31, 93, 0.5);
        transform: translateY(-2px);
    }
    
    /* Form styling */
    .stForm {
        background-color: #141d26;
        border: 1px solid #243447;
        border-radius: 12px;
        padding: 2rem;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    
    /* Text styling */
    h1, h2, h3, h4, h5, h6, p, label {
        color: #E2E2D2 !important;
    }
    
    /* Input labels */
    .stTextInput > label {
        color: #E2E2D2 !important;
        font-weight: 500;
        font-size: 14px;
        margin-bottom: 8px;
    }
    
    /* Success/Error messages */
    .stSuccess, .stError, .stWarning, .stInfo {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Load custom CSS if available
css_path = project_root / "assets" / "style.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# ============================================================================
# SESSION INITIALIZATION
# ============================================================================

def initialize_session_state():
    """Initialize session state variables if they don't exist"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'role' not in st.session_state:
        st.session_state.role = None
    if 'login_time' not in st.session_state:
        st.session_state.login_time = None
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def handle_login(username, password):
    """
    Handle user login attempt
    
    Args:
        username (str): User's username
        password (str): User's password
        
    Returns:
        bool: True if authentication successful, False otherwise
    """
    try:
        # Authenticate user
        user_data = authenticate_user(username, password)
        
        if user_data:
            # Create session
            session_created = create_session(user_data)
            
            if session_created:
                # Update session state
                st.session_state.authenticated = True
                st.session_state.user_id = user_data['id']
                st.session_state.username = user_data['username']
                st.session_state.role = user_data['role']
                st.session_state.login_time = datetime.now()
                st.session_state.login_attempts = 0
                
                # Update last login in database
                update_last_login(user_data['id'])
                
                return True
        
        # Failed authentication
        st.session_state.login_attempts += 1
        return False
        
    except Exception as e:
        st.error(f"Authentication error: {e}")
        return False


def check_existing_session():
    """Check if user has an active valid session"""
    if st.session_state.authenticated:
        # Validate session hasn't expired
        if check_session_timeout():
            return True
        else:
            # Session expired
            clear_session()
            st.session_state.authenticated = False
            st.warning("Your session has expired. Please login again.")
            return False
    return False


# ============================================================================
# UI COMPONENTS
# ============================================================================

def render_login_page():
    """Render the login page UI"""
    
    # Add spacing
    st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)
    
    # Header with logo/icon
    st.markdown("""
        <div style='text-align: center; margin-bottom: 2rem;'>
            <h1 style='color: #E2E2D2; font-size: 32px; margin-bottom: 0.5rem; font-weight: 700;'>
                Cyber Defense Platform
            </h1>
            <p style='color: #E2E2D2; font-size: 16px; opacity: 0.8;'>
                Secure Authentication Portal
            </p>
        </div>
    """, unsafe_allow_html=True)
    
    # Check for account lockout (after 5 failed attempts)
    max_attempts = security_config.get('max_login_attempts', 5)
    if st.session_state.login_attempts >= max_attempts:
        st.error("Account temporarily locked due to multiple failed login attempts.")
        st.info("Please contact your system administrator.")
        return
    
    # Login form
    with st.form("login_form", clear_on_submit=False):
        st.markdown("<div style='margin-bottom: 1.5rem;'></div>", unsafe_allow_html=True)
        
        username = st.text_input(
            "Username",
            placeholder="Enter your username",
            key="login_username"
        )
        
        password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter your password",
            key="login_password"
        )
        
        st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
        
        submit_button = st.form_submit_button("Login", use_container_width=True)
        
        if submit_button:
            if not username or not password:
                st.error("Please enter both username and password")
            else:
                with st.spinner("Authenticating..."):
                    if handle_login(username, password):
                        st.success(f"Welcome back, {username}!")
                        st.balloons()
                        # Rerun to redirect to dashboard
                        st.rerun()
                    else:
                        remaining = max_attempts - st.session_state.login_attempts
                        if remaining > 0:
                            st.error(f"Invalid credentials. {remaining} attempts remaining.")
                        else:
                            st.error("Account locked due to too many failed attempts.")
    
    # Footer information
    st.markdown("<div style='height: 40px;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style='text-align: center; padding: 2rem 0;'>
            <div style='border-top: 1px solid #243447; padding-top: 1.5rem; margin-top: 1rem;'>
                <p style='color: #E2E2D2; font-size: 14px; margin-bottom: 0.5rem; opacity: 0.8;'>
                    <strong>Multilayered Cyber Defense Platform</strong> v1.0
                </p>
                <p style='color: #E2E2D2; font-size: 12px; margin-bottom: 0;'>
                    Unauthorized access is prohibited and will be logged
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_authenticated_page():
    """Render page for authenticated users with redirect"""
    st.markdown("<div style='height: 80px;'></div>", unsafe_allow_html=True)
    
    st.markdown("""
        <div style='text-align: center; padding: 2rem;'>
            <div style='background: linear-gradient(135deg, #E2E2D2 0%, #d63574 100%); 
                        width: 100px; height: 100px; border-radius: 50%; 
                        margin: 0 auto 1.5rem auto; display: flex; 
                        align-items: center; justify-content: center;
                        box-shadow: 0 8px 16px rgba(197, 31, 93, 0.4);'>
                <span style='font-size: 50px;'></span>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    st.success(f"Welcome, **{st.session_state.username}**!")
    st.info(f"Role: **{st.session_state.role.upper()}**")
    
    st.markdown("<div style='text-align: center; margin-top: 2rem;'>", unsafe_allow_html=True)
    st.markdown("###Redirecting to Dashboard...")
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Automatic redirect to Dashboard Overview
    st.switch_page("pages/Dashboard_Overview.py")


# ============================================================================
# MAIN APPLICATION LOGIC
# ============================================================================

def main():
    """Main application entry point"""
    
    # Initialize session state
    initialize_session_state()
    
    # Check for existing valid session
    if check_existing_session():
        render_authenticated_page()
    else:
        render_login_page()


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()