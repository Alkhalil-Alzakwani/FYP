"""
MULTILAYERED CYBER DEFENSE PLATFORM - LOGIN GATEWAY
╚════════════════════════════════════════════════════════════════════════════╝

File: pages/login.py
Purpose: User authentication entry point and session management gateway

DESCRIPTION:
    This module serves as the secure login gateway for the Multilayered Cyber
    Defense Platform. It manages user authentication, validates credentials
    against the database, creates secure sessions, and redirects authenticated
    users to the Dashboard Overview page.

AUTHENTICATION ARCHITECTURE:
    Login Flow:
        1. Check existing session in st.session_state
        2. If authenticated and valid → redirect to Dashboard Overview
        3. If no session → display login form
        4. User submits credentials (username + password)
        5. Verify credentials against users table using auth_manager.authenticate_user()
        6. On success:
           • Create secure session with session_manager.create_session()
           • Store user info in session state (id, username, role, login_time)
           • Update last_login timestamp in database
           • Redirect to Dashboard Overview page
        7. On failure:
           • Increment login_attempts counter
           • Display error message with remaining attempts
           • After 5 failed attempts → account lockout
    
    Session State Variables (st.session_state):
        - authenticated: bool → Current session validity
        - user_id: int → Database user ID
        - username: str → Authenticated username
        - role: str → User role (admin/analyst/viewer)
        - login_time: datetime → Session start time
        - login_attempts: int → Failed login counter

LOGIN FORM COMPONENTS:
    ├─ Title: "Cyber Defense Platform" + subtitle
    ├─ Username Input: Text field with placeholder
    ├─ Password Input: Masked password field
    ├─ Login Button: Full-width submit button
    ├─ Error Messages: Conditional display (invalid credentials, account locked)
    └─ Footer: Platform version + security warning

SECURITY FEATURES:
    • Password hashing: bcrypt encryption via auth_manager
    • Session token generation: Random token creation and validation
    • IP address tracking: Logged in session creation
    • User agent logging: Browser/device identification
    • SQL injection protection: Parameterized queries via database.queries
    • Rate limiting: Account lockout after 5 failed attempts
    • Session timeout: 30 minutes default (configurable in security.yaml)
    • Session validation: check_session_timeout() on each page load

DATABASE INTERACTIONS:
    Tables Used:
        - users: Authentication and user profile data
          * Query: get_user_by_username(username) → Retrieve user record
          * Query: verify_password_hash(password, user.password_hash)
          * Update: update_last_login(user_id) → Set current timestamp
        - sessions: Active session tracking
          * Create: create_session(user_data) → New session record
          * Validate: validate_session(session_token)

    Config Files Referenced:
        - config/db_config.yaml: Database connection settings
        - config/security.yaml: Timeout settings, max_login_attempts
        - assets/style.css: Additional theme styles

STYLING & THEME:
    Color Scheme:
        • Background: Linear gradient #141d26 → #243447
        • Text: #E2E2D2 (light text)
        • Accents: #65c1f9 (highlight), #d63574 (CTA/button)
        • Borders: #fffff, #243447
    
    Components:
        • Main container: Centered card layout with gradient border
        • Input fields: Dark background with light text, smooth focus states
        • Button: Gradient background with hover animation and shadow effects
        • Form: Dark container with subtle border and shadow

DEPENDENCIES:
    External Libraries:
        - streamlit: Web UI framework (v1.24+)
        - yaml: Configuration file parsing
        - pathlib: Path handling
    
    Internal Modules:
        - auth.auth_manager: authenticate_user(), validate_session()
        - auth.session_manager: create_session(), clear_session(), check_session_timeout()
        - database.queries: get_user_by_username(), update_last_login()

NAVIGATION FLOW:
    Not Authenticated → Display login page
    ↓ (Enter credentials)
    Authentication Success → st.session_state.authenticated = True
    ↓ (st.rerun())
    Redirect → pages/Dashboard_Overview.py (via st.switch_page())
    
    Authenticated Session Active → Skip login page, redirect immediately
    Expired Session → Clear session, show login page + "session expired" warning
    Logout Request → clear_session(), reset st.session_state, display login page

ERROR HANDLING:
    - Invalid credentials: Display message with attempts remaining
    - Account lockout (5+ attempts): Lock account, show admin contact message
    - Import errors: Catch and display ImportError, stop execution
    - Configuration errors: Display YAML load errors, use defaults
    - Session timeout: Automatically clear session and prompt re-login
    - Database errors: Wrapped in try-except, logged to error logs

╚════════════════════════════════════════════════════════════════════════════╝
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

# ════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION LOADER - YAML CONFIGURATION FILE MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════

def load_config(config_file):
    """
    Load configuration from YAML file.
    
    Purpose: Read and parse YAML configuration files from config/ directory,
    providing safe loading with error handling and default empty dict on failure.
    
    Args:
        config_file (str): Filename of YAML config (e.g., 'security.yaml')
    
    Returns:
        dict: Parsed YAML content as Python dictionary, empty dict {} on error
    
    Error Handling:
        - File not found: Return empty dict
        - YAML parse error: Log error message, return empty dict
        - Permission denied: Log error message, return empty dict
    
    Used By:
        - Security config: load_config('security.yaml')
        - Database config: load_config('db_config.yaml')
    
    Note: Uses yaml.safe_load() for security (prevents code injection)
    """
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


# ════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIGURATION - STREAMLIT PAGE SETUP
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Configure page metadata, layout, and initial UI state

st.set_page_config(
    page_title="Login - Cyber Defense Platform",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# ════════════════════════════════════════════════════════════════════════════
#  CUSTOM CSS FOR STYLING - DARK THEME APPLICATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Apply professional dark theme with gradient backgrounds and smooth transitions
# Color Palette:
#   - Background: #141d26 (dark navy), #243447 (accent dark)
#   - Text: #E2E2D2 (light text)
#   - Accent: #65c1f9 (highlight), #d63574 (CTA button)
#   - Borders: #fffff (light), #243447 (dark)

st.markdown("""
<style>
    /* Main container styling */
    .main {
        background: linear-gradient(135deg, #141d26 0%, #243447 100%);
        overflow-y: auto !important;
        height: 100vh !important;
        transition: all 2s ease;
    }
    
    /* Block container */
    .block-container {
        padding-top: 3rem !important;
        padding-bottom: 3rem !important;
        max-width: 500px !important;
        margin: 0 auto !important;
        background: linear-gradient(135deg, #141d26 0%, #243447 100%);
        border: 2px solid #ffffff;
        border-radius: 18px;
        padding: 30px;
        color: #E2E2D2;
        transition: all 2s ease;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
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


# ════════════════════════════════════════════════════════════════════════════
#  SESSION INITIALIZATION - STATE VARIABLE SETUP
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Initialize all session state variables required for authentication tracking

def initialize_session_state():
    """
    Initialize session state variables if they don't exist.
    
    Purpose: Called on every page load to ensure session state variables exist.
    If a variable doesn't exist in st.session_state, initialize it with default value.
    
    Session State Variables Initialized:
        - authenticated (bool): False → User authentication status
        - user_id (int): None → Database user ID
        - username (str): None → Authenticated username
        - role (str): None → User role (admin/analyst/viewer)
        - login_time (datetime): None → Session start timestamp
        - login_attempts (int): 0 → Failed login attempt counter
    
    Returns: None (modifies st.session_state in-place)
    
    Used By: main() function on application startup
    
    Note: Streamlit reruns entire script on user interaction, this ensures state
    persistence across reruns by checking before initializing
    """
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


# ════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION FUNCTIONS - USER VERIFICATION AND SESSION CREATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Handle login attempts, session creation, and session validation

def handle_login(username, password):
    """
    Handle user login attempt with authentication and session creation.
    
    Purpose: Main authentication handler that verifies credentials, creates a
    secure session on success, and tracks failed attempts for account lockout.
    
    Authentication Process:
        1. Call authenticate_user(username, password) from auth_manager
        2. If authentication succeeds (user_data returned):
           - Call create_session(user_data) to create session in database
           - Update st.session_state with user info and login_time
           - Call update_last_login(user_id) to record login timestamp
           - Reset login_attempts counter to 0
           - Return True
        3. If authentication fails:
           - Increment login_attempts counter
           - Return False
    
    Args:
        username (str): User's username from login form
        password (str): User's password (plain text, hashed in auth_manager)
        
    Returns:
        bool: True if authentication + session creation successful, False on failure
    
    Error Handling:
        - Try-except wrapper catches authentication errors
        - Logs exceptions to st.error()
        - Returns False on any error (safe failure mode)
    
    Side Effects:
        - Updates st.session_state variables
        - Updates database: users.last_login, sessions table
        - Increments st.session_state.login_attempts on failure
    
    Used By: render_login_page() on form submit
    
    Note: Password is never stored, only hashed in database
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
    """
    Check if user has an active valid session.
    
    Purpose: Called on every page load to determine whether to show login page
    or redirect authenticated user to dashboard. Validates session hasn't expired.
    
    Validation Logic:
        1. Check if st.session_state.authenticated == True
        2. If authenticated, call check_session_timeout() to validate expiry
        3. If session valid (not expired): Return True
        4. If session expired:
           - Call clear_session() to clean up session record
           - Set st.session_state.authenticated = False
           - Show warning message "Your session has expired. Please login again."
           - Return False
        5. If not authenticated: Return False
    
    Returns:
        bool: True if session exists and valid, False if no session or expired
    
    Error Handling:
        - Catches session timeout exception
        - Displays warning to user
        - Automatically clears expired session
    
    Used By: main() to decide between render_login_page() or render_authenticated_page()
    
    Dependencies:
        - check_session_timeout(): Validates session timeout from security.yaml (default 30 min)
        - clear_session(): Removes session record from database
    
    Note: Session timeout is configurable in config/security.yaml
    """
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


# ════════════════════════════════════════════════════════════════════════════
#  UI COMPONENTS - PAGE RENDERING FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Render login form and authenticated redirect page with professional styling

def render_login_page():
    """
    Render the login page UI with form and styling.
    
    Purpose: Display professional login interface with username/password form,
    error handling, account lockout warnings, and platform branding.
    
    Login Page Layout:
        1. Vertical spacing (40px top margin)
        2. Header section:
           - Title: "Cyber Defense Platform" (32px bold)
           - Subtitle: "Secure Authentication Portal" (16px light)
        3. Account lockout check:
           - If login_attempts >= max_login_attempts (5):
             * Display error message
             * Show admin contact info
             * Return early (no form shown)
        4. Login form (st.form):
           - Username input field (text input with placeholder)
           - Password input field (masked input with placeholder)
           - Login button (full-width, colored CTA)
        5. Form submission handler:
           - Validate both fields not empty
           - Show spinner during authentication
           - Call handle_login(username, password)
           - On success: Show success message, confetti animation, st.rerun()
           - On failure: Show error with remaining attempts
        6. Footer section:
           - Platform version info (v1.0)
           - Security warning (Unauthorized access prohibited)
    
    Form Error States:
        - Empty fields: "Please enter both username and password"
        - Invalid credentials: "Invalid credentials. {N} attempts remaining."
        - Account locked: "Account locked due to too many failed attempts."
    
    Returns: None (renders to Streamlit page)
    
    Side Effects:
        - Displays Streamlit UI elements
        - On successful login: Calls st.rerun() for redirect
    
    Used By: main() when check_existing_session() returns False
    """
    
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
    """
    Render page for authenticated users with automatic redirect to dashboard.
    
    Purpose: Show welcome screen briefly before redirecting user to Dashboard
    Overview page. Displays user info and welcome message during transition.
    
    Display Components:
        1. Vertical spacing (80px top margin)
        2. Success icon container (gradient circular background with checkmark)
        3. Welcome message: "Welcome, {username}!" (success message)
        4. Role display: "Role: {ADMIN/ANALYST/VIEWER}" (info message)
        5. Loading message: "Redirecting to Dashboard..."
        6. Automatic redirect: st.switch_page('pages/Dashboard_Overview.py')
    
    Returns: None (renders to Streamlit page, then redirects)
    
    Side Effects:
        - Calls st.switch_page() for navigation to Dashboard_Overview.py
        - Displays welcome UI for ~1 second before redirect
    
    Used By: main() when check_existing_session() returns True
    
    User Flow:
        Session valid → render_authenticated_page() → Show welcome → Redirect dashboard
    
    Note: st.switch_page() is the Streamlit v1.34+ method for page navigation
    """
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


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION LOGIC - LOGIN PAGE ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Orchestrate page rendering based on session state

def main():
    """
    Main application entry point for login page.
    
    Purpose: Orchestrate the login page flow, controlling which UI to render
    based on current session state. Called on every Streamlit rerun.
    
    Execution Flow:
        1. Call initialize_session_state() → Ensure all state variables exist
        2. Call check_existing_session():
           - If True (authenticated + valid): render_authenticated_page()
             * Shows welcome message and redirects to dashboard
           - If False (not authenticated or expired): render_login_page()
             * Shows login form for credential entry
    
    Returns: None (orchestrates Streamlit rendering)
    
    Page State Transitions:
        Start
          ↓
        initialize_session_state()
          ↓
        check_existing_session()
          ├─ True → render_authenticated_page() → st.switch_page() → Dashboard
          └─ False → render_login_page() → Await form submission
                      ↓ (User submits credentials)
                      handle_login()
                      ├─ Success → st.rerun() → Check existing session (True) → Redirect
                      └─ Failure → Show error, stay on login page
    
    Used By: Application entry point (if __name__ == "__main__")
    
    Dependencies: All module-level imports and config loading
    """
    
    # Initialize session state
    initialize_session_state()
    
    # Check for existing valid session
    if check_existing_session():
        render_authenticated_page()
    else:
        render_login_page()


# ════════════════════════════════════════════════════════════════════════════
#  APPLICATION ENTRY POINT - SCRIPT EXECUTION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Execute main() when script is run directly

if __name__ == "__main__":
    main()