"""
CYBER DEFENSE PLATFORM - SESSION MANAGEMENT
╚════════════════════════════════════════════════════════════════════════════╝

File: auth/session_manager.py
Purpose: Streamlit session state management and user authentication lifecycle

DESCRIPTION:
    Manages user session lifecycle including creation, validation, and
    expiration. Stores authenticated user information in Streamlit's
    session_state for persistence across page reloads. Implements automatic
    timeout with sliding window expiration to balance security and usability.

SESSION MANAGEMENT ARCHITECTURE:

    Storage:
        ├─ Streamlit session_state (server-side, in memory)
        ├─ Per-user per-browser session
        ├─ Persists across page reloads
        ├─ Cleared on browser close
        └─ User-specific isolation
    
    Lifecycle:
        ├─ Created: After successful authentication
        ├─ Validated: On every page load
        ├─ Expired: After inactivity timeout or logout
        └─ Cleared: On logout or session expire
    
    Timeout:
        ├─ Default: 30 minutes (SESSION_TIMEOUT_MINUTES)
        ├─ Type: Sliding window (resets on activity)
        ├─ Grace period: None (immediate expiration)
        └─ Enforcement: Checked on every request

SESSION STATE STRUCTURE:

    Valid Authenticated Session:
        st.session_state = {
            'authenticated': True,          # bool: Is user logged in
            'user_id': 1,                  # int: Unique user identifier
            'username': 'admin',           # str: Username
            'role': 'admin',               # str: 'admin'/'analyst'/'viewer'
            'login_time': datetime,        # datetime: When user logged in
            'session_token': str,          # str: Random token (64 hex chars)
            'session_expiry': datetime,    # datetime: When session expires
            ...(other app-specific keys)
        }
    
    Unauthenticated Session:
        st.session_state = {
            'authenticated': False,
            ...(other state, but auth fields None/False)
        }

SESSION LIFECYCLE:

    1. User Opens App:
       ├─ Streamlit creates blank session_state
       ├─ authenticated = False (default)
       └─ User redirected to login page
    
    2. User Submits Credentials:
       ├─ auth_manager.authenticate_user() verifies
       ├─ If valid: create_session() called
       ├─ If invalid: session remains unauthenticated
       └─ User stays on login page
    
    3. create_session() Execution:
       ├─ Generate random session token
       ├─ Store user data in session_state
       ├─ Set login_time = now
       ├─ Set session_expiry = now + 30 minutes
       └─ User redirected to dashboard
    
    4. User Navigates Pages:
       ├─ Every page calls validate_session()
       ├─ Checks if session still valid
       ├─ Checks if time < expiry
       ├─ Updates expiry (sliding window)
       └─ Allows page to render
    
    5. Session Expires (30 min inactivity):
       ├─ validate_session() detects expiry
       ├─ clear_session() automatically called
       ├─ authenticated = False
       ├─ User redirected to login
       └─ Must re-authenticate
    
    6. User Clicks Logout:
       ├─ logout_user() in auth_manager calls clear_session()
       ├─ All session data cleared
       ├─ User redirected to login page
       └─ Must re-authenticate

SECURITY FEATURES:

    Timeout Management:
        ├─ Idle timeout: 30 minutes (default)
        ├─ Sliding window: Resets on page navigation
        ├─ Immediate expiration: No grace period
        ├─ Auto-logout: Transparent to user
        └─ Prevention: Session hijacking via timeout

    Token Generation:
        ├─ Random hex token (64 chars)
        ├─ Generated per session (not per user)
        ├─ Not used for validation currently
        ├─ Future: Stateless JWT token support
        └─ Prevention: Session fixation attacks

    State Isolation:
        ├─ Per-browser session (not per tab)
        ├─ Users isolated from each other
        ├─ No cross-session data leakage
        ├─ Cleared on browser close
        └─ Prevention: Session hijacking

    Error Handling:
        ├─ Fail closed: Return False on any error
        ├─ Graceful degradation: Log and continue
        ├─ No info leakage: Generic error messages
        └─ No exceptions: All caught internally

TIMEOUT CONFIGURATION:

    SESSION_TIMEOUT_MINUTES = 30:
        ├─ Inactive timeout duration
        ├─ Unit: Minutes
        ├─ Adjustable per deployment
        ├─ Change in this file (session_manager.py)
        └─ Takes effect on next login
    
    Sliding Window Behavior:
        ├─ Action: User loads page
        ├─ Check: Is session_expiry < now?
        ├─ No: Extend expiry by 30 minutes
        ├─ Yes: Clear session, redirect to login
        ├─ Result: Activity resets timer
        └─ Example:
            • Login at 10:00
            • Page load at 10:15 → expiry = 10:45
            • Page load at 10:40 → expiry = 11:10
            • No activity until 11:15 → expired, logout

CONFIGURATION:

    Timeout Value:
        SESSION_TIMEOUT_MINUTES = 30
        ├─ File: auth/session_manager.py (line ~25)
        ├─ Unit: Minutes (integer)
        ├─ Range: Typically 5-480 (5min-8hr)
        ├─ Default: 30 minutes (recommended)
        └─ Change example:
            SESSION_TIMEOUT_MINUTES = 60  # 1 hour

    Secret Key (for future JWT):
        ├─ Location: config/security.yaml
        ├─ Field: SECRET_KEY
        ├─ Usage: Currently unused (future enhancement)
        ├─ Length: 32+ characters (random)
        └─ Generation: openssl rand -hex 32

STREAMLIT SESSION STATE:

    What Is It:
        ├─ Dictionary-like object (st.session_state)
        ├─ Server-side storage (in Python process)
        ├─ Per-browser session (not per user)
        ├─ Persists across page reloads
        ├─ Cleared on browser close or cache clear
        └─ Cleared on Streamlit app restart

    Characteristics:
        ├─ Fast: In-memory storage (< 1ms)
        ├─ Simple: Dictionary access (key-value)
        ├─ Persistent: Survives page reloads
        ├─ Isolated: One user cannot access another's
        ├─ Temporary: Lost on app restart
        └─ Not shared: Not distributed across servers

    Why session_state (not database):
        ├─ Speed: No network/database roundtrip
        ├─ Simplicity: No schema needed
        ├─ Isolation: No cross-session pollution
        ├─ Security: No tokens in URLs
        └─ Efficiency: Minimal overhead

FUNCTION USAGE:

    create_session(user_data):
        Called after successful authentication
        
        flow:
            1. User submits credentials
            2. authenticate_user() returns user dict
            3. create_session(user_dict) called
            4. Stores user data in session_state
            5. Returns True if success
        
        Example:
            user = authenticate_user(username, password)
            if user:
                create_session(user)
                st.switch_page("Dashboard_Overview")
    
    validate_session():
        Check session is valid before rendering page
        
        Flow:
            1. Page loads
            2. validate_session() called (top of page)
            3. Returns True if valid, False if expired
            4. If False: Redirect to login
        
        Example:
            if not validate_session():
                st.error("Please log in")
                st.switch_page("pages/login")
                st.stop()
            
            # Rest of page content
            st.title("Dashboard")
    
    clear_session():
        Called during logout
        
        Flow:
            1. User clicks logout button
            2. logout_user() in auth_manager calls this
            3. Clears all session data
            4. Returns True
        
        Example:
            if st.button("Logout"):
                logout_user()  # Calls clear_session()
                st.switch_page("pages/login")

ERROR HANDLING:

    Session Creation Errors:
        - User data missing required fields
        - Exception in secrets.token_hex()
        - Exception in datetime operations
        Effect: Returns False, logs error
        Caller: Should handle False, show error
    
    Session Check Errors:
        - session_expiry not timestamp
        - Exception in datetime comparison
        Effect: Returns False (fail closed)
        Caller: Redirects to login
    
    Session Clear Errors:
        - Exception clearing individual keys
        Effect: Returns False, logs error
        Caller: Force logout anyway
    
    No Exceptions Propagated:
        - All try-except blocks catch exceptions
        - Return True/False only
        - Safe to call without error handling
        - Graceful degradation

INTEGRATION POINTS:

    Called By:
        ├─ auth.auth_manager.authenticate_user()
        │   └─ Calls create_session() after password verify
        ├─ auth.auth_manager.validate_session()
        │   └─ Wrapper around check_session_timeout()
        ├─ auth.auth_manager.logout_user()
        │   └─ Calls clear_session() on logout
        └─ Every protected page
            └─ Calls validate_session() at top
    
    Depends On:
        ├─ Streamlit: st.session_state
        ├─ Python stdlib: datetime, secrets
        └─ No database or network calls

TESTING:

    Test Cases:
        1. Session creation:
           - create_session() with valid user data
           - Verify all keys in st.session_state
           - Verify expiry = now + 30 min
        
        2. Session validation:
           - validate_session() immediately after create
           - Should return True
        
        3. Session timeout:
           - Manually set session_expiry to past time
           - Call validate_session()
           - Should return False
           - Should clear session
        
        4. Sliding window:
           - Create session at time T
           - Validate at T+15 min
           - Expiry should be T+45 min (extended)
        
        5. Error handling:
           - Create session with None user_data
           - Should return False (not exception)
        
        6. Multiple sessions:
           - Two browser tabs (simulated)
           - Each has separate session_state
           - No cross-tab pollution

TROUBLESHOOTING:

    User Gets Logged Out Frequently:
        ✗ Problem: Session expires too quickly
        ✓ Solutions:
          1. Check SESSION_TIMEOUT_MINUTES value
          2. Increase timeout: SESSION_TIMEOUT_MINUTES = 60
          3. Check server time is accurate
          4. Check datetime operations not throwing errors
          5. Monitor server logs for error messages
    
    Session Persists After Logout:
        ✗ Problem: User still sees dashboard after logout
        ✓ Solutions:
          1. Verify clear_session() is being called
          2. Check logout button calls logout_user()
          3. Verify st.switch_page() is called after logout
          4. Check st.stop() prevents page render
          5. Clear browser cache/cookies
    
    Users Logged Out When Opening Another Tab:
        ✗ Problem: Second tab shows login page
        ✓ This is expected:
          - Each browser tab has separate Streamlit app instance
          - Each instance has separate session_state
          - Requires login in each tab separately
          - Not a bug, by design

FUTURE ENHANCEMENTS:

    JWT Token Support:
        - Currently: Session stored in memory only
        - Future: JWT token for stateless sessions
        - Benefit: Works across multiple servers
        - Implementation: Use SECRET_KEY from security.yaml
        - Requires: Database session table (optional)
    
    Persistent Sessions:
        - Currently: Sessions lost on app restart
        - Future: Store sessions in database
        - Benefit: Survive app restart
        - Requires: sessions table, expire job
        - Trade-off: Performance vs. durability
    
    Multi-Device Sessions:
        - Currently: Separate session per browser
        - Future: Track multiple devices per user
        - Benefit: User can see all active sessions
        - Requires: Session management UI
    
    Advanced Timeout Options:
        - Absolute timeout (max 8 hours regardless)
        - Configurable per-role timeouts
        - Remember-me checkbox (skip timeout)
        - Session history (audit trail)

DEPLOYMENT NOTES:

    Single Server:
        ├─ Current implementation works fine
        ├─ Session in memory (one process)
        ├─ No synchronization needed
        ├─ Sessions lost on restart (acceptable)
        └─ Recommended for small deployments

    Multiple Servers (Load Balanced):
        ├─ Sessions NOT shared between servers
        ├─ User may be redirected to different server
        ├─ User would see "not logged in" on new server
        ├─ Not recommended for multi-server setup
        └─ Solution: Use persistent session storage
            (database or Redis)

AUTHOR: Multilayered Cyber Defense Team
LAST MODIFIED: December 8, 2025
VERSION: 1.0.0

╚════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
from datetime import datetime, timedelta
import secrets


# ════════════════════════════════════════════════════════════════════════════
# SESSION CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════
SESSION_TIMEOUT_MINUTES = 30


# ════════════════════════════════════════════════════════════════════════════
# SESSION CREATION FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def create_session(user_data):
    """
    ════════════════════════════════════════════════════════════════════════
    FUNCTION: create_session() - Initialize User Session
    ════════════════════════════════════════════════════════════════════════
    
    DESCRIPTION:
        Creates authenticated session after successful login. Stores user
        information in Streamlit session_state for persistence across reloads.
        Generates random session token and sets 30-minute timeout.
    
    PARAMETERS:
        user_data (dict): User record from database
            - 'user_id' or 'id': Unique identifier
            - 'username': Username string
            - 'role': Role (admin/analyst/viewer)
    
    RETURN VALUE:
        True: Session created successfully
        False: Exception occurred during creation
    
    WORKFLOW:
        1. Generate random 64-character session token
        2. Store user_id, username, role in session_state
        3. Record login_time = now
        4. Set session_expiry = now + 30 minutes
        5. Return True if success, False if error
    
    USAGE:
        Called after authenticate_user() succeeds during login.
        On success, redirect to dashboard.
        On failure, show error message.
    
    ════════════════════════════════════════════════════════════════════════
    """
    try:
        # ════════════════════════════════════════════════════════════════════
        # STEP 1: GENERATE RANDOM SESSION TOKEN
        # ════════════════════════════════════════════════════════════════════
        session_token = secrets.token_hex(32)
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 2: STORE USER DATA IN SESSION STATE
        # ════════════════════════════════════════════════════════════════════
        st.session_state.authenticated = True
        st.session_state.user_id = user_data.get('user_id') or user_data.get('id')
        st.session_state.username = user_data.get('username')
        st.session_state.role = user_data.get('role', 'viewer')
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 3: RECORD LOGIN TIME AND SESSION TOKEN
        # ════════════════════════════════════════════════════════════════════
        st.session_state.login_time = datetime.now()
        st.session_state.session_token = session_token
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 4: SET EXPIRATION TIME (SLIDING WINDOW)
        # ════════════════════════════════════════════════════════════════════
        st.session_state.session_expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        return True
    except Exception as e:
        # ════════════════════════════════════════════════════════════════════
        # ERROR HANDLING: SESSION CREATION FAILED
        # ════════════════════════════════════════════════════════════════════
        print(f"Error creating session: {e}")
        return False


# ════════════════════════════════════════════════════════════════════════════
# SESSION CLEARING FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def clear_session():
    """
    ════════════════════════════════════════════════════════════════════════
    FUNCTION: clear_session() - Clear All Session Data
    ════════════════════════════════════════════════════════════════════════
    
    DESCRIPTION:
        Clears all authentication and session data from session_state.
        Called during logout or when session expires. Removes all user
        information, effectively logging out the user.
    
    PARAMETERS:
        None - Operates on current st.session_state
    
    RETURN VALUE:
        True: Session cleared successfully
        False: Exception occurred during clearing
    
    WORKFLOW:
        1. Set authenticated = False
        2. Set user_id, username, role to None
        3. Set login_time to None
        4. Set session_token to None
        5. Set session_expiry to None
        6. Return True if success
    
    USAGE:
        Called during logout button click or session timeout.
        After clearing, redirect user to login page.
    
    ════════════════════════════════════════════════════════════════════════
    """
    try:
        # ════════════════════════════════════════════════════════════════════
        # REMOVE AUTHENTICATION FLAG
        # ════════════════════════════════════════════════════════════════════
        st.session_state.authenticated = False
        
        # ════════════════════════════════════════════════════════════════════
        # REMOVE USER INFORMATION
        # ════════════════════════════════════════════════════════════════════
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.role = None
        
        # ════════════════════════════════════════════════════════════════════
        # REMOVE SESSION METADATA
        # ════════════════════════════════════════════════════════════════════
        st.session_state.login_time = None
        st.session_state.session_token = None
        st.session_state.session_expiry = None
        
        return True
    except Exception as e:
        # ════════════════════════════════════════════════════════════════════
        # ERROR HANDLING: SESSION CLEARING FAILED
        # ════════════════════════════════════════════════════════════════════
        print(f"Error clearing session: {e}")
        return False


# ════════════════════════════════════════════════════════════════════════════
# SESSION VALIDATION FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def check_session_timeout():
    """
    ════════════════════════════════════════════════════════════════════════
    FUNCTION: check_session_timeout() - Validate Session Not Expired
    ════════════════════════════════════════════════════════════════════════
    
    DESCRIPTION:
        Validates current session is still active and not expired. Checks
        authenticated flag and expiration time. Implements sliding window
        by extending expiration on successful validation.
    
    PARAMETERS:
        None - Reads from st.session_state
    
    RETURN VALUE:
        True: Session valid, not expired
        False: Session invalid, expired, or error occurred
    
    WORKFLOW:
        1. Check if authenticated flag is True
           If False, return False immediately
        
        2. Get session_expiry timestamp
           If missing, return False
        
        3. Compare current time to session_expiry
           If expired: clear_session() and return False
           If valid: extend expiry by 30 minutes and return True
    
    SLIDING WINDOW:
        - Session extends 30 minutes on each page load
        - User stays logged in while active
        - Logout after 30 minutes of inactivity
    
    USAGE:
        Called by validate_session() wrapper.
        Called on every protected page load.
        Extends session automatically.
    
    ════════════════════════════════════════════════════════════════════════
    """
    try:
        # ════════════════════════════════════════════════════════════════════
        # STEP 1: CHECK AUTHENTICATION FLAG
        # ════════════════════════════════════════════════════════════════════
        if not st.session_state.get('authenticated', False):
            return False
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 2: GET EXPIRATION TIME
        # ════════════════════════════════════════════════════════════════════
        session_expiry = st.session_state.get('session_expiry')
        if session_expiry is None:
            return False
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 3: CHECK IF SESSION HAS EXPIRED
        # ════════════════════════════════════════════════════════════════════
        if datetime.now() > session_expiry:
            # Session expired: Clear it and return False
            clear_session()
            return False
        
        # ════════════════════════════════════════════════════════════════════
        # STEP 4: EXTEND EXPIRATION (SLIDING WINDOW)
        # ════════════════════════════════════════════════════════════════════
        st.session_state.session_expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        return True
        
    except Exception as e:
        # ════════════════════════════════════════════════════════════════════
        # ERROR HANDLING: SESSION VALIDATION FAILED
        # ════════════════════════════════════════════════════════════════════
        print(f"Error checking session timeout: {e}")
        return False


def validate_session():
    """
    ════════════════════════════════════════════════════════════════════════
    FUNCTION: validate_session() - Clean API for Session Validation
    ════════════════════════════════════════════════════════════════════════
    
    DESCRIPTION:
        Wrapper around check_session_timeout() providing clean API for pages.
        Called at top of every protected page to verify user authentication.
        Returns True if session valid, False if expired or invalid.
    
    PARAMETERS:
        None - No parameters needed
    
    RETURN VALUE:
        True: Session valid, user authenticated
        False: Session invalid, user must login
    
    USAGE:
        At top of every protected page:
        
        if not validate_session():
            st.error("Please log in")
            st.switch_page("pages/login")
            st.stop()
        
        # Rest of page content
    
    WRAPPER PATTERN:
        - Delegates to check_session_timeout()
        - Provides consistent API across all auth functions
        - Keeps actual logic in specialized functions
        - Easier to maintain and test
    
    ════════════════════════════════════════════════════════════════════════
    """
    return check_session_timeout()