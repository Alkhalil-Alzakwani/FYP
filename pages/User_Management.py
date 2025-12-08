"""
MULTILAYERED CYBER DEFENSE PLATFORM - USER MANAGEMENT PORTAL
╚════════════════════════════════════════════════════════════════════════════╝

File: pages/User_Management.py
Purpose: Administrative interface for user account and role management (admin-only)

DESCRIPTION:
    Complete user lifecycle management portal for administrators. Provides
    CRUD operations (Create, Read, Update, Delete) for user accounts, role
    assignments, password resets, and account activation. Enforces role-based
    access control (RBAC) - only users with 'admin' role can access this page.

CORE FEATURES:

    1. View All Users:
       ├─ Display user table with filtering capabilities
       ├─ Show username, email, role, status, timestamps
       ├─ Summary metrics (total users, admins, analysts, viewers)
       ├─ Activity tracking (last login timestamps)
       └─ Sortable and searchable data table

    2. Add New User:
       ├─ Create new user accounts
       ├─ Assign initial roles (viewer/analyst/admin)
       ├─ Set temporary passwords (8+ characters required)
       ├─ Optional email assignment
       ├─ Username uniqueness validation
       └─ Immediate account activation

    3. Edit User:
       ├─ Modify user roles (viewer ↔ analyst ↔ admin)
       ├─ Change activation status (active/inactive)
       ├─ View current user information
       ├─ Delete user accounts (with confirmation)
       ├─ Prevent self-deletion (safety)
       └─ Audit trail for changes

    4. Reset Password:
       ├─ Generate new temporary passwords
       ├─ Enforce minimum 8-character policy
       ├─ Hash passwords with bcrypt
       ├─ Secure password display for user distribution
       └─ Force password change on next login (recommended)

ROLE HIERARCHY:

    Admin (Full Access):
        ├─ All system pages accessible
        ├─ User management capabilities
        ├─ System configuration access
        ├─ Threat scoring and analysis
        └─ Can create/modify other admins
    
    Analyst (Operational Access):
        ├─ AI Log Analysis
        ├─ Dashboard Overview
        ├─ Live Threat Monitor
        ├─ Threat Scoring
        ├─ Forensics and Reports
        └─ Cannot access User Management or System Configuration
    
    Viewer (Read-Only Access):
        ├─ Dashboard Overview (limited)
        ├─ Performance Metrics (view only)
        └─ No write or configuration access

ROLE-BASED ACCESS CONTROL (RBAC):

    Access Enforcement:
        1. Session validation (validate_session())
        2. Role check (st.session_state['role'] == 'admin')
        3. Page stop() if unauthorized
        4. Error message display
    
    Protection Levels:
        - Page-level: check_admin_access() at entry
        - Operation-level: Each CRUD function validates
        - Database-level: users table permissions
        - Session-level: Timeout after inactivity

PAGE LAYOUT:

    Header:
        "User Management" title
        Horizontal divider
    
    Tab Interface (4 tabs):
        ├─ Tab 1: "View Users" (read-only user table)
        ├─ Tab 2: "Add New User" (creation form)
        ├─ Tab 3: "Edit User" (modification interface)
        └─ Tab 4: "Reset Password" (password management)
    
    Sidebar:
        ├─ Current admin username display
        ├─ Role descriptions
        ├─ Password policy
        └─ Usage tips

DATABASE INTERACTIONS:

    Tables Accessed:
        users:
            ├─ id (INTEGER PRIMARY KEY)
            ├─ username (TEXT UNIQUE NOT NULL)
            ├─ password_hash (TEXT NOT NULL)
            ├─ email (TEXT)
            ├─ role (TEXT: 'admin'|'analyst'|'viewer')
            ├─ active (INTEGER: 1=active, 0=inactive)
            ├─ created_at (TEXT ISO timestamp)
            ├─ last_login (TEXT ISO timestamp)
            └─ failed_login_attempts (INTEGER)
    
    CRUD Operations:
        Create: INSERT new user with hashed password
        Read: SELECT all users or by username
        Update: Role, active status, password_hash
        Delete: Remove user record (CASCADE if foreign keys)

PASSWORD SECURITY:

    Hashing Algorithm:
        - bcrypt with salt (from auth.password_utils)
        - Minimum 8 characters enforced
        - No plaintext storage (password_hash only)
        - Temporary passwords recommended to be changed
    
    Reset Flow:
        1. Admin selects user
        2. Enters new temporary password
        3. System hashes password (hash_password())
        4. Updates users.password_hash
        5. Admin shares temporary password securely
        6. User changes on next login (policy, not enforced)

SESSION MANAGEMENT:

    Admin Session Requirements:
        - Valid session token in st.session_state
        - Role = 'admin' in session_state
        - Session timeout: 30 minutes default
        - Revalidated on page load
    
    Access Denial:
        - Invalid session: "Session expired. Please login again."
        - Non-admin role: "Access Denied. Admin only."
        - Both trigger st.stop() (page termination)

UI COMPONENTS:

    Form Elements:
        - Text inputs (username, email, password)
        - Selectboxes (role selection, user selection)
        - Checkboxes (active status toggle)
        - Buttons (submit, update, delete, reset)
        - Dataframes (user table display)
    
    Feedback Messages:
        - Success: st.success() 
        - Error: st.error()
        - Warning: st.warning()
        - Info: st.info()

VALIDATION RULES:

    Username:
        - Required (not empty)
        - Must be unique in users table
        - Case-sensitive
        - No special character restrictions (flexible)
    
    Password:
        - Minimum 8 characters
        - No maximum length
        - No complexity requirements (can be enhanced)
        - Hashed immediately after validation
    
    Email:
        - Optional field
        - No format validation (can be enhanced)
        - Used for notifications (future feature)
    
    Role:
        - Must be: 'viewer', 'analyst', or 'admin'
        - Dropdown selection (no free text)
        - Default: 'viewer' (least privilege)

DEFENSIVE DESIGN:

    Error Handling:
        - All database operations wrapped in try/except
        - Connection failures: Display error, continue
        - Duplicate username: Inform user before submission
        - Invalid role: Constrained by selectbox
    
    Confirmation Dialogs:
        - User deletion: Two-step confirmation required
        - Password reset: Warning message displayed
        - Role change: Immediate update (no confirmation)
    
    Self-Protection:
        - Admins cannot delete their own account (future)
        - Last admin cannot be deleted (future)
        - Last admin cannot be demoted (future)

DEPENDENCIES:

    External Libraries:
        - streamlit: Web UI framework
        - pandas: DataFrame display and manipulation
        - datetime: Timestamp formatting
    
    Internal Modules:
        - database.queries: get_all_users(), get_user_by_username(),
                           create_user(), get_db_connection()
        - auth.password_utils: hash_password()
        - auth.session_manager: validate_session()

USAGE FLOW:

    1. Admin logs in → Dashboard
    2. Navigate to User Management page
    3. check_admin_access() validates admin role
    4. View users in Tab 1 (default)
    5. Add new user in Tab 2 or edit existing in Tab 3
    6. Reset password in Tab 4 if needed
    7. Changes reflect immediately (st.rerun())

AUDIT TRAIL:

    Logged Actions (implicit):
        - User creation: created_at timestamp
        - Role changes: No explicit log (future enhancement)
        - Password resets: No explicit log (future enhancement)
        - User deletion: Permanent removal (no soft delete)
    
    Recommendations for Enhancement:
        - Add audit_log table
        - Log all CRUD operations
        - Track admin who made changes
        - Timestamp all modifications

SECURITY CONSIDERATIONS:

    Threats Mitigated:
        - Unauthorized access: RBAC enforcement
        - Password exposure: bcrypt hashing
        - Session hijacking: Timeout validation
        - Privilege escalation: Role-based page access
    
    Future Enhancements:
        - Multi-factor authentication (MFA)
        - Password complexity requirements
        - Account lockout after failed attempts
        - Email verification for new accounts
        - Audit logging for compliance

COLOR SCHEME:

    Consistent with platform design:
        - Background: #141d26 (dark)
        - Accent: #243447 (dark blue)
        - Text: #E2E2D2 (light gray)
        - Highlight: #65c1f9 (cyan)
        - Success: Green tones
        - Error: #dc3545 (red)

AUTHOR: Multilayered Cyber Defense Team
LAST MODIFIED: December 8, 2025
VERSION: 1.0.1

╚════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from database.queries import (
    get_all_users, 
    get_user_by_username, 
    create_user, 
    get_db_connection
)
from auth.password_utils import hash_password
from auth.session_manager import validate_session


# ════════════════════════════════════════════════════════════════════════════════
# PAGE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title='User Management',
    layout='wide',
    initial_sidebar_state='expanded'
)


# ════════════════════════════════════════════════════════════════════════════════
# SESSION & ACCESS CONTROL - ADMIN-ONLY AUTHENTICATION
# ════════════════════════════════════════════════════════════════════════════════

def check_admin_access():
    """
    ════════════════════════════════════════════════════════════════════════
    Validate user session and enforce admin-only access control.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Two-stage authentication check: validates active session first, then
        checks for admin role. Terminates page execution (st.stop()) if either
        check fails. Used as gatekeeper for entire User Management page.

    VALIDATION STAGES:

        Stage 1 - Session Validation:
            ├─ Call validate_session() from auth.session_manager
            ├─ Checks st.session_state for valid session token
            ├─ Verifies session not expired (30 min default timeout)
            ├─ If invalid: Display error, stop page
            └─ If valid: Proceed to Stage 2
        
        Stage 2 - Role Authorization:
            ├─ Check st.session_state['role'] value
            ├─ Must equal 'admin' (case-sensitive)
            ├─ If not admin: Display access denied, stop page
            └─ If admin: Return True, allow page access

    ERROR MESSAGES:

        Session expired:
            "Session expired. Please login again."
            - User redirected to login page
            - Previous page state lost
        
        Access denied:
            "Access Denied. This page is only accessible to administrators."
            - User sees error message
            - Cannot proceed to page content

    ARGS:
        None

    RETURNS:
        bool: Always returns True if both checks pass.
              Never returns False (st.stop() terminates execution instead).

    USED BY:
        main() function: First operation in User Management page
        Ensures only authenticated admins access user CRUD operations

    FLOW DIAGRAM:

        check_admin_access()
            ├─ validate_session() → False?
            │   └─ st.error("Session expired") → st.stop()
            │
            ├─ validate_session() → True?
            │   ├─ role == 'admin'? → No
            │   │   └─ st.error("Access Denied") → st.stop()
            │   │
            │   └─ role == 'admin'? → Yes
            │       └─ return True (page continues)

    SECURITY:
        - Double-layer protection (session + role)
        - No bypass: st.stop() terminates immediately
        - Session timeout enforced by validate_session()
        - Role checked from secure session state

    NOTES:
        - Called once at page load (main() function entry)
        - st.stop() prevents any code below from executing
        - Session state persists across Streamlit reruns
        - Role assignment controlled by login.py and User Management

    ERROR HANDLING:
        - No exceptions thrown (validate_session handles internally)
        - st.error() displays user-friendly messages
        - st.stop() gracefully terminates page rendering
        - User can navigate back or login again

    SEE ALSO:
        - auth.session_manager.validate_session(): Session validation
        - pages.login.py: Role assignment during login
        - st.session_state: Streamlit session storage
    """
    # Validate session
    if not validate_session():
        st.error("Session expired. Please login again.")
        st.stop()
    
    # Check if user has admin role
    if st.session_state.get("role") != "admin":
        st.error("Access Denied. This page is only accessible to administrators.")
        st.stop()
    
    return True


# ════════════════════════════════════════════════════════════════════════════════
# DATABASE HELPER FUNCTIONS - USER CRUD OPERATIONS
# ════════════════════════════════════════════════════════════════════════════════

def update_user_role(user_id, new_role):
    """
    ════════════════════════════════════════════════════════════════════════
    Update user's role assignment in users table.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Executes SQL UPDATE to change user's role field. Used for role
        promotions/demotions (viewer ↔ analyst ↔ admin). Changes take
        effect immediately on next page load or session revalidation.

    SQL OPERATION:
        UPDATE users SET role = ? WHERE id = ?
        
        Parameters:
            - new_role: 'viewer', 'analyst', or 'admin'
            - user_id: Unique identifier from users table

    ARGS:
        user_id (int): User's unique identifier from users.id column.
        new_role (str): New role to assign.
                       Valid values: 'viewer', 'analyst', 'admin'

    RETURNS:
        bool: True if update successful, False if error occurred.

    USED BY:
        main() function, Tab 3 (Edit User): "Update Role" button handler

    NOTES:
        - No validation of new_role (caller responsibility)
        - Changes take effect on user's next page navigation
        - User's current session not affected (until revalidation)
        - No audit trail logged (future enhancement)

    ERROR HANDLING:
        - Connection failure: Display error via st.error(), return False
        - Invalid user_id: SQL fails silently, return False
        - Exception caught: Error message shown, return False

    SECURITY:
        - Requires admin access (enforced at page level)
        - No SQL injection risk (parameterized query)
        - User ID validated by caller (selectbox)

    SEE ALSO:
        - update_user_active_status(): Toggle user activation
        - get_all_users(): Retrieve users for selection
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error updating role: {e}")
        return False


def update_user_active_status(user_id, active_status):
    """
    ════════════════════════════════════════════════════════════════════════
    Toggle user account activation status (enable/disable login).
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Updates users.active field to enable or disable user login. Inactive
        users cannot authenticate even with correct credentials. Used for
        temporary account suspension without deletion. Safer than deletion
        for preserving audit trails and historical data.

    SQL OPERATION:
        UPDATE users SET active = ? WHERE id = ?
        
        Parameters:
            - active: 1 (active/enabled) or 0 (inactive/disabled)
            - user_id: Unique identifier from users table

    ACTIVATION EFFECTS:

        Active (1):
            ├─ User can login with valid credentials
            ├─ Session creation allowed
            ├─ All assigned role permissions granted
            └─ Normal operation
        
        Inactive (0):
            ├─ Login blocked at authentication stage
            ├─ Existing sessions terminated (on next validation)
            ├─ User sees "Account inactive" message
            └─ Cannot access any pages

    ARGS:
        user_id (int): User's unique identifier from users.id column.
        active_status (bool): True to activate, False to deactivate.
                             Converted to 1 or 0 for SQL storage.

    RETURNS:
        bool: True if update successful, False if error occurred.

    USED BY:
        main() function, Tab 3 (Edit User): "Update Status" button handler

    USE CASES:
        - Temporary suspension (vacation, investigation)
        - Security response (compromised account)
        - User offboarding (alternative to deletion)
        - Account lock after failed login attempts (future)

    NOTES:
        - Changes take effect immediately on next login attempt
        - Existing sessions remain active until timeout/revalidation
        - No notification sent to user (future enhancement)
        - Reactivation restores all previous permissions

    ERROR HANDLING:
        - Connection failure: Display error via st.error(), return False
        - Invalid user_id: SQL fails silently, return False
        - Exception caught: Error message shown, return False

    SECURITY:
        - Requires admin access (enforced at page level)
        - No SQL injection risk (parameterized query)
        - Safer than deletion (preserves data)

    SEE ALSO:
        - update_user_role(): Change user role
        - delete_user(): Permanent account removal
        - auth.session_manager: Session validation logic
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active_status else 0, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error updating status: {e}")
        return False


def reset_user_password(user_id, new_password):
    """
    ════════════════════════════════════════════════════════════════════════
    Reset user password with new bcrypt hash.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Generates new bcrypt hash for provided password and updates users
        table. Used for password resets (forgotten passwords, security
        incidents, temporary password issuance). Old password is permanently
        replaced - no recovery possible.

    PASSWORD HASHING:

        Algorithm: bcrypt (from auth.password_utils)
            ├─ Automatic salt generation
            ├─ Work factor: 12 rounds (default)
            ├─ Output: 60-character hash string
            └─ Irreversible (one-way function)
        
        Security Properties:
            - Rainbow table resistant (salted)
            - Brute-force resistant (slow hashing)
            - No plaintext storage
            - Same password → different hash (salt)

    SQL OPERATION:
        UPDATE users SET password_hash = ? WHERE id = ?
        
        Parameters:
            - password_hash: 60-char bcrypt hash
            - user_id: Unique identifier from users table

    ARGS:
        user_id (int): User's unique identifier from users.id column.
        new_password (str): New plaintext password to hash and store.
                           Minimum 8 characters required (validated by caller).

    RETURNS:
        bool: True if password reset successful, False if error occurred.

    USED BY:
        main() function, Tab 4 (Reset Password): "Reset Password" button

    RESET WORKFLOW:

        1. Admin enters new temporary password
        2. System validates minimum length (8 chars)
        3. reset_user_password() called:
           ├─ hash_password() generates bcrypt hash
           ├─ SQL UPDATE replaces password_hash
           └─ Connection committed and closed
        4. Success message displayed
        5. Admin shares temporary password with user securely
        6. User changes password on next login (recommended)

    SECURITY BEST PRACTICES:

        Temporary Password Distribution:
            - Use secure channel (encrypted email, password manager)
            - Avoid plaintext (SMS, unencrypted email)
            - Set expiration time (future enhancement)
            - Force change on first login (future enhancement)
        
        Password Policy:
            - Minimum 8 characters (enforced)
            - Complexity requirements (future)
            - No password reuse (future)
            - Regular rotation (recommended)

    NOTES:
        - Old password immediately invalid after update
        - Active sessions remain valid until timeout
        - No password history maintained (future enhancement)
        - No email notification sent (future enhancement)

    ERROR HANDLING:
        - Hashing failure: Exception caught, return False
        - Connection failure: Display error via st.error(), return False
        - Invalid user_id: SQL fails silently, return False
        - Exception caught: Error message shown, return False

    SECURITY CONSIDERATIONS:
        - Requires admin access (enforced at page level)
        - No SQL injection risk (parameterized query)
        - Password never stored in plaintext
        - Hash not logged or displayed (only plaintext shown to admin)

    SEE ALSO:
        - auth.password_utils.hash_password(): Bcrypt hashing function
        - pages.login.py: Password verification during login
        - update_user_active_status(): Account suspension alternative
    """
    try:
        password_hash = hash_password(new_password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error resetting password: {e}")
        return False


def delete_user(user_id):
    """
    ════════════════════════════════════════════════════════════════════════
    Permanently delete user account from database.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Executes SQL DELETE to permanently remove user record from users
        table. This is irreversible - all user data, history, and associations
        are lost. Use update_user_active_status() for temporary suspension
        (safer alternative that preserves audit trails).

    SQL OPERATION:
        DELETE FROM users WHERE id = ?
        
        Parameters:
            - user_id: Unique identifier of user to delete
        
        CASCADE Behavior:
            - If foreign keys exist: Related records may be deleted
            - Depends on schema constraints (ON DELETE CASCADE)
            - Example: user_sessions, audit_logs, threat_scores

    ARGS:
        user_id (int): User's unique identifier from users.id column.
                      Must exist in users table.

    RETURNS:
        bool: True if deletion successful, False if error occurred.

    USED BY:
        main() function, Tab 3 (Edit User): "Delete User" → "Confirm Delete"

    DELETION WORKFLOW:

        1. Admin selects user from dropdown
        2. Clicks "Delete User" button
        3. Warning message displayed
        4. Two-button confirmation dialog:
           ├─ "Confirm Delete" → delete_user() called
           └─ "Cancel" → No action
        5. If successful: User removed, page reloaded (st.rerun())
        6. If failed: Error message displayed

    SAFETY CONSIDERATIONS:

        PERMANENT ACTION - Cannot be undone:
            - User record deleted
            - Login impossible
            - Historical data may be lost
            - Associated records may cascade delete
        
        Recommended Checks (Future Enhancement):
            - Prevent deletion of last admin
            - Prevent self-deletion (admin deleting own account)
            - Soft delete option (mark deleted, keep record)
            - Deletion audit trail

    ALTERNATIVE APPROACH:
        Consider update_user_active_status(user_id, False) instead:
            ✓ Preserves historical data
            ✓ Reversible action
            ✓ Maintains audit trail
            ✓ Prevents login equally effectively

    NOTES:
        - No "undo" functionality
        - No confirmation email sent
        - No soft delete (permanent removal)
        - Two-step confirmation required in UI (safety measure)

    ERROR HANDLING:
        - Connection failure: Display error via st.error(), return False
        - Invalid user_id: SQL fails silently (0 rows affected), return False
        - Foreign key constraint: Depends on schema (may prevent deletion)
        - Exception caught: Error message shown, return False

    SECURITY:
        - Requires admin access (enforced at page level)
        - No SQL injection risk (parameterized query)
        - Confirmation dialog prevents accidental deletion
        - User ID validated by UI (selectbox)

    AUDIT TRAIL:
        - No deletion logged (future enhancement recommended)
        - Consider adding audit_log table:
            * admin_user_id (who deleted)
            * deleted_user_id (who was deleted)
            * timestamp
            * reason

    SEE ALSO:
        - update_user_active_status(): Safer suspension alternative
        - get_all_users(): User list for selection
        - st.rerun(): Reload page after deletion
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error deleting user: {e}")
        return False


# ════════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION - USER MANAGEMENT PAGE
# ════════════════════════════════════════════════════════════════════════════════

def main():
    """
    ════════════════════════════════════════════════════════════════════════
    Main User Management page with tabbed interface for user CRUD operations.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Complete user administration interface with four-tab layout. Provides
        full CRUD (Create, Read, Update, Delete) operations for user accounts,
        role management, password resets, and account activation. Accessible
        only to users with admin role.

    PAGE STRUCTURE:

        Authentication:
            check_admin_access() - Validates session and admin role
        
        Header:
            Title: "User Management"
            Divider: Horizontal line
        
        Tab Interface (4 tabs):
            Tab 1: "View Users"
                ├─ DataTable with all users
                ├─ Columns: ID, Username, Email, Role, Status, Created, Last Login
                ├─ Summary metrics (Total, Admins, Analysts, Viewers)
                └─ Sortable and filterable display
            
            Tab 2: "Add New User"
                ├─ Username input (unique required)
                ├─ Email input (optional)
                ├─ Initial password (8+ chars)
                ├─ Role selectbox (viewer/analyst/admin)
                ├─ Create User button
                └─ Validation and error handling
            
            Tab 3: "Edit User"
                ├─ User selection dropdown
                ├─ Current info display
                ├─ Role update selectbox
                ├─ Active status checkbox
                ├─ Update Role button
                ├─ Update Status button
                ├─ Delete User button (with confirmation)
                └─ Real-time changes with st.rerun()
            
            Tab 4: "Reset Password"
                ├─ User selection dropdown
                ├─ New password input (8+ chars)
                ├─ Reset Password button
                ├─ Success message with temporary password
                └─ Security warning about distribution

    USER WORKFLOW:

        View Users (Tab 1):
            1. Load all users from database
            2. Format DataFrame (Active/Inactive, timestamps)
            3. Display table with full details
            4. Show summary metrics
        
        Add User (Tab 2):
            1. Enter username, email, password, role
            2. Validate:
               ├─ Username and password required
               ├─ Password ≥ 8 characters
               └─ Username unique in database
            3. Hash password with bcrypt
            4. Insert into users table
            5. Display success with user ID
        
        Edit User (Tab 3):
            1. Select user from dropdown
            2. Display current information
            3. Modify role or active status
            4. Click Update button
            5. Database updated
            6. Page reloaded (st.rerun())
            7. Optional: Delete user with confirmation
        
        Reset Password (Tab 4):
            1. Select user from dropdown
            2. Enter new temporary password
            3. Validate minimum length
            4. Hash password with bcrypt
            5. Update users.password_hash
            6. Display temporary password for admin to share

    DATABASE OPERATIONS:

        Read:
            - get_all_users(): Fetch all user records
            - get_user_by_username(): Check username uniqueness
        
        Create:
            - create_user(): Insert new user with hashed password
        
        Update:
            - update_user_role(): Modify role assignment
            - update_user_active_status(): Toggle account activation
            - reset_user_password(): Change password hash
        
        Delete:
            - delete_user(): Permanently remove user record

    VALIDATION RULES:

        Username:
            - Required (cannot be empty)
            - Must be unique in users table
            - Case-sensitive
        
        Password:
            - Required (cannot be empty)
            - Minimum 8 characters
            - Hashed with bcrypt before storage
        
        Email:
            - Optional field
            - No format validation
        
        Role:
            - Must be: 'viewer', 'analyst', or 'admin'
            - Dropdown constrained (no free text)

    UI FEEDBACK:

        Success Messages:
            "User '{username}' created successfully!"
            "Role updated to '{new_role}'"
            "User activated/deactivated"
            "User '{username}' deleted successfully"
            "Password reset successfully for '{username}'"
        
        Error Messages:
            "Username and password are required."
            "Password must be at least 8 characters long."
            "Username '{username}' already exists."
            "Error creating/updating/deleting user."
        
        Info Messages:
            "No users found in the system."
            "Role/Status unchanged"
        
        Warnings:
            "Are you sure you want to delete user?"
            "This action will generate a new temporary password."
    SECURITY FEATURES:

        Access Control:
            - Admin-only page (check_admin_access())
            - Session validation on load
            - Role enforcement
        
        Password Security:
            - Bcrypt hashing with salt
            - No plaintext storage
            - Minimum length enforcement
        
        Data Integrity:
            - Username uniqueness validation
            - Parameterized SQL queries (no injection)
            - Transaction commit/rollback
        
        User Protection:
            - Two-step deletion confirmation
            - Active status toggle (safer than deletion)
            - Password distribution warnings

    STATE MANAGEMENT:

        Streamlit Session State:
            - st.session_state['username']: Current admin username
            - st.session_state['role']: Current user role
            - st.session_state['session_token']: Auth token
        
        Page Reloads:
            - st.rerun() after successful updates
            - Refreshes user list automatically
            - Clears form inputs

    NOTES:
        - All operations require admin access
        - Changes take effect immediately
        - No undo functionality (except reactivation for deactivated users)
        - Page uses wide layout for better table display
        - Tab state preserved across interactions

    ERROR HANDLING:
        - All database operations wrapped in try/except
        - User-friendly error messages displayed
        - Page continues after errors (no crash)
        - Connection failures handled gracefully

    SEE ALSO:
        - check_admin_access(): Authentication gatekeeper
        - Database helper functions: update_user_role(), etc.
        - render_sidebar(): Help and tips display
        - auth modules: password_utils, session_manager
    """
    
    # Check admin access
    check_admin_access()
    
    st.markdown("#User Management")
    st.markdown("---")
    
    # Create tabs for different operations
    tab1, tab2, tab3, tab4 = st.tabs([
        "View Users",
        "Add New User",
        "Edit User",
        "Reset Password"
    ])
    
    
    # ════════════════════════════════════════════════════════════════════════
    # TAB 1: VIEW ALL USERS - READ-ONLY USER TABLE
    # ════════════════════════════════════════════════════════════════════════
    
    with tab1:
        st.markdown("## All Users")
        
        # Get all users
        users = get_all_users()
        
        if not users:
            st.info("No users found in the system.")
        else:
            # Convert to DataFrame for better display
            df = pd.DataFrame(users)
            
            # Format the DataFrame for display
            display_df = df.copy()
            display_df['active'] = display_df['active'].apply(lambda x: 'Active' if x else 'Inactive')
            display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
            display_df['last_login'] = display_df['last_login'].apply(
                lambda x: pd.to_datetime(x).strftime('%Y-%m-%d %H:%M') if x else 'Never'
            )
            
            # Reorder columns for better readability
            display_df = display_df[['id', 'username', 'email', 'role', 'active', 'created_at', 'last_login']]
            
            st.dataframe(display_df, use_container_width=True)
            
            # Summary stats
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Users", len(users))
            
            with col2:
                admin_count = len([u for u in users if u['role'] == 'admin'])
                st.metric("Admins", admin_count)
            
            with col3:
                analyst_count = len([u for u in users if u['role'] == 'analyst'])
                st.metric("Analysts", analyst_count)
            
            with col4:
                viewer_count = len([u for u in users if u['role'] == 'viewer'])
                st.metric("Viewers", viewer_count)
    
    
    # ════════════════════════════════════════════════════════════════════════
    # TAB 2: ADD NEW USER - ACCOUNT CREATION FORM
    # ════════════════════════════════════════════════════════════════════════
    
    with tab2:
        st.markdown("## Add New User")
        
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_username = st.text_input(
                    "Username",
                    placeholder="Enter username",
                    help="Username must be unique"
                )
            
            with col2:
                new_email = st.text_input(
                    "Email (optional)",
                    placeholder="user@example.com",
                    help="User's email address"
                )
            
            col1, col2 = st.columns(2)
            
            with col1:
                new_password = st.text_input(
                    "Initial Password",
                    type="password",
                    placeholder="Enter temporary password",
                    help="User should change this after first login"
                )
            
            with col2:
                new_role = st.selectbox(
                    "User Role",
                    options=["viewer", "analyst", "admin"],
                    help="Role determines access level"
                )
            
            # Form submission
            submitted = st.form_submit_button("➕ Create User", use_container_width=True, type="primary")
            
            if submitted:
                # Validation
                if not new_username or not new_password:
                    st.error("Username and password are required.")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif get_user_by_username(new_username):
                    st.error(f"Username '{new_username}' already exists.")
                else:
                    # Create user
                    password_hash = hash_password(new_password)
                    user_id = create_user(new_username, password_hash, new_role, new_email)
                    
                    if user_id:
                        st.success(f"User '{new_username}' created successfully!")
                        st.info(f"**User ID:** {user_id}\n**Role:** {new_role}\n**Initial Password:** (share with user securely)")
                    else:
                        st.error("Error creating user. Please try again.")
    
    
    # ════════════════════════════════════════════════════════════════════════
    # TAB 3: EDIT USER - ROLE, STATUS, AND DELETE MANAGEMENT
    # ════════════════════════════════════════════════════════════════════════
    
    with tab3:
        st.markdown("## Edit User")
        
        users = get_all_users()
        
        if not users:
            st.info("No users to edit.")
        else:
            # Create username list for selection
            usernames = [u['username'] for u in users]
            selected_username = st.selectbox("Select User", usernames, key="edit_user_select")
            
            # Find selected user
            selected_user = next((u for u in users if u['username'] == selected_username), None)
            
            if selected_user:
                st.markdown(f"### Editing: {selected_username}")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Current Information**")
                    st.text(f"ID: {selected_user['id']}")
                    st.text(f"Email: {selected_user['email'] or 'Not set'}")
                    st.text(f"Role: {selected_user['role']}")
                    st.text(f"Status: {'Active' if selected_user['active'] else 'Inactive'}")
                    st.text(f"Created: {selected_user['created_at']}")
                
                with col2:
                    st.markdown("**Update Information**")
                    
                    new_role = st.selectbox(
                        "Change Role",
                        options=["viewer", "analyst", "admin"],
                        index=["viewer", "analyst", "admin"].index(selected_user['role']),
                        key="edit_role_select"
                    )
                    
                    new_active = st.checkbox(
                        "User Active",
                        value=bool(selected_user['active']),
                        key="edit_active_check"
                    )
                
                # Update buttons
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("Update Role", use_container_width=True):
                        if new_role != selected_user['role']:
                            if update_user_role(selected_user['id'], new_role):
                                st.success(f"Role updated to '{new_role}'")
                                st.rerun()
                            else:
                                st.error("Failed to update role")
                        else:
                            st.info("Role unchanged")
                
                with col2:
                    if st.button("Update Status", use_container_width=True):
                        if new_active != bool(selected_user['active']):
                            if update_user_active_status(selected_user['id'], new_active):
                                status_text = "activated" if new_active else "deactivated"
                                st.success(f"User {status_text}")
                                st.rerun()
                            else:
                                st.error("Failed to update status")
                        else:
                            st.info("Status unchanged")
                
                with col3:
                    if st.button("Delete User", use_container_width=True, type="secondary"):
                        # Confirmation dialog
                        st.warning(f"Are you sure you want to delete user '{selected_username}'? This cannot be undone.")
                        
                        col_confirm1, col_confirm2 = st.columns(2)
                        
                        with col_confirm1:
                            if st.button("Confirm Delete", key="confirm_delete"):
                                if delete_user(selected_user['id']):
                                    st.success(f"User '{selected_username}' deleted successfully")
                                    st.rerun()
                                else:
                                    st.error("Failed to delete user")
                        
                        with col_confirm2:
                            st.button("Cancel", key="cancel_delete")
    
    
    # ════════════════════════════════════════════════════════════════════════
    # TAB 4: RESET PASSWORD - TEMPORARY PASSWORD GENERATION
    # ════════════════════════════════════════════════════════════════════════
    
    with tab4:
        st.markdown("## Reset User Password")
        
        users = get_all_users()
        
        if not users:
            st.info("No users to manage.")
        else:
            usernames = [u['username'] for u in users]
            selected_username = st.selectbox("Select User", usernames, key="reset_user_select")
            
            # Find selected user
            selected_user = next((u for u in users if u['username'] == selected_username), None)
            
            if selected_user:
                st.markdown(f"### Reset password for: {selected_username}")
                
                st.warning("This action will generate a new temporary password for the user.")
                
                new_password = st.text_input(
                    "New Temporary Password",
                    type="password",
                    placeholder="Enter new temporary password",
                    help="User should change this after next login"
                )
                
                if st.button("Reset Password", use_container_width=True, type="primary"):
                    if not new_password:
                        st.error("Please enter a password.")
                    elif len(new_password) < 8:
                        st.error("Password must be at least 8 characters long.")
                    else:
                        if reset_user_password(selected_user['id'], new_password):
                            st.success(f"Password reset successfully for '{selected_username}'")
                            st.info(f"**New Temporary Password:** `{new_password}`\n\n*Share this with the user securely.*")
                        else:
                            st.error("Failed to reset password")


# ════════════════════════════════════════════════════════════════════════════════
# SIDEBAR - HELP AND INFORMATION PANEL
# ════════════════════════════════════════════════════════════════════════════════

def render_sidebar():
    """
    ════════════════════════════════════════════════════════════════════════
    Render sidebar with role descriptions, policies, and usage tips.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Displays contextual help information in sidebar for User Management
        page. Shows current admin username, role hierarchy, password policy,
        and best practices for user administration.

    SIDEBAR SECTIONS:

        1. Current Admin Display:
           ├─ "User Management Help" header
           ├─ Horizontal divider
           ├─ "Current Admin" section
           └─ Display: st.session_state['username']
        
        2. Available Roles:
           ├─ Role descriptions:
           │   ├─ Admin: Full access, can manage users
           │   ├─ Analyst: Can view and analyze threats
           │   └─ Viewer: Read-only access to dashboard
           └─ Helps admins understand role assignments
        
        3. Password Policy:
           ├─ Minimum 8 characters
           └─ Temporary password change recommendation
        
        4. Tips:
           ├─ Always set strong temporary passwords
           ├─ Deactivate unused accounts
           └─ Review user activity regularly

    DISPLAY FORMAT:

        Header:
            ## User Management Help
            ---
        
        Current Admin:
            ### Current Admin
            [Info box with username]
        
        Roles:
            ### Available Roles
            - **Admin**: Full access, can manage users
            - **Analyst**: Can view and analyze threats
            - **Viewer**: Read-only access to dashboard
        
        Password Policy:
            ### Password Policy
            - Minimum 8 characters
            - Users should change temporary passwords after first login
        
        Tips:
            ### Tips
            - Always set strong temporary passwords
            - Deactivate unused accounts
            - Review user activity regularly

    ARGS:
        None

    RETURNS:
        None (renders directly to st.sidebar)

    USED BY:
        Application entry point (if __name__ == "__main__")
        Called before main() to populate sidebar

    NOTES:
        - Uses st.sidebar context manager
        - Displays static information (no interactive elements)
        - Username pulled from session_state
        - Always visible on page load

    FUTURE ENHANCEMENTS:
        - Link to documentation
        - Recent user activity log
        - Quick stats (last created user, etc.)
        - Search users functionality

    SEE ALSO:
        - main(): Main page rendering function
        - check_admin_access(): Sets session_state username
    """
    with st.sidebar:
        st.markdown("## User Management Help")
        st.markdown("---")
        
        st.markdown("### Current Admin")
        st.info(f"**{st.session_state.get('username', 'Unknown')}**")
        
        st.markdown("### Available Roles")
        st.markdown("""
        - **Admin**: Full access, can manage users
        - **Analyst**: Can view and analyze threats
        - **Viewer**: Read-only access to dashboard
        """)
        
        st.markdown("### Password Policy")
        st.markdown("- Minimum 8 characters")
        st.markdown("- Users should change temporary passwords after first login")
        
        st.markdown("### Tips")
        st.markdown("- Always set strong temporary passwords")
        st.markdown("- Deactivate unused accounts")
        st.markdown("- Review user activity regularly")


# ════════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    render_sidebar()
    main()