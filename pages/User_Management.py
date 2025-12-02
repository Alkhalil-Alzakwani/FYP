"""
================================================================================
USER MANAGEMENT PAGE (pages/User_Management.py)
================================================================================

Accessible only by admin users.

FEATURES:
  1. View all users and their roles in a data table
  2. Add new users with role assignment
  3. Edit user roles and activation status
  4. Reset passwords (generate new hash with temporary password)
  5. Delete users (with confirmation)
  6. Search and filter users

This page interacts directly with the users table in the database.

ROLE-BASED ACCESS CONTROL:
  - Accessible only by 'admin' users
  - Non-admin users see access denied message

DEPENDENCIES:
  - streamlit
  - database.queries (for user CRUD operations)
  - auth.password_utils (for password hashing)
  - auth.session_manager (for session validation)

AUTHOR: Multilayered Cyber Defense Team
================================================================================
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


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title='User Management',
    layout='wide',
    initial_sidebar_state='expanded'
)


# ============================================================================
# SESSION & ACCESS CONTROL
# ============================================================================

def check_admin_access():
    """
    Check if user is authenticated and has admin role
    
    Returns:
        bool: True if user is admin, False otherwise
    """
    # Validate session
    if not validate_session():
        st.error("❌ Session expired. Please login again.")
        st.stop()
    
    # Check if user has admin role
    if st.session_state.get("role") != "admin":
        st.error("❌ Access Denied. This page is only accessible to administrators.")
        st.stop()
    
    return True


# ============================================================================
# DATABASE HELPER FUNCTIONS
# ============================================================================

def update_user_role(user_id, new_role):
    """Update a user's role"""
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
    """Update a user's active status"""
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
    """Reset a user's password"""
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
    """Delete a user from the database"""
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


# ============================================================================
# MAIN PAGE
# ============================================================================

def main():
    """Main User Management page"""
    
    # Check admin access
    check_admin_access()
    
    st.markdown("# 👥 User Management")
    st.markdown("---")
    
    # Create tabs for different operations
    tab1, tab2, tab3, tab4 = st.tabs([
        "👁️ View Users",
        "➕ Add New User",
        "✏️ Edit User",
        "🔑 Reset Password"
    ])
    
    
    # ========================================================================
    # TAB 1: VIEW ALL USERS
    # ========================================================================
    
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
            display_df['active'] = display_df['active'].apply(lambda x: '✅ Active' if x else '❌ Inactive')
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
    
    
    # ========================================================================
    # TAB 2: ADD NEW USER
    # ========================================================================
    
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
                    st.error("❌ Username and password are required.")
                elif len(new_password) < 8:
                    st.error("❌ Password must be at least 8 characters long.")
                elif get_user_by_username(new_username):
                    st.error(f"❌ Username '{new_username}' already exists.")
                else:
                    # Create user
                    password_hash = hash_password(new_password)
                    user_id = create_user(new_username, password_hash, new_role, new_email)
                    
                    if user_id:
                        st.success(f"✅ User '{new_username}' created successfully!")
                        st.info(f"**User ID:** {user_id}\n**Role:** {new_role}\n**Initial Password:** (share with user securely)")
                    else:
                        st.error("❌ Error creating user. Please try again.")
    
    
    # ========================================================================
    # TAB 3: EDIT USER
    # ========================================================================
    
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
                    if st.button("💾 Update Role", use_container_width=True):
                        if new_role != selected_user['role']:
                            if update_user_role(selected_user['id'], new_role):
                                st.success(f"✅ Role updated to '{new_role}'")
                                st.rerun()
                            else:
                                st.error("❌ Failed to update role")
                        else:
                            st.info("Role unchanged")
                
                with col2:
                    if st.button("💾 Update Status", use_container_width=True):
                        if new_active != bool(selected_user['active']):
                            if update_user_active_status(selected_user['id'], new_active):
                                status_text = "activated" if new_active else "deactivated"
                                st.success(f"✅ User {status_text}")
                                st.rerun()
                            else:
                                st.error("❌ Failed to update status")
                        else:
                            st.info("Status unchanged")
                
                with col3:
                    if st.button("🗑️ Delete User", use_container_width=True, type="secondary"):
                        # Confirmation dialog
                        st.warning(f"⚠️ Are you sure you want to delete user '{selected_username}'? This cannot be undone.")
                        
                        col_confirm1, col_confirm2 = st.columns(2)
                        
                        with col_confirm1:
                            if st.button("✅ Confirm Delete", key="confirm_delete"):
                                if delete_user(selected_user['id']):
                                    st.success(f"✅ User '{selected_username}' deleted successfully")
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to delete user")
                        
                        with col_confirm2:
                            st.button("❌ Cancel", key="cancel_delete")
    
    
    # ========================================================================
    # TAB 4: RESET PASSWORD
    # ========================================================================
    
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
                
                st.warning("⚠️ This action will generate a new temporary password for the user.")
                
                new_password = st.text_input(
                    "New Temporary Password",
                    type="password",
                    placeholder="Enter new temporary password",
                    help="User should change this after next login"
                )
                
                if st.button("🔑 Reset Password", use_container_width=True, type="primary"):
                    if not new_password:
                        st.error("❌ Please enter a password.")
                    elif len(new_password) < 8:
                        st.error("❌ Password must be at least 8 characters long.")
                    else:
                        if reset_user_password(selected_user['id'], new_password):
                            st.success(f"✅ Password reset successfully for '{selected_username}'")
                            st.info(f"**New Temporary Password:** `{new_password}`\n\n*Share this with the user securely.*")
                        else:
                            st.error("❌ Failed to reset password")


# ============================================================================
# SIDEBAR
# ============================================================================

def render_sidebar():
    """Render sidebar with helpful information"""
    with st.sidebar:
        st.markdown("## ℹ️ User Management Help")
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


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    render_sidebar()
    main()