"""
auth/session_manager.py

Handles:

    Session creation and expiration

    Storing minimal data in Streamlit's st.session_state

    Optional JWT token usage for stateless design

Key variables:

    SESSION_TIMEOUT_MINUTES = 30

    SECRET_KEY stored in config/security.yaml
"""

import streamlit as st
from datetime import datetime, timedelta
import secrets


# Session configuration
SESSION_TIMEOUT_MINUTES = 30


def create_session(user_data):
    """
    Create a new session for authenticated user
    
    Args:
        user_data (dict): User information from database
        
    Returns:
        bool: True if session created successfully
    """
    try:
        # Generate session token
        session_token = secrets.token_hex(32)
        
        # Store session data in st.session_state
        st.session_state.authenticated = True
        st.session_state.user_id = user_data.get('id')
        st.session_state.username = user_data.get('username')
        st.session_state.role = user_data.get('role', 'viewer')
        st.session_state.login_time = datetime.now()
        st.session_state.session_token = session_token
        st.session_state.session_expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        return True
    except Exception as e:
        print(f"Error creating session: {e}")
        return False


def clear_session():
    """Clear all session data"""
    try:
        # Clear all session state variables
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.role = None
        st.session_state.login_time = None
        st.session_state.session_token = None
        st.session_state.session_expiry = None
        return True
    except Exception as e:
        print(f"Error clearing session: {e}")
        return False


def check_session_timeout():
    """
    Check if the current session has expired
    
    Returns:
        bool: True if session is still valid, False if expired
    """
    try:
        if not st.session_state.get('authenticated', False):
            return False
        
        session_expiry = st.session_state.get('session_expiry')
        if session_expiry is None:
            return False
        
        # Check if session has expired
        if datetime.now() > session_expiry:
            clear_session()
            return False
        
        # Update session expiry (sliding window)
        st.session_state.session_expiry = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        return True
        
    except Exception as e:
        print(f"Error checking session timeout: {e}")
        return False


def validate_session():
    """
    Validate that the current session is active and valid
    
    Returns:
        bool: True if session is valid, False otherwise
    """
    return check_session_timeout()