"""
auth/auth_manager.py

Handles:

Login verification (check_credentials)

Session creation (create_session)

Logout process

Role-based access
"""

from database.queries import get_user_by_username, update_last_login
from auth.password_utils import verify_password
from auth.session_manager import create_session as create_user_session, clear_session, validate_session as check_session


def authenticate_user(username, password):
    """
    Authenticate a user with username and password
    
    Args:
        username (str): The username
        password (str): The plain text password
        
    Returns:
        dict: User data if authentication successful, None otherwise
    """
    try:
        # Get user from database
        user = get_user_by_username(username)
        
        if user is None:
            print(f"User '{username}' not found")
            return None
        
        # Check if account is active
        if not user.get('active', False):
            print(f"User '{username}' account is inactive")
            return None
        
        # Verify password
        if verify_password(password, user['password_hash']):
            print(f"User '{username}' authenticated successfully")
            return user
        else:
            print(f"Invalid password for user '{username}'")
            return None
            
    except Exception as e:
        print(f"Authentication error: {e}")
        return None


def validate_session():
    """
    Validate the current session
    
    Returns:
        bool: True if session is valid, False otherwise
    """
    return check_session()


def logout_user():
    """
    Log out the current user and clear session
    
    Returns:
        bool: True if logout successful
    """
    return clear_session()