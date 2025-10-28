"""
auth/auth_manager.py

Handles:

Login verification (check_credentials)

Session creation (create_session)

Logout process

Role-based access

################################################## delete the bellow:
Example function:

from database.queries import get_user_by_username
from auth.password_utils import verify_password
from auth.session_manager import create_session

def authenticate(username, password):
    user = get_user_by_username(username)
    if user and verify_password(password, user["password_hash"]):
        create_session(user)
        return True
    return False

"""