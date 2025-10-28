"""
database/queries.py

Database query functions for the Cyber Defense Platform
"""

import sqlite3
from pathlib import Path
from datetime import datetime


# Database path
DB_PATH = Path(__file__).parent.parent / "database" / "cyber_defense.db"


def get_db_connection():
    """Get a connection to the SQLite database"""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None


def get_user_by_username(username):
    """
    Retrieve user information by username
    
    Args:
        username (str): The username to search for
        
    Returns:
        dict: User data if found, None otherwise
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return None
        
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, email, last_login, active FROM users WHERE username = ?",
            (username,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
        
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None


def update_last_login(user_id):
    """
    Update the last login timestamp for a user
    
    Args:
        user_id (int): The user ID
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return False
        
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().isoformat(), user_id)
        )
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error updating last login: {e}")
        return False


def create_user(username, password_hash, role='viewer', email=None):
    """
    Create a new user in the database
    
    Args:
        username (str): The username
        password_hash (str): The hashed password
        role (str): User role (admin/analyst/viewer)
        email (str): Optional email address
        
    Returns:
        int: User ID if successful, None otherwise
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return None
        
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO users (username, password_hash, role, email, created_at, active) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, password_hash, role, email, datetime.now().isoformat(), 1)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id
        
    except Exception as e:
        print(f"Error creating user: {e}")
        return None


def get_all_users():
    """
    Get all users from the database
    
    Returns:
        list: List of user dictionaries
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return []
        
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, email, last_login, created_at, active FROM users")
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    except Exception as e:
        print(f"Error fetching users: {e}")
        return []