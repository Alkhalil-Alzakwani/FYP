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


# ============================================================================
# SPLUNK LOGS FUNCTIONS
# ============================================================================

def insert_splunk_logs(logs):
    """
    Insert Splunk logs into the database (avoiding duplicates)
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        int: Number of new logs inserted
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return 0
        
        cursor = conn.cursor()
        inserted = 0
        
        for log in logs:
            try:
                cursor.execute(
                    """INSERT OR IGNORE INTO splunk_logs 
                       (event_id, timestamp, host, source, sourcetype, event_data, severity, raw_log, indexed_at, created_at) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        log.get('event_id'),
                        log.get('timestamp'),
                        log.get('host'),
                        log.get('source'),
                        log.get('sourcetype'),
                        log.get('event_data'),
                        log.get('severity'),
                        log.get('raw_log'),
                        log.get('indexed_at'),
                        datetime.now().isoformat()
                    )
                )
                if cursor.rowcount > 0:
                    inserted += 1
            except Exception as e:
                print(f"Error inserting log: {e}")
                continue
        
        conn.commit()
        conn.close()
        return inserted
        
    except Exception as e:
        print(f"Error inserting Splunk logs: {e}")
        return 0


def get_splunk_logs(limit=1000, offset=0, severity_filter=None, source_filter=None, search_text=None):
    """
    Get Splunk logs from the database with optional filters
    
    Args:
        limit (int): Maximum number of logs to return
        offset (int): Offset for pagination
        severity_filter (str): Filter by severity level
        source_filter (str): Filter by source
        search_text (str): Search in event_data
        
    Returns:
        list: List of log dictionaries
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return []
        
        cursor = conn.cursor()
        
        # Build query with filters
        query = "SELECT * FROM splunk_logs WHERE 1=1"
        params = []
        
        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter)
        
        if source_filter:
            query += " AND source LIKE ?"
            params.append(f"%{source_filter}%")
        
        if search_text:
            query += " AND (event_data LIKE ? OR raw_log LIKE ?)"
            params.append(f"%{search_text}%")
            params.append(f"%{search_text}%")
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    except Exception as e:
        print(f"Error fetching Splunk logs: {e}")
        return []


def get_splunk_logs_count(severity_filter=None, source_filter=None, search_text=None):
    """
    Get total count of Splunk logs with optional filters
    
    Args:
        severity_filter (str): Filter by severity level
        source_filter (str): Filter by source
        search_text (str): Search in event_data
        
    Returns:
        int: Total count of logs
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return 0
        
        cursor = conn.cursor()
        
        # Build query with filters
        query = "SELECT COUNT(*) FROM splunk_logs WHERE 1=1"
        params = []
        
        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter)
        
        if source_filter:
            query += " AND source LIKE ?"
            params.append(f"%{source_filter}%")
        
        if search_text:
            query += " AND (event_data LIKE ? OR raw_log LIKE ?)"
            params.append(f"%{search_text}%")
            params.append(f"%{search_text}%")
        
        cursor.execute(query, params)
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
        
    except Exception as e:
        print(f"Error counting Splunk logs: {e}")
        return 0


def get_last_splunk_log_timestamp():
    """
    Get the timestamp of the most recent Splunk log
    
    Returns:
        str: Timestamp of the last log, None if no logs exist
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return None
        
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(timestamp) FROM splunk_logs")
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result and result[0] else None
        
    except Exception as e:
        print(f"Error getting last log timestamp: {e}")
        return None


def delete_all_splunk_logs():
    """
    Delete all logs from the splunk_logs table
    
    Returns:
        tuple: (success: bool, message: str, deleted_count: int)
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return (False, "Database connection failed", 0)
        
        cursor = conn.cursor()
        
        # Get count before deletion
        cursor.execute("SELECT COUNT(*) FROM splunk_logs")
        count = cursor.fetchone()[0]
        
        # Delete all logs
        cursor.execute("DELETE FROM splunk_logs")
        
        # Reset auto-increment
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='splunk_logs'")
        
        conn.commit()
        conn.close()
        
        return (True, f"Successfully deleted {count} logs", count)
        
    except Exception as e:
        print(f"Error deleting Splunk logs: {e}")
        return (False, f"Error: {str(e)}", 0)