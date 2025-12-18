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

def _has_column(conn, table: str, column: str) -> bool:
    try:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        cols = [r[1] for r in cur.fetchall()]
        return column in cols
    except Exception:
        return False


def ensure_derived_severity_column() -> bool:
    """Ensure splunk_logs has a derived_severity column (TEXT)."""
    try:
        conn = get_db_connection()
        if conn is None:
            return False
        if not _has_column(conn, 'splunk_logs', 'derived_severity'):
            cur = conn.cursor()
            cur.execute("ALTER TABLE splunk_logs ADD COLUMN derived_severity TEXT")
            conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error ensuring derived_severity column: {e}")
        return False


def _derive_severity(source: str, sourcetype: str, raw_log: str, severity: str) -> str:
    """Lightweight derived severity based on source behavior and content."""
    s = (severity or '').lower()
    text = (raw_log or '').lower()
    src = (source or '').lower()
    stp = (sourcetype or '').lower()

    def bump(level: str, steps: int = 1, direction: int = 1) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        try:
            idx = order.index(level)
        except ValueError:
            idx = 2
        idx = max(0, min(len(order)-1, idx + steps*direction))
        return order[idx]

    def normalize(label: str) -> str:
        if not label:
            return 'unknown'
        l = label.lower().strip()
        if l in ["critical","high","medium","low","info","unknown"]:
            return 'info' if l == 'informational' else l
        if l in ["emergency","emerg"]:
            return 'critical'
        if l in ["alert","error","err","severe","major"]:
            return 'high'
        if l in ["warning","warn"]:
            return 'medium'
        if l in ["notice","minor","debug","informational"]:
            return 'low'
        return 'unknown'

    base = normalize(s)

    # Trust SQU authentication successes
    import re
    domains = set(re.findall(r"[\w\.-]+@([\w\.-]+)", text))
    is_auth = any(k in src or k in stp for k in ["okta","azuread","adfs","ldap","sso","signin","logon","login"]) or any(k in text for k in ["auth","login","logon","signin"])
    if is_auth and any("squ.edu.om" in d for d in domains) and any(k in text for k in ["authentication success","login success","accepted password","succeeded","token issued","success"]):
        base = bump(base, 2, -1)
    if any("squ.edu.om" not in d for d in domains) and len(domains) > 0:
        base = bump(base, 1, 1)

    # Firewall / IDS / Email indicators
    if any(k in src or k in stp for k in ["firewall","pfsense"]) and any(k in text for k in ["deny","denied","drop","dropped","reject","blocked"]):
        base = bump(base, 1, 1)
    if any(k in src or k in stp for k in ["ids","ips","snort","suricata"]) and ("alert" in text or any(k in text for k in ["sid:","classification:"])):
        base = bump(base, 1, 1)
    if any(k in src or k in stp for k in ["email","smtp","exchange","o365","mta","gateway"]) and (any(k in text for k in ["attachment","macro",".exe",".js",".zip"]) or any(k in text for k in ["dkim fail","spf fail","dmarc fail"])):
        base = bump(base, 1, 1)

    # Strong content keywords
    if any(k in text for k in ["ransomware","data exfiltration","exfiltration","privilege escalation","remote code execution","backdoor","cobalt strike","meterpreter","command and control","c2","rootkit","wiper"]):
        base = "critical"
    elif any(k in text for k in ["phishing","malware","botnet","ddos","credential stuffing","bruteforce","sql injection","xss","csrf exploit","unauthorized access","account takeover","suspicious admin"]):
        base = "high"
    elif any(k in text for k in ["multiple failed logins","failed login","policy violation","anomaly detected","suspicious","scan","port scan","nmap"]):
        base = "medium"

    # Auth failures bump
    if is_auth and any(k in text for k in ["authentication failure","login failed","invalid password","bad credentials","locked","mfa failed","denied"]):
        base = bump(base, 1, 1)

    return base


def backfill_derived_severity(max_rows: int | None = None) -> int:
    """Fill derived_severity for rows where it's NULL."""
    try:
        conn = get_db_connection()
        if conn is None:
            return 0
        if not _has_column(conn, 'splunk_logs', 'derived_severity'):
            conn.close()
            return 0
        cur = conn.cursor()
        # Select rows needing backfill
        limit_clause = f" LIMIT {int(max_rows)}" if max_rows else ""
        cur.execute(f"SELECT id, source, sourcetype, raw_log, severity FROM splunk_logs WHERE derived_severity IS NULL OR derived_severity = ''{limit_clause}")
        rows = cur.fetchall()
        updated = 0
        for r in rows:
            dv = _derive_severity(r[1], r[2], r[3], r[4])
            try:
                cur.execute("UPDATE splunk_logs SET derived_severity = ? WHERE id = ?", (dv, r[0]))
                updated += 1
            except Exception as e:
                print(f"Backfill error id={r[0]}: {e}")
        conn.commit()
        conn.close()
        return updated
    except Exception as e:
        print(f"Error backfilling derived severity: {e}")
        return 0


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
        
        # Ensure derived_severity column exists
        has_derived = _has_column(conn, 'splunk_logs', 'derived_severity')
        
        for log in logs:
            try:
                if has_derived:
                    derived = _derive_severity(log.get('source'), log.get('sourcetype'), log.get('raw_log'), log.get('severity'))
                    cursor.execute(
                        """INSERT OR IGNORE INTO splunk_logs 
                           (event_id, timestamp, host, source, sourcetype, event_data, severity, raw_log, indexed_at, created_at, derived_severity) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                            datetime.now().isoformat(),
                            derived
                        )
                    )
                else:
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


def get_splunk_logs(limit=1000, offset=0, severity_filter=None, source_filter=None, search_text=None, host_filter=None):
    """
    Get Splunk logs from the database with optional filters
    
    Args:
        limit (int): Maximum number of logs to return
        offset (int): Offset for pagination
        severity_filter (str): Filter by severity level
        source_filter (str): Filter by source (exact match)
        search_text (str): Search in event_data
        host_filter (str): Filter by host (exact match)
        
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
            query += " AND LOWER(severity) = LOWER(?)"
            params.append(severity_filter)
        
        if source_filter:
            query += " AND source = ?"
            params.append(source_filter)
        
        if host_filter:
            query += " AND host = ?"
            params.append(host_filter)
        
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


def get_splunk_logs_count(severity_filter=None, source_filter=None, search_text=None, host_filter=None):
    """
    Get total count of Splunk logs with optional filters
    
    Args:
        severity_filter (str): Filter by severity level
        source_filter (str): Filter by source (exact match)
        search_text (str): Search in event_data
        host_filter (str): Filter by host (exact match)
        
    Returns:
        int: Total count of logs
    """
    try:
        conn = get_db_connection()
        if conn is None:
            return 0
        
        cursor = conn.cursor()
        
        # Build query with filters (use derived_severity if available)
        query = "SELECT COUNT(*) FROM splunk_logs WHERE 1=1"
        params = []
        
        if severity_filter:
            query += " AND LOWER(COALESCE(derived_severity, severity)) = LOWER(?)"
            params.append(severity_filter)
        
        if source_filter:
            query += " AND source = ?"
            params.append(source_filter)
        
        if host_filter:
            query += " AND host = ?"
            params.append(host_filter)
        
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