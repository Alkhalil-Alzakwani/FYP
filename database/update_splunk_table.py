"""
Update splunk_logs table to include all required columns
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "cyber_defense.db"

def update_splunk_logs_table():
    """Drop and recreate splunk_logs table with correct schema"""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        print("Dropping old splunk_logs table...")
        cursor.execute("DROP TABLE IF EXISTS splunk_logs")
        
        print("Creating new splunk_logs table with correct schema...")
        cursor.execute("""
            CREATE TABLE splunk_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                host TEXT,
                source TEXT,
                sourcetype TEXT,
                event_data TEXT NOT NULL,
                severity TEXT,
                raw_log TEXT,
                indexed_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        print("Creating indexes...")
        cursor.execute("CREATE INDEX idx_splunk_logs_timestamp ON splunk_logs(timestamp)")
        cursor.execute("CREATE INDEX idx_splunk_logs_event_id ON splunk_logs(event_id)")
        
        conn.commit()
        conn.close()
        
        print("✓ Successfully updated splunk_logs table!")
        return True
        
    except Exception as e:
        print(f"✗ Error updating table: {e}")
        return False

if __name__ == "__main__":
    update_splunk_logs_table()
