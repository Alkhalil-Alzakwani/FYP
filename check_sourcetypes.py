"""
Check what sourcetypes are in the database and search for message_rfc822
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "database" / "cyber_defense.db"

def check_database():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        print("=" * 60)
        print("Checking database for sourcetypes")
        print("=" * 60)
        
        # Get all sourcetypes with counts
        cursor.execute("""
            SELECT sourcetype, COUNT(*) as count 
            FROM splunk_logs 
            GROUP BY sourcetype 
            ORDER BY count DESC
        """)
        
        results = cursor.fetchall()
        
        print("\nSourcetypes in database:")
        print("-" * 60)
        for sourcetype, count in results:
            print(f"{sourcetype}: {count}")
        
        # Check specifically for message_rfc822
        print("\n" + "=" * 60)
        print("Checking for message_rfc822 logs:")
        print("=" * 60)
        
        cursor.execute("""
            SELECT COUNT(*) 
            FROM splunk_logs 
            WHERE sourcetype LIKE '%message_rfc822%' OR sourcetype LIKE '%rfc822%'
        """)
        
        count = cursor.fetchone()[0]
        print(f"\nLogs with message_rfc822: {count}")
        
        if count > 0:
            print("\nSample message_rfc822 logs:")
            cursor.execute("""
                SELECT id, timestamp, host, source, sourcetype, severity
                FROM splunk_logs 
                WHERE sourcetype LIKE '%message_rfc822%' OR sourcetype LIKE '%rfc822%'
                LIMIT 5
            """)
            samples = cursor.fetchall()
            for sample in samples:
                print(f"  ID: {sample[0]}, Time: {sample[1]}, Host: {sample[2]}, Source: {sample[3]}, Type: {sample[4]}, Severity: {sample[5]}")
        
        # Check total logs
        cursor.execute("SELECT COUNT(*) FROM splunk_logs")
        total = cursor.fetchone()[0]
        print(f"\nTotal logs in database: {total}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database()
