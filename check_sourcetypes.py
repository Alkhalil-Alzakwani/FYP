"""
CYBER DEFENSE PLATFORM - DATABASE SOURCETYPE AUDIT
╚════════════════════════════════════════════════════════════════════════════╝

File: check_sourcetypes.py
Purpose: Diagnostic utility to inspect Splunk log sourcetypes in database

DESCRIPTION:
    Command-line utility for database auditing and troubleshooting. Inspects
    splunk_logs table to identify available sourcetypes, their distribution,
    and searches for specific patterns (e.g., message_rfc822 email logs).
    Useful for validating data ingestion, identifying data gaps, and
    debugging Splunk configuration issues.

FUNCTIONALITY:

    1. Sourcetype Inventory:
       ├─ Query all distinct sourcetypes in database
       ├─ Count events per sourcetype
       ├─ Sort by frequency (descending)
       └─ Display comprehensive list
    
    2. Pattern Search:
       ├─ Search for specific sourcetype patterns
       ├─ Case-insensitive LIKE matching
       ├─ Example: message_rfc822 (email logs)
       └─ Show matching records with sample data
    
    3. Database Statistics:
       ├─ Total log count
       ├─ Sourcetype distribution
       └─ Sample records with metadata

USAGE:
    python check_sourcetypes.py

OUTPUT SECTIONS:
    1. Header with separator
    2. Sourcetype list with counts
    3. Pattern search results
    4. Sample records (if matches found)
    5. Database summary statistics

DATABASE SCHEMA (splunk_logs table):

    id (INTEGER): Unique log identifier
    timestamp (TEXT): ISO 8601 timestamp
    host (TEXT): Source hostname/IP
    source (TEXT): Log source file/path
    sourcetype (TEXT): Splunk event type classification
    severity (TEXT): Event severity level
    raw_log (TEXT): Complete log message (optional in output)
    
    Indexed columns:
        - sourcetype: Used for GROUP BY queries
        - timestamp: Time-range filtering

COMMON SOURCETYPES:

    Security/IDS:
        suricata: Suricata IDS/IPS alerts
        snort: Snort IDS alerts
        zeek: Zeek network analysis
        palo_alto: Palo Alto firewall logs
    
    Mail/SMTP:
        message_rfc822: Email message logs (RFC 822 format)
        postfix: Postfix mail server logs
        sendmail: Sendmail logs
    
    System/OS:
        syslog: Standard syslog format
        linux_secure: Linux authentication logs
        windows_event: Windows Event Log
    
    Application:
        apache: Apache web server logs
        nginx: Nginx web server logs
        syslog: Generic application logs

DEPENDENCIES:

    External Libraries:
        - sqlite3: Database connectivity (stdlib)
        - pathlib: File path manipulation (stdlib)
    
    Database:
        - cyber_defense.db in database/ directory
        - Must have splunk_logs table populated

ERROR HANDLING:

    Database Connection Errors:
        - File not found: Print error message
        - Permissions denied: Print error message
        - Corrupted DB: Print error message
        - Continues gracefully without crash
    
    Query Errors:
        - Invalid column: Prints exception
        - Missing table: Prints exception
        - Syntax error: Prints exception

TROUBLESHOOTING:

    If sourcetypes missing:
        ✓ Check Splunk ingestion (see Live_Threat_Monitor.py)
        ✓ Verify database connection in database/queries.py
        ✓ Confirm splunk_logs table exists and has data
    
    If message_rfc822 missing:
        ✓ Verify email data ingestion source in Splunk
        ✓ Check Splunk props.conf for sourcetype definition
        ✓ Look for errors in Splunk logs

DEVELOPMENT NOTES:

    Design Pattern:
        - Utility script (not imported elsewhere)
        - Single entry point: check_database()
        - Console output formatting
        - Error handling with try/except
    
    Future Enhancements:
        - Export results to CSV/JSON
        - Filter by date range
        - Show event distribution over time
        - Compare with previous runs
        - Add command-line arguments
        - Generate diagnostic report

AUTHOR: Multilayered Cyber Defense Team
LAST MODIFIED: December 8, 2025
VERSION: 1.0.0

╚════════════════════════════════════════════════════════════════════════════╝
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "database" / "cyber_defense.db"

def check_database():
    """
    ════════════════════════════════════════════════════════════════════════
    Inspect Splunk logs database: sourcetypes, patterns, and statistics.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Main diagnostic function. Connects to SQLite database and performs
        three analysis queries:
        1. List all sourcetypes with event counts
        2. Search for pattern matches (message_rfc822)
        3. Display total database statistics

    DATABASE OPERATIONS:

        Query 1 - Sourcetype Inventory:
            SELECT sourcetype, COUNT(*) as count
            FROM splunk_logs
            GROUP BY sourcetype
            ORDER BY count DESC
            
            Results:
                All distinct sourcetypes
                Sorted by frequency (most common first)
                Count of events per sourcetype
        
        Query 2 - Pattern Search:
            SELECT COUNT(*)
            FROM splunk_logs
            WHERE sourcetype LIKE '%message_rfc822%'
                  OR sourcetype LIKE '%rfc822%'
            
            Results:
                Total matching event count
                If > 0: Shows sample records with metadata
        
        Query 3 - Statistics:
            SELECT COUNT(*)
            FROM splunk_logs
            
            Results:
                Total event count in database

    OUTPUT FORMAT:

        Section 1: Sourcetype List
            ├─ Separator line (60 chars)
            ├─ Title: \"Sourcetypes in database:\"
            ├─ Separator line
            └─ Each sourcetype: \"name: count\" format
        
        Section 2: Pattern Search
            ├─ Separator line
            ├─ Title: \"Checking for message_rfc822 logs:\"
            ├─ Separator line
            ├─ Match count: \"Logs with message_rfc822: X\"
            ├─ Sample records (if any):
            │   ├─ Sample header
            │   └─ Each record: \"ID: X, Time: Y, Host: Z, ...\"
            └─ [Skip sample section if 0 matches]
        
        Section 3: Statistics
            └─ Total log count

    ARGS:
        None

    RETURNS:
        None (prints to console)

    DATABASE CONNECTION:

        Path: database/cyber_defense.db (relative to script)
        Type: SQLite3
        Mode: Read-only (no modifications)
        Timeout: Default (no explicit timeout)

    ERROR HANDLING:

        Connection Errors:
            - File not found: \"Error: [Errno 2] No such file or directory\"
            - Print error message and return gracefully
            - No crash or stack trace (user-friendly)
        
        Query Errors:
            - Invalid column: \"Error: no such column\"
            - Missing table: \"Error: no such table\"
            - Catch all exceptions with try/except
        
        All exceptions printed with \"Error: {e}\" format

    NOTES:
        - Uses string formatting for console output
        - Separators: \"=\" * 60 for major sections, \"-\" * 60 for subsections
        - Sourcetype names printed as-is (case-preserved)
        - Pattern search case-insensitive (LIKE with % wildcards)
        - Connection closed after queries (no resource leak)

    USAGE EXAMPLE:
        python check_sourcetypes.py
        
        Output:
            ============================================================
            Checking database for sourcetypes
            ============================================================
            
            Sourcetypes in database:
            ------------------------------------------------------------
            suricata: 1250
            syslog: 890
            postfix: 450
            ...

    TROUBLESHOOTING:

        No sourcetypes displayed:
            1. Verify cyber_defense.db exists in database/
            2. Check splunk_logs table has data (see queries.py)
            3. Run seed_users.py to populate initial data
        
        0 message_rfc822 logs:
            1. Check Splunk is configured to ingest email logs
            2. Verify email datasource is properly connected
            3. Look for other email sourcetypes in main list

    SEE ALSO:
        - database/queries.py: Database query functions
        - database/schema.sql: Schema definition
        - pages/Live_Threat_Monitor.py: Log ingestion source
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        print("=" * 60)
        print("Checking database for sourcetypes")
        print("=" * 60)
        
        # ════════════════════════════════════════════════════════════════
        # QUERY 1 - SOURCETYPE INVENTORY
        # ════════════════════════════════════════════════════════════════
        
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
        
        # ════════════════════════════════════════════════════════════════
        # QUERY 2 - PATTERN SEARCH: MESSAGE_RFC822 EMAIL LOGS
        # ════════════════════════════════════════════════════════════════
        
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
        
        # ════════════════════════════════════════════════════════════════
        # QUERY 3 - DATABASE SUMMARY: TOTAL LOG COUNT
        # ════════════════════════════════════════════════════════════════
        
        # Check total logs
        cursor.execute("SELECT COUNT(*) FROM splunk_logs")
        total = cursor.fetchone()[0]
        print(f"\nTotal logs in database: {total}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database()
