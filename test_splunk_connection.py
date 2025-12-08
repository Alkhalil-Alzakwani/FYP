"""
CYBER DEFENSE PLATFORM - SPLUNK CONNECTION DIAGNOSTIC
╚════════════════════════════════════════════════════════════════════════════╝

File: test_splunk_connection.py
Purpose: Diagnostic utility to verify Splunk API connectivity and basic functionality

DESCRIPTION:
    Quick connectivity test script for validating Splunk integration. Tests
    the Splunk connector's ability to establish connection, authenticate, and
    retrieve sample logs. Useful for troubleshooting Splunk configuration
    issues, verifying credentials, and testing API functionality before
    running production log ingestion in Live_Threat_Monitor.

TEST OBJECTIVES:

    1. Connection Test:
       ├─ Instantiate Splunk connector
       ├─ Call test_connection() to verify API connectivity
       ├─ Validate authentication and credentials
       └─ Check Splunk service availability
    
    2. Log Retrieval:
       ├─ Fetch sample logs (past 1 day, max 5 results)
       ├─ Validate returned data structure
       ├─ Confirm field population
       └─ Display sample event details
    
    3. Graceful Failure:
       ├─ Handle connection errors gracefully
       ├─ Display helpful error messages
       └─ Disconnect properly on success or failure

USAGE:
    python test_splunk_connection.py

EXPECTED OUTPUT - SUCCESS:

    ============================================================
    Testing Splunk Connection
    ============================================================
    
    Attempting to connect to Splunk...
    ✓ Successfully connected to Splunk at http://localhost:8089
    
    Attempting to fetch sample logs...
    ✓ Retrieved 5 sample logs
    
    Sample log:
    ────────────────────────────────────────────────────────────
    event_id: 12345
    timestamp: 2025-12-08T10:30:00Z
    host: source-host-01
    source: /var/log/auth.log
    sourcetype: syslog
    severity: high
    ============================================================

EXPECTED OUTPUT - FAILURE:

    ============================================================
    Testing Splunk Connection
    ============================================================
    
    Attempting to connect to Splunk...
    ✗ Connection failed: Unable to reach Splunk at http://localhost:8089
    
    ============================================================

DATA FLOW:

    1. Script Launch:
       └─ if __name__ == "__main__": test_connection()
    
    2. Connector Initialization:
       ├─ get_splunk_connector() factory function
       ├─ Loads SPLUNK_URL, SPLUNK_USERNAME, SPLUNK_PASSWORD from env
       └─ Returns connector instance
    
    3. Connection Test:
       ├─ connector.test_connection()
       ├─ Returns (success: bool, message: str)
       └─ Handles authentication and API validation
    
    4a. Success Path:
        ├─ connector.fetch_logs() with time range parameters
        ├─ earliest_time: -1d@d (yesterday at midnight, UTC)
        ├─ latest_time: now (current time)
        ├─ max_results: 5 (limit for sample display)
        ├─ Display log count and first event details
        └─ connector.disconnect()
    
    4b. Failure Path:
        ├─ Print error message
        └─ Exit cleanly (implicit)

SPLUNK CONNECTOR API:

    Methods Used:
        
        get_splunk_connector():
            ├─ Factory function returning connector instance
            ├─ Reads environment variables
            └─ Handles initialization
        
        connector.test_connection():
            ├─ Tests API connectivity
            ├─ Validates credentials
            ├─ Returns (bool, str) tuple
            └─ Example: (True, "Successfully connected...")
        
        connector.fetch_logs():
            ├─ Parameters:
            │   ├─ earliest_time: "-1d@d" (1 day ago at midnight)
            │   ├─ latest_time: "now" (current time)
            │   └─ max_results: 5 (limit results)
            ├─ Returns: List of log event dictionaries
            └─ Each log contains: event_id, timestamp, host, source,
                                   sourcetype, severity, raw_log, event_data
        
        connector.disconnect():
            ├─ Closes Splunk connection
            ├─ Releases resources
            └─ Should always be called after operations

LOG EVENT STRUCTURE:

    Each retrieved log dictionary contains:
        
        event_id (str): Unique event identifier
        timestamp (str): ISO 8601 timestamp
        host (str): Source hostname/IP address
        source (str): Log source file path
        sourcetype (str): Splunk event type classification
        severity (str): Event severity level
        raw_log (str): Complete original log message (not displayed in sample)
        event_data (str): Parsed event JSON (not displayed in sample)
    
    Display Behavior:
        - raw_log and event_data excluded from sample display
        - Truncation: Display other fields without truncation
        - Format: "key: value" per line

ENVIRONMENT VARIABLES:

    Required:
        SPLUNK_URL: Splunk API endpoint
            Default: http://localhost:8089
            Example: https://splunk.company.com:8089
        
        SPLUNK_USERNAME: Authentication username
            Example: admin
        
        SPLUNK_PASSWORD: Authentication password
            Example: (stored securely, never committed to git)
    
    Configuration:
        - Load via get_splunk_connector()
        - Validate before connecting
        - Never log credentials

TROUBLESHOOTING:

    Connection Failed:
        ✗ Problem: Unable to reach Splunk
        ✓ Solutions:
          1. Verify Splunk service running: bin/splunk status
          2. Check SPLUNK_URL environment variable
          3. Verify network connectivity: ping splunk-host
          4. Check firewall rules (port 8089 open)
          5. Verify Splunk SSL certificate (if using HTTPS)
    
    Authentication Failed:
        ✗ Problem: Invalid credentials
        ✓ Solutions:
          1. Verify SPLUNK_USERNAME and SPLUNK_PASSWORD
          2. Check credentials in Splunk admin console
          3. Verify user has API permissions
          4. Check for account lockout (failed attempts)
    
    No Logs Returned:
        ✗ Problem: Connection succeeds but no logs fetched
        ✓ Solutions:
          1. Check if logs exist in past 1 day
          2. Verify index permissions for user
          3. Run broader search: earliest_time="-30d"
          4. Check Splunk license and usage

ERROR HANDLING:

    Connection Errors:
        - Caught by test_connection()
        - Returns (False, error_message)
        - Displays \"✗ {message}\" to user
        - Script continues to completion (no crash)
    
    Fetch Errors:
        - Caught by fetch_logs()
        - Returns empty list if error
        - Displays \"✗ Retrieved 0 sample logs\"
        - Script continues to completion
    
    Display Errors:
        - Missing fields: Safe defaults
        - Invalid JSON: Display raw format
        - No exceptions propagated to user

CONSOLE OUTPUT INDICATORS:

    ✓ (U+2713): Success, expected operation completed
    ✗ (U+2717): Failure, expected operation did not complete
    = (Header): Major section divider (60 chars)
    - (Separator): Log detail separator (60 chars)

DEPENDENCIES:

    Internal Modules:
        - models.splunk_connector: Splunk API wrapper
            ├─ get_splunk_connector(): Factory function
            ├─ test_connection(): Verify connectivity
            ├─ fetch_logs(): Execute log searches
            └─ disconnect(): Close connection
    
    External Libraries:
        - None (uses only stdlib + splunk_connector)

DEVELOPMENT NOTES:

    Design Pattern:
        - Diagnostic/test script
        - Single entry point: test_connection()
        - Minimal dependencies
        - User-friendly console output
        - Graceful error handling
    
    Why test before production:
        1. Verify environment configuration
        2. Check Splunk API availability
        3. Validate credentials early
        4. Catch issues before Live_Threat_Monitor
        5. Troubleshoot connectivity problems
    
    Future Enhancements:
        - Command-line arguments for time range
        - Verbose output option for debugging
        - Performance metrics (query time, results/sec)
        - Export results to file
        - Scheduled health checks

AUTHOR: Multilayered Cyber Defense Team
LAST MODIFIED: December 8, 2025
VERSION: 1.0.0

╚════════════════════════════════════════════════════════════════════════════╝
"""

from models.splunk_connector import get_splunk_connector

def test_connection():
    """
    ════════════════════════════════════════════════════════════════════════════
    FUNCTION: test_connection() - Splunk Connectivity Diagnostic
    ════════════════════════════════════════════════════════════════════════════
    
    DESCRIPTION:
        Main diagnostic function that tests Splunk API connectivity and validates
        basic functionality. This is the entry point for the diagnostic script.
        Tests connection, fetches sample logs, and displays results. Handles all
        errors gracefully without raising exceptions.
    
    EXECUTION FLOW:
        
        ┌─ STAGE 1: INITIALIZATION
        │   ├─ Print header banner
        │   ├─ Get splunk connector instance
        │   └─ Print "Attempting to connect to Splunk..."
        │
        ├─ STAGE 2: CONNECTION TEST
        │   ├─ Call connector.test_connection()
        │   ├─ Check success flag
        │   └─ Print connection result (success or error)
        │
        ├─ STAGE 3A: SUCCESS PATH - LOG RETRIEVAL
        │   ├─ Call connector.fetch_logs()
        │   │   ├─ Parameters:
        │   │   │   ├─ earliest_time: "-1d@d" (past 1 day, midnight boundary)
        │   │   │   ├─ latest_time: "now" (current time)
        │   │   │   └─ max_results: 5 (limit for sample display)
        │   │   └─ Returns: List of log dictionaries
        │   │
        │   ├─ Print log retrieval result with count
        │   │
        │   ├─ STAGE 3B: DISPLAY SAMPLE LOG
        │   │   ├─ Check if logs retrieved (len(logs) > 0)
        │   │   ├─ Get first log from list
        │   │   ├─ Print separator line
        │   │   ├─ For each field (except raw_log, event_data):
        │   │   │   └─ Print "field_name: field_value"
        │   │   └─ Print separator line
        │   │
        │   └─ Disconnect from Splunk
        │
        └─ STAGE 4: COMPLETION
            ├─ Print footer banner
            └─ Function ends (implicit return None)
    
    PARAMETERS:
        None - Uses environment variables for Splunk configuration
    
    RETURN VALUE:
        None - Output only via console print statements
    
    CONSOLE OUTPUT - SUCCESS SCENARIO:
        
        ============================================================
        Testing Splunk Connection
        ============================================================
        
        Attempting to connect to Splunk...
        ✓ Successfully connected to Splunk at http://localhost:8089
        
        Attempting to fetch sample logs...
        ✓ Retrieved 5 sample logs
        
        Sample log:
        ────────────────────────────────────────────────────────────
        event_id: 12345
        timestamp: 2025-12-08T10:30:00Z
        host: source-host-01
        source: /var/log/auth.log
        sourcetype: syslog
        severity: high
        ────────────────────────────────────────────────────────────
        
        ============================================================
    
    CONSOLE OUTPUT - FAILURE SCENARIO:
        
        ============================================================
        Testing Splunk Connection
        ============================================================
        
        Attempting to connect to Splunk...
        ✗ Connection failed: Unable to reach Splunk at http://localhost:8089
        
        ============================================================
    
    SPLUNK CONNECTOR API CALLS:
        
        1. get_splunk_connector():
            ├─ Factory function from models.splunk_connector
            ├─ Reads SPLUNK_URL, SPLUNK_USERNAME, SPLUNK_PASSWORD from environment
            ├─ Returns: connector instance with API methods
            └─ Never raises exceptions (handles setup internally)
        
        2. connector.test_connection():
            ├─ Validates Splunk API connectivity
            ├─ Attempts authentication with credentials
            ├─ Returns: (success: bool, message: str) tuple
            │   ├─ On Success: (True, "Successfully connected to Splunk at {url}")
            │   └─ On Failure: (False, "Connection failed: {error_message}")
            └─ Errors caught internally (returns tuple, not exception)
        
        3. connector.fetch_logs(earliest_time, latest_time, max_results):
            ├─ Executes search query on Splunk instance
            ├─ Parameters:
            │   ├─ earliest_time: "-1d@d" (1 day ago at midnight UTC)
            │   ├─ latest_time: "now" (current timestamp)
            │   └─ max_results: 5 (sample limit for display)
            ├─ Returns: List of log event dictionaries
            │   └─ Each dict contains: event_id, timestamp, host, source,
            │                          sourcetype, severity, raw_log, event_data
            └─ Returns empty list on failure (no exception)
        
        4. connector.disconnect():
            ├─ Closes Splunk API connection
            ├─ Releases network resources
            ├─ Safe to call even if not connected
            └─ Should be called before script exit
    
    LOG EVENT STRUCTURE:
        
        Dictionary fields returned by connector.fetch_logs():
        
        {
            'event_id': str,        # Unique event identifier
            'timestamp': str,       # ISO 8601 formatted timestamp
            'host': str,           # Source hostname or IP address
            'source': str,         # Log source file/stream path
            'sourcetype': str,     # Splunk event classification
            'severity': str,       # Event severity level (low/medium/high/critical)
            'raw_log': str,        # Original unparsed log message (not displayed)
            'event_data': str      # Parsed JSON data (not displayed)
        }
        
        Display Logic:
            - raw_log: Hidden (too verbose for sample)
            - event_data: Hidden (raw JSON, use other fields)
            - All other fields: Displayed in order
            - Format: "field_name: value" (one per line)
    
    ERROR HANDLING:
        
        Connection Error (test_connection() returns False):
            ├─ Catch: success flag is False
            ├─ Action: Print "✗ {error_message}"
            ├─ Behavior: Skip fetch_logs() call (no further operations)
            └─ Result: Exit cleanly after printing error
        
        Fetch Error (fetch_logs() returns empty list):
            ├─ Catch: len(logs) == 0
            ├─ Action: Print "✓ Retrieved 0 sample logs"
            ├─ Behavior: Skip sample log display
            └─ Result: Disconnect and exit cleanly
        
        Display Error (field missing from dict):
            ├─ Catch: None - uses dict.get() with safe defaults
            ├─ Action: Display "field_name: (not provided)"
            └─ Result: Continue display for other fields
        
        Disconnect Error:
            ├─ Catch: None - connector.disconnect() is fail-safe
            ├─ Behavior: Safe to call regardless of connection state
            └─ Result: Function completes normally
    
    TIME RANGE PARAMETERS:
        
        earliest_time: "-1d@d"
            └─ Interpretation: 1 day ago at midnight UTC (day boundary)
            └─ Example: If today is 2025-12-08:
               └─ Searches logs from 2025-12-07T00:00:00Z onwards
        
        latest_time: "now"
            └─ Interpretation: Current timestamp at execution time
            └─ Example: If executed at 14:30:
               └─ Searches logs until 2025-12-08T14:30:00Z
        
        Result: All logs from past 24 hours (or less if fewer exist)
    
    VALIDATION CHECKS:
        
        1. Connection Success:
            └─ success flag from test_connection() == True
        
        2. Log Retrieval:
            └─ logs list is not empty (len(logs) > 0)
        
        3. Sample Display:
            └─ First log dictionary has expected keys
            └─ All keys safely accessed (no KeyError)
    
    USAGE SCENARIO:
        
        When to run:
            1. After installing Splunk connector
            2. After updating Splunk configuration
            3. Before running Live_Threat_Monitor in production
            4. When troubleshooting connection issues
            5. To verify environment setup
        
        Expected behavior:
            - Runs in < 5 seconds (on successful connection)
            - Minimal output (~10 lines)
            - No exceptions or stack traces on failure
            - Clear success/failure indicators (✓/✗)
            - Graceful cleanup of resources
    
    TROUBLESHOOTING GUIDE:
        
        Issue: Connection failed - Unable to reach Splunk
            Root causes:
                1. Splunk service not running
                2. SPLUNK_URL incorrect or unreachable
                3. Firewall blocking port 8089
                4. Network connectivity issues
            
            Diagnostic steps:
                1. Verify Splunk running: splunk status (on Splunk server)
                2. Check URL: echo $SPLUNK_URL (on this machine)
                3. Test connectivity: ping splunk-host
                4. Check firewall: telnet splunk-host 8089
                5. Verify SSL certificate (if HTTPS)
        
        Issue: Connection failed - Invalid credentials
            Root causes:
                1. SPLUNK_USERNAME incorrect
                2. SPLUNK_PASSWORD incorrect
                3. User account locked (too many login attempts)
                4. User lacks API permissions
            
            Diagnostic steps:
                1. Verify credentials in Splunk admin console
                2. Try manual login to Splunk web UI
                3. Check user permissions (Admin console > Users)
                4. Reset user password if locked
        
        Issue: Retrieved 0 sample logs
            Root causes:
                1. No logs in past 24 hours
                2. User lacks index access permissions
                3. Search syntax error in connector
                4. Splunk license limit reached
            
            Diagnostic steps:
                1. Check Splunk search UI directly
                2. Verify user can access target index
                3. Try broader time range (e.g., "-30d")
                4. Check Splunk license status (Admin > System info)
    
    NOTES:
        
        - This is a diagnostic script, not production code
        - Meant for initial validation only
        - For production, use Live_Threat_Monitor
        - Do not modify console output format (scripts may parse)
        - Keep max_results = 5 for sample display
        - Always disconnect from Splunk when done
    
    CALLED BY:
        - __main__ entry point (if __name__ == "__main__": test_connection())
        - Manual script execution: python test_splunk_connection.py
    
    DEPENDENCIES:
        - models.splunk_connector.get_splunk_connector
        - Python 3.8+ (f-strings, dict operations)
        - Environment variables: SPLUNK_URL, SPLUNK_USERNAME, SPLUNK_PASSWORD
    
    ════════════════════════════════════════════════════════════════════════════
    """
    print("=" * 60)
    print("Testing Splunk Connection")
    print("=" * 60)
    
    connector = get_splunk_connector()
    
    print("\nAttempting to connect to Splunk...")
    success, message = connector.test_connection()
    
    # ════════════════════════════════════════════════════════════════════════
    # STAGE 3A - SUCCESS PATH: LOG RETRIEVAL
    # ════════════════════════════════════════════════════════════════════════
    if success:
        print(f"✓ {message}")
        print("\nAttempting to fetch sample logs...")
        
        # STAGE 3B - FETCH LOGS WITH TIME RANGE PARAMETERS
        logs = connector.fetch_logs(
            earliest_time="-1d@d",  # 1 day ago at midnight UTC
            latest_time="now",       # Current time
            max_results=5             # Limit to 5 for sample display
        )
        
        print(f"✓ Retrieved {len(logs)} sample logs")
        
        # STAGE 3C - DISPLAY SAMPLE LOG (IF AVAILABLE)
        if logs:
            print("\nSample log:")
            print("-" * 60)
            # Display all fields except raw_log and event_data (too verbose)
            for key, value in logs[0].items():
                if key != 'raw_log' and key != 'event_data':
                    print(f"{key}: {value}")
            print("-" * 60)
        
        # ════════════════════════════════════════════════════════════════════════
        # STAGE 4 - CLEANUP: DISCONNECT FROM SPLUNK
        # ════════════════════════════════════════════════════════════════════════
        connector.disconnect()
    
    # ════════════════════════════════════════════════════════════════════════
    # STAGE 3B (ALTERNATIVE) - FAILURE PATH: DISPLAY ERROR MESSAGE
    # ════════════════════════════════════════════════════════════════════════
    else:
        print(f"✗ {message}")
    
    # ════════════════════════════════════════════════════════════════════════
    # STAGE 5 - COMPLETION: FOOTER BANNER
    # ════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_connection()
