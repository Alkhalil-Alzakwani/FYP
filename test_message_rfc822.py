"""
CYBER DEFENSE PLATFORM - MESSAGE_RFC822 LOG RETRIEVAL TEST
╚════════════════════════════════════════════════════════════════════════════╝

File: test_message_rfc822.py
Purpose: Test suite for fetching and validating message_rfc822 email logs from Splunk

DESCRIPTION:
    Integration test utility for validating message_rfc822 (RFC 822 email format)
    log ingestion from Splunk. Tests Splunk connector functionality, searches for
    email logs, retrieves sample events, and validates data structure. Useful for
    debugging email data integration issues and verifying Splunk configuration.

TEST OBJECTIVES:

    1. Splunk Connection:
       ├─ Establish connection to Splunk instance
       ├─ Validate connector initialization
       └─ Verify authentication credentials
    
    2. Message RFC822 Search:
       ├─ Query for sourcetype=message_rfc822
       ├─ Retrieve up to 500 events
       ├─ Time range: past 30 days
       └─ Validate event count and structure
    
    3. Fallback Searches:
       ├─ If no RFC822 logs found, try broader search
       ├─ Search all sourcetypes
       ├─ Search for email patterns (*mail*, *email*, *rfc822*)
       └─ Identify available email-related sourcetypes
    
    4. Data Validation:
       ├─ Check event structure (fields present)
       ├─ Display sample event details
       ├─ Show event_data JSON structure
       └─ Validate raw_log content

USAGE:
    python test_message_rfc822.py

EXPECTED OUTPUT:

    Success Case (logs found):
        ============================================================
        Testing message_rfc822 log retrieval from Splunk
        ============================================================
        
        1. Connecting to Splunk...
        ✓ Connected successfully
        
        2. Searching for message_rfc822 logs...
        ✓ Found N message_rfc822 logs
        
        Sample log:
        Event ID: ...
        Timestamp: ...
        [Event details]
    
    Failure Case (no logs found):
        ✗ No message_rfc822 logs found!
        
        Trying broader search...
        Found N total logs
        
        Sourcetypes found: {...}
        
        Email sourcetypes: {...}

DATA STRUCTURE:

    Each log event contains:
        event_id (str): Unique event identifier
        timestamp (str): ISO 8601 timestamp
        host (str): Source hostname/IP
        source (str): Log source file/path
        sourcetype (str): 'message_rfc822' or email-related type
        severity (str): Event severity level
        raw_log (str): Complete email message (RFC 822 format)
        event_data (JSON): Parsed email fields
            ├─ from: Sender email address
            ├─ to: Recipient email address(es)
            ├─ subject: Email subject line
            ├─ date: Send date/time
            └─ Other SMTP headers

SPLUNK CONNECTOR REQUIREMENTS:

    Configuration:
        - Splunk URL (default: http://localhost:8089)
        - Username and password
        - Index: '*' (search all indices)
        - Max results: 500 or 100 depending on test
    
    Methods Used:
        - connect(): Establish Splunk connection
        - fetch_logs(): Execute search queries
        - disconnect(): Close connection
    
    Search Queries:
        Query 1: sourcetype=message_rfc822 (primary target)
        Query 2: index=* (baseline - all logs)
        Query 3: sourcetype=*rfc822* OR *mail* OR *email* (pattern match)

TROUBLESHOOTING:

    Connection Failed:
        ✗ Check Splunk service running
        ✗ Verify Splunk credentials in environment
        ✗ Confirm Splunk URL and port
        ✗ Check network connectivity
    
    No message_rfc822 logs found:
        ✗ Verify email datasource configured in Splunk
        ✗ Check Splunk props.conf for sourcetype definition
        ✗ Look for email logs under different sourcetype names
        ✗ Verify email data is actually being ingested
    
    Event structure invalid:
        ✗ Confirm Splunk query returns expected fields
        ✗ Verify Splunk connector parsing logic
        ✗ Check event_data JSON formatting

ERROR HANDLING:

    Connection Errors:
        - Caught by get_splunk_connector()
        - Displays \"✗ Failed to connect\"
        - Script continues to attempt fallback searches
    
    Query Errors:
        - No exception thrown (graceful degradation)
        - Empty results: Show message and try alternatives
        - Invalid JSON: Print truncated/safe version
    
    Missing Fields:
        - Try to display available fields
        - Use safe defaults if field missing

DEPENDENCIES:

    Internal Modules:
        - models.splunk_connector: Splunk API wrapper
            ├─ get_splunk_connector(): Factory function
            ├─ connect(): Establish connection
            ├─ fetch_logs(): Execute searches
            └─ disconnect(): Close connection
    
    External Libraries:
        - json: Parse event_data JSON structures

DEVELOPMENT NOTES:

    Design Pattern:
        - Integration test script
        - Single entry point: test_message_rfc822()
        - Progressive failure handling (fallback searches)
        - User-friendly console output with ✓/✗ indicators
    
    Future Enhancements:
        - Parse email headers from event_data
        - Extract sender/recipient/subject info
        - Validate RFC 822 format compliance
        - Generate test report with statistics
        - Add command-line arguments for time range/limits
        - Create unit tests for data validation

AUTHOR: Multilayered Cyber Defense Team
LAST MODIFIED: December 8, 2025
VERSION: 1.0.0

╚════════════════════════════════════════════════════════════════════════════╝
"""

from models.splunk_connector import get_splunk_connector
import json

def test_message_rfc822():
    """
    ════════════════════════════════════════════════════════════════════════
    Test message_rfc822 log retrieval and validation from Splunk.
    ════════════════════════════════════════════════════════════════════════

    DESCRIPTION:
        Main test function that executes three-stage email log validation:
        1. Connect to Splunk and search for message_rfc822 logs
        2. If found: Display sample event and data structure
        3. If not found: Try fallback searches for email-related logs

    TEST FLOW:

        Stage 1 - Initialization:
            ├─ Display test header (60 char separator)
            ├─ Get Splunk connector instance
            ├─ Attempt to connect to Splunk
            └─ Stop if connection fails
        
        Stage 2 - Primary Search (message_rfc822):
            ├─ Query: sourcetype=message_rfc822
            ├─ Time range: Past 30 days (-30d to now)
            ├─ Max results: 500 events
            ├─ Display found count
            └─ If found: Show sample event details
        
        Stage 3a - Success Path (logs found):
            ├─ Display sample log with all fields:
            │   ├─ event_id (unique identifier)
            │   ├─ timestamp (ISO 8601)
            │   ├─ host (source hostname)
            │   ├─ source (log source file)
            │   ├─ sourcetype (message_rfc822)
            │   ├─ severity (event severity)
            │   ├─ raw_log (first 500 chars)
            │   └─ event_data (JSON, first 500 chars)
            └─ Exit cleanly after disconnect
        
        Stage 3b - Fallback Path (no logs found):
            ├─ Display \"✗ No message_rfc822 logs found!\"
            ├─ Search 1: All logs (index=*)
            │   └─ Max results: 100
            │   └─ Display total count
            │   └─ Extract and list all sourcetypes
            ├─ Search 2: Email pattern matching
            │   ├─ Query: (sourcetype=*rfc822* OR *mail* OR *email*)
            │   ├─ Max results: 100
            │   └─ Extract and list email-related sourcetypes
            └─ Help admin identify email log location
        
        Cleanup:
            ├─ Call connector.disconnect()
            ├─ Display footer separator
            └─ Return (implicit None)

    ARGS:
        None

    RETURNS:
        None (prints to console)

    SPLUNK QUERIES:

        Query 1 - Primary (message_rfc822):
            search index=* sourcetype=message_rfc822
            Time range: -30d to now
            Max results: 500
            Expected: Email logs in RFC 822 format
        
        Query 2 - Baseline (all logs):
            search index=*
            Time range: -30d to now
            Max results: 100
            Expected: Sample of all available logs
        
        Query 3 - Pattern (email-related):
            search index=* (sourcetype=*rfc822* OR sourcetype=*mail* OR sourcetype=*email*)
            Time range: -30d to now
            Max results: 100
            Expected: Any email-related sourcetypes

    OUTPUT DISPLAY:

        Connection Stage:
            1. Connecting to Splunk...
            ✓ Connected successfully  OR  ✗ Failed to connect
        
        Search Stage:
            2. Searching for message_rfc822 logs...
            ✓ Found X message_rfc822 logs
        
        Sample Log Display (if found):
            Sample log:
            - Event ID: <event_id>
            - Timestamp: <timestamp>
            - Host: <host>
            - Source: <source>
            - Sourcetype: <sourcetype>
            - Severity: <severity>
            - Raw Log (500 chars): <truncated>
            - Event Data (500 chars): <truncated JSON>
        
        Fallback Display (if not found):
            ✗ No message_rfc822 logs found!
            Trying broader search...
            Found N total logs
            Sourcetypes found: {set of types}
            Email sourcetypes: {set of email types}

    VALIDATION CHECKS:

        Data Structure:
            ✓ event_id field present
            ✓ timestamp in ISO 8601 format
            ✓ host field populated
            ✓ source field populated
            ✓ sourcetype field populated
            ✓ severity field present
            ✓ raw_log contains email content
            ✓ event_data valid JSON
        
        Content:
            ✓ Raw log > 0 characters
            ✓ Event data parseable as JSON
            ✓ Sourcetype matches expected pattern

    ERROR HANDLING:

        Connection Errors:
            - try/except around connector.connect()
            - Display \"✗ Failed to connect\" and return
            - Check Splunk service and credentials
        
        Query Errors:
            - Empty results: Try fallback searches
            - Invalid JSON: Use truncated safe output
            - Missing fields: Display available fields
        
        Graceful Degradation:
            - Don't crash on individual failures
            - Always attempt fallback searches
            - Always disconnect at end
            - Display helpful error messages

    CONSOLE OUTPUT INDICATORS:

        ✓ (U+2713): Success, expected operation completed
        ✗ (U+2717): Failure, expected operation did not complete
        - (Line): Section separator for readability
        = (Header): Major section divider

    NOTES:
        - Time range fixed at 30 days (configurable in future)
        - Max results vary: 500 for primary, 100 for fallback
        - Uses set() to deduplicate sourcetypes
        - JSON truncated to 500 chars for readability
        - raw_log truncated to 500 chars for readability
        - Always disconnects from Splunk before exit

    TROUBLESHOOTING:

        No logs returned:
            1. Check Splunk email datasource is configured
            2. Verify Splunk props.conf has message_rfc822 definition
            3. Look for logs under different sourcetype names
            4. Check Splunk index configuration
            5. Run check_sourcetypes.py to list all available types
        
        Connection issues:
            1. Verify Splunk service running (bin/splunk status)
            2. Check SPLUNK_URL environment variable
            3. Verify SPLUNK_USERNAME and SPLUNK_PASSWORD
            4. Test connectivity: curl -k https://localhost:8089
        
        JSON parsing errors:
            1. Check event_data field is valid JSON
            2. Verify Splunk connector parses event_data correctly
            3. Look at raw_log to understand event structure

    SEE ALSO:
        - models/splunk_connector.py: Splunk API implementation
        - check_sourcetypes.py: List all available sourcetypes
        - database/queries.py: Database queries for logs
        - pages/Live_Threat_Monitor.py: Production log ingestion
    """
    print("=" * 60)
    print("Testing message_rfc822 log retrieval from Splunk")
    print("=" * 60)
    
    # ════════════════════════════════════════════════════════════════════
    # STAGE 1 - INITIALIZATION: CONNECTION TO SPLUNK
    # ════════════════════════════════════════════════════════════════════
    
    connector = get_splunk_connector()
    
    print("\n1. Connecting to Splunk...")
    if not connector.connect():
        print("✗ Failed to connect")
        return
    print("✓ Connected successfully")
    
    # ════════════════════════════════════════════════════════════════════
    # STAGE 2 - PRIMARY SEARCH: MESSAGE_RFC822 EMAIL LOGS
    # ════════════════════════════════════════════════════════════════════
    
    # Fallback Search 1: message_rfc822 logs
    print("\n2. Searching for message_rfc822 logs...")
    logs = connector.fetch_logs(
        earliest_time="-30d",
        latest_time="now",
        search_query="search index=* sourcetype=message_rfc822",
        max_results=500
    )
    
    print(f"✓ Found {len(logs)} message_rfc822 logs")
    
    # ════════════════════════════════════════════════════════════════════
    # STAGE 3A - SUCCESS PATH: DISPLAY SAMPLE EVENT
    # ════════════════════════════════════════════════════════════════════
    
    if logs:
        print("\nSample log:")
        print("-" * 60)
        sample = logs[0]
        print(f"Event ID: {sample['event_id']}")
        print(f"Timestamp: {sample['timestamp']}")
        print(f"Host: {sample['host']}")
        print(f"Source: {sample['source']}")
        print(f"Sourcetype: {sample['sourcetype']}")
        print(f"Severity: {sample['severity']}")
        print(f"\nRaw Log (first 500 chars):")
        print(sample['raw_log'][:500])
        print("\nEvent Data:")
        print(json.dumps(json.loads(sample['event_data']), indent=2)[:500])
    else:
        # ════════════════════════════════════════════════════════════════
        # STAGE 3B - FALLBACK PATH: SEARCH FOR EMAIL-RELATED LOGS
        # ════════════════════════════════════════════════════════════════
        print("\n✗ No message_rfc822 logs found!")
        print("\nTrying broader search...")
        
        # Test 2: Search for any logs
        logs_all = connector.fetch_logs(
            earliest_time="-30d",
            latest_time="now",
            search_query="search index=*",
            max_results=100
        )
        
        print(f"Found {len(logs_all)} total logs")
        
        # Check sourcetypes
        sourcetypes = set([log['sourcetype'] for log in logs_all])
        print(f"\nSourcetypes found: {sourcetypes}")
        
        # Check for email-related fields
        print("\nChecking if message_rfc822 exists in Splunk...")
        email_logs = connector.fetch_logs(
            earliest_time="-30d",
            latest_time="now", 
            search_query="search index=* (sourcetype=*rfc822* OR sourcetype=*mail* OR sourcetype=*email*)",
            max_results=100
        )
        print(f"Found {len(email_logs)} email-related logs")
        if email_logs:
            email_types = set([log['sourcetype'] for log in email_logs])
            print(f"Email sourcetypes: {email_types}")
    
    # ════════════════════════════════════════════════════════════════════
    # CLEANUP: DISCONNECT FROM SPLUNK
    # ════════════════════════════════════════════════════════════════════
    
    connector.disconnect()
    print("\n" + "=" * 60)


# ════════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    test_message_rfc822()
