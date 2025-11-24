"""
Test fetching message_rfc822 logs specifically from Splunk
"""

from models.splunk_connector import get_splunk_connector
import json

def test_message_rfc822():
    print("=" * 60)
    print("Testing message_rfc822 log retrieval from Splunk")
    print("=" * 60)
    
    connector = get_splunk_connector()
    
    print("\n1. Connecting to Splunk...")
    if not connector.connect():
        print("✗ Failed to connect")
        return
    print("✓ Connected successfully")
    
    # Test 1: Search for all message_rfc822 logs
    print("\n2. Searching for message_rfc822 logs...")
    logs = connector.fetch_logs(
        earliest_time="-30d",
        latest_time="now",
        search_query="search index=* sourcetype=message_rfc822",
        max_results=500
    )
    
    print(f"✓ Found {len(logs)} message_rfc822 logs")
    
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
    
    connector.disconnect()
    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_message_rfc822()
