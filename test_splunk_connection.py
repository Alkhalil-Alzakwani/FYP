"""
Test script to verify Splunk connection
"""

from models.splunk_connector import get_splunk_connector

def test_connection():
    """Test the Splunk connection"""
    print("=" * 60)
    print("Testing Splunk Connection")
    print("=" * 60)
    
    connector = get_splunk_connector()
    
    print("\nAttempting to connect to Splunk...")
    success, message = connector.test_connection()
    
    if success:
        print(f"✓ {message}")
        print("\nAttempting to fetch sample logs...")
        
        logs = connector.fetch_logs(
            earliest_time="-1d@d",
            latest_time="now",
            max_results=5
        )
        
        print(f"✓ Retrieved {len(logs)} sample logs")
        
        if logs:
            print("\nSample log:")
            print("-" * 60)
            for key, value in logs[0].items():
                if key != 'raw_log' and key != 'event_data':
                    print(f"{key}: {value}")
        
        connector.disconnect()
    else:
        print(f"✗ {message}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_connection()
