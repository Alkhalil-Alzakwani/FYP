"""
models/splunk_connector.py

Splunk API connector for fetching and syncing logs
"""

import splunklib.client as client
import splunklib.results as results
from datetime import datetime, timedelta
import json
import hashlib
import yaml
from pathlib import Path


class SplunkConnector:
    """Handle Splunk API connections and log retrieval"""
    
    def __init__(self, config_path=None):
        """
        Initialize Splunk connector
        
        Args:
            config_path (str): Path to splunk_config.yaml
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "splunk_config.yaml"
        
        self.config = self._load_config(config_path)
        self.service = None
        
    def _load_config(self, config_path):
        """Load Splunk configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading Splunk config: {e}")
            return {}
    
    def connect(self):
        """
        Establish connection to Splunk
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            splunk_config = self.config.get('splunk', {})
            
            # Disable SSL verification for local testing (enable in production)
            self.service = client.connect(
                host=splunk_config.get('host', 'localhost'),
                port=splunk_config.get('port', 8089),
                username=splunk_config.get('username'),
                password=splunk_config.get('password'),
                scheme=splunk_config.get('scheme', 'https'),
                verify=False  # Set to True in production with valid SSL cert
            )
            
            return True
            
        except Exception as e:
            print(f"Splunk connection error: {e}")
            return False
    
    def disconnect(self):
        """Close Splunk connection"""
        if self.service:
            self.service.logout()
            self.service = None
    
    def fetch_logs(self, earliest_time="-30d@d", latest_time="now", search_query=None, max_results=10000):
        """
        Fetch logs from Splunk
        
        Args:
            earliest_time (str): Start time for search (Splunk time format)
            latest_time (str): End time for search (Splunk time format)
            search_query (str): Custom search query
            max_results (int): Maximum number of results to return
            
        Returns:
            list: List of log dictionaries
        """
        if not self.service:
            if not self.connect():
                return []
        
        try:
            # Use custom query or default from config
            if search_query is None:
                search_config = self.config.get('search', {})
                # Default query fetches only relevant sourcetypes for the project
                search_query = search_config.get('query', 'search index=* (sourcetype=pfsense:syslog OR sourcetype=snort:alert OR sourcetype=syslog OR sourcetype=message_rfc822 OR sourcetype=WinEventLog:System OR sourcetype=WinEventLog:Security)')
            
            # Create search job with better parameters for retrieving all results
            kwargs_search = {
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "count": 0,  # No limit on results returned
                "max_count": max_results,
                "output_mode": "json"
            }
            
            job = self.service.jobs.create(search_query, **kwargs_search)
            
            # Wait for job to complete with progress updates
            print("Waiting for Splunk search job to complete...")
            while not job.is_done():
                stats = job._state.content
                progress = float(stats.get('doneProgress', 0)) * 100
                scan_count = int(stats.get('scanCount', 0))
                result_count = int(stats.get('resultCount', 0))
                print(f"Progress: {progress:.1f}% | Scanned: {scan_count} | Results: {result_count}", end='\r')
            
            # Get final result count
            result_count = int(job._state.content.get('resultCount', 0))
            print(f"\nSearch complete! Total results available: {result_count}")
            
            # Get ALL results using proper pagination
            logs = []
            offset = 0
            batch_size = 10000  # Splunk default max per request
            
            while offset < result_count and len(logs) < max_results:
                print(f"Fetching batch: offset={offset}, batch_size={batch_size}")
                
                # Use results() method with proper parameters
                result_stream = job.results(
                    output_mode='json',
                    count=batch_size,
                    offset=offset
                )
                
                result_data = json.loads(result_stream.read())
                results = result_data.get('results', [])
                
                if not results:
                    print(f"No more results at offset {offset}")
                    break
                
                print(f"Processing {len(results)} logs from this batch...")
                for result in results:
                    try:
                        log_entry = self._parse_log_entry(result)
                        logs.append(log_entry)
                    except Exception as e:
                        print(f"Error parsing log: {e}")
                        continue
                
                offset += len(results)
                print(f"Total logs fetched so far: {len(logs)}")
            
            # Clean up job
            job.cancel()
            
            print(f"\nFinal: Fetched {len(logs)} logs from Splunk")
            
            return logs
            
        except Exception as e:
            print(f"Error fetching Splunk logs: {e}")
            return []
    
    def fetch_logs_since(self, last_timestamp, max_results=10000):
        """
        Fetch logs since a specific timestamp
        
        Args:
            last_timestamp (str): ISO format timestamp
            max_results (int): Maximum number of results to return
            
        Returns:
            list: List of new log dictionaries
        """
        try:
            # Convert ISO timestamp to Splunk time format
            dt = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))
            earliest_time = dt.strftime("%Y-%m-%dT%H:%M:%S")
            
            return self.fetch_logs(
                earliest_time=earliest_time,
                latest_time="now",
                max_results=max_results
            )
            
        except Exception as e:
            print(f"Error fetching logs since timestamp: {e}")
            return []
    
    def _parse_log_entry(self, result):
        """
        Parse a single Splunk log entry
        
        Args:
            result (dict): Raw Splunk result
            
        Returns:
            dict: Parsed log entry
        """
        # Get timestamp
        timestamp = result.get('_time', datetime.now().isoformat())
        
        # Get host and source
        host = result.get('host', 'unknown')
        source = result.get('source', 'unknown')
        sourcetype = result.get('sourcetype', 'unknown')
        
        # Generate unique event ID from multiple fields to ensure uniqueness across all sourcetypes
        raw_log = result.get('_raw', '')
        unique_components = [
            str(timestamp),
            str(host),
            str(source),
            str(sourcetype),
            raw_log[:100] if raw_log else ''  # First 100 chars of raw log
        ]
        unique_string = '|'.join(unique_components)
        event_id = hashlib.md5(unique_string.encode()).hexdigest()
        
        # Extract severity (if available)
        severity = self._determine_severity(result)
        
        # Parse event data - extract all non-internal fields
        event_data = {}
        
        # List of common fields across different sourcetypes
        important_fields = [
            # Windows Event Log fields
            'LogName', 'EventCode', 'EventType', 'ComputerName', 'User', 'Message', 
            'Category', 'SourceName', 'RecordNumber', 'Keywords',
            # Snort/IDS fields
            'signature', 'classification', 'priority', 'src_ip', 'dest_ip', 'src_port', 'dest_port',
            # pfSense/Firewall fields  
            'action', 'protocol', 'direction', 'interface',
            # Syslog fields
            'facility', 'severity', 'app_name', 'process_id',
            # Email fields
            'sender', 'recipient', 'subject', 'message_id'
        ]
        
        # Extract important fields first
        for field in important_fields:
            if field in result:
                event_data[field] = result[field]
        
        # Add any other non-internal fields that weren't already captured
        for k, v in result.items():
            if not k.startswith('_') and k not in event_data and k not in ['raw', 'time', 'host', 'source', 'sourcetype']:
                event_data[k] = v
        
        return {
            'event_id': event_id,
            'timestamp': timestamp,
            'host': host,
            'source': source,
            'sourcetype': sourcetype,
            'event_data': json.dumps(event_data) if event_data else '{}',
            'severity': severity,
            'raw_log': raw_log if raw_log else json.dumps(result, sort_keys=True),
            'indexed_at': result.get('_indextime', timestamp)
        }
    
    def _determine_severity(self, result):
        """
        Determine log severity based on content
        
        Args:
            result (dict): Log entry
            
        Returns:
            str: Severity level (critical/high/medium/low/info)
        """
        # Check for Windows Event Log EventType
        # EventType: 1=Error, 2=Warning, 3=Information, 4=Success Audit, 5=Failure Audit
        event_type = result.get('EventType', '')
        if event_type:
            event_type_str = str(event_type)
            if event_type_str == '1':  # Error
                return 'high'
            elif event_type_str == '2':  # Warning
                return 'medium'
            elif event_type_str == '3':  # Information
                return 'info'
            elif event_type_str == '4':  # Success Audit
                return 'low'
            elif event_type_str == '5':  # Failure Audit
                return 'high'
        
        # Check for explicit severity fields
        if 'severity' in result:
            return result['severity'].lower()
        if 'level' in result:
            level = str(result['level']).lower()
            if 'error' in level or 'fail' in level:
                return 'high'
            elif 'warn' in level:
                return 'medium'
            elif 'info' in level:
                return 'info'
        
        # Check raw log content
        raw = result.get('_raw', '').lower()
        
        # Keyword-based detection
        if any(word in raw for word in ['critical', 'fatal', 'emergency']):
            return 'critical'
        elif any(word in raw for word in ['error', 'fail', 'denied', 'attack']):
            return 'high'
        elif any(word in raw for word in ['warning', 'warn', 'suspicious']):
            return 'medium'
        elif any(word in raw for word in ['info', 'information', 'success']):
            return 'info'
        else:
            return 'low'
    
    def test_connection(self):
        """
        Test Splunk connection
        
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            if self.connect():
                # Try a simple search
                job = self.service.jobs.create("search index=* | head 1")
                while not job.is_done():
                    pass
                job.cancel()
                
                return (True, "Connection successful")
            else:
                return (False, "Failed to establish connection")
                
        except Exception as e:
            return (False, f"Connection test failed: {str(e)}")


# Helper function for easy access
def get_splunk_connector():
    """Get a configured Splunk connector instance"""
    return SplunkConnector()
