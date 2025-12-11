"""Generate test data for MTTD analysis with realistic detection delays"""
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import random

# Create data directory
data_dir = Path(__file__).parent.parent / "data"
data_dir.mkdir(exist_ok=True)

# Generate attack events with occurrence times
events = []
base_time = datetime.now() - timedelta(hours=12)

print("Generating attack/phishing events...")

# Generate 80 phishing/attack events
for i in range(80):
    occurrence_time = base_time + timedelta(minutes=i*5 + random.randint(0, 3))
    events.append({
        "event_id": f"ATK-{i+1:04d}",
        "occurrence_time": occurrence_time.isoformat(),
        "event_time": occurrence_time.strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": occurrence_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": random.choice(["phishing_email", "port_scan", "sql_injection", "brute_force", "malware_download"]),
        "sourcetype": random.choice(["message_rfc822", "snort:alert", "pfsense:syslog", "wineventlog:security"]),
        "src_ip": f"{random.randint(100, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "dest_ip": f"192.168.1.{random.randint(10, 100)}",
        "severity": random.choice(["high", "critical", "medium"]),
        "campaign_id": f"CAMP-{random.randint(1, 10):03d}",
        "description": random.choice([
            "Phishing email with malicious attachment",
            "Port scanning activity detected",
            "SQL injection attempt on web server",
            "Multiple failed login attempts",
            "Malware download from suspicious domain"
        ])
    })

events_df = pd.DataFrame(events)

# Save events
events_path = data_dir / "attack_simulation_results.csv"
events_df.to_csv(events_path, index=False)
print(f"✓ Generated {len(events_df)} attack events: {events_path}")

# Generate detections with realistic delays
detections = []
detected_count = 0

print("\nGenerating AI detections with realistic MTTD...")

for idx, event in events_df.iterrows():
    occurrence = datetime.fromisoformat(event['occurrence_time'])
    
    # 90% detection rate
    if random.random() < 0.90:
        detected_count += 1
        
        # Realistic detection delays based on event type:
        # - Fast detection (5-30s): Real-time systems like IDS/IPS
        # - Medium detection (30s-5min): SIEM correlation rules
        # - Slow detection (5-30min): Manual analysis, complex patterns
        
        event_type = event['event_type']
        sourcetype = event['sourcetype']
        
        if sourcetype == "snort:alert":
            # IDS is fast (5-30 seconds)
            detection_delay = random.uniform(5, 30)
        elif event_type == "phishing_email":
            # Email analysis takes longer (1-10 minutes)
            detection_delay = random.uniform(60, 600)
        elif event_type in ["sql_injection", "brute_force"]:
            # Pattern-based detection is medium (30s-3min)
            detection_delay = random.uniform(30, 180)
        else:
            # Other events (1-5 minutes)
            detection_delay = random.uniform(60, 300)
        
        # Add Splunk ingestion delay (typically 20-60 seconds)
        splunk_delay = random.uniform(20, 60)
        
        # Total delay
        total_delay = detection_delay + splunk_delay
        
        detection_time = occurrence + timedelta(seconds=total_delay)
        
        detections.append({
            "event_id": event['event_id'],
            "detection_time": detection_time.isoformat(),
            "detected_at": detection_time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": detection_time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_detected": True,
            "ai_verdict": "malicious",
            "confidence": random.uniform(0.75, 0.99),
            "detection_method": random.choice(["ML_model", "SIEM_rule", "IDS_signature", "anomaly_detection"]),
            "mttd_actual_seconds": detection_delay,  # Without Splunk delay
            "total_delay_seconds": total_delay  # Including Splunk delay
        })

detections_df = pd.DataFrame(detections)

# Save detections
detections_path = data_dir / "detected_from_db.csv"
detections_df.to_csv(detections_path, index=False)
print(f"✓ Generated {len(detections_df)} detections: {detections_path}")

# Calculate expected MTTD
if not detections_df.empty:
    avg_mttd_with_splunk = detections_df['total_delay_seconds'].mean()
    avg_mttd_without_splunk = detections_df['mttd_actual_seconds'].mean()
    median_mttd = detections_df['mttd_actual_seconds'].median()
    
    print(f"\nExpected Metrics:")
    print(f"  Total events: {len(events_df)}")
    print(f"  Detected: {detected_count} ({detected_count/len(events_df)*100:.1f}%)")
    print(f"  Undetected: {len(events_df) - detected_count}")
    print(f"\n  Expected Avg MTTD (with Splunk delay): {avg_mttd_with_splunk:.1f}s ({avg_mttd_with_splunk/60:.1f}min)")
    print(f"  Expected Avg MTTD (adjusted): {avg_mttd_without_splunk:.1f}s ({avg_mttd_without_splunk/60:.1f}min)")
    print(f"  Expected Median MTTD: {median_mttd:.1f}s ({median_mttd/60:.1f}min)")
    print(f"  Expected Avg Splunk Delay: ~40s")
    
    # By event type
    print(f"\n  MTTD by Event Type:")
    for event_type in events_df['event_type'].unique():
        type_events = events_df[events_df['event_type'] == event_type]
        type_detections = detections_df[detections_df['event_id'].isin(type_events['event_id'])]
        if not type_detections.empty:
            avg = type_detections['mttd_actual_seconds'].mean()
            print(f"    {event_type}: {avg:.1f}s ({avg/60:.1f}min)")
