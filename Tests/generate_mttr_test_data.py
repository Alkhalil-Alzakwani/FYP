"""Generate test data for MTTR analysis with response actions"""
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import random

# Create data directory
data_dir = Path(__file__).parent.parent / "data"
data_dir.mkdir(exist_ok=True)

# Load existing detections
detections_path = data_dir / "detected_from_db.csv"
if not detections_path.exists():
    print("Error: No detections file found. Run generate_mttd_test_data.py first.")
    exit(1)

detections_df = pd.read_csv(detections_path)
print(f"Loaded {len(detections_df)} detections")

# Generate response actions
responses = []
responded_count = 0

print("\nGenerating response actions...")

for idx, detection in detections_df.iterrows():
    detection_time = datetime.fromisoformat(detection['detection_time'])
    
    # 85% response rate (some detections may not require immediate action)
    if random.random() < 0.85:
        responded_count += 1
        
        # Determine if automated or manual response
        # High-confidence detections (>0.90) -> mostly automated
        # Lower confidence -> manual review
        confidence = detection.get('confidence', 0.8)
        threat_method = detection.get('detection_method', '')
        
        if confidence > 0.90 or 'IDS_signature' in str(threat_method):
            # Automated response (fast: 1-30 seconds)
            response_type = 'automated'
            response_delay = random.uniform(1, 30)
            
            # Automated actions
            action = random.choice([
                'block_ip_firewall',
                'quarantine_email',
                'isolate_host',
                'block_domain',
                'kill_process'
            ])
        else:
            # Manual response (slower: 2-15 minutes for analysis)
            response_type = 'manual'
            response_delay = random.uniform(120, 900)  # 2-15 minutes
            
            # Manual actions
            action = random.choice([
                'analyst_review',
                'escalate_to_soc',
                'request_more_info',
                'block_ip_firewall',
                'create_ticket',
                'notify_admin'
            ])
        
        response_time = detection_time + timedelta(seconds=response_delay)
        
        responses.append({
            "event_id": detection['event_id'],
            "detection_id": detection['event_id'],
            "response_time": response_time.isoformat(),
            "responded_at": response_time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": response_time.strftime("%Y-%m-%d %H:%M:%S"),
            "response_type": response_type,
            "type": response_type,
            "action": action,
            "response_action": action,
            "mttr_seconds": response_delay,
            "analyst": "AUTO-SYSTEM" if response_type == 'automated' else random.choice([
                "analyst_john", "analyst_sarah", "analyst_mike", "soc_lead"
            ]),
            "status": "completed",
            "notes": f"{response_type.capitalize()} response: {action.replace('_', ' ')}"
        })

responses_df = pd.DataFrame(responses)

# Save responses
responses_path = data_dir / "response_actions.csv"
responses_df.to_csv(responses_path, index=False)
print(f"Generated {len(responses_df)} response actions: {responses_path}")

# Calculate expected MTTR
if not responses_df.empty:
    avg_mttr = responses_df['mttr_seconds'].mean()
    median_mttr = responses_df['mttr_seconds'].median()
    
    automated = responses_df[responses_df['response_type'] == 'automated']
    manual = responses_df[responses_df['response_type'] == 'manual']
    
    avg_auto = automated['mttr_seconds'].mean() if not automated.empty else 0
    avg_manual = manual['mttr_seconds'].mean() if not manual.empty else 0
    
    print(f"\nExpected Metrics:")
    print(f"  Total detections: {len(detections_df)}")
    print(f"  Responded: {responded_count} ({responded_count/len(detections_df)*100:.1f}%)")
    print(f"  Unresponded: {len(detections_df) - responded_count}")
    print(f"\n  Response breakdown:")
    print(f"    Automated: {len(automated)} ({len(automated)/len(responses_df)*100:.1f}%)")
    print(f"    Manual: {len(manual)} ({len(manual)/len(responses_df)*100:.1f}%)")
    print(f"\n  Expected Avg MTTR: {avg_mttr:.1f}s ({avg_mttr/60:.1f}min)")
    print(f"  Expected Median MTTR: {median_mttr:.1f}s ({median_mttr/60:.1f}min)")
    print(f"  Expected Automated MTTR: {avg_auto:.1f}s")
    print(f"  Expected Manual MTTR: {avg_manual:.1f}s ({avg_manual/60:.1f}min)")
    
    if avg_auto > 0 and avg_manual > 0:
        speedup = avg_manual / avg_auto
        print(f"\n  Automation speedup: {speedup:.1f}x faster")
    
    # By action type
    print(f"\n  Top actions:")
    action_counts = responses_df['action'].value_counts().head(5)
    for action, count in action_counts.items():
        print(f"    {action}: {count}")
