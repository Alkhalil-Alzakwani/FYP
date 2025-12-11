"""Demo script to generate sample data and test False Positive Rate calculation"""
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import random

# Create data directory if it doesn't exist
data_dir = Path(__file__).parent.parent / "data"
data_dir.mkdir(exist_ok=True)

# Generate sample logs with benign and malicious events
sample_logs = []
base_time = datetime.now() - timedelta(days=7)

# Generate 100 benign events (normal traffic)
for i in range(100):
    timestamp = base_time + timedelta(hours=i)
    sample_logs.append({
        "event_id": f"EVT-BENIGN-{i:04d}",
        "timestamp": timestamp.isoformat(),
        "_time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "sourcetype": random.choice(["syslog", "wineventlog:system", "pfsense:syslog"]),
        "action": random.choice(["allow", "permit", "pass", "accept"]),
        "severity": random.choice(["info", "low", "notice"]),
        "src_ip": f"192.168.1.{random.randint(1, 254)}",
        "dest_ip": f"8.8.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "dest_port": random.choice([80, 443, 53, 22]),
        "message": random.choice([
            "Normal HTTP traffic to google.com",
            "DNS query for legitimate domain",
            "SSH connection from admin workstation",
            "Regular system update check"
        ]),
        "threat_score": random.randint(0, 30),
        "category": "normal"
    })

# Generate 50 malicious events (actual threats)
for i in range(50):
    timestamp = base_time + timedelta(hours=i*2)
    sample_logs.append({
        "event_id": f"EVT-MALICIOUS-{i:04d}",
        "timestamp": timestamp.isoformat(),
        "_time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "sourcetype": random.choice(["snort:alert", "pfsense:syslog"]),
        "action": random.choice(["block", "deny", "reject", "drop"]),
        "severity": random.choice(["high", "critical", "alert"]),
        "src_ip": f"{random.randint(100, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "dest_ip": f"192.168.1.{random.randint(1, 254)}",
        "dest_port": random.choice([445, 3389, 1433, 8080]),
        "message": random.choice([
            "SQL injection attempt detected",
            "Port scan detected from external IP",
            "Malware signature matched: Trojan.Generic",
            "Brute force attack on RDP port"
        ]),
        "threat_score": random.randint(70, 100),
        "category": "threat"
    })

# Create DataFrame and shuffle
df_logs = pd.DataFrame(sample_logs)
df_logs = df_logs.sample(frac=1).reset_index(drop=True)

# Save sample logs
logs_path = data_dir / "sample_logs.csv"
df_logs.to_csv(logs_path, index=False)
print(f"✓ Generated {len(df_logs)} sample log events: {logs_path}")

# Generate AI detections (with some false positives)
detections = []
fp_count = 0

for idx, row in df_logs.iterrows():
    # Detect all malicious events (True Positives)
    if row['category'] == 'threat':
        detections.append({
            "event_id": row['event_id'],
            "timestamp": row['timestamp'],
            "threat_detected": True,
            "ai_verdict": "malicious",
            "confidence": random.uniform(0.85, 0.99)
        })
    # Incorrectly flag 15% of benign events as malicious (False Positives)
    elif random.random() < 0.15:  # 15% FPR
        fp_count += 1
        detections.append({
            "event_id": row['event_id'],
            "timestamp": row['timestamp'],
            "threat_detected": True,
            "ai_verdict": "malicious",
            "confidence": random.uniform(0.60, 0.80)
        })

df_detections = pd.DataFrame(detections)
detections_path = data_dir / "detected_from_db.csv"
df_detections.to_csv(detections_path, index=False)
print(f"✓ Generated {len(df_detections)} AI detections: {detections_path}")
print(f"  - {fp_count} expected false positives (~15% FPR)")

print(f"\nSummary:")
print(f"  Total events: {len(df_logs)}")
print(f"  Benign events: {len(df_logs[df_logs['category'] == 'normal'])}")
print(f"  Malicious events: {len(df_logs[df_logs['category'] == 'threat'])}")
print(f"  Total detections: {len(df_detections)}")
print(f"  Expected FPR: ~15%")
