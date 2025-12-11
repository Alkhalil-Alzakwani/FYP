"""Check False Positive Rate (FPR)

This script computes the False Positive Rate for the project by analyzing 
legitimate (benign) events that are incorrectly classified as malicious by 
the AI-based detection and evaluation rules.

False Positive Rate is defined as:
    FPR = False Positives / (False Positives + True Negatives)
    
Where:
- False Positives: Legitimate events incorrectly flagged as malicious
- True Negatives: Legitimate events correctly identified as benign

The script queries Splunk for both malicious and benign traffic, then cross-references
with the AI detection results to identify misclassifications.

Usage:
    python Tests/check_false_positive_rate.py
    python Tests/check_false_positive_rate.py --use-splunk
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

import pandas as pd
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.splunk_connector import SplunkConnector


def safe_read_csv(p: Path) -> pd.DataFrame:
    """Safely read CSV file, return empty DataFrame if file missing or invalid"""
    if not p.exists():
        return pd.DataFrame()
    try:
        df = pd.read_csv(p)
    except Exception as e:
        print(f"Warning: Could not read {p}: {e}")
        return pd.DataFrame()
    return df


def classify_event_as_benign(row: pd.Series) -> bool:
    """
    Classify whether an event is benign (legitimate) based on various indicators.
    
    Args:
        row: DataFrame row with event data
    
    Returns:
        bool: True if event is benign, False if suspicious/malicious
    """
    # Common indicators of benign traffic
    benign_indicators = {
        'action': ['allow', 'allowed', 'permit', 'pass', 'accept'],
        'severity': ['info', 'informational', 'low', 'notice'],
        'sourcetype': ['syslog', 'wineventlog:system'],
        'event_type': ['normal', 'legitimate', 'benign', 'regular'],
        'category': ['normal', 'admin', 'system', 'maintenance'],
    }
    
    # Convert row to dict for easier access
    row_dict = row.to_dict()
    row_lower = {k.lower(): str(v).lower() if v is not None else '' for k, v in row_dict.items()}
    
    # Check for benign indicators
    benign_score = 0
    for field, keywords in benign_indicators.items():
        for key, val in row_lower.items():
            if field in key:
                if any(keyword in val for keyword in keywords):
                    benign_score += 1
    
    # Check for malicious indicators (exclusion criteria)
    malicious_keywords = [
        'attack', 'malware', 'threat', 'intrusion', 'exploit', 
        'vulnerability', 'suspicious', 'blocked', 'denied', 'reject',
        'alert', 'critical', 'high', 'phishing', 'virus', 'trojan'
    ]
    
    for val in row_lower.values():
        if any(keyword in val for keyword in malicious_keywords):
            return False  # Definitely not benign
    
    # If we found benign indicators and no malicious ones
    return benign_score > 0


def is_flagged_as_malicious(row: pd.Series, ai_detections_df: pd.DataFrame = None) -> bool:
    """
    Check if an event was flagged as malicious by the AI/detection system.
    
    Args:
        row: DataFrame row with event data
        ai_detections_df: DataFrame with AI detection results
    
    Returns:
        bool: True if event was flagged as malicious
    """
    row_dict = row.to_dict()
    row_lower = {k.lower(): str(v).lower() if v is not None else '' for k, v in row_dict.items()}
    
    # PRIORITY 1: Check against AI detections DataFrame if provided
    if ai_detections_df is not None and not ai_detections_df.empty:
        # Try to match by event ID first (most reliable)
        match_cols = ['event_id', 'id', 'signature', 'hash']
        for col in match_cols:
            col_lower = col.lower()
            # Check if this column exists in the row
            row_col = None
            for k in row_dict.keys():
                if k.lower() == col_lower:
                    row_col = k
                    break
            
            if row_col and row_col in row_dict:
                # Check if this value exists in AI detections
                for ai_col in ai_detections_df.columns:
                    if ai_col.lower() == col_lower:
                        if row_dict[row_col] in ai_detections_df[ai_col].values:
                            # Check if threat_detected is True
                            matched_rows = ai_detections_df[ai_detections_df[ai_col] == row_dict[row_col]]
                            if not matched_rows.empty:
                                # Check if any detection flag is set
                                for det_col in ['threat_detected', 'is_threat', 'flagged']:
                                    if det_col in matched_rows.columns:
                                        if matched_rows[det_col].iloc[0] in [True, 'True', 'true', 1, '1', 'yes']:
                                            return True
                                # If ai_verdict is present
                                if 'ai_verdict' in matched_rows.columns:
                                    verdict = str(matched_rows['ai_verdict'].iloc[0]).lower()
                                    if verdict in ['malicious', 'threat', 'suspicious']:
                                        return True
                                # If matched but no explicit flag, consider it detected
                                return True
    
    # PRIORITY 2: Check for detection/threat flags in the row itself
    detection_indicators = {
        'threat_detected': ['true', '1', 'yes', 'detected'],
        'is_threat': ['true', '1', 'yes'],
        'flagged': ['true', '1', 'yes', 'malicious'],
        'ai_verdict': ['malicious', 'threat', 'suspicious', 'high risk'],
        'threat_score': None,  # Will check numeric threshold
    }
    
    for field, keywords in detection_indicators.items():
        for key, val in row_lower.items():
            if field in key:
                if keywords is None:
                    # Numeric check (e.g., threat_score > 70)
                    try:
                        score = float(val)
                        if score > 70:
                            return True
                    except (ValueError, TypeError):
                        continue
                else:
                    if any(keyword in val for keyword in keywords):
                        return True
    
    return False


def fetch_splunk_data(connector: SplunkConnector, time_range: str = "-7d@d") -> pd.DataFrame:
    """
    Fetch data from Splunk for FPR analysis.
    
    Args:
        connector: SplunkConnector instance
        time_range: Time range for the query (e.g., "-7d@d" for last 7 days)
    
    Returns:
        DataFrame with Splunk events
    """
    print(f"Connecting to Splunk at {connector.config.get('splunk', {}).get('host')}...")
    
    if not connector.connect():
        print("Failed to connect to Splunk")
        return pd.DataFrame()
    
    print("Connected successfully. Fetching events...")
    
    try:
        # Use fetch_logs method instead of search
        events = connector.fetch_logs(
            earliest_time=time_range,
            latest_time="now",
            max_results=10000
        )
        if events:
            df = pd.DataFrame(events)
            print(f"Fetched {len(df)} events from Splunk")
            return df
        else:
            print("No events returned from Splunk")
            return pd.DataFrame()
    except Exception as e:
        print(f"Error fetching from Splunk: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()


def compute_false_positive_rate(
    events_df: pd.DataFrame,
    ai_detections_df: pd.DataFrame = None,
    use_splunk: bool = False
) -> dict:
    """
    Compute False Positive Rate from event data.
    
    Args:
        events_df: DataFrame with all events
        ai_detections_df: DataFrame with AI detection results
        use_splunk: Whether to fetch additional data from Splunk
    
    Returns:
        dict with FPR metrics
    """
    result = {
        "total_events": 0,
        "benign_events": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_positive_rate": None,
        "accuracy": None,
        "details": []
    }
    
    if events_df.empty:
        print("No events data available for analysis")
        return result
    
    result["total_events"] = len(events_df)
    
    # Classify each event
    print("\nClassifying events...")
    false_positives = []
    true_negatives = []
    
    for idx, row in events_df.iterrows():
        is_benign = classify_event_as_benign(row)
        is_flagged = is_flagged_as_malicious(row, ai_detections_df)
        
        if is_benign:
            result["benign_events"] += 1
            if is_flagged:
                # False Positive: Benign but flagged as malicious
                result["false_positives"] += 1
                false_positives.append({
                    "index": idx,
                    "timestamp": row.get('_time', row.get('timestamp', 'N/A')),
                    "sourcetype": row.get('sourcetype', 'N/A'),
                    "description": row.get('message', row.get('description', str(row)[:100]))
                })
            else:
                # True Negative: Benign and correctly identified as benign
                result["true_negatives"] += 1
                true_negatives.append(idx)
    
    # Calculate FPR
    denominator = result["false_positives"] + result["true_negatives"]
    if denominator > 0:
        result["false_positive_rate"] = result["false_positives"] / denominator
        result["accuracy"] = result["true_negatives"] / denominator
    else:
        result["false_positive_rate"] = None
        result["accuracy"] = None
    
    # Store sample false positives for details
    result["details"] = false_positives[:10]  # Limit to 10 examples
    
    return result


def compute_fpr_by_sourcetype(events_df: pd.DataFrame, ai_detections_df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Compute FPR grouped by sourcetype.
    
    Returns:
        DataFrame with columns: Sourcetype, Total Events, Benign Events, False Positives, 
                                True Negatives, FPR (%)
    """
    rows = []
    
    if events_df.empty:
        return pd.DataFrame(columns=[
            "Sourcetype", "Total Events", "Benign Events", 
            "False Positives", "True Negatives", "FPR (%)"
        ])
    
    # Group by sourcetype if available
    if 'sourcetype' in events_df.columns:
        groups = events_df.groupby('sourcetype')
    else:
        # Create a single group
        groups = [(None, events_df)]
    
    for sourcetype, group in groups:
        total = len(group)
        benign = 0
        fp = 0
        tn = 0
        
        for idx, row in group.iterrows():
            is_benign = classify_event_as_benign(row)
            is_flagged = is_flagged_as_malicious(row, ai_detections_df)
            
            if is_benign:
                benign += 1
                if is_flagged:
                    fp += 1
                else:
                    tn += 1
        
        denominator = fp + tn
        fpr = (fp / denominator * 100) if denominator > 0 else None
        
        rows.append({
            "Sourcetype": sourcetype if sourcetype else "Unknown",
            "Total Events": total,
            "Benign Events": benign,
            "False Positives": fp,
            "True Negatives": tn,
            "FPR (%)": round(fpr, 2) if fpr is not None else "N/A"
        })
    
    df = pd.DataFrame(rows)
    if not df.empty and len(df) > 1:
        # Convert FPR to numeric for sorting, handling "N/A" values
        df['FPR_numeric'] = pd.to_numeric(df['FPR (%)'], errors='coerce')
        df = df.sort_values('FPR_numeric', ascending=False).drop('FPR_numeric', axis=1)
    return df


def print_results_table(result: dict, by_sourcetype_df: pd.DataFrame):
    """Print formatted results tables"""
    print("\n" + "="*80)
    print(" FALSE POSITIVE RATE (FPR) ANALYSIS")
    print("="*80)
    
    # Overall metrics
    print("\nOVERALL METRICS:")
    print("-" * 80)
    print(f"Total Events Analyzed:        {result['total_events']:,}")
    print(f"Benign Events (Legitimate):   {result['benign_events']:,}")
    print(f"True Negatives (Correct):     {result['true_negatives']:,}")
    print(f"False Positives (Errors):     {result['false_positives']:,}")
    print("-" * 80)
    
    if result['false_positive_rate'] is not None:
        fpr_pct = result['false_positive_rate'] * 100
        accuracy_pct = result['accuracy'] * 100
        print(f"False Positive Rate (FPR):    {fpr_pct:.2f}%")
        print(f"Detection Accuracy:           {accuracy_pct:.2f}%")
        
        # Interpretation
        print("\nINTERPRETATION:")
        if fpr_pct < 5:
            status = "EXCELLENT"
            msg = "Very low false positive rate. System is highly accurate."
        elif fpr_pct < 10:
            status = "GOOD"
            msg = "Acceptable false positive rate. Minor tuning recommended."
        elif fpr_pct < 20:
            status = "MODERATE"
            msg = "Elevated false positive rate. Review detection rules."
        else:
            status = "HIGH"
            msg = "High false positive rate. Significant tuning needed."
        
        print(f"Status: {status}")
        print(f"       {msg}")
    else:
        print("False Positive Rate:          N/A (insufficient data)")
    
    # By sourcetype
    if not by_sourcetype_df.empty:
        print("\n\nFALSE POSITIVE RATE BY SOURCETYPE:")
        print("-" * 80)
        print(by_sourcetype_df.to_string(index=False))
    
    # Sample false positives
    if result['details']:
        print("\n\nSAMPLE FALSE POSITIVES (First 10):")
        print("-" * 80)
        for i, fp in enumerate(result['details'][:10], 1):
            print(f"\n{i}. Timestamp: {fp['timestamp']}")
            print(f"   Sourcetype: {fp['sourcetype']}")
            print(f"   Description: {fp['description']}")
    
    print("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Compute False Positive Rate (FPR) for AI-based threat detection"
    )
    parser.add_argument(
        "--logs",
        type=str,
        default="data/sample_logs.csv",
        help="Path to logs CSV file"
    )
    parser.add_argument(
        "--detections",
        type=str,
        default="data/detected_from_db.csv",
        help="Path to AI detections CSV file"
    )
    parser.add_argument(
        "--use-splunk",
        action="store_true",
        help="Fetch additional data from Splunk"
    )
    parser.add_argument(
        "--time-range",
        type=str,
        default="-7d@d",
        help="Time range for Splunk query (default: last 7 days)"
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    base_dir = Path(__file__).parent.parent
    logs_path = base_dir / args.logs
    detections_path = base_dir / args.detections
    
    print("="*80)
    print(" FALSE POSITIVE RATE ANALYSIS")
    print("="*80)
    print(f"\nLogs file: {logs_path}")
    print(f"Detections file: {detections_path}")
    
    # Load data
    events_df = safe_read_csv(logs_path)
    ai_detections_df = safe_read_csv(detections_path)
    
    print(f"\nLoaded {len(events_df)} events from logs")
    print(f"Loaded {len(ai_detections_df)} AI detections")
    
    # Fetch from Splunk if requested
    if args.use_splunk:
        try:
            connector = SplunkConnector()
            splunk_df = fetch_splunk_data(connector, args.time_range)
            
            if not splunk_df.empty:
                # Merge with existing events
                events_df = pd.concat([events_df, splunk_df], ignore_index=True)
                events_df = events_df.drop_duplicates()
                print(f"\nTotal events after Splunk fetch: {len(events_df)}")
        except Exception as e:
            print(f"\nWarning: Could not fetch from Splunk: {e}")
            print("Continuing with local data only...")
    
    # Compute FPR
    result = compute_false_positive_rate(events_df, ai_detections_df, args.use_splunk)
    by_sourcetype_df = compute_fpr_by_sourcetype(events_df, ai_detections_df)
    
    # Print results
    print_results_table(result, by_sourcetype_df)
    
    # Save results
    output_dir = base_dir / "data"
    output_dir.mkdir(exist_ok=True)
    
    # Save overall results
    results_file = output_dir / "false_positive_rate_results.csv"
    pd.DataFrame([{
        "timestamp": datetime.now().isoformat(),
        "total_events": result["total_events"],
        "benign_events": result["benign_events"],
        "false_positives": result["false_positives"],
        "true_negatives": result["true_negatives"],
        "fpr_percentage": round(result["false_positive_rate"] * 100, 2) if result["false_positive_rate"] else None,
        "accuracy_percentage": round(result["accuracy"] * 100, 2) if result["accuracy"] else None
    }]).to_csv(results_file, mode='a', header=not results_file.exists(), index=False)
    
    # Save by-sourcetype results
    if not by_sourcetype_df.empty:
        sourcetype_file = output_dir / "fpr_by_sourcetype.csv"
        by_sourcetype_df.to_csv(sourcetype_file, index=False)
        print(f"\n✓ Results saved to {sourcetype_file}")
    
    print(f"✓ Overall results appended to {results_file}")


if __name__ == "__main__":
    main()
