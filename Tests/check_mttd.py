"""Check Mean Time to Detect (MTTD)

This script computes the Mean Time to Detect for phishing and other security events.
MTTD measures the time elapsed between when an event occurs and when the system 
detects/identifies it.

MTTD = Detection Timestamp - Event Occurrence Timestamp

The script accounts for Splunk ingestion delays (inherent system delay in log collection)
and provides both raw and adjusted MTTD metrics.

Usage:
    python Tests/check_mttd.py
    python Tests/check_mttd.py --use-splunk
    python Tests/check_mttd.py --events path/to/events.csv --detections path/to/detections.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import statistics

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


def parse_timestamp(ts) -> Optional[datetime]:
    """Parse timestamp from various formats"""
    if pd.isna(ts):
        return None
    
    ts_str = str(ts)
    
    # Try multiple datetime formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    
    # Try pandas to_datetime as fallback
    try:
        return pd.to_datetime(ts_str)
    except:
        return None


def estimate_splunk_delay(events_df: pd.DataFrame) -> timedelta:
    """
    Estimate typical Splunk ingestion delay from the data.
    Uses events that have both occurrence and index time.
    
    Returns:
        timedelta: Estimated average Splunk delay
    """
    delays = []
    
    # Look for fields that indicate index time vs event time
    time_cols = {
        'index_time': [],
        'indexed_at': [],
        '_indextime': [],
        'ingestion_time': [],
    }
    
    event_cols = {
        'event_time': [],
        'occurrence_time': [],
        '_time': [],
        'timestamp': [],
    }
    
    # Find relevant columns
    for col in events_df.columns:
        col_lower = col.lower()
        for key in time_cols.keys():
            if key in col_lower:
                time_cols[key].append(col)
        for key in event_cols.keys():
            if key in col_lower:
                event_cols[key].append(col)
    
    # Calculate delays where both timestamps exist
    for idx, row in events_df.iterrows():
        event_ts = None
        index_ts = None
        
        # Get event time
        for col_list in event_cols.values():
            for col in col_list:
                if col in row.index:
                    event_ts = parse_timestamp(row[col])
                    if event_ts:
                        break
            if event_ts:
                break
        
        # Get index time
        for col_list in time_cols.values():
            for col in col_list:
                if col in row.index:
                    index_ts = parse_timestamp(row[col])
                    if index_ts:
                        break
            if index_ts:
                break
        
        if event_ts and index_ts and index_ts > event_ts:
            delay = (index_ts - event_ts).total_seconds()
            if 0 < delay < 3600:  # Reasonable delay (less than 1 hour)
                delays.append(delay)
    
    if delays:
        avg_delay = statistics.mean(delays)
        return timedelta(seconds=avg_delay)
    else:
        # Default estimate: 30 seconds typical Splunk delay
        return timedelta(seconds=30)


def compute_mttd(events_df: pd.DataFrame, detections_df: pd.DataFrame, 
                 splunk_delay: timedelta = None) -> dict:
    """
    Compute Mean Time to Detect metrics.
    
    Args:
        events_df: DataFrame with events (must have occurrence timestamp)
        detections_df: DataFrame with detections (must have detection timestamp)
        splunk_delay: Estimated Splunk ingestion delay (optional)
    
    Returns:
        dict with MTTD metrics and details
    """
    result = {
        "total_events": 0,
        "detected_events": 0,
        "undetected_events": 0,
        "mttd_raw_seconds": [],
        "mttd_adjusted_seconds": [],
        "avg_mttd_raw": None,
        "avg_mttd_adjusted": None,
        "median_mttd_raw": None,
        "median_mttd_adjusted": None,
        "min_mttd": None,
        "max_mttd": None,
        "splunk_delay_seconds": splunk_delay.total_seconds() if splunk_delay else 30,
        "details": []
    }
    
    if events_df.empty:
        print("No events data available")
        return result
    
    if detections_df.empty:
        print("No detections data available")
        return result
    
    # Auto-estimate Splunk delay if not provided
    if splunk_delay is None:
        splunk_delay = estimate_splunk_delay(events_df)
        result["splunk_delay_seconds"] = splunk_delay.total_seconds()
    
    result["total_events"] = len(events_df)
    
    print(f"\nEstimated Splunk ingestion delay: {splunk_delay.total_seconds():.1f} seconds")
    print("Calculating MTTD for each event...")
    
    # Match events with detections
    for idx, event in events_df.iterrows():
        # Get event occurrence time
        event_time = None
        for col in ['occurrence_time', 'event_time', 'timestamp', '_time']:
            if col in event.index:
                event_time = parse_timestamp(event[col])
                if event_time:
                    break
        
        if not event_time:
            continue
        
        # Find matching detection
        detection_time = None
        matched_detection = None
        
        # Try to match by event_id
        event_id = event.get('event_id', event.get('id', None))
        if event_id and not pd.isna(event_id):
            for d_idx, detection in detections_df.iterrows():
                det_id = detection.get('event_id', detection.get('id', None))
                if det_id == event_id:
                    matched_detection = detection
                    # Get detection time
                    for col in ['detection_time', 'detected_at', 'timestamp', '_time']:
                        if col in detection.index:
                            detection_time = parse_timestamp(detection[col])
                            if detection_time:
                                break
                    break
        
        if detection_time and event_time:
            result["detected_events"] += 1
            
            # Calculate raw MTTD (includes all delays)
            mttd_raw = (detection_time - event_time).total_seconds()
            
            # Calculate adjusted MTTD (remove Splunk delay)
            mttd_adjusted = max(0, mttd_raw - splunk_delay.total_seconds())
            
            if mttd_raw >= 0:  # Only include positive delays
                result["mttd_raw_seconds"].append(mttd_raw)
                result["mttd_adjusted_seconds"].append(mttd_adjusted)
                
                result["details"].append({
                    "event_id": event_id,
                    "event_time": event_time.isoformat(),
                    "detection_time": detection_time.isoformat(),
                    "mttd_raw_seconds": mttd_raw,
                    "mttd_adjusted_seconds": mttd_adjusted,
                    "sourcetype": event.get('sourcetype', 'N/A'),
                    "description": event.get('message', event.get('description', 'N/A'))[:100]
                })
    
    result["undetected_events"] = result["total_events"] - result["detected_events"]
    
    # Calculate statistics
    if result["mttd_raw_seconds"]:
        result["avg_mttd_raw"] = statistics.mean(result["mttd_raw_seconds"])
        result["median_mttd_raw"] = statistics.median(result["mttd_raw_seconds"])
        result["min_mttd"] = min(result["mttd_raw_seconds"])
        result["max_mttd"] = max(result["mttd_raw_seconds"])
    
    if result["mttd_adjusted_seconds"]:
        result["avg_mttd_adjusted"] = statistics.mean(result["mttd_adjusted_seconds"])
        result["median_mttd_adjusted"] = statistics.median(result["mttd_adjusted_seconds"])
    
    return result


def compute_mttd_by_sourcetype(events_df: pd.DataFrame, detections_df: pd.DataFrame,
                                splunk_delay: timedelta = None) -> pd.DataFrame:
    """
    Compute MTTD grouped by sourcetype.
    
    Returns:
        DataFrame with MTTD metrics per sourcetype
    """
    rows = []
    
    if events_df.empty or detections_df.empty:
        return pd.DataFrame(columns=[
            "Sourcetype", "Events", "Detected", "Avg MTTD (s)", 
            "Median MTTD (s)", "Min (s)", "Max (s)"
        ])
    
    if splunk_delay is None:
        splunk_delay = estimate_splunk_delay(events_df)
    
    # Group by sourcetype
    if 'sourcetype' in events_df.columns:
        groups = events_df.groupby('sourcetype')
    else:
        groups = [(None, events_df)]
    
    for sourcetype, group in groups:
        mttd_values = []
        detected = 0
        
        for idx, event in group.iterrows():
            # Get event time
            event_time = None
            for col in ['occurrence_time', 'event_time', 'timestamp', '_time']:
                if col in event.index:
                    event_time = parse_timestamp(event[col])
                    if event_time:
                        break
            
            if not event_time:
                continue
            
            # Find detection
            event_id = event.get('event_id', event.get('id', None))
            if event_id and not pd.isna(event_id):
                for d_idx, detection in detections_df.iterrows():
                    det_id = detection.get('event_id', detection.get('id', None))
                    if det_id == event_id:
                        detected += 1
                        # Get detection time
                        detection_time = None
                        for col in ['detection_time', 'detected_at', 'timestamp', '_time']:
                            if col in detection.index:
                                detection_time = parse_timestamp(detection[col])
                                if detection_time:
                                    break
                        
                        if detection_time:
                            mttd = (detection_time - event_time).total_seconds()
                            mttd_adj = max(0, mttd - splunk_delay.total_seconds())
                            if mttd >= 0:
                                mttd_values.append(mttd_adj)
                        break
        
        avg_mttd = statistics.mean(mttd_values) if mttd_values else None
        median_mttd = statistics.median(mttd_values) if mttd_values else None
        min_mttd = min(mttd_values) if mttd_values else None
        max_mttd = max(mttd_values) if mttd_values else None
        
        rows.append({
            "Sourcetype": sourcetype if sourcetype else "Unknown",
            "Events": len(group),
            "Detected": detected,
            "Avg MTTD (s)": round(avg_mttd, 2) if avg_mttd is not None else "N/A",
            "Median MTTD (s)": round(median_mttd, 2) if median_mttd is not None else "N/A",
            "Min (s)": round(min_mttd, 2) if min_mttd is not None else "N/A",
            "Max (s)": round(max_mttd, 2) if max_mttd is not None else "N/A"
        })
    
    return pd.DataFrame(rows)


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}min"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}hr"


def print_results_table(result: dict, by_sourcetype_df: pd.DataFrame):
    """Print formatted results tables"""
    print("\n" + "="*80)
    print(" MEAN TIME TO DETECT (MTTD) ANALYSIS")
    print("="*80)
    
    # Overall metrics
    print("\nOVERALL METRICS:")
    print("-" * 80)
    print(f"Total Events:                 {result['total_events']:,}")
    print(f"Detected Events:              {result['detected_events']:,}")
    print(f"Undetected Events:            {result['undetected_events']:,}")
    print(f"Detection Rate:               {(result['detected_events']/result['total_events']*100):.1f}%" if result['total_events'] > 0 else "Detection Rate: N/A")
    print(f"Splunk Ingestion Delay:       {format_duration(result['splunk_delay_seconds'])}")
    print("-" * 80)
    
    if result['avg_mttd_raw'] is not None:
        print(f"\nTIME TO DETECT (Raw - includes all delays):")
        print(f"  Average MTTD:               {format_duration(result['avg_mttd_raw'])} ({result['avg_mttd_raw']:.2f}s)")
        print(f"  Median MTTD:                {format_duration(result['median_mttd_raw'])} ({result['median_mttd_raw']:.2f}s)")
        print(f"  Minimum MTTD:               {format_duration(result['min_mttd'])} ({result['min_mttd']:.2f}s)")
        print(f"  Maximum MTTD:               {format_duration(result['max_mttd'])} ({result['max_mttd']:.2f}s)")
        
        print(f"\nTIME TO DETECT (Adjusted - Splunk delay removed):")
        print(f"  Average MTTD:               {format_duration(result['avg_mttd_adjusted'])} ({result['avg_mttd_adjusted']:.2f}s)")
        print(f"  Median MTTD:                {format_duration(result['median_mttd_adjusted'])} ({result['median_mttd_adjusted']:.2f}s)")
        
        # Interpretation
        avg_adj = result['avg_mttd_adjusted']
        print("\nINTERPRETATION:")
        if avg_adj < 10:
            status = "EXCELLENT"
            msg = "Near real-time detection. System is highly responsive."
        elif avg_adj < 60:
            status = "GOOD"
            msg = "Fast detection within 1 minute. Good system performance."
        elif avg_adj < 300:
            status = "MODERATE"
            msg = "Detection within 5 minutes. Consider optimization."
        else:
            status = "SLOW"
            msg = "Slow detection (>5 min). Review pipeline and correlation rules."
        
        print(f"Status: {status}")
        print(f"       {msg}")
    else:
        print("\nMean Time to Detect:          N/A (no detections found)")
    
    # By sourcetype
    if not by_sourcetype_df.empty:
        print("\n\nMTTD BY SOURCETYPE:")
        print("-" * 80)
        print(by_sourcetype_df.to_string(index=False))
    
    # Sample detections
    if result['details']:
        print("\n\nSAMPLE DETECTIONS (First 10):")
        print("-" * 80)
        for i, detail in enumerate(result['details'][:10], 1):
            print(f"\n{i}. Event ID: {detail['event_id']}")
            print(f"   Event Time: {detail['event_time']}")
            print(f"   Detection Time: {detail['detection_time']}")
            print(f"   MTTD (Raw): {format_duration(detail['mttd_raw_seconds'])}")
            print(f"   MTTD (Adjusted): {format_duration(detail['mttd_adjusted_seconds'])}")
            print(f"   Sourcetype: {detail['sourcetype']}")
    
    print("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Compute Mean Time to Detect (MTTD) for security events"
    )
    parser.add_argument(
        "--events",
        type=str,
        default="data/attack_simulation_results.csv",
        help="Path to events CSV file (with occurrence timestamps)"
    )
    parser.add_argument(
        "--detections",
        type=str,
        default="data/detected_from_db.csv",
        help="Path to detections CSV file (with detection timestamps)"
    )
    parser.add_argument(
        "--use-splunk",
        action="store_true",
        help="Fetch additional data from Splunk"
    )
    parser.add_argument(
        "--splunk-delay",
        type=float,
        default=None,
        help="Splunk ingestion delay in seconds (auto-estimated if not provided)"
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    base_dir = Path(__file__).parent.parent
    events_path = base_dir / args.events
    detections_path = base_dir / args.detections
    
    print("="*80)
    print(" MEAN TIME TO DETECT (MTTD) ANALYSIS")
    print("="*80)
    print(f"\nEvents file: {events_path}")
    print(f"Detections file: {detections_path}")
    
    # Load data
    events_df = safe_read_csv(events_path)
    detections_df = safe_read_csv(detections_path)
    
    print(f"\nLoaded {len(events_df)} events")
    print(f"Loaded {len(detections_df)} detections")
    
    # Set Splunk delay
    splunk_delay = timedelta(seconds=args.splunk_delay) if args.splunk_delay else None
    
    # Compute MTTD
    result = compute_mttd(events_df, detections_df, splunk_delay)
    by_sourcetype_df = compute_mttd_by_sourcetype(events_df, detections_df, splunk_delay)
    
    # Print results
    print_results_table(result, by_sourcetype_df)
    
    # Save results
    output_dir = base_dir / "data"
    output_dir.mkdir(exist_ok=True)
    
    # Save overall results
    results_file = output_dir / "mttd_results.csv"
    pd.DataFrame([{
        "timestamp": datetime.now().isoformat(),
        "total_events": result["total_events"],
        "detected_events": result["detected_events"],
        "avg_mttd_raw_seconds": result["avg_mttd_raw"],
        "avg_mttd_adjusted_seconds": result["avg_mttd_adjusted"],
        "median_mttd_raw_seconds": result["median_mttd_raw"],
        "median_mttd_adjusted_seconds": result["median_mttd_adjusted"],
        "min_mttd_seconds": result["min_mttd"],
        "max_mttd_seconds": result["max_mttd"],
        "splunk_delay_seconds": result["splunk_delay_seconds"]
    }]).to_csv(results_file, mode='a', header=not results_file.exists(), index=False)
    
    # Save by-sourcetype results
    if not by_sourcetype_df.empty:
        sourcetype_file = output_dir / "mttd_by_sourcetype.csv"
        by_sourcetype_df.to_csv(sourcetype_file, index=False)
        print(f"✓ Results saved to {sourcetype_file}")
    
    print(f"✓ Overall results appended to {results_file}")


if __name__ == "__main__":
    main()
