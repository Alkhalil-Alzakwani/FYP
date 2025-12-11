"""Check Mean Time to Respond (MTTR)

This script computes the Mean Time to Respond for detected security events.
MTTR measures the time elapsed between when an event is detected and when a 
response action is taken (manual or automated).

MTTR = Response Timestamp - Detection Timestamp

This metric assesses the efficiency of the response workflow, dashboard usability,
and the effectiveness of automated response mechanisms.

Usage:
    python Tests/check_mttr.py
    python Tests/check_mttr.py --detections path/to/detections.csv --responses path/to/responses.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import statistics

import pandas as pd

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


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


def compute_mttr(detections_df: pd.DataFrame, responses_df: pd.DataFrame) -> dict:
    """
    Compute Mean Time to Respond metrics.
    
    Args:
        detections_df: DataFrame with detections (must have detection timestamp)
        responses_df: DataFrame with responses (must have response timestamp and action)
    
    Returns:
        dict with MTTR metrics and details
    """
    result = {
        "total_detections": 0,
        "responded_detections": 0,
        "unresponded_detections": 0,
        "automated_responses": 0,
        "manual_responses": 0,
        "mttr_seconds": [],
        "mttr_automated_seconds": [],
        "mttr_manual_seconds": [],
        "avg_mttr": None,
        "median_mttr": None,
        "avg_mttr_automated": None,
        "avg_mttr_manual": None,
        "min_mttr": None,
        "max_mttr": None,
        "response_rate": None,
        "details": []
    }
    
    if detections_df.empty:
        print("No detections data available")
        return result
    
    if responses_df.empty:
        print("No responses data available")
        return result
    
    result["total_detections"] = len(detections_df)
    
    print("\nCalculating MTTR for each detection...")
    
    # Match detections with responses
    for idx, detection in detections_df.iterrows():
        # Get detection time
        detection_time = None
        for col in ['detection_time', 'detected_at', 'timestamp', '_time']:
            if col in detection.index:
                detection_time = parse_timestamp(detection[col])
                if detection_time:
                    break
        
        if not detection_time:
            continue
        
        # Find matching response
        detection_id = detection.get('event_id', detection.get('id', None))
        if not detection_id or pd.isna(detection_id):
            continue
        
        # Look for response
        response_time = None
        response_type = None
        response_action = None
        
        for r_idx, response in responses_df.iterrows():
            resp_id = response.get('event_id', response.get('detection_id', response.get('id', None)))
            if resp_id == detection_id:
                # Get response time
                for col in ['response_time', 'responded_at', 'action_time', 'timestamp', '_time']:
                    if col in response.index:
                        response_time = parse_timestamp(response[col])
                        if response_time:
                            break
                
                response_type = response.get('response_type', response.get('type', 'manual'))
                response_action = response.get('action', response.get('response_action', 'unknown'))
                break
        
        if response_time and detection_time:
            result["responded_detections"] += 1
            
            # Calculate MTTR
            mttr = (response_time - detection_time).total_seconds()
            
            if mttr >= 0:  # Only include positive delays
                result["mttr_seconds"].append(mttr)
                
                # Categorize by response type
                if response_type and 'auto' in str(response_type).lower():
                    result["automated_responses"] += 1
                    result["mttr_automated_seconds"].append(mttr)
                else:
                    result["manual_responses"] += 1
                    result["mttr_manual_seconds"].append(mttr)
                
                result["details"].append({
                    "detection_id": detection_id,
                    "detection_time": detection_time.isoformat(),
                    "response_time": response_time.isoformat(),
                    "mttr_seconds": mttr,
                    "response_type": response_type,
                    "action": response_action,
                    "threat_type": detection.get('event_type', detection.get('threat_type', 'N/A')),
                })
    
    result["unresponded_detections"] = result["total_detections"] - result["responded_detections"]
    result["response_rate"] = (result["responded_detections"] / result["total_detections"] * 100) if result["total_detections"] > 0 else 0
    
    # Calculate statistics
    if result["mttr_seconds"]:
        result["avg_mttr"] = statistics.mean(result["mttr_seconds"])
        result["median_mttr"] = statistics.median(result["mttr_seconds"])
        result["min_mttr"] = min(result["mttr_seconds"])
        result["max_mttr"] = max(result["mttr_seconds"])
    
    if result["mttr_automated_seconds"]:
        result["avg_mttr_automated"] = statistics.mean(result["mttr_automated_seconds"])
    
    if result["mttr_manual_seconds"]:
        result["avg_mttr_manual"] = statistics.mean(result["mttr_manual_seconds"])
    
    return result


def compute_mttr_by_response_type(detections_df: pd.DataFrame, responses_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute MTTR grouped by response type (automated vs manual).
    
    Returns:
        DataFrame with MTTR metrics per response type
    """
    rows = []
    
    if detections_df.empty or responses_df.empty:
        return pd.DataFrame(columns=[
            "Response Type", "Count", "Avg MTTR (s)", 
            "Median MTTR (s)", "Min (s)", "Max (s)"
        ])
    
    # Match and categorize
    response_data = {'automated': [], 'manual': []}
    
    for idx, detection in detections_df.iterrows():
        detection_time = None
        for col in ['detection_time', 'detected_at', 'timestamp', '_time']:
            if col in detection.index:
                detection_time = parse_timestamp(detection[col])
                if detection_time:
                    break
        
        if not detection_time:
            continue
        
        detection_id = detection.get('event_id', detection.get('id', None))
        if not detection_id or pd.isna(detection_id):
            continue
        
        for r_idx, response in responses_df.iterrows():
            resp_id = response.get('event_id', response.get('detection_id', response.get('id', None)))
            if resp_id == detection_id:
                response_time = None
                for col in ['response_time', 'responded_at', 'action_time', 'timestamp', '_time']:
                    if col in response.index:
                        response_time = parse_timestamp(response[col])
                        if response_time:
                            break
                
                if response_time:
                    mttr = (response_time - detection_time).total_seconds()
                    if mttr >= 0:
                        response_type = response.get('response_type', response.get('type', 'manual'))
                        if 'auto' in str(response_type).lower():
                            response_data['automated'].append(mttr)
                        else:
                            response_data['manual'].append(mttr)
                break
    
    # Build table
    for resp_type, values in response_data.items():
        if values:
            rows.append({
                "Response Type": resp_type.capitalize(),
                "Count": len(values),
                "Avg MTTR (s)": round(statistics.mean(values), 2),
                "Median MTTR (s)": round(statistics.median(values), 2),
                "Min (s)": round(min(values), 2),
                "Max (s)": round(max(values), 2)
            })
    
    return pd.DataFrame(rows)


def compute_mttr_by_threat_type(detections_df: pd.DataFrame, responses_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute MTTR grouped by threat/event type.
    
    Returns:
        DataFrame with MTTR metrics per threat type
    """
    rows = []
    
    if detections_df.empty or responses_df.empty:
        return pd.DataFrame(columns=[
            "Threat Type", "Detections", "Responded", "Avg MTTR (s)", "Median MTTR (s)"
        ])
    
    # Group by threat type
    threat_col = None
    for col in ['event_type', 'threat_type', 'category', 'attack_type']:
        if col in detections_df.columns:
            threat_col = col
            break
    
    if not threat_col:
        return pd.DataFrame()
    
    for threat_type, group in detections_df.groupby(threat_col):
        mttr_values = []
        responded = 0
        
        for idx, detection in group.iterrows():
            detection_time = None
            for col in ['detection_time', 'detected_at', 'timestamp', '_time']:
                if col in detection.index:
                    detection_time = parse_timestamp(detection[col])
                    if detection_time:
                        break
            
            if not detection_time:
                continue
            
            detection_id = detection.get('event_id', detection.get('id', None))
            if not detection_id or pd.isna(detection_id):
                continue
            
            for r_idx, response in responses_df.iterrows():
                resp_id = response.get('event_id', response.get('detection_id', response.get('id', None)))
                if resp_id == detection_id:
                    responded += 1
                    response_time = None
                    for col in ['response_time', 'responded_at', 'action_time', 'timestamp', '_time']:
                        if col in response.index:
                            response_time = parse_timestamp(response[col])
                            if response_time:
                                break
                    
                    if response_time:
                        mttr = (response_time - detection_time).total_seconds()
                        if mttr >= 0:
                            mttr_values.append(mttr)
                    break
        
        avg_mttr = statistics.mean(mttr_values) if mttr_values else None
        median_mttr = statistics.median(mttr_values) if mttr_values else None
        
        rows.append({
            "Threat Type": threat_type,
            "Detections": len(group),
            "Responded": responded,
            "Avg MTTR (s)": round(avg_mttr, 2) if avg_mttr is not None else "N/A",
            "Median MTTR (s)": round(median_mttr, 2) if median_mttr is not None else "N/A"
        })
    
    df = pd.DataFrame(rows)
    if not df.empty and 'Avg MTTR (s)' in df.columns:
        # Sort by average MTTR
        df['_sort_key'] = pd.to_numeric(df['Avg MTTR (s)'], errors='coerce')
        df = df.sort_values('_sort_key').drop('_sort_key', axis=1)
    return df


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


def print_results_table(result: dict, by_type_df: pd.DataFrame, by_threat_df: pd.DataFrame):
    """Print formatted results tables"""
    print("\n" + "="*80)
    print(" MEAN TIME TO RESPOND (MTTR) ANALYSIS")
    print("="*80)
    
    # Overall metrics
    print("\nOVERALL METRICS:")
    print("-" * 80)
    print(f"Total Detections:             {result['total_detections']:,}")
    print(f"Responded Detections:         {result['responded_detections']:,}")
    print(f"Unresponded Detections:       {result['unresponded_detections']:,}")
    print(f"Response Rate:                {result['response_rate']:.1f}%")
    print("-" * 80)
    print(f"Automated Responses:          {result['automated_responses']:,}")
    print(f"Manual Responses:             {result['manual_responses']:,}")
    print("-" * 80)
    
    if result['avg_mttr'] is not None:
        print(f"\nMEAN TIME TO RESPOND:")
        print(f"  Average MTTR:               {format_duration(result['avg_mttr'])} ({result['avg_mttr']:.2f}s)")
        print(f"  Median MTTR:                {format_duration(result['median_mttr'])} ({result['median_mttr']:.2f}s)")
        print(f"  Minimum MTTR:               {format_duration(result['min_mttr'])} ({result['min_mttr']:.2f}s)")
        print(f"  Maximum MTTR:               {format_duration(result['max_mttr'])} ({result['max_mttr']:.2f}s)")
        
        if result['avg_mttr_automated'] is not None:
            print(f"\n  Automated MTTR (avg):       {format_duration(result['avg_mttr_automated'])} ({result['avg_mttr_automated']:.2f}s)")
        if result['avg_mttr_manual'] is not None:
            print(f"  Manual MTTR (avg):          {format_duration(result['avg_mttr_manual'])} ({result['avg_mttr_manual']:.2f}s)")
        
        # Interpretation
        avg_mttr = result['avg_mttr']
        print("\nINTERPRETATION:")
        if avg_mttr < 30:
            status = "EXCELLENT"
            msg = "Near-instant response. Automated systems working optimally."
        elif avg_mttr < 300:
            status = "GOOD"
            msg = "Fast response within 5 minutes. Efficient workflow."
        elif avg_mttr < 900:
            status = "MODERATE"
            msg = "Response within 15 minutes. Consider workflow optimization."
        else:
            status = "SLOW"
            msg = "Slow response (>15 min). Review dashboard usability and automation."
        
        print(f"Status: {status}")
        print(f"       {msg}")
        
        # Automation efficiency
        if result['avg_mttr_automated'] and result['avg_mttr_manual']:
            speedup = result['avg_mttr_manual'] / result['avg_mttr_automated']
            print(f"\nAUTOMATION EFFICIENCY:")
            print(f"  Automation is {speedup:.1f}x faster than manual response")
    else:
        print("\nMean Time to Respond:         N/A (no responses found)")
    
    # By response type
    if not by_type_df.empty:
        print("\n\nMTTR BY RESPONSE TYPE:")
        print("-" * 80)
        print(by_type_df.to_string(index=False))
    
    # By threat type
    if not by_threat_df.empty:
        print("\n\nMTTR BY THREAT TYPE:")
        print("-" * 80)
        print(by_threat_df.to_string(index=False))
    
    # Sample responses
    if result['details']:
        print("\n\nSAMPLE RESPONSES (First 10):")
        print("-" * 80)
        for i, detail in enumerate(result['details'][:10], 1):
            print(f"\n{i}. Detection ID: {detail['detection_id']}")
            print(f"   Detection Time: {detail['detection_time']}")
            print(f"   Response Time: {detail['response_time']}")
            print(f"   MTTR: {format_duration(detail['mttr_seconds'])}")
            print(f"   Response Type: {detail['response_type']}")
            print(f"   Action: {detail['action']}")
    
    print("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Compute Mean Time to Respond (MTTR) for security events"
    )
    parser.add_argument(
        "--detections",
        type=str,
        default="data/detected_from_db.csv",
        help="Path to detections CSV file"
    )
    parser.add_argument(
        "--responses",
        type=str,
        default="data/response_actions.csv",
        help="Path to responses CSV file"
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    base_dir = Path(__file__).parent.parent
    detections_path = base_dir / args.detections
    responses_path = base_dir / args.responses
    
    print("="*80)
    print(" MEAN TIME TO RESPOND (MTTR) ANALYSIS")
    print("="*80)
    print(f"\nDetections file: {detections_path}")
    print(f"Responses file: {responses_path}")
    
    # Load data
    detections_df = safe_read_csv(detections_path)
    responses_df = safe_read_csv(responses_path)
    
    print(f"\nLoaded {len(detections_df)} detections")
    print(f"Loaded {len(responses_df)} responses")
    
    # Compute MTTR
    result = compute_mttr(detections_df, responses_df)
    by_type_df = compute_mttr_by_response_type(detections_df, responses_df)
    by_threat_df = compute_mttr_by_threat_type(detections_df, responses_df)
    
    # Print results
    print_results_table(result, by_type_df, by_threat_df)
    
    # Save results
    output_dir = base_dir / "data"
    output_dir.mkdir(exist_ok=True)
    
    # Save overall results
    results_file = output_dir / "mttr_results.csv"
    pd.DataFrame([{
        "timestamp": datetime.now().isoformat(),
        "total_detections": result["total_detections"],
        "responded_detections": result["responded_detections"],
        "response_rate_percentage": result["response_rate"],
        "automated_responses": result["automated_responses"],
        "manual_responses": result["manual_responses"],
        "avg_mttr_seconds": result["avg_mttr"],
        "median_mttr_seconds": result["median_mttr"],
        "avg_mttr_automated_seconds": result["avg_mttr_automated"],
        "avg_mttr_manual_seconds": result["avg_mttr_manual"],
        "min_mttr_seconds": result["min_mttr"],
        "max_mttr_seconds": result["max_mttr"]
    }]).to_csv(results_file, mode='a', header=not results_file.exists(), index=False)
    
    # Save by-type results
    if not by_type_df.empty:
        type_file = output_dir / "mttr_by_response_type.csv"
        by_type_df.to_csv(type_file, index=False)
        print(f"Results saved to {type_file}")
    
    # Save by-threat results
    if not by_threat_df.empty:
        threat_file = output_dir / "mttr_by_threat_type.csv"
        by_threat_df.to_csv(threat_file, index=False)
        print(f"Results saved to {threat_file}")
    
    print(f"Overall results appended to {results_file}")


if __name__ == "__main__":
    main()
