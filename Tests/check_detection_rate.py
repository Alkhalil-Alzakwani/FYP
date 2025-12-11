"""Check Detection Rate

This script computes the Detection Rate for the project using available
CSV evidence files in the `data/` directory. Detection Rate is defined as:

    detection_rate = detected_attempts / total_attempts

Where `total_attempts` comes from an attack/campaign simulation file (if
available) and `detected_attempts` comes from IDS/SIEM/log evidence.

The script is robust to missing or empty files and prints a small summary
table showing the computed metrics and supporting evidence counts.

Usage:
    python Tests/check_detection_rate.py
    python Tests/check_detection_rate.py --attacks path/to/attacks.csv --logs path/to/logs.csv
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

import pandas as pd


def safe_read_csv(p: Path) -> pd.DataFrame:
    if not p.exists():
        return pd.DataFrame()
    try:
        df = pd.read_csv(p)
    except Exception:
        # fallback: empty dataframe
        return pd.DataFrame()
    return df


def compute_detection_rate(attacks_df: pd.DataFrame, logs_df: pd.DataFrame) -> dict:
    result = {
        "total_attempts": 0,
        "detected_attempts": 0,
        "detection_rate": None,
        "evidence_files": [],
    }

    # Count total attempts
    if not attacks_df.empty:
        # If there is an explicit 'count' column or each row is an attempt
        result["total_attempts"] = len(attacks_df)
        result["evidence_files"].append("data/attack_simulation_results.csv")
    
    # Try to detect explicit detection column in attacks_df
    detection_cols = [c for c in attacks_df.columns if c.lower() in ("detected", "was_detected", "detected_flag", "detected_by")]
    if detection_cols:
        # sum truthy values in first matching column
        col = detection_cols[0]
        try:
            detected = attacks_df[col].astype(bool).sum()
        except Exception:
            detected = int((attacks_df[col] == "true").sum()) if attacks_df[col].dtype == object else 0
        result["detected_attempts"] = int(detected)

    # If logs_df contains explicit attack ids, attempt to match
    if not logs_df.empty:
        result["evidence_files"].append("data/sample_logs.csv")
        # heuristics: look for attack id columns
        attack_id_cols = [c for c in attacks_df.columns if "attack" in c.lower() or "id" == c.lower()]
        log_id_cols = [c for c in logs_df.columns if "attack" in c.lower() or "id" == c.lower() or "signature" in c.lower()]

        if attack_id_cols and log_id_cols:
            aid = attack_id_cols[0]
            lid = log_id_cols[0]
            try:
                matched = logs_df[logs_df[lid].isin(attacks_df[aid])]
                result["detected_attempts"] = max(result["detected_attempts"], int(matched[aid if aid in matched.columns else lid].nunique()))
            except Exception:
                pass

        # fallback: count log rows that look like detections using keywords
        if result["detected_attempts"] == 0:
            text_cols = [c for c in logs_df.columns if logs_df[c].dtype == object]
            if text_cols:
                keywords = ["alert", "detected", "threat", "malware", "intrusion", "hit", "blocked"]
                mask = pd.Series(False, index=logs_df.index)
                for c in text_cols:
                    col_lower = logs_df[c].astype(str).str.lower()
                    for kw in keywords:
                        mask = mask | col_lower.str.contains(kw, na=False)
                result["detected_attempts"] = int(mask.sum())

    # If no attacks_df but logs_df present, use logs count as total attempts
    if result["total_attempts"] == 0 and not logs_df.empty:
        result["total_attempts"] = len(logs_df)

    # Compute detection rate
    if result["total_attempts"] > 0:
        result["detection_rate"] = result["detected_attempts"] / result["total_attempts"]
    else:
        result["detection_rate"] = None

    return result


def compute_campaign_table(attacks_df: pd.DataFrame, logs_df: pd.DataFrame) -> pd.DataFrame:
    """Compute detection metrics grouped by campaign and return a DataFrame.

    Columns: Campaign ID, Total Attempts, Correctly Detected, Missed, Detection Rate (%)
    """
    rows = []

    # Helper: find columns
    def find_col(df, candidates):
        for c in df.columns:
            for cand in candidates:
                if cand in c.lower():
                    return c
        return None

    campaign_col = find_col(attacks_df, ["campaign", "campaign_id", "campaignid"])
    attack_id_col = find_col(attacks_df, ["attack_id", "attackid", "event_id", "id", "attempt_id"])
    log_id_col = find_col(logs_df, ["event_id", "attack_id", "attackid", "id", "signature"])
    detected_flag_col = find_col(attacks_df, ["detected", "was_detected", "detected_flag", "detected_by"])

    # If we have attack simulation data grouped by campaign
    if not attacks_df.empty and campaign_col is not None:
        for campaign, group in attacks_df.groupby(campaign_col):
            total = len(group)
            detected = 0

            if attack_id_col and log_id_col and attack_id_col in group.columns and log_id_col in logs_df.columns:
                try:
                    detected = int(group[attack_id_col].isin(logs_df[log_id_col]).sum())
                except Exception:
                    detected = 0
            elif detected_flag_col and detected_flag_col in group.columns:
                try:
                    detected = int(group[detected_flag_col].astype(bool).sum())
                except Exception:
                    detected = 0
            else:
                # No reliable matching info; try to use logs_df 'sourcetype' or keywords as fallback (best-effort)
                detected = 0

            missed = total - detected
            rate = (detected / total * 100) if total > 0 else None
            rows.append({
                "Campaign ID": campaign,
                "Total Attempts": total,
                "Correctly Detected": detected,
                "Missed": missed,
                "Detection Rate (%)": f"{rate:.2f}" if rate is not None else "N/A",
            })

        df_out = pd.DataFrame(rows)
        if not df_out.empty:
            df_out = df_out.sort_values(by="Detection Rate (%)", ascending=False)
        return df_out

    # If no campaign info but attacks present, treat each row as its own campaign if it has an id
    if not attacks_df.empty and campaign_col is None:
        # Attempt to group by attack id if present
        if attack_id_col:
            for aid, group in attacks_df.groupby(attack_id_col):
                total = len(group)
                detected = 0
                if log_id_col and log_id_col in logs_df.columns:
                    try:
                        detected = int(group[attack_id_col].isin(logs_df[log_id_col]).sum())
                    except Exception:
                        detected = 0
                missed = total - detected
                rate = (detected / total * 100) if total > 0 else None
                rows.append({
                    "Campaign ID": aid,
                    "Total Attempts": total,
                    "Correctly Detected": detected,
                    "Missed": missed,
                    "Detection Rate (%)": f"{rate:.2f}" if rate is not None else "N/A",
                })
            return pd.DataFrame(rows)

    # Fallback: use logs_df as a single 'all' campaign and attempt keyword-based detection
    if not logs_df.empty:
        total = len(logs_df)
        # keyword-based detection mask
        text_cols = [c for c in logs_df.columns if logs_df[c].dtype == object]
        detected = 0
        if text_cols:
            keywords = ["alert", "detected", "threat", "malware", "intrusion", "hit", "blocked"]
            mask = pd.Series(False, index=logs_df.index)
            for c in text_cols:
                col_lower = logs_df[c].astype(str).str.lower()
                for kw in keywords:
                    mask = mask | col_lower.str.contains(kw, na=False)
            detected = int(mask.sum())

        missed = total - detected
        rate = (detected / total * 100) if total > 0 else None
        rows.append({
            "Campaign ID": "all",
            "Total Attempts": total,
            "Correctly Detected": detected,
            "Missed": missed,
            "Detection Rate (%)": f"{rate:.2f}" if rate is not None else "N/A",
        })
        return pd.DataFrame(rows)

    # No data available
    return pd.DataFrame(columns=["Campaign ID", "Total Attempts", "Correctly Detected", "Missed", "Detection Rate (%)"]) 


def print_table(result: dict) -> None:
    rows = [
        {"Metric": "Total Attempts", "Value": result["total_attempts"]},
        {"Metric": "Detected Attempts", "Value": result["detected_attempts"]},
        {"Metric": "Detection Rate", "Value": f"{(result['detection_rate']*100):.2f}%" if result["detection_rate"] is not None else "N/A"},
        {"Metric": "Evidence Files", "Value": ", ".join(result["evidence_files"]) if result["evidence_files"] else "None"},
    ]
    df = pd.DataFrame(rows)
    print('\nDetection Rate Summary:\n')
    print(df.to_string(index=False))


def main(attacks: Optional[Path], logs: Optional[Path]) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = repo_root / "data"

    attacks_path = Path(attacks) if attacks else data_dir / "attack_simulation_results.csv"
    logs_path = Path(logs) if logs else data_dir / "sample_logs.csv"

    attacks_df = safe_read_csv(attacks_path)
    logs_df = safe_read_csv(logs_path)

    # Prefer per-campaign table when possible
    campaign_df = compute_campaign_table(attacks_df, logs_df)
    if campaign_df is None or campaign_df.empty:
        # fallback to the original overall summary
        result = compute_detection_rate(attacks_df, logs_df)
        print_table(result)
    else:
        print('\nDetection Rate By Campaign:\n')
        # Ensure consistent column order
        cols = ["Campaign ID", "Total Attempts", "Correctly Detected", "Missed", "Detection Rate (%)"]
        # Some rows may be missing columns if empty; reindex to cols
        try:
            out_df = campaign_df.reindex(columns=cols)
        except Exception:
            out_df = campaign_df
        print(out_df.to_string(index=False))

    # Print a tiny sample of supporting evidence if available
    if not logs_df.empty:
        print('\nSample detection-like log rows (up to 5):')
        text_cols = [c for c in logs_df.columns if logs_df[c].dtype == object]
        if text_cols:
            sample = logs_df[text_cols].head(5)
        else:
            sample = logs_df.head(5)
        print(sample.to_string(index=False))

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute Detection Rate from project data files.")
    parser.add_argument("--attacks", help="Path to attack simulation CSV", default=None)
    parser.add_argument("--logs", help="Path to logs/IDS CSV", default=None)
    args = parser.parse_args()
    raise SystemExit(main(args.attacks, args.logs))
