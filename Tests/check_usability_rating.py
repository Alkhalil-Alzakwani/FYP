"""Check Usability Rating

Quantifies dashboard usability from UI telemetry: navigation efficiency,
alert comprehension, response actionability, and error rate.

Outputs overall 0-100 rating and subscores.

Usage:
  python Tests/check_usability_rating.py
  python Tests/check_usability_rating.py --ui data/ui_events.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path
import pandas as pd
import numpy as np

# Weights for overall score
WEIGHTS = {
    "navigation": 0.30,
    "comprehension": 0.25,
    "actionability": 0.35,
    "errors": 0.10,
}


def safe_read_csv(p: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(p)
    except Exception:
        return pd.DataFrame()


def percentile_score(x, low_good=True, cap_low=0, cap_high=None):
    # Convert a positive metric into 0..100 (lower-is-better if low_good)
    x = float(x)
    if cap_high is not None:
        x = min(x, cap_high)
    if low_good:
        # map 0 -> 100, cap_high -> 0
        if cap_high is None or cap_high == 0:
            return max(0, 100 - x)
        return max(0.0, 100.0 * (1.0 - x / cap_high))
    else:
        # high is good; cap_high is max
        if cap_high is None or cap_high == 0:
            return min(100.0, x)
        return min(100.0, 100.0 * (x / cap_high))


def compute_metrics(ui: pd.DataFrame) -> dict:
    out = {
        "sessions": 0,
        "alerts_viewed": 0,
        "alerts_responded": 0,
        "nav_clicks_per_task": None,
        "time_to_action_sec": None,
        "tooltip_coverage": None,
        "help_usage_rate": None,
        "error_rate_per_task": None,
        "steps_to_response": None,
        "scores": {},
        "overall": None,
    }
    if ui.empty:
        return out

    ui["timestamp"] = pd.to_datetime(ui["timestamp"], errors="coerce")
    ui = ui.sort_values(["session_id", "timestamp"])  # chronologically per session

    out["sessions"] = ui["session_id"].nunique()

    # Define tasks as sequences starting at open_alert_details for an alert_id until confirm/dismiss/back
    tasks = []
    for sid, group in ui.groupby("session_id"):
        current = None
        for _, r in group.iterrows():
            act = str(r.get("action"))
            if act == "open_alert_details" and pd.notna(r.get("alert_id")):
                if current is not None:
                    tasks.append(current)
                current = {
                    "session_id": sid,
                    "alert_id": r["alert_id"],
                    "start": r["timestamp"],
                    "clicks": 1,
                    "errors": 1 if r.get("error") is True else 0,
                    "saw_tooltip": bool(r.get("tooltip_seen")),
                    "help_clicked": bool(r.get("help_clicked")),
                    "dwell_ms": int(r.get("dwell_time_ms", 0) or 0),
                    "responded": False,
                    "steps_to_response": None,
                    "time_to_action_sec": None,
                }
            elif current is not None:
                # within a task
                current["clicks"] += 1
                if r.get("error") is True:
                    current["errors"] += 1
                if str(r.get("action")) in ("click_respond", "confirm_action") and current["steps_to_response"] is None:
                    # first actionable click from start
                    current["steps_to_response"] = current["clicks"]
                    current["time_to_action_sec"] = (r["timestamp"] - current["start"]).total_seconds()
                if act == "confirm_action":
                    current["responded"] = True
                    tasks.append(current)
                    current = None
                elif act in ("dismiss_alert", "back"):
                    tasks.append(current)
                    current = None
        if current is not None:
            tasks.append(current)

    if not tasks:
        return out

    tdf = pd.DataFrame(tasks)

    out["alerts_viewed"] = len(tdf)
    out["alerts_responded"] = int(tdf["responded"].sum())

    # Core KPIs
    nav_clicks = tdf["clicks"].median()
    time_to_action = tdf["time_to_action_sec"].dropna().median() if tdf["time_to_action_sec"].notna().any() else np.nan
    tooltip_cov = (tdf["saw_tooltip"].mean() * 100.0) if len(tdf) > 0 else np.nan
    help_rate = (tdf["help_clicked"].mean() * 100.0) if len(tdf) > 0 else np.nan
    error_rate = (tdf["errors"].sum() / len(tdf)) if len(tdf) > 0 else np.nan
    steps_resp = tdf["steps_to_response"].dropna().median() if tdf["steps_to_response"].notna().any() else np.nan

    out.update({
        "nav_clicks_per_task": float(nav_clicks) if nav_clicks == nav_clicks else None,
        "time_to_action_sec": float(time_to_action) if time_to_action == time_to_action else None,
        "tooltip_coverage": float(tooltip_cov) if tooltip_cov == tooltip_cov else None,
        "help_usage_rate": float(help_rate) if help_rate == help_rate else None,
        "error_rate_per_task": float(error_rate) if error_rate == error_rate else None,
        "steps_to_response": float(steps_resp) if steps_resp == steps_resp else None,
    })

    # Convert KPIs to 0..100 sub-scores with simple caps
    scores = {}
    scores["navigation"] = (
        0.5 * percentile_score(nav_clicks, low_good=True, cap_high=12) +
        0.5 * percentile_score(time_to_action or 120, low_good=True, cap_high=120)
    )
    scores["comprehension"] = (
        0.7 * percentile_score(100 - (tooltip_cov or 0), low_good=True, cap_high=100) +
        0.3 * percentile_score(100 - (help_rate or 0), low_good=True, cap_high=100)
    )
    # Actionability: faster steps and higher response rate imply higher score
    response_rate = (tdf["responded"].mean() * 100.0)
    scores["actionability"] = (
        0.6 * percentile_score(steps_resp or 6, low_good=True, cap_high=6) +
        0.4 * percentile_score(response_rate, low_good=False, cap_high=100)
    )
    scores["errors"] = percentile_score(error_rate or 1.0, low_good=True, cap_high=1.0)

    out["scores"] = {k: round(v, 2) for k, v in scores.items()}
    overall = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
    out["overall"] = round(overall, 2)
    return out


def interpret(overall: float) -> str:
    if overall >= 85:
        return "EXCELLENT – very easy to use"
    if overall >= 70:
        return "GOOD – efficient and understandable"
    if overall >= 55:
        return "MODERATE – some friction present"
    return "POOR – needs UX improvements"


def print_results(r: dict):
    print("\n" + "="*80)
    print(" USABILITY RATING ANALYSIS")
    print("="*80)
    print("\nSUMMARY:")
    print("-"*80)
    print(f"Sessions:                     {r['sessions']}")
    print(f"Alerts Viewed (tasks):        {r['alerts_viewed']}")
    print(f"Alerts Responded:             {r['alerts_responded']}")
    print("-"*80)
    print(f"Clicks per Task (median):     {r['nav_clicks_per_task']}")
    print(f"Time to First Action (s):     {r['time_to_action_sec']}")
    print(f"Tooltip Coverage (%):         {r['tooltip_coverage']}")
    print(f"Help Usage Rate (%):          {r['help_usage_rate']}")
    print(f"Errors per Task:              {r['error_rate_per_task']}")
    print(f"Steps to Response (median):   {r['steps_to_response']}")
    print("-"*80)
    print("\nSUB-SCORES (0..100):")
    print("-"*80)
    for k, v in r["scores"].items():
        print(f"{k.capitalize():<15}: {v:>6.2f}")
    print("-"*80)
    print(f"Overall Usability Rating:     {r['overall']}/100")
    print(f"Status: {interpret(r['overall'])}")
    print("\n" + "="*80 + "\n")


def main():
    p = argparse.ArgumentParser(description="Compute Usability Rating from UI telemetry")
    p.add_argument("--ui", type=str, default="data/ui_events.csv", help="Path to UI events CSV")
    args = p.parse_args()

    base = Path(__file__).parent.parent
    ui_path = base / args.ui

    print("="*80)
    print(" USABILITY RATING")
    print("="*80)
    print(f"UI telemetry: {ui_path}")

    if not ui_path.exists():
        print("No UI telemetry found. Generate with Tests/generate_usability_test_data.py")
        return

    ui = safe_read_csv(ui_path)
    r = compute_metrics(ui)
    print_results(r)

    # Save summary
    out_dir = base / "data"
    out_dir.mkdir(exist_ok=True)
    pd.DataFrame([{**r, "scores": None}]).to_csv(out_dir / "usability_results.csv", mode="a", header=not (out_dir/"usability_results.csv").exists(), index=False)

if __name__ == "__main__":
    main()
