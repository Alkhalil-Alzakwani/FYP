"""Check Dashboard Responsiveness

Measures:
- Data loading speed (CSV read, DB query, optional Splunk fetch)
- Visual refresh latency proxy (action->next-UI-event latency)
- Interaction processing latency (first respond click -> confirm)

Outputs raw timings and a 0..100 responsiveness score.

Usage:
  python Tests/check_dashboard_responsiveness.py
  python Tests/check_dashboard_responsiveness.py --use-splunk
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path
from statistics import median

import pandas as pd

# Optional imports
try:
    from models.splunk_connector import SplunkConnector
except Exception:
    SplunkConnector = None

try:
    from database.queries import get_splunk_logs
except Exception:
    get_splunk_logs = None


WEIGHTS = {
    "data_loading": 0.45,
    "visual_refresh": 0.25,
    "interaction": 0.30,
}


def safe_read_csv_timed(path: Path):
    t0 = time.perf_counter()
    try:
        df = pd.read_csv(path)
    except Exception:
        df = pd.DataFrame()
    dur = time.perf_counter() - t0
    return df, dur


def time_db_query(limit=1000):
    if get_splunk_logs is None:
        return None
    t0 = time.perf_counter()
    try:
        rows = get_splunk_logs(limit=limit)
    except Exception:
        rows = []
    dur = time.perf_counter() - t0
    return dur, len(rows) if rows else 0


def time_splunk_fetch(time_range: str = "-1h@h", max_results: int = 1000):
    if SplunkConnector is None:
        return None
    t0 = time.perf_counter()
    try:
        conn = SplunkConnector()
        ok = conn.connect()
        if not ok:
            return None
        logs = conn.fetch_logs(earliest_time=time_range, latest_time="now", max_results=max_results)
        count = len(logs) if logs else 0
    except Exception:
        count = 0
    dur = time.perf_counter() - t0
    return dur, count


def compute_visual_refresh_latency(ui: pd.DataFrame):
    # Proxy: time from user-triggered change to the next event
    if ui.empty:
        return None
    ui = ui.sort_values(["session_id", "timestamp"])  # assume timestamp parsed later

    triggers = {"filter_change", "search"}
    deltas = []

    for sid, grp in ui.groupby("session_id"):
        g = grp.reset_index(drop=True)
        for i, row in g.iterrows():
            act = str(row.get("action"))
            if act in triggers:
                # find next event in this session (any action)
                if i + 1 < len(g):
                    t1 = pd.to_datetime(row.get("timestamp"), errors="coerce")
                    t2 = pd.to_datetime(g.loc[i + 1, "timestamp"], errors="coerce")
                    if pd.notna(t1) and pd.notna(t2):
                        dt = (t2 - t1).total_seconds()
                        if 0 <= dt < 30:
                            deltas.append(dt)
    if not deltas:
        return None
    return median(deltas)


def compute_interaction_latency(ui: pd.DataFrame):
    # Time from first click_respond in a task to confirm_action
    if ui.empty:
        return None
    ui = ui.sort_values(["session_id", "timestamp"])  # assume timestamp parsed later

    deltas = []
    for sid, grp in ui.groupby("session_id"):
        g = grp.reset_index(drop=True)
        start = None
        for i, row in g.iterrows():
            act = str(row.get("action"))
            ts = pd.to_datetime(row.get("timestamp"), errors="coerce")
            if act == "click_respond" and start is None:
                start = ts
            elif act == "confirm_action" and start is not None and pd.notna(ts) and pd.notna(start):
                dt = (ts - start).total_seconds()
                if 0 <= dt < 600:
                    deltas.append(dt)
                start = None
            elif act in ("dismiss_alert", "back"):
                start = None
    if not deltas:
        return None
    return median(deltas)


def pct_score(value, low_good=True, cap=5.0):
    # Convert seconds to score 0..100
    if value is None:
        return None
    v = max(0.0, float(value))
    if low_good:
        # 0 sec -> 100; cap sec -> 0
        return max(0.0, 100.0 * (1.0 - min(v, cap) / cap))
    else:
        # high good (unused here)
        return min(100.0, 100.0 * min(v, cap) / cap)


def print_results(res):
    print("\n" + "="*80)
    print(" DASHBOARD RESPONSIVENESS ANALYSIS")
    print("="*80)
    print("\nDATA LOADING:")
    print("-"*80)
    print(f"CSV load time (s):            {res['csv_load_time']:.3f}" if res.get('csv_load_time') is not None else "CSV load time: N/A")
    print(f"DB query time (s):            {res['db_time']:.3f} (rows={res['db_rows']})" if res.get('db_time') is not None else "DB query time: N/A")
    print(f"Splunk fetch time (s):        {res['splunk_time']:.3f} (events={res['splunk_rows']})" if res.get('splunk_time') is not None else "Splunk fetch time: skipped/failed")

    print("\nVISUAL REFRESH (proxy):")
    print("-"*80)
    print(f"Action→next event latency (s): {res['visual_refresh_latency']:.3f}" if res.get('visual_refresh_latency') is not None else "Visual refresh latency: N/A")

    print("\nINTERACTION PROCESSING:")
    print("-"*80)
    print(f"click_respond→confirm (s):    {res['interaction_latency']:.3f}" if res.get('interaction_latency') is not None else "Interaction latency: N/A")

    print("\nSCORES (0..100):")
    print("-"*80)
    for k, v in res["subscores"].items():
        print(f"{k.capitalize():<16}: {v if v is not None else 'N/A'}")
    print("-"*80)
    print(f"Overall Responsiveness:       {res['overall'] if res['overall'] is not None else 'N/A'}")
    print("\n" + "="*80 + "\n")


def main():
    ap = argparse.ArgumentParser(description="Measure dashboard responsiveness")
    ap.add_argument("--logs", type=str, default="data/sample_logs.csv", help="Path to sample logs CSV to time CSV loading")
    ap.add_argument("--ui", type=str, default="data/ui_events.csv", help="Path to UI telemetry CSV")
    ap.add_argument("--use-splunk", action="store_true", help="Attempt Splunk fetch timing")
    args = ap.parse_args()

    base = Path(__file__).parent.parent
    logs_path = base / args.logs
    ui_path = base / args.ui

    # CSV load timing
    df_logs, csv_time = safe_read_csv_timed(logs_path)

    # DB timing
    db_timing = time_db_query(limit=1000)
    if db_timing is not None:
        db_time, db_rows = db_timing
    else:
        db_time, db_rows = None, 0

    # Splunk timing
    splunk_time = None
    splunk_rows = 0
    if args.use_splunk and SplunkConnector is not None:
        t = time_splunk_fetch()
        if t is not None:
            splunk_time, splunk_rows = t

    # UI telemetry
    try:
        ui = pd.read_csv(ui_path)
        ui["timestamp"] = pd.to_datetime(ui["timestamp"], errors="coerce")
    except Exception:
        ui = pd.DataFrame()

    visual = compute_visual_refresh_latency(ui)
    inter = compute_interaction_latency(ui)

    # Scores (caps set to reasonable UX thresholds)
    subs = {
        "data_loading": None,
        "visual_refresh": None,
        "interaction": None,
    }

    # Data loading score: combine CSV and DB (median), cap=2s
    times = [t for t in [csv_time, db_time] if t is not None]
    data_time = median(times) if times else None
    subs["data_loading"] = round(pct_score(data_time, low_good=True, cap=2.0), 2) if data_time is not None else None

    # Visual refresh score (cap=0.5s perceived immediate)
    subs["visual_refresh"] = round(pct_score(visual, low_good=True, cap=0.5), 2) if visual is not None else None

    # Interaction processing score (cap=1.0s for confirm flow)
    subs["interaction"] = round(pct_score(inter, low_good=True, cap=1.0), 2) if inter is not None else None

    # Overall
    overall = None
    available = [(k, subs[k]) for k in subs if subs[k] is not None]
    if available:
        # Normalize weights for available subs
        total_w = sum(WEIGHTS[k] for k, v in available)
        overall = 0.0
        for k, v in available:
            w = WEIGHTS[k] / total_w if total_w > 0 else 0
            overall += w * v
        overall = round(overall, 2)

    result = {
        "csv_load_time": csv_time,
        "db_time": db_time,
        "db_rows": db_rows,
        "splunk_time": splunk_time,
        "splunk_rows": splunk_rows,
        "visual_refresh_latency": visual,
        "interaction_latency": inter,
        "subscores": subs,
        "overall": overall,
    }

    print_results(result)

    # Save summary
    out_dir = base / "data"
    out_dir.mkdir(exist_ok=True)
    pd.DataFrame([{**result, "subscores": None}]).to_csv(out_dir / "dashboard_responsiveness_results.csv", mode="a", header=not (out_dir/"dashboard_responsiveness_results.csv").exists(), index=False)


if __name__ == "__main__":
    main()
