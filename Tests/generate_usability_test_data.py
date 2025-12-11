"""Generate synthetic UI telemetry for usability rating analysis"""
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import random
import uuid

base = Path(__file__).parent.parent
out_dir = base / "data"
out_dir.mkdir(exist_ok=True)

random.seed(42)

users = ["analyst_john","analyst_sarah","analyst_mike","soc_lead"]

# Load detections for alert ids if available
Detections = None
try:
    det_path = out_dir / "detected_from_db.csv"
    if det_path.exists():
        Detections = pd.read_csv(det_path)
except Exception:
    Detections = None

alert_ids = []
if Detections is not None and "event_id" in Detections.columns:
    alert_ids = list(Detections["event_id"].dropna().astype(str).unique())
else:
    # fallback
    alert_ids = [f"ALERT-{i:04d}" for i in range(1, 101)]

start = datetime.now() - timedelta(hours=6)

rows = []

def add_event(session, user, ts, action, alert_id=None, dwell_ms=None, extra=None):
    rows.append({
        "session_id": session,
        "user_id": user,
        "timestamp": ts.isoformat(timespec="seconds"),
        "action": action,
        "alert_id": alert_id,
        "dwell_time_ms": dwell_ms if dwell_ms is not None else 0,
        "tooltip_seen": extra.get("tooltip_seen") if extra else False,
        "help_clicked": extra.get("help_clicked") if extra else False,
        "error": extra.get("error") if extra else False,
        "view": extra.get("view") if extra else None,
    })

# Simulate ~50 sessions
for s in range(50):
    session_id = str(uuid.uuid4())
    user = random.choice(users)
    t = start + timedelta(minutes=random.randint(0, 300))

    # open dashboard
    add_event(session_id, user, t, "view_dashboard", extra={"view":"overview"})

    tasks = random.randint(1, 5)  # alerts inspected/responded in session
    for _ in range(tasks):
        alert = random.choice(alert_ids)
        t += timedelta(seconds=random.randint(5, 60))
        add_event(session_id, user, t, "view_alert_list", extra={"view":"alerts"})

        # open details
        t += timedelta(seconds=random.randint(2, 20))
        dwell = random.randint(3_000, 45_000)
        tooltip = random.random() < 0.6
        helpc = (not tooltip) and (random.random() < 0.2)
        add_event(session_id, user, t, "open_alert_details", alert_id=alert, dwell_ms=dwell,
                  extra={"tooltip_seen": tooltip, "help_clicked": helpc})

        # some filtering/search
        for _ in range(random.randint(0, 2)):
            t += timedelta(seconds=random.randint(1, 10))
            add_event(session_id, user, t, random.choice(["filter_change","search"]), alert_id=alert)

        # possible error/backtrack
        if random.random() < 0.1:
            t += timedelta(seconds=2)
            add_event(session_id, user, t, "error_modal", alert_id=alert, extra={"error": True})
            t += timedelta(seconds=1)
            add_event(session_id, user, t, "back", alert_id=alert)

        # decide to respond or dismiss
        will_respond = random.random() < 0.7
        if will_respond:
            steps = random.randint(1, 3)
            for _ in range(steps):
                t += timedelta(seconds=random.randint(2, 6))
                add_event(session_id, user, t, "click_respond", alert_id=alert)
            t += timedelta(seconds=random.randint(2, 6))
            add_event(session_id, user, t, "confirm_action", alert_id=alert)
        else:
            t += timedelta(seconds=random.randint(2, 8))
            add_event(session_id, user, t, "dismiss_alert", alert_id=alert)

ui_path = out_dir / "ui_events.csv"
pd.DataFrame(rows).to_csv(ui_path, index=False)
print(f"✓ Generated {len(rows)} UI events: {ui_path}")
