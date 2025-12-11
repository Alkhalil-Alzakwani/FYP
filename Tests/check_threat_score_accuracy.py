"""Check Threat-Score Accuracy

Assesses how well the system's automated threat scores align with the
actual severity labels on events. Helps prioritize alerts correctly.

Metrics reported:
- Classification Accuracy (score bands vs. labeled severity)
- Confusion Matrix (Actual vs. Predicted severity class)
- Correlation (Spearman) between numeric severity and score
- MAE (mean absolute error) between expected severity (scaled) and score

Usage:
  python Tests/check_threat_score_accuracy.py
  python Tests/check_threat_score_accuracy.py --logs data/sample_logs.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Tuple, Optional

import pandas as pd
import numpy as np
 # Spearman correlation without scipy: Pearson on ranks


SEVERITY_NORMALIZATION = {
    # map many common labels to four classes: low, medium, high, critical
    "informational": "low",
    "info": "low",
    "notice": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "alert": "high",
    "high": "high",
    "severe": "high",
    "critical": "critical",
    "emergency": "critical",
}

SEVERITY_TO_INDEX = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INDEX_TO_SEVERITY = {v: k for k, v in SEVERITY_TO_INDEX.items()}

# Expected numeric target (for MAE vs. score), center points of bands
SEVERITY_INDEX_TO_TARGET = {
    0: 12.5,   # low 0-25
    1: 37.5,   # medium 25-50
    2: 62.5,   # high 50-75
    3: 87.5,   # critical 75-100
}


def normalize_severity(s: Optional[str]) -> Optional[str]:
    if s is None or (isinstance(s, float) and np.isnan(s)):
        return None
    val = str(s).strip().lower()
    return SEVERITY_NORMALIZATION.get(val, val if val in SEVERITY_TO_INDEX else None)


def score_to_class(score: Optional[float]) -> Optional[str]:
    try:
        x = float(score)
    except (TypeError, ValueError):
        return None
    if x < 0:
        return None
    if x < 25:
        return "low"
    if x < 50:
        return "medium"
    if x < 75:
        return "high"
    return "critical"


def pick_predicted_class(row: pd.Series) -> Optional[str]:
    # Prefer numeric threat_score if available
    pred = score_to_class(row.get("threat_score"))
    if pred:
        return pred
    # Fallback using verdict keywords
    for fld in ["ai_verdict", "flagged", "is_threat"]:
        if fld in row.index:
            v = str(row.get(fld)).lower()
            if any(k in v for k in ["critical", "severe"]):
                return "critical"
            if any(k in v for k in ["high", "urgent"]):
                return "high"
            if any(k in v for k in ["medium", "moderate", "suspicious"]):
                return "medium"
            if any(k in v for k in ["low", "benign"]):
                return "low"
    return None


def compute_metrics(df: pd.DataFrame) -> dict:
    out = {
        "total": 0,
        "usable": 0,
        "accuracy": None,
        "spearman_corr": None,
        "mae": None,
        "confusion": pd.DataFrame(),
        "by_class": pd.DataFrame(),
    }
    if df.empty:
        return out

    # Build actual and predicted
    actual = df["actual_class"].dropna()
    pred = df.loc[actual.index, "pred_class"].dropna()
    aligned_idx = actual.index.intersection(pred.index)

    if len(aligned_idx) == 0:
        return out

    actual = actual.loc[aligned_idx]
    pred = df.loc[aligned_idx, "pred_class"]

    out["total"] = len(df)
    out["usable"] = len(aligned_idx)

    # Accuracy
    acc = float((actual.values == pred.values).mean()) if len(aligned_idx) else np.nan
    out["accuracy"] = acc

    # Confusion matrix
    labels = ["low", "medium", "high", "critical"]
    conf = pd.crosstab(actual, pred, rownames=["Actual"], colnames=["Predicted"], dropna=False)
    # Ensure all labels present
    for l in labels:
        if l not in conf.index:
            conf.loc[l] = 0
        if l not in conf.columns:
            conf[l] = 0
    conf = conf.loc[labels, labels]
    out["confusion"] = conf.astype(int)

    # Per-class precision/recall (simple)
    prec = {}
    rec = {}
    for l in labels:
        tp = conf.loc[l, l]
        col_sum = conf[l].sum()
        row_sum = conf.loc[l].sum()
        prec[l] = (tp / col_sum) if col_sum > 0 else np.nan
        rec[l] = (tp / row_sum) if row_sum > 0 else np.nan
    out["by_class"] = pd.DataFrame({"precision": prec, "recall": rec})

    # Spearman correlation between numeric severity and threat_score
    # Build numeric arrays on aligned rows only where score is present
    scores = df.loc[aligned_idx, "threat_score_numeric"].astype(float)
    sev_idx = actual.map(SEVERITY_TO_INDEX).astype(float)
    valid = scores.notna() & sev_idx.notna()
    if valid.any():
        # rank the data and compute Pearson on ranks
        s1 = pd.Series(sev_idx[valid]).rank(method="average")
        s2 = pd.Series(scores[valid]).rank(method="average")
        arr1 = s1.to_numpy(dtype=float)
        arr2 = s2.to_numpy(dtype=float)
        if arr1.std() > 0 and arr2.std() > 0:
            corr = float(np.corrcoef(arr1, arr2)[0, 1])
            out["spearman_corr"] = corr if corr == corr else None

    # MAE between score and target centers of actual class
    targets = actual.map(SEVERITY_TO_INDEX).map(SEVERITY_INDEX_TO_TARGET).astype(float)
    valid2 = scores.notna() & targets.notna()
    if valid2.any():
        mae = np.abs(scores[valid2] - targets[valid2]).mean()
        out["mae"] = float(mae)

    return out


def build_dataset(logs_path: Path) -> pd.DataFrame:
    df = pd.read_csv(logs_path)

    # Normalize actual severity from available fields
    actual = None
    for col in ["severity", "actual_severity", "label", "ground_truth"]:
        if col in df.columns:
            actual = df[col].map(normalize_severity)
            break
    if actual is None:
        # try to infer: if category == normal -> low, if threat -> high/critical
        if "category" in df.columns:
            inferred = df["category"].astype(str).str.lower().map({"normal": "low", "benign": "low", "threat": "high"})
            actual = inferred
        else:
            actual = pd.Series([None]*len(df))

    # Predicted from score/verdict
    pred = df.apply(pick_predicted_class, axis=1)

    # Numeric score
    score_num = pd.to_numeric(df.get("threat_score", pd.Series(index=df.index, dtype=float)), errors="coerce")

    out = pd.DataFrame({
        "event_id": df.get("event_id", pd.Series(index=df.index, dtype=object)),
        "actual_class": actual,
        "pred_class": pred,
        "threat_score_numeric": score_num,
        "sourcetype": df.get("sourcetype", pd.Series(index=df.index, dtype=object)),
    })
    return out


def print_results(metrics: dict):
    print("\n" + "="*80)
    print(" THREAT-SCORE ACCURACY ANALYSIS")
    print("="*80)
    print("\nOVERALL METRICS:")
    print("-"*80)
    print(f"Total Events:                 {metrics['total']}")
    print(f"Usable (with labels+scores):  {metrics['usable']}")
    if metrics["accuracy"] is not None:
        print(f"Classification Accuracy:      {metrics['accuracy']*100:.2f}%")
    else:
        print("Classification Accuracy:      N/A")
    if metrics["spearman_corr"] is not None:
        print(f"Spearman Correlation:         {metrics['spearman_corr']:.3f}")
    else:
        print("Spearman Correlation:         N/A")
    if metrics["mae"] is not None:
        print(f"MAE vs Target Center:         {metrics['mae']:.2f}")
    else:
        print("MAE vs Target Center:         N/A")

    if not metrics["confusion"].empty:
        print("\n\nCONFUSION MATRIX (Actual x Predicted):")
        print("-"*80)
        print(metrics["confusion"].to_string())

    if not metrics["by_class"].empty:
        print("\n\nPER-CLASS PRECISION/RECALL:")
        print("-"*80)
        print(metrics["by_class"].to_string())
    print("\n" + "="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Compute Threat-Score Accuracy metrics")
    parser.add_argument("--logs", type=str, default="data/sample_logs.csv", help="Path to logs CSV with severity and threat_score")
    args = parser.parse_args()

    base = Path(__file__).parent.parent
    logs_path = base / args.logs

    print("="*80)
    print(" THREAT-SCORE ACCURACY")
    print("="*80)
    print(f"Logs file: {logs_path}")

    if not logs_path.exists():
        print("Error: logs file not found. Provide --logs path.")
        return

    data = build_dataset(logs_path)
    metrics = compute_metrics(data)
    print_results(metrics)

    # Save outputs
    out_dir = base / "data"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "threat_score_accuracy_summary.csv").write_text(
        pd.DataFrame([{
            "total": metrics["total"],
            "usable": metrics["usable"],
            "accuracy_pct": round(metrics["accuracy"]*100, 2) if metrics["accuracy"] is not None else None,
            "spearman_corr": metrics["spearman_corr"],
            "mae": metrics["mae"],
        }]).to_csv(index=False)
    )
    if not metrics["confusion"].empty:
        metrics["confusion"].to_csv(out_dir / "threat_score_confusion_matrix.csv")
    if not metrics["by_class"].empty:
        metrics["by_class"].to_csv(out_dir / "threat_score_per_class.csv")


if __name__ == "__main__":
    main()
