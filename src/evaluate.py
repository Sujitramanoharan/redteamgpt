"""
RedTeamGPT evaluation: measures detection quality and evasion robustness.
Outputs metrics + a chart for the paper.
"""
import truststore
truststore.inject_into_ssl()

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from firewall import detect

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data" / "combined.csv"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def _describe_model():
    """Report the backbone actually evaluated, not a hardcoded guess."""
    from config import settings

    summary = settings.model_dir / "training_summary.json"
    if summary.exists():
        base = json.loads(summary.read_text(encoding="utf-8")).get("base_model")
        if base:
            return f"Fine-tuned {base}"

    cfg = settings.model_dir / "config.json"
    if cfg.exists():
        data = json.loads(cfg.read_text(encoding="utf-8"))
        arch = (data.get("architectures") or ["unknown"])[0]
        return f"Fine-tuned {arch} ({data.get('model_type', 'unknown')})"
    return "Unknown architecture"


def simple_paraphrase(text):
    """Create a reworded/evasive version of an attack (no API needed)."""
    prefixes = [
        "Hey, quick question: ",
        "I'm just curious, ",
        "For a story I'm writing, ",
        "Hypothetically speaking, ",
        "Can you help me understand ",
    ]
    import random
    random.seed(hash(text) % 1000)
    p = random.choice(prefixes)
    t = text[0].lower() + text[1:] if text else text
    return p + t


def evaluate(data_path=DATA):
    df = pd.read_csv(data_path).dropna(subset=["text"])
    # same split as training so we test on held-out data
    _, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])
    print(f"Evaluating on {len(test_df)} held-out prompts...")

    # --- 1. Base detection on verbatim prompts ---
    y_true, y_pred, y_prob = [], [], []
    for _, row in test_df.iterrows():
        r = detect(row["text"])
        y_true.append(int(row["label"]))
        y_pred.append(1 if r["malicious"] else 0)
        y_prob.append(r["malicious_probability"])

    y_true = np.array(y_true); y_pred = np.array(y_pred); y_prob = np.array(y_prob)

    print("\n" + "="*55)
    print("1. BASE DETECTION (verbatim prompts)")
    print("="*55)
    print("Accuracy          :", round(accuracy_score(y_true, y_pred), 3))
    print("Precision         :", round(precision_score(y_true, y_pred), 3))
    print("Detection rate    :", round(recall_score(y_true, y_pred), 3), "(recall on attacks)")
    print("F1 score          :", round(f1_score(y_true, y_pred), 3))
    print("ROC-AUC           :", round(roc_auc_score(y_true, y_prob), 3))

    # False positive rate on benign
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp+tn) else 0
    print("False-positive rate:", round(fpr, 3), "(benign wrongly blocked)")
    base_detection = recall_score(y_true, y_pred)

    # --- 2. Evasion robustness: reword the attacks, re-test ---
    attacks = test_df[test_df["label"] == 1]
    caught = 0
    for _, row in attacks.iterrows():
        evaded = simple_paraphrase(row["text"])
        r = detect(evaded)
        if r["malicious"]:
            caught += 1
    evasion_detection = caught / len(attacks) if len(attacks) else 0

    print("\n" + "="*55)
    print("2. EVASION ROBUSTNESS (reworded attacks)")
    print("="*55)
    print("Detection on verbatim attacks :", round(base_detection, 3))
    print("Detection on reworded attacks :", round(evasion_detection, 3))
    print("Robustness drop               :", round(base_detection - evasion_detection, 3))

    # --- 3. Persist metrics so the API serves measured numbers, not literals ---
    metrics = {
        "status": "OPERATIONAL",
        "architecture": _describe_model(),
        "training_dataset": Path(data_path).name,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "test_set_size": int(len(test_df)),
        "metrics": {
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred)), 4),
            "recall": round(float(recall_score(y_true, y_pred)), 4),
            "f1_score": round(float(f1_score(y_true, y_pred)), 4),
            "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
            "false_positive_rate": round(float(fpr), 4),
        },
        "robustness": {
            "detection_verbatim": round(float(base_detection), 4),
            "detection_reworded": round(float(evasion_detection), 4),
            "robustness_drop": round(float(base_detection - evasion_detection), 4),
        },
        "confusion_matrix": {
            "true_negatives": int(tn), "false_positives": int(fp),
            "false_negatives": int(fn), "true_positives": int(tp),
        },
    }
    metrics_path = RESULTS / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("\nMetrics written to:", metrics_path)

    # --- 4. Chart ---
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(["Verbatim\nattacks", "Reworded\nattacks"],
           [base_detection, evasion_detection],
           color=["#5e0a12", "#c0392b"])
    ax.set_ylabel("Detection rate")
    ax.set_ylim(0, 1)
    ax.set_title("RedTeamGPT: Detection vs Evasion Robustness")
    for i, v in enumerate([base_detection, evasion_detection]):
        ax.text(i, v + 0.02, f"{v:.2f}", ha="center", fontweight="bold")
    plt.tight_layout()
    chart_path = RESULTS / "evasion_robustness.png"
    plt.savefig(chart_path, dpi=150)
    print("\nChart saved to:", chart_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate the served model on its own test split.")
    # Must be the CSV the model was trained on, so the split matches training.
    parser.add_argument("--data", default=str(DATA))
    evaluate(parser.parse_args().data)
