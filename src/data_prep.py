"""
RedTeamGPT data preparation.
Downloads attack + benign prompts, labels them, saves a combined dataset.
label: 1 = malicious (attack/jailbreak), 0 = benign (safe)
"""
import truststore
truststore.inject_into_ssl()   # office network SSL

import pandas as pd
from datasets import load_dataset
from pathlib import Path

OUT = Path(__file__).parent.parent / "data" / "combined.csv"


def load_main():
    """jackhhao/jailbreak-classification: ungated, jailbreak vs benign."""
    rows = []
    try:
        ds = load_dataset("jackhhao/jailbreak-classification", split="train")
        for r in ds:
            label = 1 if str(r["type"]).lower().startswith("jail") else 0
            rows.append({"text": r["prompt"], "label": label, "source": "jailbreak-classification"})
        print(f"jailbreak-classification: {len(rows)} rows")
    except Exception as e:
        print("main dataset failed:", e)
    return rows


def load_jbb():
    """JailbreakBench harmful behaviors as extra attacks."""
    rows = []
    try:
        jbb = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        for r in jbb:
            rows.append({"text": r["Goal"], "label": 1, "source": "JailbreakBench"})
        print(f"JailbreakBench: {len(jbb)} attack prompts")
    except Exception as e:
        print("JailbreakBench failed:", e)
    return rows


def load_alpaca(n):
    """Alpaca normal instructions as extra benign."""
    rows = []
    try:
        alp = load_dataset("tatsu-lab/alpaca", split=f"train[:{n}]")
        for r in alp:
            text = r["instruction"] + ((" " + r["input"]) if r.get("input") else "")
            rows.append({"text": text, "label": 0, "source": "Alpaca"})
        print(f"Alpaca: {len(rows)} benign prompts")
    except Exception as e:
        print("Alpaca failed:", e)
    return rows


def main():
    rows = load_main() + load_jbb()
    attacks = sum(1 for r in rows if r["label"] == 1)
    benign = sum(1 for r in rows if r["label"] == 0)
    # top up benign with Alpaca so classes are roughly balanced
    if attacks > benign:
        rows += load_alpaca(attacks - benign)

    df = pd.DataFrame(rows).dropna(subset=["text"])
    df = df[df["text"].str.len() > 5]
    df = df.drop_duplicates(subset=["text"])
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    df.to_csv(OUT, index=False)
    print("\nSaved:", OUT)
    print("Total:", len(df), "| attacks:", (df.label==1).sum(), "| benign:", (df.label==0).sum())


if __name__ == "__main__":
    main()
