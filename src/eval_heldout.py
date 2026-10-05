"""Score the full firewall on data/heldout.csv, broken down by source.

Uses firewall.detect(), not the bare classifier, because the rule layer,
normaliser and base64 decoding all change verdicts and users get the whole
pipeline. Choose the model with MODEL_DIR:

    MODEL_DIR=models/detector-v5 python src/eval_heldout.py --save results/heldout-v5.json
    MODEL_DIR=models/detector-v6 python src/eval_heldout.py --save results/heldout-v6.json
    python src/eval_heldout.py --compare results/heldout-v5.json results/heldout-v6.json
"""
import truststore
truststore.inject_into_ssl()

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))
HELDOUT = ROOT / "data" / "heldout.csv"


def evaluate() -> dict:
    from config import settings
    from firewall import detect

    df = pd.read_csv(HELDOUT).dropna(subset=["text"])
    df["blocked"] = [bool(detect(t)["malicious"]) for t in df["text"]]
    df["correct"] = df["blocked"] == (df["label"] == 1)

    by_source = {}
    # Some sources (deepset) hold both labels, so group on the pair.
    for (source, label), part in df.groupby(["source", "label"]):
        label = int(label)
        by_source[f"{source} [{'attack' if label else 'benign'}]"] = {
            "label": label,
            "n": len(part),
            # For attack sources this is recall; for benign sources, the share allowed.
            "correct_rate": round(float(part["correct"].mean()), 4),
            "misses": part.loc[~part["correct"], "text"].str.slice(0, 120).tolist()[:15],
        }

    attacks, benign = df[df["label"] == 1], df[df["label"] == 0]
    return {
        "model_dir": str(settings.model_dir),
        "n": len(df),
        "attack_recall": round(float(attacks["blocked"].mean()), 4),
        "false_positive_rate": round(float(benign["blocked"].mean()), 4),
        "by_source": by_source,
    }


def print_report(r: dict) -> None:
    print(f"Model: {r['model_dir']}   prompts: {r['n']}")
    print(f"Attack recall      : {r['attack_recall']:.1%}")
    print(f"False-positive rate: {r['false_positive_rate']:.1%}")
    for source, s in sorted(r["by_source"].items()):
        kind = "blocked" if s["label"] == 1 else "allowed"
        print(f"  {source:28s} {s['correct_rate']:6.1%} {kind}  (n={s['n']})")


def compare(a: dict, b: dict) -> None:
    print(f"{'':30s}{Path(a['model_dir']).name:>14s}{Path(b['model_dir']).name:>14s}")
    print(f"{'attack recall':30s}{a['attack_recall']:14.1%}{b['attack_recall']:14.1%}")
    print(f"{'false-positive rate':30s}{a['false_positive_rate']:14.1%}{b['false_positive_rate']:14.1%}")
    for source in sorted(set(a["by_source"]) | set(b["by_source"])):
        ra = a["by_source"].get(source, {}).get("correct_rate", float("nan"))
        rb = b["by_source"].get(source, {}).get("correct_rate", float("nan"))
        print(f"  {source:28s}{ra:14.1%}{rb:14.1%}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--save", help="write the report as JSON")
    p.add_argument("--compare", nargs=2, metavar=("A", "B"), help="compare two saved reports")
    args = p.parse_args()

    if args.compare:
        a, b = (json.loads(Path(x).read_text(encoding="utf-8")) for x in args.compare)
        compare(a, b)
        return 0

    report = evaluate()
    print_report(report)
    if args.save:
        Path(args.save).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nSaved {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
