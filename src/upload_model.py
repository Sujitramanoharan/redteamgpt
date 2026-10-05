"""Push trained detector weights to the Hugging Face Hub.

The `hf` CLI fails behind TLS-inspecting corporate proxies because it does not
use the system trust store. Every script here injects truststore first, so this
does the same rather than relying on the CLI.

    python src/upload_model.py --repo Sujimano/redteamgpt-detector

Needs a WRITE token: set HF_WRITE_TOKEN in .env, or pass --token. A read-only
token (such as the HF_TOKEN used to download gated datasets) will be rejected.
"""
import truststore
truststore.inject_into_ssl()

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import HfApi

ROOT = Path(__file__).parent.parent
load_dotenv(dotenv_path=ROOT / ".env")

REQUIRED_FILES = ["config.json", "model.safetensors", "tokenizer.json"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="e.g. username/redteamgpt-detector")
    parser.add_argument("--path", default=str(ROOT / "models" / "detector"),
                        help="local model directory")
    parser.add_argument("--token", default=None, help="HF write token")
    parser.add_argument("--private", action="store_true")
    args = parser.parse_args()

    model_dir = Path(args.path)
    missing = [f for f in REQUIRED_FILES if not (model_dir / f).exists()]
    if missing:
        print(f"ERROR: {model_dir} is missing {missing}", file=sys.stderr)
        print("Train the detector first: python src/train_detector.py", file=sys.stderr)
        return 1

    token = args.token or os.getenv("HF_WRITE_TOKEN") or os.getenv("HF_TOKEN")
    api = HfApi(token=token)

    try:
        who = api.whoami()
        print(f"Authenticated as: {who['name']}")
    except Exception as exc:
        print(f"ERROR: authentication failed - {exc}", file=sys.stderr)
        print("Create a WRITE token at https://huggingface.co/settings/tokens",
              file=sys.stderr)
        return 1

    size_mb = sum(f.stat().st_size for f in model_dir.rglob("*") if f.is_file()) / 1e6
    print(f"Uploading {model_dir} ({size_mb:.0f} MB) to {args.repo} ...")

    api.create_repo(repo_id=args.repo, repo_type="model",
                    private=args.private, exist_ok=True)
    commit = api.upload_folder(
        folder_path=str(model_dir),
        repo_id=args.repo,
        repo_type="model",
        # Training checkpoints can be many GB and are not needed for inference.
        ignore_patterns=["checkpoints/*", "**/optimizer.pt", "**/scheduler.pt"],
        commit_message=f"Upload detector from {model_dir.name}",
    )

    print(f"\nDone: https://huggingface.co/{args.repo}")
    print("Set these in your deployment environment:")
    print(f"  MODEL_HUB_ID={args.repo}")
    # Pinning the commit means a later push cannot silently change production.
    print(f"  MODEL_HUB_REVISION={commit.oid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
