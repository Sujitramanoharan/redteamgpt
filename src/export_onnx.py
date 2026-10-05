"""Export a detector to ONNX and prove it still makes the same decisions.

ONNX Runtime needs far less memory than PyTorch and runs faster on CPU, which
decides how small (and cheap) a server can host the API. It is only worth
shipping if verdicts do not change, so every candidate is measured against the
PyTorch model on the held-out set and the benchmark, and the smallest one that
agrees on at least 99.5% of verdicts is kept.

Plain dynamic int8 quantisation of everything failed that bar on v5 (96.3%,
46 flipped verdicts, mostly long role-play prompts), so the candidates are, in
order of preference: int8 on MatMul weights only with per-channel scales, then
full-precision ONNX.

    python src/export_onnx.py --model models/detector-v6
    # then serve it with INFERENCE_BACKEND=onnx

Writes model.onnx (the winning candidate) and onnx_parity.json.
"""
import argparse
import ast
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))

MAX_LEN = 256
MIN_AGREEMENT = 0.995


def export_fp32(model_dir: Path) -> Path:
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).eval()
    sample = tokenizer(["example prompt"], return_tensors="pt")
    fp32 = model_dir / "model.fp32.onnx"
    torch.onnx.export(
        model, (sample["input_ids"], sample["attention_mask"]), str(fp32),
        input_names=["input_ids", "attention_mask"], output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch", 1: "seq"},
                      "attention_mask": {0: "batch", 1: "seq"},
                      "logits": {0: "batch"}},
        opset_version=17, dynamo=False,
    )
    return fp32


def quantise_matmul(fp32: Path) -> Path:
    from onnxruntime.quantization import QuantType, quantize_dynamic

    out = fp32.with_name("model.int8-matmul.onnx")
    # Embeddings, layer norms and attention softmax stay in fp32; only the
    # large MatMul weights are quantised, each output channel with its own scale.
    quantize_dynamic(str(fp32), str(out), weight_type=QuantType.QInt8,
                     per_channel=True, reduce_range=True, op_types_to_quantize=["MatMul"])
    return out


def _texts() -> list[str]:
    texts = pd.read_csv(ROOT / "data" / "heldout.csv")["text"].dropna().tolist()
    tree = ast.parse((ROOT / "src" / "benchmark.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") in ("ATTACKS", "BENIGN"):
            for elt in node.value.elts:
                try:
                    texts.append(eval(compile(ast.Expression(elt), "<b>", "eval"),
                                      {"__builtins__": {}}, {})[1])
                except Exception:
                    pass
    return texts


def _max_window_prob(tokenizer, run, text: str) -> float:
    enc = tokenizer(text, truncation=True, max_length=MAX_LEN, stride=64,
                    return_overflowing_tokens=True, padding=True, return_tensors="np")
    logits = run(enc["input_ids"][:32].astype(np.int64), enc["attention_mask"][:32].astype(np.int64))
    exp = np.exp(logits - logits.max(axis=1, keepdims=True))
    return float((exp[:, 1] / exp.sum(axis=1)).max())


def parity(model_dir: Path, onnx_path: Path, threshold: float = 0.5) -> dict:
    import onnxruntime as ort

    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).eval()
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])

    def run_torch(ids, mask):
        with torch.no_grad():
            return model(input_ids=torch.from_numpy(ids), attention_mask=torch.from_numpy(mask)).logits.numpy()

    def run_onnx(ids, mask):
        return session.run(["logits"], {"input_ids": ids, "attention_mask": mask})[0]

    texts = _texts()
    timings = {"torch": 0.0, "onnx": 0.0}
    p_torch, p_onnx = [], []
    for t in texts:
        start = time.perf_counter()
        p_torch.append(_max_window_prob(tokenizer, run_torch, t))
        timings["torch"] += time.perf_counter() - start
        start = time.perf_counter()
        p_onnx.append(_max_window_prob(tokenizer, run_onnx, t))
        timings["onnx"] += time.perf_counter() - start

    p_torch, p_onnx = np.array(p_torch), np.array(p_onnx)
    agree = (p_torch >= threshold) == (p_onnx >= threshold)
    flips = [texts[i][:100] for i in np.where(~agree)[0][:10]]
    return {
        "onnx_file": onnx_path.name,
        "prompts": len(texts),
        "verdict_agreement": round(float(agree.mean()), 4),
        "flipped_verdicts": int((~agree).sum()),
        "flipped_examples": flips,
        "max_probability_delta": round(float(np.abs(p_torch - p_onnx).max()), 4),
        "mean_ms_torch": round(timings["torch"] / len(texts) * 1000, 1),
        "mean_ms_onnx": round(timings["onnx"] / len(texts) * 1000, 1),
        "size_mb": round(onnx_path.stat().st_size / 1e6, 1),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", required=True)
    p.add_argument("--threads", type=int, default=2)
    args = p.parse_args()
    torch.set_num_threads(args.threads)

    model_dir = Path(args.model)
    fp32 = export_fp32(model_dir)
    candidates = [("int8-matmul-per-channel", quantise_matmul(fp32)), ("fp32", fp32)]

    reports, chosen = [], None
    for name, path in candidates:
        report = parity(model_dir, path) | {"variant": name}
        report["passes"] = report["verdict_agreement"] >= MIN_AGREEMENT
        reports.append(report)
        print(json.dumps(report, indent=2), flush=True)
        if report["passes"]:
            chosen = (name, path)
            break

    summary = {"torch_weights_mb": round((model_dir / "model.safetensors").stat().st_size / 1e6, 1),
               "min_agreement": MIN_AGREEMENT, "candidates": reports,
               "chosen": chosen[0] if chosen else None}
    (model_dir / "onnx_parity.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    for _, path in candidates:
        if not chosen or path != chosen[1]:
            path.unlink(missing_ok=True)
    if not chosen:
        print(f"No candidate reached {MIN_AGREEMENT:.1%} agreement: keep INFERENCE_BACKEND=torch.")
        return 1
    chosen[1].replace(model_dir / "model.onnx")
    print(f"Serving candidate: {chosen[0]} -> {model_dir / 'model.onnx'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
