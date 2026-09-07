"""
Train the RedTeamGPT detector: a small transformer that classifies
a prompt as malicious (1) or benign (0).
"""
import truststore
truststore.inject_into_ssl()

import numpy as np
import pandas as pd
from pathlib import Path
from datasets import Dataset
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    TrainingArguments, Trainer,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data" / "combined.csv"
MODEL_DIR = ROOT / "models" / "detector"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_NAME = "distilbert-base-uncased"   # small, CPU-friendly


def main():
    df = pd.read_csv(DATA).dropna(subset=["text"])
    train_df, test_df = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df["label"]
    )
    print(f"Train: {len(train_df)} | Test: {len(test_df)}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tok(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=128)

    train_ds = Dataset.from_pandas(train_df[["text", "label"]]).map(tok, batched=True)
    test_ds = Dataset.from_pandas(test_df[["text", "label"]]).map(tok, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    args = TrainingArguments(
        output_dir=str(MODEL_DIR / "checkpoints"),
        num_train_epochs=2,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        logging_steps=50,
        save_strategy="no",
        report_to="none",
    )

    trainer = Trainer(model=model, args=args, train_dataset=train_ds, eval_dataset=test_ds)
    print("Training... (a few minutes on CPU)")
    trainer.train()

    # Evaluate
    preds_output = trainer.predict(test_ds)
    logits = preds_output.predictions
    probs = (np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True))[:, 1]
    preds = logits.argmax(axis=1)
    y = test_df["label"].values

    print("\n" + "=" * 50)
    print("RedTeamGPT Detector - Test Performance")
    print("=" * 50)
    print("Accuracy :", round(accuracy_score(y, preds), 3))
    print("Precision:", round(precision_score(y, preds), 3))
    print("Recall   :", round(recall_score(y, preds), 3), " (attacks caught)")
    print("F1 score :", round(f1_score(y, preds), 3))
    print("ROC-AUC  :", round(roc_auc_score(y, probs), 3))

    # Save
    model.save_pretrained(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)
    print("\nModel saved to:", MODEL_DIR)


if __name__ == "__main__":
    main()
