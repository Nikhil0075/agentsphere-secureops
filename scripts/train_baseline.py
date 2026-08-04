"""Train and evaluate the non-LLM baseline classifier.

    python scripts/train_baseline.py

Trains on the ``train`` split, evaluates on ``val``, and writes:

* ``artifacts/models/baseline.pkl``
* ``artifacts/metrics/baseline.json`` — accuracy, macro F1, per-class precision/recall/F1,
  confusion matrix, true-positive recall, feature importance
* ``artifacts/metrics/baseline_confusion_matrix.png``

True-positive recall is reported separately from macro F1 because a missed attack is the
operationally dangerous failure (§13.2), and an averaged score hides it.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from app.config import METRICS_DIR, MODELS_DIR, ensure_dirs  # noqa: E402
from app.data import loader  # noqa: E402
from app.data.schema import LABELS  # noqa: E402
from app.models.baseline import BaselineModel  # noqa: E402

MODEL_PATH = MODELS_DIR / "baseline.pkl"
METRICS_PATH = METRICS_DIR / "baseline.json"
PLOT_PATH = METRICS_DIR / "baseline_confusion_matrix.png"


def plot_confusion(matrix: np.ndarray, path: Path, title: str) -> None:
    fig, ax = plt.subplots(figsize=(5.6, 5.0))
    ax.imshow(matrix, cmap="Blues")
    ax.set_xticks(range(len(LABELS)), LABELS, rotation=30, ha="right")
    ax.set_yticks(range(len(LABELS)), LABELS)
    ax.set_xlabel("predicted")
    ax.set_ylabel("actual")
    ax.set_title(title)

    threshold = matrix.max() / 2 if matrix.max() else 0
    for i in range(len(LABELS)):
        for j in range(len(LABELS)):
            ax.text(
                j,
                i,
                str(matrix[i, j]),
                ha="center",
                va="center",
                color="white" if matrix[i, j] > threshold else "black",
            )
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main() -> int:
    ensure_dirs()
    _, incidents = loader.load_prepared()

    train = incidents[incidents["split"] == "train"]
    val = incidents[incidents["split"] == "val"]
    if train.empty or val.empty:
        print("train or val split is empty; run scripts/prepare_data.py first", file=sys.stderr)
        return 1

    print(f"training on {len(train)} incidents, evaluating on {len(val)}")
    model = BaselineModel().fit(train)
    model.save(MODEL_PATH)
    print(f"implementation: {model.implementation}")

    predicted = model.predict(val)
    actual = val["label"].tolist()

    matrix = confusion_matrix(actual, predicted, labels=list(LABELS))
    report = classification_report(
        actual, predicted, labels=list(LABELS), output_dict=True, zero_division=0
    )

    tp_index = LABELS.index("TruePositive")
    tp_support = int(matrix[tp_index].sum())
    tp_recall = float(matrix[tp_index, tp_index] / tp_support) if tp_support else 0.0

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "implementation": model.implementation,
        "dataset": {
            "train_incidents": int(len(train)),
            "val_incidents": int(len(val)),
            "train_label_distribution": {
                str(k): int(v) for k, v in train["label"].value_counts().items()
            },
            "val_label_distribution": {
                str(k): int(v) for k, v in val["label"].value_counts().items()
            },
        },
        "accuracy": round(float(accuracy_score(actual, predicted)), 4),
        "macro_f1": round(float(f1_score(actual, predicted, average="macro", zero_division=0)), 4),
        "weighted_f1": round(
            float(f1_score(actual, predicted, average="weighted", zero_division=0)), 4
        ),
        "true_positive_recall": round(tp_recall, 4),
        "per_class": {
            label: {
                "precision": round(float(report[label]["precision"]), 4),
                "recall": round(float(report[label]["recall"]), 4),
                "f1": round(float(report[label]["f1-score"]), 4),
                "support": int(report[label]["support"]),
            }
            for label in LABELS
        },
        "confusion_matrix": {
            "labels": list(LABELS),
            "rows_are_actual": True,
            "matrix": matrix.tolist(),
        },
        "feature_importance": model.feature_importance(),
    }

    METRICS_PATH.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    plot_confusion(matrix, PLOT_PATH, f"Baseline ({model.implementation}) — validation split")

    print(f"\naccuracy             {metrics['accuracy']:.4f}")
    print(f"macro F1             {metrics['macro_f1']:.4f}")
    print(f"true-positive recall {metrics['true_positive_recall']:.4f}")
    for label in LABELS:
        c = metrics["per_class"][label]
        print(
            f"  {label:16s} P={c['precision']:.3f} R={c['recall']:.3f} "
            f"F1={c['f1']:.3f} n={c['support']}"
        )
    print(f"\ntop features: {list(metrics['feature_importance'])[:5]}")
    print(f"model   -> {MODEL_PATH}")
    print(f"metrics -> {METRICS_PATH}")
    print(f"plot    -> {PLOT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
