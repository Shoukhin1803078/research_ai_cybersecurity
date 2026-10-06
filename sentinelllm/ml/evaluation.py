"""Evaluation metrics, plots, and experiment logging (Week 4).

Primary task is binary: is this incident a confirmed attack (``malicious``)?
Everything that is not malicious (benign and suspicious) counts as negative, so
the false-positive rate reflects analyst-visible noise.
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIGURES = PACKAGE_ROOT / "reports" / "figures"
DEFAULT_EXPERIMENTS = PACKAGE_ROOT / "reports" / "experiments.csv"

EXPERIMENT_COLUMNS = [
    "experiment_id", "date", "stage", "model", "features", "dataset_version",
    "prompt_version", "seed", "precision", "recall", "f1", "pr_auc", "fpr", "notes",
]


def binary_metrics(y_true, y_score, threshold: float = 0.5) -> dict:
    """Precision, recall, F1, PR-AUC, ROC-AUC, FPR and the confusion-matrix cells."""
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    y_pred = (y_score >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = len(set(y_true.tolist())) == 2

    return {
        "threshold": threshold,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, y_score)) if both_classes else float("nan"),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if both_classes else float("nan"),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
    }


def benign_quarantine_rate(labels, y_pred) -> float:
    """Fraction of truly benign incidents flagged positive. A first-class metric."""
    labels = np.asarray(labels)
    y_pred = np.asarray(y_pred).astype(int)
    benign = labels == "benign"
    return float(y_pred[benign].mean()) if benign.any() else float("nan")


def save_confusion_matrix(y_true, y_pred, path: str | Path, title: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    matrix = confusion_matrix(np.asarray(y_true).astype(int), np.asarray(y_pred).astype(int), labels=[0, 1])

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.imshow(matrix, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(matrix[i, j]), ha="center", va="center",
                    color="white" if matrix[i, j] > matrix.max() / 2 else "black", fontsize=14)
    ax.set_xticks([0, 1], ["pred neg", "pred pos"])
    ax.set_yticks([0, 1], ["true neg", "true pos"])
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def save_pr_curve(y_true, y_score, path: str | Path, title: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    precision, recall, _ = precision_recall_curve(np.asarray(y_true).astype(int), np.asarray(y_score, dtype=float))
    ap = average_precision_score(np.asarray(y_true).astype(int), np.asarray(y_score, dtype=float))

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.plot(recall, precision, color="darkorange", label=f"AP = {ap:.3f}")
    ax.set_xlabel("recall")
    ax.set_ylabel("precision")
    ax.set_title(title)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.05)
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def append_experiment(path: str | Path, row: dict) -> None:
    """Append one experiment row, writing the header if the file is new/empty."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPERIMENT_COLUMNS)
        if needs_header:
            writer.writeheader()
        writer.writerow({column: row.get(column, "") for column in EXPERIMENT_COLUMNS})
