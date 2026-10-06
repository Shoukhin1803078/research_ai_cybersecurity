#!/usr/bin/env python3
"""Week 3: interpretable ML baselines for incident detection.

Trains Logistic Regression (interpretable first) and Random Forest
(nonlinear baseline), evaluates both on a family-aware test split, saves the
models with joblib, writes a results table, and appends to the experiment log.

Task: binary - is the incident a confirmed attack (``malicious``)? Benign and
suspicious incidents are negative.

Usage::

    python sentinelllm/ml/baseline_models.py
    python sentinelllm/ml/baseline_models.py --seed 7 --test-fraction 0.34
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from analysis.load_events import DEFAULT_EVENTS, DEFAULT_LABELS, load_events, load_labels  # noqa: E402
from ml import evaluation as ev  # noqa: E402
from ml.features import FEATURE_COLUMNS, extract_features  # noqa: E402
from ml.splits import describe_split, family_aware_split  # noqa: E402

DEFAULT_MODELS_DIR = PACKAGE_ROOT / "reports" / "models"
DEFAULT_RESULTS = PACKAGE_ROOT / "reports" / "results_baseline.csv"

# `label` is the target; `incident_id` is an identifier. Everything else is a feature.
NUMERIC_FEATURES = [c for c in FEATURE_COLUMNS if c not in ("incident_id", "label")]


def make_models(seed: int) -> dict:
    return {
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=400, class_weight="balanced", random_state=seed, n_jobs=-1
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SentinelLLM ML baselines.")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--models-dir", type=Path, default=DEFAULT_MODELS_DIR)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--experiments", type=Path, default=ev.DEFAULT_EXPERIMENTS)
    parser.add_argument("--seed", type=int, default=20260901)
    parser.add_argument("--test-fraction", type=float, default=0.34)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    events = load_events(args.events)
    manifest = load_labels(args.labels)
    features = extract_features(events).merge(
        manifest[["incident_id", "scenario"]], on="incident_id", how="left"
    )

    train_ids, test_ids = family_aware_split(manifest, test_fraction=args.test_fraction, seed=args.seed)
    train = features[features["incident_id"].isin(train_ids)]
    test = features[features["incident_id"].isin(test_ids)]

    x_train = train[NUMERIC_FEATURES].astype(float)
    y_train = (train["label"] == "malicious").astype(int)
    x_test = test[NUMERIC_FEATURES].astype(float)
    y_test = (test["label"] == "malicious").astype(int)

    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise SystemExit("Split does not contain both classes on each side; adjust --test-fraction/--seed.")

    print(f"Train: {len(train)} incidents ({int(y_train.sum())} malicious) | Test: {len(test)} incidents ({int(y_test.sum())} malicious)")
    print("Held-out test scenarios:", ", ".join(sorted(test["scenario"].unique())))
    print()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dataset_version = f"synthetic-1.0-seed{args.seed}"
    feature_set = f"{len(NUMERIC_FEATURES)}_tabular"
    rows = []

    for name, model in make_models(args.seed).items():
        model.fit(x_train, y_train)
        scores = model.predict_proba(x_test)[:, 1]
        metrics = ev.binary_metrics(y_test, scores, threshold=args.threshold)
        bqr = ev.benign_quarantine_rate(test["label"], scores >= args.threshold)

        model_path = args.models_dir / f"{name}_seed{args.seed}.joblib"
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, model_path)

        y_pred = (scores >= args.threshold).astype(int)
        ev.save_confusion_matrix(y_test, y_pred, ev.DEFAULT_FIGURES / f"cm_{name}_seed{args.seed}.png",
                                 f"{name} (seed {args.seed})")
        ev.save_pr_curve(y_test, scores, ev.DEFAULT_FIGURES / f"pr_{name}_seed{args.seed}.png",
                         f"{name} (seed {args.seed})")

        rows.append({
            "model": name,
            "precision": metrics["precision"], "recall": metrics["recall"], "f1": metrics["f1"],
            "pr_auc": metrics["pr_auc"], "roc_auc": metrics["roc_auc"], "fpr": metrics["fpr"],
            "benign_quarantine_rate": bqr,
            "tn": metrics["tn"], "fp": metrics["fp"], "fn": metrics["fn"], "tp": metrics["tp"],
            "model_path": str(model_path.relative_to(PACKAGE_ROOT.parent)),
        })

        ev.append_experiment(args.experiments, {
            "experiment_id": f"bl-{name}-seed{args.seed}",
            "date": timestamp, "stage": "baseline", "model": name, "features": feature_set,
            "dataset_version": dataset_version, "prompt_version": "", "seed": args.seed,
            "precision": f"{metrics['precision']:.4f}", "recall": f"{metrics['recall']:.4f}",
            "f1": f"{metrics['f1']:.4f}", "pr_auc": f"{metrics['pr_auc']:.4f}", "fpr": f"{metrics['fpr']:.4f}",
            "notes": f"family-aware split; benign_quarantine_rate={bqr:.3f}",
        })

    results = pd.DataFrame(rows)
    args.results.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(args.results, index=False)

    pd.set_option("display.width", 200)
    print(results[["model", "precision", "recall", "f1", "pr_auc", "fpr", "benign_quarantine_rate"]].to_string(index=False))
    print(f"\nResults -> {args.results}")
    print(f"Experiment log -> {args.experiments}")

    split_report = describe_split(manifest, train_ids, test_ids)
    split_report.to_csv(args.results.with_name("split_report.csv"), index=False)


if __name__ == "__main__":
    main()
