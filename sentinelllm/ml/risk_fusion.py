#!/usr/bin/env python3
"""Week 5: transparent, bounded risk fusion (v1).

Combines independent evidence into one explainable 0-100 score, following the
proposal's additive form:

    risk  = rule_score + calibrated_ml_score + vlm_score + av_corroboration
            - trusted_signature_credit - known_good_allowlist_credit
    risk  = clamp(risk, 0, 100)

Every contribution is preserved so the dashboard / LLM can show *why* the risk is
high. The weights are provisional and will be calibrated on validation data.

Safety rule enforced here: a visual/LLM signal **alone** can never reach Critical.
If there is no deterministic corroboration (no rules, no AV, no ML), the score is
capped below the Critical band.

Usage::

    python sentinelllm/ml/risk_fusion.py
    python sentinelllm/ml/risk_fusion.py --seed 7
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from analysis.load_events import DEFAULT_EVENTS, DEFAULT_LABELS, load_events, load_labels  # noqa: E402
from ml import evaluation as ev  # noqa: E402
from ml.baseline_models import NUMERIC_FEATURES, make_models  # noqa: E402
from ml.features import extract_features  # noqa: E402
from ml.splits import family_aware_split  # noqa: E402

DEFAULT_SCORES = PACKAGE_ROOT / "reports" / "risk_scores.csv"
DEFAULT_RESULTS = PACKAGE_ROOT / "reports" / "results_fusion.csv"

# Provisional rule weights (proposal S8, illustrative only).
RULE_WEIGHTS: dict[str, int] = {
    "R001": 15,  # hidden PowerShell
    "R002": 10,  # ExecutionPolicy Bypass
    "R003": 15,  # remote script download
    "R004": 10,  # password-protected archive staged to Temp
    "R005": 15,  # unsigned executable from Temp
    "R006": 20,  # browser credential-store access by unknown process
    "R007": 15,  # rare outbound destination
    "R008": 10,  # new executable creates persistence
    "R009": 10,  # LOLBin abuse
    "R010": 15,  # deceptive page + clipboard command
    "R011": 10,  # encoded PowerShell command
}

RISK_CLASSES = [(80, "Critical"), (60, "High"), (40, "Suspicious"), (20, "Observe"), (0, "Normal")]


@dataclass(frozen=True)
class RiskWeights:
    rule: dict[str, int] = field(default_factory=lambda: dict(RULE_WEIGHTS))
    max_ml_score: int = 45          # ML probability scaled to at most +45 (ML alone -> Suspicious, never High)
    max_vlm_score: int = 25         # VLM probability scaled to at most +25
    av_corroboration: int = 40      # independent AV/YARA hit
    trusted_signature_credit: int = 30   # subtracted only when no rule fired and nothing is unsigned
    known_good_credit: int = 50          # subtracted for a known-good hash/allowlist
    critical_cap_without_corroboration: int = 79


DEFAULT_WEIGHTS = RiskWeights()


@dataclass
class RiskAssessment:
    incident_id: str
    score: int
    risk_class: str
    contributions: dict[str, int]
    explanation: list[str]
    capped: bool


def classify(score: int) -> str:
    for threshold, name in RISK_CLASSES:
        if score >= threshold:
            return name
    return "Normal"


def assess(
    incident_id: str,
    rule_hits,
    ml_probability: float,
    has_unsigned: bool,
    av_detect: bool,
    vlm_probability: float = 0.0,
    known_good: bool = False,
    weights: RiskWeights = DEFAULT_WEIGHTS,
) -> RiskAssessment:
    """Fuse one incident's evidence into a bounded, explained risk score."""
    hits = sorted(set(rule_hits or []))
    rule_score = sum(weights.rule[h] for h in hits if h in weights.rule)
    ml_contrib = round(weights.max_ml_score * float(ml_probability))
    vlm_contrib = round(weights.max_vlm_score * float(vlm_probability))
    av_contrib = weights.av_corroboration if av_detect else 0
    # A valid signature excuses "looks new/unsigned" only when no behavioral rule
    # fired; it must never wash away behavioral evidence (e.g. a signed binary
    # abuse, or hidden PowerShell with a bypass flag).
    signature_applies = (not has_unsigned) and rule_score == 0
    signature_credit = -weights.trusted_signature_credit if signature_applies else 0
    allowlist_credit = -weights.known_good_credit if known_good else 0

    raw = rule_score + ml_contrib + vlm_contrib + av_contrib + signature_credit + allowlist_credit

    corroborated = (rule_score > 0) or (av_contrib > 0) or (ml_contrib > 0)
    capped = False
    if not corroborated and vlm_contrib > 0 and raw > weights.critical_cap_without_corroboration:
        raw = weights.critical_cap_without_corroboration
        capped = True

    score = int(max(0, min(100, raw)))

    explanation = [
        f"rules {hits}: +{rule_score}" if rule_score else "rules: +0",
        f"ML probability {ml_probability:.3f} -> +{ml_contrib}",
        f"VLM score {vlm_probability:.3f} -> +{vlm_contrib}",
        f"AV/YARA corroboration: +{av_contrib}",
        f"trusted signature credit: {signature_credit}",
        f"known-good allowlist credit: {allowlist_credit}",
    ]
    if capped:
        explanation.append(
            f"capped at {weights.critical_cap_without_corroboration}: visual/LLM signal alone cannot reach Critical"
        )
    return RiskAssessment(incident_id, score, classify(score), {
        "rule": rule_score, "ml": ml_contrib, "vlm": vlm_contrib,
        "av": av_contrib, "signature": signature_credit, "allowlist": allowlist_credit,
    }, explanation, capped)


def _rule_union(events: pd.DataFrame) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for incident_id, group in events.groupby("incident_id"):
        rules: set[str] = set()
        for value in group["rule_hits"]:
            if isinstance(value, list):
                rules.update(value)
        out[incident_id] = rules
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Transparent risk fusion (v1).")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--scores-out", type=Path, default=DEFAULT_SCORES)
    parser.add_argument("--results-out", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--experiments", type=Path, default=ev.DEFAULT_EXPERIMENTS)
    parser.add_argument("--seed", type=int, default=20260901)
    parser.add_argument("--detection-threshold", type=int, default=60, help="Risk score treated as an alert (default High band).")
    args = parser.parse_args()

    events = load_events(args.events)
    manifest = load_labels(args.labels)
    features = extract_features(events).merge(manifest[["incident_id", "scenario"]], on="incident_id", how="left")
    rules_by_incident = _rule_union(events)

    train_ids, test_ids = family_aware_split(manifest, seed=args.seed)
    train = features[features["incident_id"].isin(train_ids)]
    test = features[features["incident_id"].isin(test_ids)].copy().reset_index(drop=True)

    model = make_models(args.seed)["logistic_regression"]
    model.fit(train[NUMERIC_FEATURES].astype(float), (train["label"] == "malicious").astype(int))
    ml_prob = model.predict_proba(test[NUMERIC_FEATURES].astype(float))[:, 1]

    score_rows = []
    for position, row in test.iterrows():
        assessment = assess(
            row["incident_id"],
            rules_by_incident.get(row["incident_id"], set()),
            ml_probability=ml_prob[position],
            has_unsigned=bool(row["has_unsigned_process"]),
            av_detect=bool(row["av_hit"]),
        )
        score_rows.append({
            "incident_id": row["incident_id"], "scenario": row["scenario"], "label": row["label"],
            "ml_probability": round(float(ml_prob[position]), 4),
            "risk_score": assessment.score, "risk_class": assessment.risk_class,
            "rule_contrib": assessment.contributions["rule"], "ml_contrib": assessment.contributions["ml"],
            "vlm_contrib": assessment.contributions["vlm"], "av_contrib": assessment.contributions["av"],
            "signature_contrib": assessment.contributions["signature"],
            "capped": assessment.capped,
        })

    scores = pd.DataFrame(score_rows)
    args.scores_out.parent.mkdir(parents=True, exist_ok=True)
    scores.to_csv(args.scores_out, index=False)

    y_true = (scores["label"] == "malicious").astype(int)

    # Ablation preview: rules only vs ML only vs full fusion.
    rules_only = np.clip(scores["rule_contrib"], 0, 100)
    ml_only = np.clip(scores["ml_contrib"], 0, 100)
    configs = {"rules_only": rules_only, "ml_only": ml_only, "rules_ml_fusion": scores["risk_score"]}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    for name, vector in configs.items():
        metrics = ev.binary_metrics(y_true, vector, threshold=args.detection_threshold)
        bqr = ev.benign_quarantine_rate(scores["label"], (vector >= args.detection_threshold).astype(int).to_numpy())
        rows.append({"config": name, "threshold": args.detection_threshold,
                     "precision": metrics["precision"], "recall": metrics["recall"], "f1": metrics["f1"],
                     "pr_auc": metrics["pr_auc"], "fpr": metrics["fpr"], "benign_quarantine_rate": bqr})
        ev.append_experiment(args.experiments, {
            "experiment_id": f"fusion-{name}-seed{args.seed}", "date": timestamp, "stage": "fusion",
            "model": name, "features": "rules+ml", "dataset_version": f"synthetic-1.0-seed{args.seed}",
            "prompt_version": "", "seed": args.seed,
            "precision": f"{metrics['precision']:.4f}", "recall": f"{metrics['recall']:.4f}",
            "f1": f"{metrics['f1']:.4f}", "pr_auc": f"{metrics['pr_auc']:.4f}", "fpr": f"{metrics['fpr']:.4f}",
            "notes": f"risk fusion; threshold={args.detection_threshold}; benign_quarantine_rate={bqr:.3f}",
        })

    results = pd.DataFrame(rows)
    results.to_csv(args.results_out, index=False)

    pd.set_option("display.width", 200)
    print(f"Scored {len(scores)} test incidents (threshold >= {args.detection_threshold})")
    print("\nRisk-class distribution:")
    print(pd.crosstab(scores["label"], scores["risk_class"]).to_string())
    print("\nAblation preview (detection):")
    print(results.to_string(index=False))
    print(f"\nRisk scores -> {args.scores_out}")
    print(f"Results -> {args.results_out}")


if __name__ == "__main__":
    main()
