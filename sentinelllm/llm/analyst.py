#!/usr/bin/env python3
"""Week 7: evidence-grounded LLM incident analyst.

Assembles a structured incident per event set, runs an analyst backend, and
scores the output with the grounding validator (schema validity, unknown event
IDs, per-claim grounding, hallucination rate).

Default backend is the deterministic ``rule_based`` analyst so the pipeline runs
with no model. Point ``--candidates`` at a JSONL file of external model outputs
to score a real local/API model with the same harness.

Usage::

    python sentinelllm/llm/analyst.py
    python sentinelllm/llm/analyst.py --backend candidates --candidates llm/example_candidates.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from analysis.load_events import DEFAULT_EVENTS  # noqa: E402
from llm.backends import CandidateBackend, RuleBasedBackend, load_candidates  # noqa: E402
from llm.grounding import evaluate_grounding  # noqa: E402
from llm.incident import build_incident, load_raw_events  # noqa: E402
from llm.prompts import PROMPT_VERSION  # noqa: E402
from llm.schema import POSITIVE_ACTIONS  # noqa: E402
from ml import evaluation as ev  # noqa: E402

DEFAULT_RISK_SCORES = PACKAGE_ROOT / "reports" / "risk_scores.csv"
DEFAULT_REPORT = PACKAGE_ROOT / "reports" / "llm_report.json"
DEFAULT_RESULTS = PACKAGE_ROOT / "reports" / "results_llm.csv"


def _report_to_dict(report) -> dict:
    return {
        "valid": report.valid,
        "passes": report.passes,
        "schema_valid": report.schema_valid,
        "schema_errors": report.schema_errors,
        "unknown_ids": report.unknown_ids,
        "claims_total": report.claims_total,
        "claims_grounded": report.claims_grounded,
        "grounding_rate": round(report.grounding_rate, 4),
        "hallucination_rate": round(report.hallucination_rate, 4),
        "unsupported_claims": report.unsupported_claims,
        "concealed_unsupported": report.concealed_unsupported,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evidence-grounded LLM analyst (offline harness).")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--risk-scores", type=Path, default=DEFAULT_RISK_SCORES)
    parser.add_argument("--backend", choices=["rule_based", "candidates"], default="rule_based")
    parser.add_argument("--candidates", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--results-out", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--experiments", type=Path, default=ev.DEFAULT_EXPERIMENTS)
    parser.add_argument("--limit", type=int, default=0, help="Analyze at most N incidents (0 = all).")
    args = parser.parse_args()

    if not args.risk_scores.exists():
        raise SystemExit(f"Missing {args.risk_scores}. Run: make fusion  (or: python sentinelllm/ml/risk_fusion.py)")

    scores = pd.read_csv(args.risk_scores)
    if args.limit:
        scores = scores.head(args.limit)
    raw_by_incident = load_raw_events(args.events)

    if args.backend == "candidates":
        if not args.candidates:
            raise SystemExit("--backend candidates requires --candidates <file.jsonl>")
        backend = CandidateBackend(load_candidates(args.candidates))
    else:
        backend = RuleBasedBackend()

    incidents_json = []
    reports = []
    details = []
    y_true, y_pred = [], []

    for _, row in scores.iterrows():
        incident_id = row["incident_id"]
        raw_events = raw_by_incident.get(incident_id, [])
        incident = build_incident(incident_id, raw_events, row["ml_probability"], row["risk_score"], row["risk_class"])
        output = backend.analyze(incident)
        report = evaluate_grounding(incident, output)
        incidents_json.append({"incident": incident, "output": output, "grounding": _report_to_dict(report)})
        reports.append(report)

        action = output.get("recommended_action") if isinstance(output, dict) else None
        y_true.append(int(row["label"] == "malicious"))
        y_pred.append(int(action in POSITIVE_ACTIONS))

    n = len(reports)
    passes = sum(1 for r in reports if r.passes)
    schema_valid = sum(1 for r in reports if r.schema_valid)
    unknown_incidents = sum(1 for r in reports if r.unknown_ids)
    concealed = sum(len(r.concealed_unsupported) for r in reports)
    avg_grounding = sum(r.grounding_rate for r in reports) / n if n else 0.0
    avg_hallucination = sum(r.hallucination_rate for r in reports) / n if n else 0.0

    summary = {
        "backend": backend.name,
        "prompt_version": PROMPT_VERSION,
        "n_incidents": n,
        "schema_valid_rate": round(schema_valid / n, 4) if n else 0.0,
        "grounding_rate": round(avg_grounding, 4),
        "hallucination_rate": round(avg_hallucination, 4),
        "no_unsupported_claim_rate": round(passes / n, 4) if n else 0.0,
        "incidents_with_unknown_ids": unknown_incidents,
        "concealed_unsupported_claims": concealed,
        "classification_accuracy": round(accuracy_score(y_true, y_pred), 4) if n else 0.0,
        "classification_precision": round(precision_score(y_true, y_pred, zero_division=0), 4) if n else 0.0,
        "classification_recall": round(recall_score(y_true, y_pred, zero_division=0), 4) if n else 0.0,
        "classification_f1": round(f1_score(y_true, y_pred, zero_division=0), 4) if n else 0.0,
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps({"summary": summary, "incidents": incidents_json}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    results = pd.DataFrame([{**summary}])
    results.to_csv(args.results_out, index=False)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev.append_experiment(args.experiments, {
        "experiment_id": f"llm-{backend.name}",
        "date": timestamp, "stage": "llm", "model": backend.name, "features": "structured_incident",
        "dataset_version": "synthetic-1.0", "prompt_version": PROMPT_VERSION, "seed": "",
        "precision": f"{summary['classification_precision']:.4f}",
        "recall": f"{summary['classification_recall']:.4f}",
        "f1": f"{summary['classification_f1']:.4f}", "pr_auc": "", "fpr": "",
        "notes": f"grounding={summary['grounding_rate']:.3f}; hallucination={summary['hallucination_rate']:.3f}; no_unsupported={summary['no_unsupported_claim_rate']:.3f}",
    })

    print(f"Backend: {backend.name} | prompt {PROMPT_VERSION} | incidents: {n}")
    for key, value in summary.items():
        if key not in ("backend", "prompt_version", "n_incidents"):
            print(f"  {key}: {value}")
    print(f"\nReport -> {args.report}")
    print(f"Results -> {args.results_out}")


if __name__ == "__main__":
    main()
