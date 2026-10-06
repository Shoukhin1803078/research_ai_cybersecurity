"""Analyst backends (Week 7).

An ``AnalystBackend`` maps a structured incident to a schema-shaped output. Two
ship here:

- ``RuleBasedBackend`` - a deterministic, fully-grounded offline analyst. Runs the
  whole pipeline with no model and gives a zero-hallucination reference.
- ``CandidateBackend`` - serves pre-computed outputs from any external model
  (local or API) so those outputs can be scored by the same grounding validator.

A real model plugs in by producing a JSONL of ``{"incident_id": ..., "output": {...}}``
records and pointing ``--candidates`` at it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from llm.incident import SIGNAL_LABELS

ACTION_BY_RISK = {
    "Critical": "quarantine",
    "High": "quarantine",
    "Suspicious": "alert",
    "Observe": "monitor",
    "Normal": "none",
}


class AnalystBackend(Protocol):
    def analyze(self, incident: dict) -> dict: ...


def _hypothesis(signals: set[str]) -> str:
    if "browser_store_access" in signals and "rare_domain" in signals:
        return "credential/session theft with exfiltration"
    if "persistence" in signals:
        return "staged execution establishing persistence"
    if "remote_download" in signals and (signals & {"hidden_powershell", "encoded_command"}):
        return "staged remote script execution"
    if "deceptive_clipboard" in signals:
        return "social-engineering (ClickFix-style) leading to execution"
    if "av_detection" in signals:
        return "malicious payload corroborated by independent AV"
    if signals & {"hidden_powershell", "exec_policy_bypass", "encoded_command"}:
        return "suspicious hidden/obfuscated execution without corroboration"
    if signals & {"unsigned_temp", "lolbin"}:
        return "suspicious unsigned or LOLBin artifact"
    return "no malicious behavior observed"


class RuleBasedBackend:
    """Deterministic analyst: every claim cites real event IDs, so it never hallucinates."""

    name = "rule_based"

    def analyze(self, incident: dict) -> dict:
        signals = {name: ids for name, ids in incident.get("signals", {}).items() if ids}
        present = set(signals)
        risk_class = incident.get("risk_class", "Normal")

        claims = [
            {"text": f"Observed {SIGNAL_LABELS[name]}", "evidence": list(ids)}
            for name, ids in sorted(signals.items())
        ]

        supporting = sorted({event_id for ids in signals.values() for event_id in ids})
        signal_ids = set(supporting)
        contradicting = [e["id"] for e in incident.get("events", []) if e["id"] not in signal_ids][:2]

        if risk_class == "Critical" or len(present) >= 3:
            confidence = "high"
        elif risk_class in ("High", "Suspicious") or present:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "incident_id": incident["incident_id"],
            "hypothesis": _hypothesis(present),
            "confidence": confidence,
            "claims": claims,
            "supporting_evidence": supporting,
            "contradicting_evidence": contradicting,
            "recommended_action": ACTION_BY_RISK.get(risk_class, "monitor"),
            "unsupported_claims": [],
        }


def load_candidates(path: str | Path) -> dict[str, dict]:
    """Load ``{"incident_id", "output"}`` JSONL records into a lookup."""
    candidates: dict[str, dict] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            candidates[record["incident_id"]] = record["output"]
    return candidates


class CandidateBackend:
    """Serve pre-computed model outputs; a missing candidate is surfaced as invalid."""

    name = "candidates"

    def __init__(self, candidates: dict[str, dict]) -> None:
        self.candidates = candidates

    def analyze(self, incident: dict) -> dict:
        output = self.candidates.get(incident["incident_id"])
        if output is None:
            return {"incident_id": incident["incident_id"], "error": "no candidate output for this incident"}
        return output
