"""Frozen analyst prompts (Week 6).

Prompts are versioned and must be frozen before final test evaluation - never
edited during a test run (see the guide's "Common Beginner Mistakes").
"""

from __future__ import annotations

import json

PROMPT_VERSION = "analyst-v1"

SYSTEM_PROMPT = """\
You are a defensive security analyst. You receive a STRUCTURED incident that was
assembled from endpoint telemetry. You must not invent evidence.

Rules:
- Every claim must cite the exact event IDs (e.g. "E000123") that support it.
- Only reference event IDs that appear in the incident's events list.
- If evidence is mixed, list the contradicting event IDs too.
- Never claim to have inspected anything not present in the incident.
- Never output shell commands or attempt actions; only recommend an action.
- Respond with a single JSON object matching the required output schema. No prose.
"""

OUTPUT_SCHEMA_HINT = {
    "incident_id": "string",
    "hypothesis": "string",
    "confidence": "low | medium | high",
    "claims": [{"text": "string", "evidence": ["event_id", "..."]}],
    "supporting_evidence": ["event_id", "..."],
    "contradicting_evidence": ["event_id", "..."],
    "recommended_action": "none | monitor | alert | suspend | isolate | quarantine",
    "unsupported_claims": ["string"],
}


def build_user_prompt(incident: dict) -> str:
    """Render the structured incident into the (frozen) user prompt."""
    return (
        "Analyze this incident and return the required JSON.\n\n"
        "REQUIRED OUTPUT SCHEMA:\n"
        f"{json.dumps(OUTPUT_SCHEMA_HINT, indent=2)}\n\n"
        "INCIDENT:\n"
        f"{json.dumps(incident, indent=2, ensure_ascii=False)}\n"
    )
