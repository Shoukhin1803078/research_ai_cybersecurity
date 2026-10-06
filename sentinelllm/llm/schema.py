"""Required LLM output schema and a dependency-free validator.

The analyst must return machine-readable JSON that can be checked automatically.
Every conclusion must cite **event IDs** that exist in the incident; anything else
is rejected as ungrounded.

This mirrors the guide's required output and adds a `claims` list (one entry per
assertion, each with its evidence) so grounding can be measured per claim rather
than taken on trust from the model's self-reported `unsupported_claims`.
"""

from __future__ import annotations

CONFIDENCE_VALUES = ("low", "medium", "high")
ACTION_VALUES = ("none", "monitor", "alert", "suspend", "isolate", "quarantine")

REQUIRED_FIELDS = (
    "incident_id",
    "hypothesis",
    "confidence",
    "claims",
    "supporting_evidence",
    "contradicting_evidence",
    "recommended_action",
    "unsupported_claims",
)

# Actions that assert the incident is a confirmed attack.
POSITIVE_ACTIONS = {"suspend", "isolate", "quarantine"}


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def validate_output(output: object) -> list[str]:
    """Return a list of schema errors (empty means valid)."""
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["output is not a JSON object"]

    for field in REQUIRED_FIELDS:
        if field not in output:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    if not isinstance(output["incident_id"], str):
        errors.append("incident_id must be a string")
    if not isinstance(output["hypothesis"], str) or not output["hypothesis"].strip():
        errors.append("hypothesis must be a non-empty string")
    if output["confidence"] not in CONFIDENCE_VALUES:
        errors.append(f"confidence must be one of {list(CONFIDENCE_VALUES)}")
    if output["recommended_action"] not in ACTION_VALUES:
        errors.append(f"recommended_action must be one of {list(ACTION_VALUES)}")

    for field in ("supporting_evidence", "contradicting_evidence", "unsupported_claims"):
        if not _is_str_list(output[field]):
            errors.append(f"{field} must be a list of strings")

    claims = output["claims"]
    if not isinstance(claims, list):
        errors.append("claims must be a list")
    else:
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                errors.append(f"claims[{index}] must be an object")
                continue
            if not isinstance(claim.get("text"), str) or not claim["text"].strip():
                errors.append(f"claims[{index}].text must be a non-empty string")
            if not _is_str_list(claim.get("evidence")):
                errors.append(f"claims[{index}].evidence must be a list of strings")

    return errors
