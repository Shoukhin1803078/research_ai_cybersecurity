"""Evidence-grounding validator (Weeks 6-7).

Checks whether an analyst output is schema-valid and whether every claim cites
event IDs that actually exist in the incident. Produces the grounding rate and
hallucination / unsupported-claim rate used as research metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from llm.schema import validate_output


@dataclass
class GroundingReport:
    incident_id: str
    schema_valid: bool
    schema_errors: list[str] = field(default_factory=list)
    unknown_ids: list[str] = field(default_factory=list)
    contradiction_listed: bool = False
    claims_total: int = 0
    claims_grounded: int = 0
    unsupported_claims: list[str] = field(default_factory=list)
    concealed_unsupported: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.schema_valid and not self.unknown_ids

    @property
    def grounding_rate(self) -> float:
        return 1.0 if self.claims_total == 0 else self.claims_grounded / self.claims_total

    @property
    def hallucination_rate(self) -> float:
        total = self.claims_total + len(self.unknown_ids)
        if total == 0:
            return 0.0
        return (len(self.unsupported_claims) + len(self.unknown_ids)) / total

    @property
    def passes(self) -> bool:
        """No schema errors, no unknown IDs, no unsupported claims."""
        return self.valid and not self.unsupported_claims


def _referenced_ids(output: dict) -> list[str]:
    ids: list[str] = []
    ids.extend(output.get("supporting_evidence", []))
    ids.extend(output.get("contradicting_evidence", []))
    for claim in output.get("claims", []):
        if isinstance(claim, dict):
            ids.extend(claim.get("evidence", []))
    return ids


def evaluate_grounding(incident: dict, output: object) -> GroundingReport:
    """Validate one analyst output against the incident's real event IDs."""
    incident_id = incident.get("incident_id", "?")
    schema_errors = validate_output(output)
    report = GroundingReport(incident_id=incident_id, schema_valid=not schema_errors, schema_errors=schema_errors)
    if not isinstance(output, dict):
        return report

    evidence_ids = {event["id"] for event in incident.get("events", [])}

    referenced = _referenced_ids(output)
    report.unknown_ids = sorted({ref for ref in referenced if ref not in evidence_ids})
    report.contradiction_listed = bool(output.get("contradicting_evidence"))

    claims = output.get("claims", [])
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            report.claims_total += 1
            evidence = claim.get("evidence", [])
            grounded = bool(evidence) and all(ref in evidence_ids for ref in evidence)
            if grounded:
                report.claims_grounded += 1
            else:
                text = str(claim.get("text", "")).strip() or "<unnamed claim>"
                report.unsupported_claims.append(text)

    self_reported = set(output.get("unsupported_claims", []))
    report.concealed_unsupported = [c for c in report.unsupported_claims if c not in self_reported]
    return report
