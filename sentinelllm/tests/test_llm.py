"""Tests for the evidence-grounded LLM analyst (Weeks 6-7)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from data_synthetic.generate_events import generate  # noqa: E402
from llm.backends import CandidateBackend, RuleBasedBackend  # noqa: E402
from llm.grounding import evaluate_grounding  # noqa: E402
from llm.incident import build_incident, extract_signals  # noqa: E402
from llm.schema import validate_output  # noqa: E402

INCIDENT = {
    "incident_id": "INC-TEST",
    "events": [
        {"id": "E1", "type": "process_create", "fact": "hidden powershell"},
        {"id": "E2", "type": "network_connect", "fact": "outbound to rare domain"},
    ],
    "rule_hits": ["R001"],
    "ml_probability": 0.9,
    "risk_score": 75,
    "risk_class": "High",
    "signals": {"hidden_powershell": ["E1"]},
}


def _valid_output() -> dict:
    return {
        "incident_id": "INC-TEST",
        "hypothesis": "hidden execution",
        "confidence": "high",
        "claims": [{"text": "hidden powershell", "evidence": ["E1"]}],
        "supporting_evidence": ["E1"],
        "contradicting_evidence": ["E2"],
        "recommended_action": "quarantine",
        "unsupported_claims": [],
    }


class TestSchema(unittest.TestCase):
    def test_valid_passes(self):
        self.assertEqual(validate_output(_valid_output()), [])

    def test_rejects_bad_action_and_confidence(self):
        output = _valid_output()
        output["recommended_action"] = "delete_everything"
        output["confidence"] = "certain"
        errors = validate_output(output)
        self.assertTrue(any("recommended_action" in e for e in errors))
        self.assertTrue(any("confidence" in e for e in errors))

    def test_rejects_missing_field(self):
        output = _valid_output()
        del output["claims"]
        self.assertIn("missing required field: claims", validate_output(output))

    def test_rejects_non_object(self):
        self.assertEqual(validate_output("not json"), ["output is not a JSON object"])


class TestGrounding(unittest.TestCase):
    def test_fully_grounded_passes(self):
        report = evaluate_grounding(INCIDENT, _valid_output())
        self.assertTrue(report.passes)
        self.assertEqual(report.grounding_rate, 1.0)
        self.assertEqual(report.hallucination_rate, 0.0)

    def test_unknown_event_id_is_flagged(self):
        output = _valid_output()
        output["claims"].append({"text": "beacon", "evidence": ["E999999"]})
        report = evaluate_grounding(INCIDENT, output)
        self.assertIn("E999999", report.unknown_ids)
        self.assertFalse(report.valid)
        self.assertFalse(report.passes)

    def test_claim_without_evidence_is_unsupported(self):
        output = _valid_output()
        output["claims"].append({"text": "persistence created", "evidence": []})
        report = evaluate_grounding(INCIDENT, output)
        self.assertIn("persistence created", report.unsupported_claims)
        self.assertEqual(report.grounding_rate, 0.5)
        self.assertFalse(report.passes)

    def test_concealed_unsupported_claim_detected(self):
        output = _valid_output()
        output["claims"].append({"text": "silent claim", "evidence": []})
        report = evaluate_grounding(INCIDENT, output)  # self-report still empty
        self.assertIn("silent claim", report.concealed_unsupported)

    def test_self_reported_unsupported_is_not_concealed(self):
        output = _valid_output()
        output["claims"].append({"text": "admitted", "evidence": []})
        output["unsupported_claims"] = ["admitted"]
        report = evaluate_grounding(INCIDENT, output)
        self.assertNotIn("admitted", report.concealed_unsupported)


class TestIncidentAndBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events, _ = generate({"malicious_clickfix_staged_stealer": 1}, seed=1)
        cls.incident = build_incident("INC-0001", events, 0.9, 90, "Critical")

    def test_incident_shape(self):
        self.assertTrue(all("id" in e and "fact" in e for e in self.incident["events"]))
        self.assertIn("browser_store_access", self.incident["signals"])
        self.assertIn("av_detection", self.incident["signals"])

    def test_signals_reference_real_event_ids(self):
        event_ids = {e["id"] for e in self.incident["events"]}
        for ids in extract_signals(self.incident_events()).values():
            for event_id in ids:
                self.assertIn(event_id, event_ids)

    def incident_events(self):
        events, _ = generate({"malicious_clickfix_staged_stealer": 1}, seed=1)
        return events

    def test_rule_based_backend_is_grounded(self):
        output = RuleBasedBackend().analyze(self.incident)
        self.assertEqual(validate_output(output), [])
        report = evaluate_grounding(self.incident, output)
        self.assertTrue(report.passes)
        self.assertEqual(report.hallucination_rate, 0.0)

    def test_candidate_backend_missing_is_invalid(self):
        output = CandidateBackend({}).analyze(self.incident)
        self.assertTrue(validate_output(output), "missing candidate must fail schema validation")


if __name__ == "__main__":
    unittest.main()
