"""End-to-end tests for the Person 2 pipeline (stdlib unittest).

Run from the repo root::

    .venv/bin/python -m unittest discover -s sentinelllm/tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import pandas as pd

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from data_synthetic.generate_events import generate  # noqa: E402
from ml import evaluation as ev  # noqa: E402
from ml.features import FEATURE_COLUMNS, extract_features  # noqa: E402
from ml.risk_fusion import RiskWeights, assess, classify  # noqa: E402
from ml.splits import family_aware_split  # noqa: E402

COMMON_FIELDS = {"schema_version", "event_id", "incident_id", "timestamp", "event_type", "host", "user", "source", "label", "rule_hits"}

TEST_COUNTS = {
    "benign_office": 2, "benign_dev": 2, "benign_browsing": 2,
    "ambiguous_unsigned_temp_tool": 2, "ambiguous_portable_app": 2,
    "suspicious_hidden_script": 2, "suspicious_encoded_command": 2,
    "malicious_clickfix_staged_stealer": 2, "malicious_persistence_loader": 2,
    "malicious_remote_access_loader": 2,
}


def _features_and_manifest(seed: int = 7):
    events, manifest_rows = generate(TEST_COUNTS, seed=seed)
    frame = pd.json_normalize(events, sep=".")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    features = extract_features(frame)
    manifest = pd.DataFrame(manifest_rows)
    return features.merge(manifest[["incident_id", "scenario"]], on="incident_id")


class TestGenerator(unittest.TestCase):
    def test_common_fields_and_unique_ids(self):
        events, manifest = generate(TEST_COUNTS, seed=1)
        self.assertEqual(len(manifest), sum(TEST_COUNTS.values()))
        ids = [e["event_id"] for e in events]
        self.assertEqual(len(ids), len(set(ids)), "event IDs must be unique")
        for event in events:
            self.assertTrue(COMMON_FIELDS.issubset(event), f"missing fields in {event['event_id']}")
            self.assertIn(event["label"], {"benign", "suspicious", "malicious"})

    def test_deterministic_for_same_seed(self):
        self.assertEqual(generate(TEST_COUNTS, seed=42)[0], generate(TEST_COUNTS, seed=42)[0])

    def test_no_secret_fields(self):
        events, _ = generate(TEST_COUNTS, seed=3)
        blob = str(events).lower()
        for token in ("password", "cookie_value", "token", "card_number", "cvv"):
            self.assertNotIn(token, blob, f"event stream must not contain '{token}'")


class TestFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.features = _features_and_manifest()

    def test_schema(self):
        self.assertEqual(list(self.features.columns), FEATURE_COLUMNS + ["scenario"])
        self.assertEqual(self.features["incident_id"].nunique(), len(self.features))

    def test_known_scenarios(self):
        by_scenario = self.features.groupby("scenario").mean(numeric_only=True)

        office = by_scenario.loc["benign_office"]
        signal = [c for c in FEATURE_COLUMNS if c not in ("incident_id", "label", "n_events")]
        self.assertEqual([c for c in signal if office[c] > 0], [], "benign_office must be clean")

        unsigned = by_scenario.loc["ambiguous_unsigned_temp_tool"]
        self.assertEqual(unsigned["has_unsigned_process"], 1.0)
        self.assertEqual(unsigned["temp_path"], 1.0)
        self.assertEqual(unsigned["browser_store_access"], 0.0)
        self.assertEqual(unsigned["rare_domain"], 0.0)

        clickfix = by_scenario.loc["malicious_clickfix_staged_stealer"]
        for column in ["browser_store_access", "rare_domain", "av_hit", "encrypted_archive", "deceptive_page"]:
            self.assertEqual(clickfix[column], 1.0, column)


class TestSplits(unittest.TestCase):
    def test_no_scenario_overlap_and_both_classes(self):
        _, manifest = generate(TEST_COUNTS, seed=5)
        manifest = pd.DataFrame(manifest)
        train_ids, test_ids = family_aware_split(manifest, seed=5)

        train_scenarios = set(manifest[manifest.incident_id.isin(train_ids)]["scenario"])
        test_scenarios = set(manifest[manifest.incident_id.isin(test_ids)]["scenario"])
        self.assertFalse(train_scenarios & test_scenarios, "no scenario may span train and test")

        for ids in (train_ids, test_ids):
            labels = set(manifest[manifest.incident_id.isin(ids)]["label"])
            self.assertIn("malicious", labels)
            self.assertTrue(labels & {"benign", "suspicious"})


class TestEvaluation(unittest.TestCase):
    def test_perfect_predictions(self):
        metrics = ev.binary_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["fp"], 0)
        self.assertEqual(metrics["fpr"], 0.0)

    def test_false_positive_rate(self):
        metrics = ev.binary_metrics([0, 0, 1, 1], [0.9, 0.1, 0.7, 0.2])
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["fn"], 1)
        self.assertAlmostEqual(metrics["fpr"], 0.5)

    def test_benign_quarantine_rate(self):
        rate = ev.benign_quarantine_rate(["benign", "benign", "malicious"], [1, 0, 1])
        self.assertAlmostEqual(rate, 0.5)


class TestRiskFusion(unittest.TestCase):
    ALL_RULES = ["R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R009", "R010", "R011"]

    def test_bounded_and_critical(self):
        assessment = assess("X", self.ALL_RULES, 1.0, has_unsigned=True, av_detect=True)
        self.assertLessEqual(assessment.score, 100)
        self.assertGreaterEqual(assessment.score, 0)
        self.assertEqual(assessment.risk_class, "Critical")

    def test_classify_thresholds(self):
        self.assertEqual(classify(0), "Normal")
        self.assertEqual(classify(19), "Normal")
        self.assertEqual(classify(20), "Observe")
        self.assertEqual(classify(40), "Suspicious")
        self.assertEqual(classify(60), "High")
        self.assertEqual(classify(80), "Critical")
        self.assertEqual(classify(100), "Critical")

    def test_visual_signal_alone_never_critical_with_defaults(self):
        assessment = assess("X", [], 0.0, has_unsigned=True, av_detect=False, vlm_probability=1.0)
        self.assertLess(assessment.score, 80)
        self.assertNotEqual(assessment.risk_class, "Critical")

    def test_cap_engages_when_weights_would_allow_it(self):
        weights = RiskWeights(max_vlm_score=100)
        assessment = assess("X", [], 0.0, has_unsigned=True, av_detect=False, vlm_probability=1.0, weights=weights)
        self.assertTrue(assessment.capped)
        self.assertEqual(assessment.score, weights.critical_cap_without_corroboration)
        self.assertNotEqual(assessment.risk_class, "Critical")

    def test_signature_credit_only_without_behavioral_rules(self):
        with_rules = assess("X", ["R001"], 0.0, has_unsigned=False, av_detect=False)
        self.assertEqual(with_rules.contributions["signature"], 0)
        without_rules = assess("X", [], 0.0, has_unsigned=False, av_detect=False)
        self.assertEqual(without_rules.contributions["signature"], -30)

    def test_av_corroboration_adds_fixed_credit(self):
        assessment = assess("X", [], 0.0, has_unsigned=True, av_detect=True)
        self.assertEqual(assessment.contributions["av"], 40)


if __name__ == "__main__":
    unittest.main()
