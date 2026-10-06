"""Family-aware (scenario-grouped) train/test split.

Random splits leak on this data: variants within a scenario are near-duplicates.
This module keeps every incident of a scenario on one side of the split, and
stratifies by label so both sides see all classes.

See the "Common Beginner Mistakes" section of the work guide.
"""

from __future__ import annotations

import random

import pandas as pd

DEFAULT_SEED = 20260901


def family_aware_split(
    manifest: pd.DataFrame,
    test_fraction: float = 0.34,
    seed: int = DEFAULT_SEED,
) -> tuple[set[str], set[str]]:
    """Return ``(train_ids, test_ids)`` grouped by scenario, stratified by label."""
    rng = random.Random(seed)
    test_scenarios: set[str] = set()

    for _label, group in manifest.groupby("label", sort=True):
        scenarios = sorted(group["scenario"].unique())
        rng.shuffle(scenarios)
        n_test = min(max(1, round(len(scenarios) * test_fraction)), len(scenarios) - 1)
        if n_test > 0:
            test_scenarios.update(scenarios[:n_test])

    is_test = manifest["scenario"].isin(test_scenarios)
    test_ids = set(manifest.loc[is_test, "incident_id"])
    train_ids = set(manifest.loc[~is_test, "incident_id"])
    return train_ids, test_ids


def describe_split(manifest: pd.DataFrame, train_ids: set[str], test_ids: set[str]) -> pd.DataFrame:
    """Per-scenario counts on each side, for a transparency log."""
    frame = manifest.copy()
    frame["split"] = ["train" if i in train_ids else "test" for i in frame["incident_id"]]
    return (
        frame.groupby(["label", "scenario", "split"])["incident_id"]
        .count()
        .unstack("split", fill_value=0)
        .reset_index()
    )
