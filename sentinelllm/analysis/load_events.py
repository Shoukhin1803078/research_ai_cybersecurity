"""Load normalized SentinelLLM events into pandas (Person 2, analysis/).

Reads the JSONL stream defined in ``docs/event_schema.md`` and flattens the
nested type-specific objects into dotted columns (e.g. ``process.signed``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVENTS = PACKAGE_ROOT / "data_synthetic" / "events.jsonl"
DEFAULT_LABELS = PACKAGE_ROOT / "data_synthetic" / "incident_labels.csv"


def load_events(path: str | Path = DEFAULT_EVENTS) -> pd.DataFrame:
    """Load a JSONL event file into a flattened DataFrame."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"No events at {path}. Generate synthetic data first:\n"
            f"  python sentinelllm/data_synthetic/generate_events.py"
        )
    records: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"Invalid JSON on line {line_no} of {path}: {exc}") from exc
    frame = pd.json_normalize(records, sep=".")
    if "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    return frame


def load_labels(path: str | Path = DEFAULT_LABELS) -> pd.DataFrame:
    """Load the incident label manifest."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No label manifest at {path}. Run the generator first.")
    return pd.read_csv(path)


def event_type_counts(frame: pd.DataFrame) -> pd.Series:
    """Count events by ``event_type``, most frequent first."""
    return frame["event_type"].value_counts()


def missing_values(frame: pd.DataFrame) -> pd.Series:
    """Missing-value counts per column, worst first. Sparse by design (typed events)."""
    return frame.isna().sum().sort_values(ascending=False)


def incident_summary(frame: pd.DataFrame) -> pd.DataFrame:
    """One row per incident: label, event count, time span and distinct event types."""
    grouped = frame.groupby("incident_id")
    summary = grouped.agg(
        label=("label", "first"),
        n_events=("event_id", "count"),
        start=("timestamp", "min"),
        end=("timestamp", "max"),
        event_types=("event_type", lambda s: sorted(set(s))),
    )
    summary["duration_s"] = (summary["end"] - summary["start"]).dt.total_seconds()
    return summary.reset_index()
