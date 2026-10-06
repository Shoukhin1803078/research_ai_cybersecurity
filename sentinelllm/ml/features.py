#!/usr/bin/env python3
"""Per-incident feature extraction (Week 2 deliverable).

Turns the event stream into one interpretable feature row per incident, as the
proposal's Day-3 example describes. Binary features are preferred for the first
baseline so that every column can be explained.

Usage::

    python sentinelllm/ml/features.py
    python sentinelllm/ml/features.py --events ... --labels ... --out features.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from analysis.load_events import DEFAULT_EVENTS, DEFAULT_LABELS, load_events  # noqa: E402

DEFAULT_OUT = PACKAGE_ROOT / "data_synthetic" / "features.csv"

ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
LOLBINS = {"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"}
CREDENTIAL_STORE_MARKERS = ("login data", "cookies", "web data")
PERSISTENCE_EVENTS = {"registry_set", "scheduled_task_create", "service_install"}

FEATURE_COLUMNS = [
    "incident_id",
    "n_events",
    "has_unsigned_process",
    "temp_path",
    "powershell_hidden",
    "exec_policy_bypass",
    "powershell_encoded",
    "remote_download",
    "browser_store_access",
    "rare_domain",
    "av_hit",
    "encrypted_archive",
    "persistence_created",
    "clipboard_write",
    "deceptive_page",
    "lolbin_abuse",
    "n_rule_hits",
    "n_distinct_rules",
    "label",
]


def _collect_rules(group: pd.DataFrame) -> set[str]:
    rules: set[str] = set()
    for value in group["rule_hits"]:
        if isinstance(value, list):
            rules.update(value)
    return rules


def _contains(series: pd.Series, pattern: str) -> bool:
    values = series.dropna().astype(str).str.lower()
    return bool(values.str.contains(pattern, regex=True).any())


def extract_features(events: pd.DataFrame) -> pd.DataFrame:
    """Build one feature row per incident from a flattened event DataFrame."""
    rows: list[dict] = []
    for incident_id, group in events.groupby("incident_id", sort=True):
        rules = _collect_rules(group)

        process_signed = group.get("process.signed")
        file_signed = group.get("file.signed")
        path_category = group.get("file.path_category")
        extension = group.get("file.extension")
        cmdline = group.get("process.cmdline")
        process_name = group.get("process.name")
        file_path = group.get("file.path")
        page_kind = group.get("browser.page_kind")
        event_types = set(group["event_type"])

        has_unsigned = bool((process_signed == False).any() or (file_signed == False).any())  # noqa: E712
        temp_path = bool((path_category == "temp").any())
        powershell_hidden = _contains(cmdline, r"-w(?:indowstyle)?\s+hidden")
        exec_policy_bypass = _contains(cmdline, r"executionpolicy\s+bypass|-ep\s+bypass")
        powershell_encoded = ("R011" in rules) or _contains(cmdline, r"-encodedcommand|frombase64string")
        remote_download = ("R003" in rules) or _contains(cmdline, r"downloadstring|invoke-webrequest|\biwr\b")

        credentials = _contains(file_path, "|".join(CREDENTIAL_STORE_MARKERS))
        browser_store_access = ("R006" in rules) or credentials

        rare_dns = group.get("dns.is_rare")
        rare_domain = ("R007" in rules) or bool(rare_dns.fillna(False).astype(bool).any())
        av_hit = "av_detect" in event_types

        archive_in_temp = bool(
            ((extension.astype(str).str.lower().isin(ARCHIVE_EXTENSIONS)) & (path_category == "temp")).any()
        )
        encrypted_archive = archive_in_temp  # password-protected archive proxy
        persistence_created = bool(event_types & PERSISTENCE_EVENTS)
        clipboard_write = "clipboard_event" in event_types

        kinds = page_kind.dropna().astype(str) if page_kind is not None else pd.Series(dtype=str)
        deceptive_page = bool(
            kinds.str.startswith("fake").any() or (kinds == "clickfix_instruction").any()
        )

        names = process_name.dropna().astype(str).str.lower() if process_name is not None else pd.Series(dtype=str)
        lolbin_abuse = ("R009" in rules) or bool(names.isin(LOLBINS).any())

        rows.append(
            {
                "incident_id": incident_id,
                "n_events": int(len(group)),
                "has_unsigned_process": has_unsigned,
                "temp_path": temp_path,
                "powershell_hidden": powershell_hidden,
                "exec_policy_bypass": exec_policy_bypass,
                "powershell_encoded": powershell_encoded,
                "remote_download": remote_download,
                "browser_store_access": browser_store_access,
                "rare_domain": rare_domain,
                "av_hit": av_hit,
                "encrypted_archive": encrypted_archive,
                "persistence_created": persistence_created,
                "clipboard_write": clipboard_write,
                "deceptive_page": deceptive_page,
                "lolbin_abuse": lolbin_abuse,
                "n_rule_hits": int(sum(len(v) for v in group["rule_hits"] if isinstance(v, list))),
                "n_distinct_rules": len(rules),
                "label": group["label"].iloc[0],
            }
        )

    features = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    return features.sort_values("incident_id").reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract per-incident features.")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    events = load_events(args.events)
    features = extract_features(events)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(args.out, index=False)
    print(f"Wrote {len(features)} incident feature rows x {features.shape[1]} columns -> {args.out}")
    print(features["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
