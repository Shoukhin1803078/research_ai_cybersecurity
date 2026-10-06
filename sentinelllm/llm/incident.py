"""Build structured incident JSON from raw events (Week 6).

The LLM receives a structured incident - a list of event facts, rule hits, ML
probability and fused risk - never raw filesystem access. Each event keeps its
``id`` so every later claim can cite it.
"""

from __future__ import annotations

import json
from pathlib import Path

RULE_NAMES = {
    "R001": "hidden PowerShell process",
    "R002": "PowerShell ExecutionPolicy bypass",
    "R003": "remote script download",
    "R004": "password-protected archive staged to Temp",
    "R005": "unsigned executable launched from Temp",
    "R006": "browser credential-store access by unknown process",
    "R007": "rare outbound destination",
    "R008": "new executable creates persistence",
    "R009": "LOLBin abuse",
    "R010": "deceptive verification page followed by a clipboard command",
    "R011": "encoded PowerShell command",
}

# Rule -> signal name.
RULE_SIGNAL = {
    "R001": "hidden_powershell", "R002": "exec_policy_bypass", "R011": "encoded_command",
    "R003": "remote_download", "R004": "encrypted_archive", "R005": "unsigned_temp",
    "R006": "browser_store_access", "R007": "rare_domain", "R008": "persistence",
    "R009": "lolbin", "R010": "deceptive_clipboard",
}

SIGNAL_LABELS = {
    "hidden_powershell": "hidden PowerShell window",
    "exec_policy_bypass": "ExecutionPolicy bypass",
    "encoded_command": "encoded PowerShell command",
    "remote_download": "remote script/payload download",
    "encrypted_archive": "password-protected archive staged to Temp",
    "unsigned_temp": "unsigned executable from a Temp path",
    "browser_store_access": "browser credential-store access by an unknown process",
    "rare_domain": "contact with a rare/unusual destination",
    "persistence": "persistence established",
    "lolbin": "LOLBin abuse",
    "deceptive_clipboard": "deceptive page followed by a clipboard command",
    "av_detection": "independent AV detection",
}

ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}


def load_raw_events(path: str | Path) -> dict[str, list[dict]]:
    """Read JSONL events and group the raw records by incident_id (input order kept)."""
    grouped: dict[str, list[dict]] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            grouped.setdefault(event["incident_id"], []).append(event)
    return grouped


def _shorten(text: str | None, limit: int = 140) -> str:
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def describe_event(event: dict) -> str:
    """A short, human-readable fact for one event (never includes file contents)."""
    kind = event.get("event_type", "unknown")
    if kind == "process_create":
        process = event.get("process", {})
        signer = process.get("signer") or ("unsigned" if process.get("signed") is False else "unknown signer")
        return f"process {process.get('name')} ({signer}) launched: {_shorten(process.get('cmdline'), 100)}"
    if kind in ("file_create", "file_modify"):
        file = event.get("file", {})
        return f"{kind}: {file.get('path')} [{file.get('path_category')}] signed={file.get('signed')}"
    if kind == "file_access":
        return f"sensitive file access: {event.get('file', {}).get('path')}"
    if kind == "network_connect":
        net = event.get("network", {})
        return f"outbound connection to {net.get('dst_domain')} ({net.get('dst_ip')}:{net.get('dst_port')})"
    if kind == "dns_query":
        dns = event.get("dns", {})
        return f"DNS query for {dns.get('query')} (rare={dns.get('is_rare')})"
    if kind == "browser_event":
        browser = event.get("browser", {})
        return f"{browser.get('browser')} {browser.get('action')} {browser.get('url')} [page={browser.get('page_kind')}]"
    if kind == "clipboard_event":
        return f"clipboard write observed: {_shorten(event.get('clipboard', {}).get('content_preview'), 60)}"
    if kind == "registry_set":
        reg = event.get("registry", {})
        return f"registry set {reg.get('hive')}\\{reg.get('key')} -> {reg.get('value_name')}"
    if kind == "scheduled_task_create":
        task = event.get("task", {})
        return f"scheduled task created: {task.get('task_name')} ({task.get('trigger')})"
    if kind == "service_install":
        service = event.get("service", {})
        return f"service installed: {service.get('service_name')} ({service.get('binary_path')})"
    if kind == "av_detect":
        av = event.get("av", {})
        return f"AV detection: {av.get('detection_name')} on {av.get('target_path')}"
    if kind == "quarantine":
        quarantine = event.get("quarantine", {})
        return f"policy action: {quarantine.get('action')} {quarantine.get('target_path')}"
    return kind


def extract_signals(raw_events: list[dict]) -> dict[str, list[str]]:
    """Map each signal to the event IDs that evidence it (rules + content fallback)."""
    signals: dict[str, list[str]] = {}

    def add(name: str, event_id: str) -> None:
        signals.setdefault(name, [])
        if event_id not in signals[name]:
            signals[name].append(event_id)

    for event in raw_events:
        event_id = event["event_id"]
        for rule in event.get("rule_hits") or []:
            if rule in RULE_SIGNAL:
                add(RULE_SIGNAL[rule], event_id)

        kind = event.get("event_type")
        if kind == "av_detect":
            add("av_detection", event_id)
        if kind == "clipboard_event":
            add("deceptive_clipboard", event_id)

        process = event.get("process") or {}
        cmdline = (process.get("cmdline") or "").lower()
        if "-windowstyle hidden" in cmdline or "-w hidden" in cmdline:
            add("hidden_powershell", event_id)
        if "executionpolicy bypass" in cmdline or "-ep bypass" in cmdline:
            add("exec_policy_bypass", event_id)
        if "-encodedcommand" in cmdline or "frombase64string" in cmdline:
            add("encoded_command", event_id)
        if any(token in cmdline for token in ("downloadstring", "invoke-webrequest", "iwr ", "urlcache")):
            add("remote_download", event_id)

        file = event.get("file") or {}
        path = str(file.get("path") or "").lower()
        if any(marker in path for marker in ("login data", "cookies", "web data")):
            add("browser_store_access", event_id)
        if file.get("signed") is False and file.get("path_category") == "temp":
            add("unsigned_temp", event_id)
        if str(file.get("extension") or "").lower() in ARCHIVE_EXTENSIONS and file.get("path_category") == "temp":
            add("encrypted_archive", event_id)

        dns = event.get("dns") or {}
        if dns.get("is_rare") is True:
            add("rare_domain", event_id)

        browser = event.get("browser") or {}
        page_kind = str(browser.get("page_kind") or "")
        if page_kind.startswith("fake") or page_kind == "clickfix_instruction":
            add("deceptive_clipboard", event_id)

    return signals


def build_incident(
    incident_id: str,
    raw_events: list[dict],
    ml_probability: float,
    risk_score: int,
    risk_class: str,
) -> dict:
    """Assemble the structured incident the analyst receives."""
    ordered = sorted(raw_events, key=lambda e: (e["timestamp"], e["event_id"]))
    rule_hits: list[str] = []
    for event in ordered:
        for rule in event.get("rule_hits") or []:
            if rule not in rule_hits:
                rule_hits.append(rule)

    return {
        "incident_id": incident_id,
        "events": [{"id": e["event_id"], "type": e["event_type"], "fact": describe_event(e)} for e in ordered],
        "rule_hits": sorted(rule_hits),
        "ml_probability": round(float(ml_probability), 4),
        "risk_score": int(risk_score),
        "risk_class": risk_class,
        "signals": extract_signals(ordered),
    }
