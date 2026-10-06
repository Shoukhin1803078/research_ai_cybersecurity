# SentinelLLM Event Schema

**Schema version:** `1.0`
**Owner:** Person 1 (`collector/`)
**Consumer:** Person 2 (`analysis/`, `ml/`, `llm/`, `vlm/`)

Person 1's collector normalizes raw Windows telemetry into a stream of JSON Lines
(`.jsonl`), one JSON object per line. This document is the contract Person 2 builds
against. If a field changes, the schema version must be bumped by Person 1.

> The synthetic files under `data_synthetic/` follow this schema exactly so Person 2 can
> build and test the whole AI pipeline before the real collector is ready.

## 1. Common fields (present on every event)

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Schema revision, currently `"1.0"`. |
| `event_id` | string | Globally unique event identifier, e.g. `E000123`. LLM outputs must reference these. |
| `incident_id` | string | Groups related events into one incident, e.g. `INC-0007`. |
| `timestamp` | string | ISO-8601 UTC, e.g. `2026-09-14T08:05:03Z`. |
| `event_type` | string | One of the `event_type` values below. |
| `host` | string | Machine name (synthetic in our data). |
| `user` | string | Local account name (never a real identity in our data). |
| `source` | string | Producing component, e.g. `"collector"`. |
| `label` | string | Incident ground truth: `benign` \| `suspicious` \| `malicious`. Denormalized onto every event for convenience; it is an **incident-level** label. |
| `rule_hits` | list[string] | Rule IDs that fired on this event, e.g. `["R001","R002"]`. |

## 2. `event_type` values

| `event_type` | Emitted when |
| --- | --- |
| `process_create` | A process starts. |
| `file_create` | A file is written/created. |
| `file_modify` | A tracked file changes. |
| `file_access` | A process opens a sensitive file (e.g. a browser credential store). **Metadata only — never file contents.** |
| `registry_set` | A registry value is written (persistence surface). |
| `scheduled_task_create` | A scheduled task is registered. |
| `service_install` | A service is installed. |
| `network_connect` | A process opens an outbound connection. |
| `dns_query` | A DNS lookup occurs. |
| `browser_event` | A browser navigation/UI event (including a detected deceptive page). |
| `clipboard_event` | Clipboard write observed (used to fuse ClickFix flows). |
| `av_detect` | Defender/AV reports a detection. |
| `quarantine` | The policy engine quarantines/restores/blocks an artifact (Person 1). |

## 3. Type-specific nested objects

### `process` (on `process_create`)
`pid`, `ppid`, `name`, `path`, `cmdline`, `parent_name`, `parent_path`,
`integrity_level` (`low|medium|high|system`), `signed` (bool), `signer` (string|null),
`sha256`.

### `file` (on `file_create`, `file_modify`, `file_access`, `quarantine`)
`path`, `name`, `sha256`, `size_bytes`, `extension`, `signed` (bool|null),
`signer` (string|null), `first_seen` (ISO-8601), `path_category`.

`path_category` ∈ `program_files`, `windows`, `user_profile`, `documents`,
`downloads`, `appdata`, `temp`, `other`.

### `registry` (on `registry_set`)
`hive`, `key`, `value_name`, `value_data`.

### `task` (on `scheduled_task_create`)
`task_name`, `action`, `trigger`.

### `service` (on `service_install`)
`service_name`, `binary_path`, `start_type`.

### `network` (on `network_connect`)
`dst_ip`, `dst_domain`, `dst_port`, `protocol`, `direction`, `bytes_out`.

### `dns` (on `dns_query`)
`query`, `response_ip`, `is_rare` (bool).

### `browser` (on `browser_event`)
`browser`, `url`, `page_kind`, `action`.

`page_kind` ∈ `benign_website`, `benign_captcha`, `fake_verification`,
`fake_login`, `fake_update`, `fake_download`, `fake_antivirus`, `clickfix_instruction`.

### `clipboard` (on `clipboard_event`)
`content_preview`, `page_kind`. Preview is a short synthetic command string — never real clipboard secrets.

### `av` (on `av_detect`)
`engine`, `detection_name`, `severity`, `target_path`, `target_sha256`.

### `quarantine`
`action` (`quarantined|restored|blocked`), `target_path`, `target_sha256`, `reason`.

## 4. Rule catalog (`rule_hits`)

| Rule | Meaning |
| --- | --- |
| `R001` | Hidden PowerShell process. |
| `R002` | PowerShell ExecutionPolicy Bypass. |
| `R003` | Remote script download. |
| `R004` | Password-protected archive staged to Temp. |
| `R005` | Unsigned executable launched from Temp. |
| `R006` | Browser credential-store access by unknown process. |
| `R007` | Rare outbound destination. |
| `R008` | New executable creates persistence. |
| `R009` | LOLBin abuse (mshta/wscript/rundll32/regsvr32/certutil). |
| `R010` | Deceptive verification page followed by a clipboard command. |
| `R011` | Encoded PowerShell command (`-EncodedCommand` / `FromBase64String`). |

## 5. Example event

```json
{"schema_version":"1.0","event_id":"E000101","incident_id":"INC-0009","timestamp":"2026-09-14T08:05:03Z","event_type":"process_create","host":"WIN-LAB-01","user":"synthetic_user","source":"collector","label":"malicious","rule_hits":["R001","R002"],"process":{"pid":6120,"ppid":4880,"name":"powershell.exe","path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","cmdline":"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"...\"","parent_name":"explorer.exe","parent_path":"C:\\Windows\\explorer.exe","integrity_level":"medium","signed":true,"signer":"Microsoft Corporation","sha256":"..."}}
```
