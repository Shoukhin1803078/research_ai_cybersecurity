# Field Glossary (Week 1, Day 1 deliverable)

One-line meaning of every field Person 2 consumes, plus the ML terms from the guide.

## Event fields

| Field | Plain-English meaning |
| --- | --- |
| `schema_version` | Which revision of the event contract this record obeys. |
| `event_id` | Unique ID for one event; the anchor the LLM must cite. |
| `incident_id` | Groups events that belong to the same suspected incident. |
| `timestamp` | When it happened (UTC). |
| `event_type` | What kind of thing happened (see schema doc). |
| `host` | Which machine produced the event. |
| `user` | Which account was active. |
| `source` | Which component emitted the event. |
| `label` | Ground-truth class of the incident: benign / suspicious / malicious. |
| `rule_hits` | IDs of deterministic rules that fired. |

## Nested fields

| Field | Meaning |
| --- | --- |
| `process.pid` / `process.ppid` | Process and parent-process IDs (used to rebuild ancestry). |
| `process.name` / `process.path` | Executable name and full path. |
| `process.cmdline` | Full command line (where hidden flags / downloads show up). |
| `process.parent_name` | Parent executable name. |
| `process.integrity_level` | Windows integrity level (privilege context). |
| `process.signed` / `process.signer` | Authenticode status and publisher. |
| `process.sha256` | Hash of the executable. |
| `file.path` / `file.name` | Where the artifact lives. |
| `file.sha256` | Content hash (identity + reputation lookup). |
| `file.size_bytes` | Size in bytes. |
| `file.extension` | File extension. |
| `file.signed` / `file.signer` | Signature status of the artifact. |
| `file.first_seen` | When this artifact was first observed on the host. |
| `file.path_category` | Coarse location class (temp, appdata, program_files...). |
| `registry.*` | Persistence surface written (hive, key, value). |
| `task.*` / `service.*` | Persistence via scheduled task or service. |
| `network.dst_ip` / `dst_domain` / `dst_port` | Where a process connected. |
| `network.bytes_out` | Outbound bytes (crude exfiltration signal). |
| `dns.query` / `dns.is_rare` | Lookup name and whether it is rare/unseen. |
| `browser.url` / `browser.page_kind` | Page visited and whether it looks deceptive. |
| `clipboard.content_preview` | Short synthetic preview of a copied command (ClickFix signal). |
| `av.detection_name` / `av.severity` | Independent AV verdict (corroboration). |
| `quarantine.action` | What the policy engine did (quarantined/restored/blocked). |

## ML terms

| Term | Beginner meaning |
| --- | --- |
| **Feature** | A measurable value a model uses (e.g. `powershell_hidden` = 0/1). |
| **Label** | The expected answer for training/testing (benign/suspicious/malicious). |
| **Train / validation / test** | Disjoint data so we test on what the model never saw. |
| **Precision** | Of the alerts we raised, how many were correct. |
| **Recall** | Of the true attacks, how many we caught. |
| **F1** | Harmonic mean of precision and recall. |
| **PR-AUC** | Area under the precision-recall curve; better than ROC-AUC under class imbalance. |
| **False positive** | Benign activity wrongly flagged. |
| **FPR** | False-positive rate; endpoint security must keep this low. |
| **Calibration** | Making model confidence match real correctness. |
| **LLM grounding** | Requiring every conclusion to cite provided evidence. |
| **Hallucination / unsupported claim** | A claim the LLM makes with no supporting evidence ID. |
| **VLM** | A model that reasons over images/screenshots plus text. |
| **Ablation** | Remove one component to measure whether it actually helps. |
| **Leakage** | Test data too similar to training data, inflating scores. |
