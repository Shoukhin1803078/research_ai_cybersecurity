# Feature Reference (Week 2)

One row per **incident**. Produced by `ml/features.py` from the flattened event
table (`analysis/load_events.py`). All features are binary except the counts, so
every column is explainable to an analyst.

| Column | Type | Meaning | Derived from |
| --- | --- | --- | --- |
| `incident_id` | string | Incident key. | `incident_id` |
| `n_events` | int | Number of events in the incident. | event count |
| `has_unsigned_process` | 0/1 | Any process or file is unsigned. | `process.signed` / `file.signed` = false |
| `temp_path` | 0/1 | Any artifact lives in a Temp path. | `file.path_category` = `temp` |
| `powershell_hidden` | 0/1 | A hidden-window PowerShell command line. | `process.cmdline` matches `-w(indowstyle) hidden` |
| `exec_policy_bypass` | 0/1 | PowerShell ExecutionPolicy bypass. | `process.cmdline` matches `executionpolicy bypass` / `-ep bypass` |
| `powershell_encoded` | 0/1 | Encoded/base64 PowerShell command. | rule `R011` or cmdline `-encodedcommand`/`frombase64string` |
| `remote_download` | 0/1 | Remote script download. | rule `R003` or cmdline `downloadstring`/`iwr`/`invoke-webrequest` |
| `browser_store_access` | 0/1 | Access to a browser credential/session store. | rule `R006` or path contains `Login Data`/`Cookies`/`Web Data` |
| `rare_domain` | 0/1 | Contact with a rare/unseen destination. | rule `R007` or `dns.is_rare` = true |
| `av_hit` | 0/1 | Independent AV detection. | an `av_detect` event exists |
| `encrypted_archive` | 0/1 | Archive staged to Temp (password-protected proxy). | `file.extension` ∈ {zip,7z,rar} and `path_category` = `temp` |
| `persistence_created` | 0/1 | Persistence established. | any `registry_set` / `scheduled_task_create` / `service_install` |
| `clipboard_write` | 0/1 | Clipboard command (ClickFix signal). | an `clipboard_event` exists |
| `deceptive_page` | 0/1 | Deceptive UI page shown. | `browser.page_kind` starts with `fake` or is `clickfix_instruction` |
| `lolbin_abuse` | 0/1 | LOLBin execution. | rule `R009` or process name ∈ {wscript, cscript, mshta, rundll32, regsvr32, certutil} |
| `n_rule_hits` | int | Total rule hits across the incident. | sum of `rule_hits` lengths |
| `n_distinct_rules` | int | Distinct rules fired. | set of `rule_hits` |
| `label` | string | Ground-truth class: `benign` / `suspicious` / `malicious`. | `label` |

## Notes and honest limitations

- **`encrypted_archive` is a proxy.** The collector does not report archive
  encryption, so we approximate it as "an archive written to Temp". Flag this to
  Person 1 if a real `is_encrypted` field becomes available.
- **`powershell_hidden` is text-matched, not behavioral.** Obfuscated command
  lines can evade it - a known limitation the Week 12 adversarial-robustness
  experiment should probe.
- **`label` is incident-level**, denormalized onto events. Never feed it to the
  model as a feature.
- **No secrets/PII.** All values are metadata; `file_access` events record paths
  only, never file contents.

## Reproduce

```bash
python sentinelllm/data_synthetic/generate_events.py   # -> events.jsonl, incident_labels.csv
python sentinelllm/ml/features.py                      # -> features.csv
```
