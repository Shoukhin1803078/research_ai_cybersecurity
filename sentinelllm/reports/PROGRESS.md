# SentinelLLM — Person 2 Progress & Results Log

Living document. **Append a new dated section at the top of "Session log" every
work session**, then update the cumulative tables. Goal: anyone can see what was
built, what the numbers were, what we decided, and what is next — without reading
the code.

- **Owner:** Person 2 (AI / ML / Multimodal)
- **Branch:** `person2-ai`
- **Reproduce everything:** `make repro` (data → features → baselines → tests)

---

## Cumulative results

Detection task = binary: is the incident a **confirmed attack** (`malicious`)?
Benign **and** suspicious incidents are negatives, so FPR reflects analyst-visible noise.
Split = family-aware (no scenario spans train/test), stratified by label.

| Date | Stage | Model | Features | Seed | Precision | Recall | F1 | PR-AUC | FPR | Benign-quarantine | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-06 | baseline | logistic_regression | 17 tabular | 20260901 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | scaled + balanced |
| 2026-10-06 | baseline | random_forest | 17 tabular | 20260901 | 1.000 | 0.667 | 0.800 | 1.000 | 0.000 | 0.000 | 7 FN: unseen `browser_extension_hijack` family; probabilities uncalibrated |
| 2026-10-06 | fusion (ablation preview) | rules_only (thr 60) | rules | 20260901 | 1.000 | 0.333 | 0.500 | 1.000 | 0.000 | 0.000 | misses signed-LOLBin + extension-hijack |
| 2026-10-06 | fusion (ablation preview) | ml_only (thr 60) | ml | 20260901 | 0.000 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | ML alone tops out at Suspicious by design |
| 2026-10-06 | fusion (ablation preview) | rules_ml_fusion (thr 60) | rules+ml | 20260901 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | fusion v1 |
| 2026-10-06 | llm | rule_based (grounded) | structured incident | — | 1.000 | 1.000 | 1.000 | — | — | — | grounding 1.000, hallucination 0.000, no-unsupported 1.000 |
| 2026-10-06 | llm (validator demo) | candidates (flawed fixture) | structured incident | — | 0.000 | 0.000 | 0.000 | — | — | — | hallucinated ID + 2 concealed claims caught; grounding 0.333, hallucination 0.667 |

> These are **smoke-test numbers on synthetic data**, not a scientific result.
> See "Known limitations".

Machine-readable version: `reports/experiments.csv` (append-only) and
`reports/results_baseline.csv` (latest run).

---

## Dataset snapshot

| Field | Value |
| --- | --- |
| Incidents | 169 |
| Events | 573 |
| Scenarios | 25 |
| Labels | 92 benign (incl. 18 ambiguous), 18 suspicious, 59 malicious |
| Schema version | 1.0 |

---

## Session log

### 2026-10-06 — Weeks 6-7: evidence-grounded LLM analyst

**Built**

- `llm/incident.py` — structured incident JSON: event facts with stable IDs,
  rule hits, ML probability, fused risk, and a derived `signals` map
  (signal -> evidence event IDs).
- `llm/llm_schema.json` + `llm/schema.py` — required output schema and a
  dependency-free validator (types, enums, required fields).
- `llm/prompts.py` — **frozen** prompt (`analyst-v1`) with the grounding rules.
- `llm/grounding.py` — grounding validator: unknown event IDs, per-claim
  grounding rate, hallucination rate, concealed-unsupported detection.
- `llm/backends.py` — `RuleBasedBackend` (deterministic, fully grounded offline
  analyst) and `CandidateBackend` (scores any external model's pre-computed outputs).
- `llm/analyst.py` — CLI harness; writes `reports/llm_report.json` +
  `reports/results_llm.csv`, logs to `experiments.csv`.
- `llm/example_candidates.jsonl` — fixture with a hallucinated event ID and a
  concealed unsupported claim, to prove the validator catches them.
- 13 new tests (`tests/test_llm.py`); 28 total.

**Output schema** (guide's required output + a `claims` list so grounding is
checkable per assertion):

```json
{"incident_id","hypothesis","confidence":"low|medium|high",
 "claims":[{"text","evidence":[event_id]}],
 "supporting_evidence":[],"contradicting_evidence":[],
 "recommended_action":"none|monitor|alert|suspend|isolate|quarantine",
 "unsupported_claims":[]}
```

**Results** (61 test incidents)

| backend | schema valid | grounding | hallucination | no-unsupported | classification F1 |
| --- | --- | --- | --- | --- | --- |
| rule_based | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| candidates (flawed fixture) | 1.000 | 0.333 | 0.667 | 0.333 | 0.000 |

The flawed fixture is caught exactly as intended: 1 incident with an unknown
event ID (`E999999`), and 2 concealed unsupported claims the model did not
self-report.

**Decisions**

- **Grounding is checked per claim, not taken from the model's self-report.**
  The model's `unsupported_claims` field is cross-checked; claims it omits are
  recorded as `concealed_unsupported`.
- **Offline-first:** the deterministic backend lets the whole pipeline run with
  no model and sets a zero-hallucination reference. A real local/API model plugs
  in via a candidates JSONL — no API keys or network required in this repo.
- **No shell access for the LLM.** Outputs are advisory; the deterministic policy
  engine (Person 1) owns actions.
- **Prompt frozen at `analyst-v1`** before evaluation, per the guide.

**Caveats**

- The rule-based reference trivially scores 1.0 grounding because it cites IDs it
  was handed; the real test is a learned model scored through the same harness.
- `classification_*` maps `recommended_action ∈ {suspend,isolate,quarantine}` to
  positive; it measures the analyst's *decision*, not grounding quality.

**Next**

- Weeks 8-10: VLM social-engineering dataset + zero/few-shot baseline, then fuse
  the visual score into `risk_fusion`.

---

### 2026-10-06 — Week 5: transparent risk fusion v1

**Built**

- `ml/risk_fusion.py` — additive, bounded 0-100 scorer:
  `rule_score + ml + vlm + av − signature_credit − allowlist_credit`, clamped.
  Every component is kept per incident (`reports/risk_scores.csv`) so the dashboard
  and LLM can show *why* risk is high.
- Risk classes: Normal 0-19, Observe 20-39, Suspicious 40-59, High 60-79, Critical 80-100.
- Safety guard: a visual/LLM signal **alone** (no rules, no AV, no ML) can never reach
  Critical - capped at 79.
- Ablation preview: rules-only vs ML-only vs fusion, plus `reports/results_fusion.csv`.
- 6 new unit tests for fusion (bounds, class thresholds, visual cap, signature credit).

**Results** (test split, detection threshold = 60 / High)

| config | precision | recall | F1 | PR-AUC | FPR | benign-quarantine |
| --- | --- | --- | --- | --- | --- | --- |
| rules_only | 1.00 | 0.333 | 0.500 | 1.000 | 0.000 | 0.000 |
| ml_only | 0.00 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 |
| **rules_ml_fusion** | **1.00** | **1.000** | **1.000** | **1.000** | **0.000** | **0.000** |

Risk-class distribution: benign all Normal; malicious 7 Critical + 14 High;
suspicious all Observe (34). Zero benign false positives / zero quarantines.

**Decisions**

- **ML alone caps below High** (`max_ml_score=45`) — matches "rules/ML make the
  first-pass decision, but a single learned signal shouldn't be authoritative".
- **Trusted-signature credit only applies when no rule fired.** A valid signature
  must not wash away behavioral evidence (a hidden PowerShell with `-ExecutionPolicy
  Bypass`, or a signed `certutil` downloader). This fixed `suspicious_hidden_script`
  scoring Normal.
- **VLM is a placeholder (0) in the CLI** until Weeks 8-10; the parameter and cap
  are wired in now.

**Caveats**

- Fusion lifts recall from 0.33 to 1.00 on synthetic data mainly because the ML
  signal is strong on this data; real-world gains will be smaller.
- Weights are provisional and uncalibrated (Week 5 explicitly precedes calibration).
- `ml_only` reaching 0 recall at threshold 60 is by design, not a failure.

**Next**

- Week 6: structured incident JSON + LLM output schema (evidence-ID grounding),
  then Week 7 the grounded analyst.

---

### 2026-10-06 — Weeks 1-4: data, features, ML baselines, evaluation

**Built**

- Repo scaffold `sentinelllm/` with ownership split; branch `person2-ai` created.
- `docs/event_schema.md` (event contract, rules R001-R011), `docs/glossary.md` (field + ML terms).
- `data_synthetic/generate_events.py` — deterministic synthetic Person 1 telemetry.
- `analysis/load_events.py` — JSONL → flattened DataFrame.
- `ml/features.py` — per-incident feature table (17 numeric features + id + label), documented in `ml/features.md`.
- `ml/splits.py` — family-aware (scenario-grouped) stratified split.
- `ml/evaluation.py` — P/R/F1, PR-AUC, ROC-AUC, FPR, benign-quarantine rate, confusion-matrix + PR-curve plots, experiment logging.
- `ml/baseline_models.py` — Logistic Regression + Random Forest, joblib save, results + split report.
- `notebooks/notebook_01_events.ipynb`, `notebook_02_features.ipynb`.
- `tests/test_pipeline.py` — 9 tests (generator, features, splits, evaluation).
- `Makefile` (`setup/data/features/baseline/test/repro/clean`), `requirements.txt`, `.gitignore`.

**Results** (see cumulative table above)

- Logistic Regression: perfect on the default split.
- Random Forest: recall 0.667 — misses the held-out `browser_extension_hijack`
  family (feature region unseen in training; scores 0.34 vs 0.5 threshold). LR
  catches the same incidents at 0.74.

**Decisions**

- **Family-aware split over random** — variants within a scenario are near-duplicates;
  a random split would leak and inflate metrics.
- **Binary task (malicious vs rest)** — suspicious is "not confirmed malicious",
  so it counts as a negative for the detection/FPR framing.
- **Added deliberate difficulty** — hard negatives (browser reading its own
  credential store; signed installer in Temp), hard positives (signed `certutil`
  downloader), and one intentionally indistinguishable pair
  (`benign_encoded_admin_tool` vs `malicious_encoded_only_loader`) that sets an
  honest error floor and motivates the LLM layer.
- **No notebooks as deliverables** — logic lives in `ml/*.py`; notebooks are optional.

**Caveats**

- Metrics are inflated by synthetic separability; treat as pipeline validation only.
- `encrypted_archive` is a proxy (archive-in-Temp) — needs a real `is_encrypted` field.
- `powershell_hidden` / `encoded` / `remote_download` are text matches; obfuscation can evade them.
- RF probabilities need calibration before any threshold-based policy use.

**Next**

- Week 5: transparent risk fusion (rule score + calibrated ML + placeholders for
  VLM/AV), bounded 0-100, every contribution visible.

---

## Known limitations

1. Synthetic data makes classes more separable than reality; metrics are a smoke test.
2. Feature text-matching can be evaded by obfuscation (Week 12 adversarial experiment).
3. `label` is incident-level and denormalized on events — never use as a feature.
4. ML probabilities are uncalibrated; thresholds are not yet policy-grade.

## Open questions for Person 1

- Confirm/version the event schema; add `is_encrypted` for archives.
- Provide real benign baseline captures and ≥3 synthetic attack chains.
- Confirm rule IDs/definitions match `docs/event_schema.md` (R001-R011).
- Quarantine result event shape.

## Roadmap status

| Week | Area | Status |
| --- | --- | --- |
| 1-2 | Data + features | Done |
| 3-4 | ML baselines + evaluation | Done |
| 5 | Risk fusion | Done |
| 6-7 | LLM schema + grounded analyst | Done |
| 8-10 | VLM dataset + baseline + fusion | Next |
| 11 | Dashboard | Pending |
| 12 | Ablation + paper | Pending |
