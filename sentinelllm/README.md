# SentinelLLM

A multimodal agentic framework for endpoint compromise detection, unauthorized
file analysis, and safe automated remediation.

This repository is the shared workspace for both team members. **Person 1** owns
telemetry collection, baselines, rules, and the policy engine; **Person 2** owns
the AI/ML/multimodal half; several areas are shared.

> **Progress & results log:** [`reports/PROGRESS.md`](./reports/PROGRESS.md) — what
> was built, the numbers, decisions, caveats, and what's next (updated each session).

## Status

| Area | State |
| --- | --- |
| Event schema + synthetic data | Done (Weeks 1-2) |
| Data loading + Week 1 notebook | Done |
| Feature pipeline + Week 2 notebook | Done |
| ML baselines (LR, RF) | Done (Week 3) |
| Evaluation (P/R/F1, PR-AUC, FPR, benign-quarantine) | Done (Week 4) |
| Risk fusion | Done (Week 5) |
| LLM analyst | Done (Weeks 6-7) |
| VLM social-engineering detector | Not started (Weeks 8-10) |
| Dashboard | Not started (Week 11) |
| Ablation + paper | Not started (Week 12) |

## Repository layout

```
sentinelllm/
├── docs/            # event schema, glossary, feature reference (shared)
├── collector/       # Person 1: Windows telemetry collector
├── baseline/        # Person 1: trusted baseline / first-seen inventory
├── rules/           # Person 1: deterministic rule engine
├── policy/          # Person 1: policy-controlled remediation
├── analysis/        # Person 2: data cleaning + event loading
├── ml/              # Person 2: features + ML baselines
├── llm/             # Person 2: evidence-grounded incident analyst
├── vlm/             # Person 2: visual social-engineering detector
├── dashboard/       # Person 2: FastAPI + web UI
├── tests/           # pipeline + integration tests
├── data_synthetic/  # shared: synthetic events, labels, features
└── reports/         # shared: experiment log, figures, tables
```

## Quickstart

```bash
# 1. Environment (Python 3.11+; 3.13 recommended for ML wheel support)
python3.13 -m venv .venv
.venv/bin/pip install -r sentinelllm/requirements.txt

# 2. Generate synthetic Person 1 events (JSONL + labels)
.venv/bin/python sentinelllm/data_synthetic/generate_events.py

# 3. Build the per-incident feature table
.venv/bin/python sentinelllm/ml/features.py

# 4. Run the tests
.venv/bin/python -m unittest discover -s sentinelllm/tests -v
```

Or just: `make repro`

Notebooks are in `sentinelllm/notebooks/` (`notebook_01_events.ipynb`,
`notebook_02_features.ipynb`). Open them with JupyterLab or VS Code.

## Synthetic data (stand-in for Person 1)

`sentinelllm/data_synthetic/generate_events.py` produces a deterministic,
schema-conformant event stream so the AI pipeline can be built before the real
collector is ready. **169 incidents / 573 events across 25 scenarios:**

- **92 benign** incidents (11 scenarios: browsing, office, updates, dev, backup,
  conferencing, media, visible admin script, plus three *hard* negatives -
  signed installer in Temp, a browser reading its own credential store, and a
  legitimately encoded admin command)
- **18 ambiguous** incidents (3 scenarios: unsigned tool in Temp, portable app,
  local script) - benign but risky-looking
- **18 suspicious** incidents (3 scenarios: hidden script, encoded command, LOLBin recon)
- **59 malicious** incidents (8 chains: ClickFix staged stealer, credential-phishing
  session theft, downloader-to-persistence, remote-access loader, browser-extension
  hijack, obfuscated loader, signed-LOLBin loader, encoded-only loader)

Two deliberate design choices make the evaluation honest:

1. **Hard negatives and hard positives** (browser store access by a legit process;
   a signed `certutil` downloader) so a detector cannot win by keying on a single
   feature.
2. **`malicious_encoded_only_loader` is intentionally indistinguishable** from
   `benign_encoded_admin_tool` on these features. It sets an error floor and
   demonstrates why the ML layer alone is not enough - the LLM/context layer exists
   for exactly this ambiguity.

**This is 100% synthetic.** No real malware, domains, credentials, or PII. It
uses RFC-2606/RFC-5737 style names and addresses only.

### Split and evaluation notes

`ml/splits.py` performs a **family-aware split**: every incident of a scenario
stays on one side, so near-duplicate variants never leak across the boundary, and
it stratifies by label so both sides see all classes. On the default split the
Logistic Regression is perfect, while Random Forest misses the held-out
`browser_extension_hijack` family (its feature region is unseen in training) -
a genuine generalization gap, not a bug. These numbers are a smoke test on
synthetic data, not a scientific result.

## Safety rules (both members)

- Never run real malware outside a disposable, isolated VM.
- Metadata only: no raw passwords, cookies, tokens, or card data anywhere.
- The LLM/VLM recommend; only deterministic policy code authorizes destructive action.
- Quarantine, never delete, during development - preserve SHA-256 and metadata.
- Every experiment is logged in `reports/experiments.csv`.

## What Person 2 needs from Person 1

Stable versioned event schema, incident/event IDs, defined rule hits, artifact
metadata (hash, signer, path category, first-seen), process/network metadata with
synthetic ground-truth labels, quarantine result events, and benign baselines plus
at least three synthetic attack-chain scenarios.
