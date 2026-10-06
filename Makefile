PY ?= .venv/bin/python

.PHONY: help setup data features baseline fusion llm test repro clean

help:
	@echo "setup    - create .venv and install requirements"
	@echo "data     - generate synthetic Person 1 events"
	@echo "features - build the per-incident feature table"
	@echo "baseline - train ML baselines and evaluate (Weeks 3-4)"
	@echo "fusion   - transparent risk fusion v1 (Week 5)"
	@echo "llm      - evidence-grounded analyst + grounding metrics (Weeks 6-7)"
	@echo "test     - run the test suite"
	@echo "repro    - one command: regenerate data, features, baselines, fusion, llm, tests"
	@echo "clean    - remove generated data and report artifacts"

setup:
	python3.13 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r sentinelllm/requirements.txt

data:
	$(PY) sentinelllm/data_synthetic/generate_events.py

features: data
	$(PY) sentinelllm/ml/features.py

baseline: features
	$(PY) sentinelllm/ml/baseline_models.py

fusion: baseline
	$(PY) sentinelllm/ml/risk_fusion.py

llm: fusion
	$(PY) sentinelllm/llm/analyst.py

test:
	$(PY) -m unittest discover -s sentinelllm/tests -v

repro: llm test

clean:
	rm -f sentinelllm/data_synthetic/events.jsonl
	rm -f sentinelllm/data_synthetic/incident_labels.csv
	rm -f sentinelllm/data_synthetic/features.csv
	rm -f sentinelllm/reports/results_baseline.csv
	rm -f sentinelllm/reports/split_report.csv
	rm -f sentinelllm/reports/results_fusion.csv
	rm -f sentinelllm/reports/risk_scores.csv
	rm -f sentinelllm/reports/llm_report.json
	rm -f sentinelllm/reports/results_llm.csv
	rm -rf sentinelllm/reports/figures
	rm -rf sentinelllm/reports/models

