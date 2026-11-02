.PHONY: test tour
test:
	pytest -q
tour:
	incident run --system rules --backend rules --out results/smoke/inc_rules.jsonl
	incident run --system base  --backend mock  --out results/smoke/inc_base.jsonl
	incident run --system guard --backend mock  --guard phrouros --out results/smoke/inc_guard.jsonl
	incident report results/smoke/inc_rules.jsonl results/smoke/inc_base.jsonl results/smoke/inc_guard.jsonl --out results/smoke/incident_report.md
	-govern gate --incident results/smoke/inc_guard.jsonl --model mock --mitigation phrouros --out results/smoke/certificate.json
