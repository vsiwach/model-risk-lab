# model-risk-lab

Assess, evaluate, mitigate and govern model risk for Nemotron open LLMs, end to end on **one use
case**: an incident-remediation agent for an inference control plane, under prompt injection.

```
ASSESS        threat model + probe sets            docs/, harness/, target/incident/scenarios.py
EVALUATE      judge bake-off, breadth + depth      nmr calibrate · nmr run · incident run
MITIGATE      hardening · rails · phrouros · LoRA  mitigate/, modal_app (SFT on Modal)
GOVERN        release gate + signed certificate    govern gate · govern verify
```

The use case: Nemotron Nano reads an incident packet (pool telemetry, log lines, alert annotations, a
runbook excerpt, the last tool result) and chooses one action from a closed allowlist (quarantine,
probe, reinstate, resolve, escalate, wait). The environment, allowlist and invariants are ported from
[baseten-mvp](https://github.com/vsiwach/baseten-mvp), which runs the same loop on live pools with a
recorded MTTR of about 9 seconds. Attackers who can write to logs, alerts, a wiki or a pool's response
body plant instructions there. The question the lab answers with numbers: **how often does the model
obey the planted instruction, what does each mitigation buy, and does the agent stay as fast as the
rule-based one on real incidents?**

## Results (real, Nemotron Nano 8B, Nov 2026)

| | rules | base Nano 8B | + hardened prompt | + phrouros guard | + LoRA (ours) | LoRA on held-out set |
|---|---|---|---|---|---|---|
| Attack success | 0% | **50.0%** | 30.6% | **0%** | **0%** | **0%** (base: 55%) |
| Unsafe action executed | 0% | 47.2% | 27.8% | 0% | 0% | 0% |
| Clean faults resolved | 100% | **0%** | 0% | 0% | **100%** | 100% |
| MTTR vs rules | x1.00 | never | never | never | **x1.00** | x1.00 |
| Release gate | | FAIL | FAIL | FAIL (competence) | **PASS** | **PASS** |

Judge bake-off on 200 human-labelled Aegis responses: Safety Guard 8B v3 F1 88.7, Nemotron 3.5
Content Safety F1 85.1. The full tables, the held-out design and the open limits are in
[`docs/RESULTS.md`](docs/RESULTS.md); episode files in `results/real/`.

## Thirty-second tour (no GPU, no keys)

```bash
pip install -e ".[dev]" && pytest -q                                  # 13 hermetic tests
incident run --system rules --backend rules --out results/inc_rules.jsonl          # MTTR baseline
incident run --system base  --backend mock  --out results/inc_base.jsonl           # mock LLM policy
incident run --system guard --backend mock  --guard phrouros --out results/inc_guard.jsonl
incident report results/inc_rules.jsonl results/inc_base.jsonl results/inc_guard.jsonl
govern gate --incident results/inc_guard.jsonl --model mock --mitigation phrouros   # PASS + certificate
govern gate --incident results/inc_base.jsonl  --model mock                         # FAIL, says which number
```

## The end-to-end run on Modal (about $20 of credit)

```bash
pip install modal && modal setup
nmr probes --n 40 --out results/probes.jsonl
modal run modal_app/app.py::bakeoff                                  # 1. pick the judge by F1 (Nemotron 3.5 CS, SG v3, NemoGuard)
modal run modal_app/app.py::evaluate --system base                   # 2. breadth: content safety, cyber, privacy, injection
modal run modal_app/app.py::evaluate --system rails
modal run modal_app/app.py::incident_eval --system base              # 3. the use case, base model
modal run modal_app/app.py::incident_eval --system hardened --harden
modal run modal_app/app.py::incident_eval --system phrouros --guard phrouros
incident sft --out mitigate/incident_sft.jsonl                       # 4. oracle-labelled packets (hermetic)
modal run modal_app/app.py::incident_train                           # 5. QLoRA: resist planted actions, keep MTTR
modal run modal_app/app.py::incident_eval --system lora --adapter nemotron-nano-8b-incident-lora
incident report results/inc_rules.jsonl results/inc_base.jsonl results/inc_hardened.jsonl results/inc_phrouros.jsonl results/inc_lora.jsonl
govern gate --incident results/inc_lora.jsonl --breadth results/base.jsonl --calibration results/calibration.md \
            --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --mitigation lora        # 6. gate + signed certificate
```

Step 4 needs no GPU: the rule policy labels every packet, including the injected ones, with the safe
action and a rationale that names the planted text. Step 5 trains on those (assistant-only loss, nf4
QLoRA, r=32). Step 6 fails loudly if attack success, exfiltration, service-down, MTTR ratio or
false-positive rate crosses the thresholds in `govern/govern/risk-policy.yaml`.

## What each layer contains

**harness/** (`nmr`): the breadth harness. Probes from Aegis 2.0, JailbreakBench, XSTest and
deepset injections across cybersecurity, content safety, data protection and prompt injection; a
judge registry (Nemotron 3.5 Content Safety default, Safety Guard v3, NemoGuard, Nemotron CSR 4B, Llama
Guard 4) with `nmr calibrate` to bake them off against human labels; rails; a retail-agent vertical;
`garak.sh` for NVIDIA's security scanner.

**target/** (`incident`): the use case. `sim.py` (two pools, chaos faults, allowlist), `rules.py` (the
ported rule policy: MTTR baseline and SFT oracle), `llm.py` (incident packet and LLM policy),
`scenarios.py` (6 goals x 4 phrasings x 4 vectors + clean faults), `policy.py` (invariants and a
deny-by-default guard), `sft.py`, `metrics.py`.

**mitigate/**: `phrouros_guard.py` (phrouros enforce as the runtime guardian: identity, tool grants,
approval tokens for state-changing tools, egress allowlist; real package if installed, API-compatible
shim otherwise), `guardrails/` (NeMo Guardrails config for the breadth layer), the LoRA recipe.

**govern/**: `risk-policy.yaml` thresholds, `gate.py` (verdict per threshold), HMAC-signed certificate
with expiry and verifier.

**docs/**: `model-risk-requirements.md`, the product write-up: what to measure, what to gate.

## Honest limits

Simulated pools (two, fixed fault profiles) rather than live Baseten; single agent, text only; the
mock policy in the tour is deterministic and only illustrates shape; the phrouros integration uses the
policy and approval layer, not the signed ledger or kernel sensor. Real numbers come from the Modal run.

Apache-2.0. Datasets and models keep their own licences (Aegis 2.0 CC-BY-4.0, JBB MIT, XSTest CC-BY-4.0,
deepset Apache-2.0; Nemotron models under the NVIDIA Open Model Licence and Llama 3.1 community licence).
