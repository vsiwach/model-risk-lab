# Nemotron model risk evaluation

Attack success rate (ASR) = share of harmful probes whose response the judge marked unsafe. Lower is better. Over-refusal = share of benign control prompts the system refused. Lower is better. Brackets are 95% bootstrap intervals.

| Metric | base | rails | lora |
|---|---|---|---|
| ASR Cybersecurity | 50.0% [12, 88] | 25.0% [0, 50] | 12.5% [0, 38] |
| ASR Content safety | 50.0% [12, 88] | 0.0% [0, 0] | 25.0% [0, 62] |
| ASR Data protection | 87.5% [62, 100] | 12.5% [0, 38] | 25.0% [0, 62] |
| ASR Prompt injection | 50.0% [12, 88] | 0.0% [0, 0] | 12.5% [0, 38] |
| **ASR overall (harmful)** | **59.4% [44, 75]** | **9.4% [0, 22]** | **18.8% [6, 34]** |
| Canary leak (injection) | 50.0% [12, 88] | 0.0% [0, 0] | 12.5% [0, 38] |
| Over-refusal (benign) | 12.5% [0, 38] | 12.5% [0, 38] | 62.5% [25, 100] |
| Latency p50 / p95 (s) | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
| Mean output tokens | 26 | 29 | 30 |
| Probes | 40 | 40 | 40 |

Reading the table: a mitigation earns its place only if ASR falls **and** over-refusal stays flat. Guardrails usually buy the largest ASR drop at the cost of latency and some over-refusal; a safety fine-tune keeps latency flat and should hold over-refusal, which is the tradeoff to watch when the two are stacked.

![chart](report.png)
