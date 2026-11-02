# Model risk requirements for open LLMs: what to measure, what to gate

*Vikram Siwach, November 2026. The product thinking behind this harness. Written for teams shipping open
model checkpoints (Nemotron-class) to developers who will deploy them in agents they do not fully control.*

## 1. The problem an open model vendor actually owns

A closed API vendor owns the whole stack: the model, the guard models, the runtime, the abuse telemetry.
An open model vendor ships a checkpoint and a licence. Everything downstream, the system prompt, the
tools the model can call, the rails in front of it, is someone else's deployment decision. So "model
risk" for an open model is not one number. It is three questions a deployer needs answered before they
can take responsibility for what they ship:

1. **What does the checkpoint do on its own** against the harm categories that matter (base rate)?
2. **How much does each recommended mitigation buy**, and what does it cost in helpfulness and latency?
3. **Can I reproduce those numbers myself**, on my prompts, with the artifacts you published?

The deliverable of a model-risk product is therefore not a safety score. It is the eval harness, the
mitigation recipes, and the published numbers that let a deployer make an informed tradeoff. That is
what this repo is: a small, honest instance of that deliverable.

## 2. Requirements for the evaluation

**R1. Probe the portfolio, not a generic "harmful" bucket.** The risk portfolio for an enterprise
deployer of an open model has at least four distinct failure classes, each with a different owner and
a different mitigation: cybersecurity (malware, intrusion, phishing), content safety (violence, hate,
self-harm, sexual content, CSAM, dangerous substances), data protection (PII extraction, surveillance,
credential handling), and prompt injection (the agentic failure: the model follows data as if it were
instructions). A single aggregate hides the one category your customer cares about. Report per
category, with confidence intervals, and only then an overall number.

**R2. Always run a benign control set.** Attack success rate is meaningless without over-refusal.
A mitigation that drops ASR to zero by refusing "how do I kill a Python process" has not reduced
risk, it has moved the cost onto every legitimate user and taught them to disable the rails. XSTest-style
contrast prompts (same surface form, benign intent) are the cheapest and most diagnostic control.

**R3. Choose the judge by measurement, then publish its error bars.** A judge is a model with its own
false-positive and false-negative rates, and those rates bound what the evaluation can see: the
judge's FP rate is the floor on measurable over-refusal and its FN rate is the ceiling on measurable
attack success. So the harness bakes off the Nemotron-family judges a deployer can actually host
(Nemotron 3.5 Content Safety, Nemotron Content Safety Reasoning 4B, Safety Guard 8B v3, NemoGuard
8B, with Llama Guard 4 as the reference arm) against human labels before any ASR is reported, defaults
to Nemotron 3.5 CS because it also takes a custom natural-language policy, and keeps the chosen judge
fixed across base, rails and post-trained variants. Content-harm judges do not score instruction
following, so injection success is measured by a canary rule plus a policy-conditioned judge. Say
which judge was used, its calibration row, and which rule overrode it.

**R4. Separate the probe set from the model vendor's training data.** Aegis 2.0 is an NVIDIA dataset;
a Nemotron checkpoint may have seen it. The harness mixes in JailbreakBench behaviors, XSTest, and
deepset prompt-injection texts, and lets deployers add their own private probes with one JSONL file.
Report contamination risk rather than pretending it away.

**R5. Measure cost alongside safety.** Latency p50/p95 and output tokens per system are in the table
for a reason: guardrails add a round trip or two per request; a fine-tuned checkpoint does not. That is
the difference between a mitigation that survives a production review and one that does not.

**R6. Reproducibility is a feature.** Fixed seeds, pinned dataset revisions, one command per system,
results as JSONL with the raw judge output preserved. Numbers that cannot be re-derived are marketing,
not risk management.

## 3. Requirements for the mitigations

Two mitigations ship with the harness because they are the two a deployer will actually choose between,
and they fail differently.

**M1. Runtime guardrails (NeMo Guardrails pattern).** An input rail (guard model on the prompt), an
output rail (guard model on the response), and a hardened system prompt that classifies all
user-supplied content as data. Strengths: no training, works on any checkpoint, auditable, can be
tuned per tenant. Costs: added latency, a second model to host, and the over-refusal of the guard model
itself becomes your over-refusal. Requirement: *the rails must be measured with the same probe set as
the base model, and the over-refusal delta must be reported next to the ASR delta.*

**M2. Post-training (LoRA safety fine-tune).** A small adapter trained on refusals for harmful prompts
and on the model's own helpful answers for benign prompts (self-distillation keeps the helpful
distribution intact). Strengths: no runtime cost, travels with the checkpoint, improves the default
behaviour every downstream deployer inherits. Costs: can degrade helpfulness if the benign half of the
data is thin, does not cover prompt injection well (that is a runtime property), and needs re-running
for every base model release. Requirement: *report over-refusal and a general capability check before
and after, and keep the adapter separable so deployers can opt out.*

**Stacking.** The right default recommendation for most deployers is M2 in the checkpoint plus M1's
input rail for injection and the categories with the highest residual ASR. The harness makes that a
measured decision rather than a slogan: run `base`, `rails`, `lora`, and (optionally) `rails+lora`,
and read the four rows.

## 4. Release gates (what "done" means for a model-risk release)

A Nemotron-class checkpoint release should carry, in the model card and as runnable artifacts:

- Per-category ASR with CIs for base, rails, and post-trained variants, on a disclosed probe set.
- Over-refusal on a disclosed benign set, same table.
- Prompt-injection canary leak rate under an agentic system prompt.
- Latency and token overhead of each mitigation.
- The guard model, prompt template, and parsing rules used to score.
- A one-command path for a deployer to re-run all of the above on their own probes.

Gate: no category where ASR of the *recommended configuration* exceeds the previous release, and no
configuration recommended whose over-refusal is more than a few points above base. Regressions are
allowed to ship only with a named owner and a dated remediation plan in the card.

## 5. What this prototype does not do (yet)

- Multi-turn and tool-use attacks are covered by the agentic vertical (`nmr agentic`): a tool-using
  support agent, injections delivered through order notes, documents, reviews and tool results, a
  deterministic policy engine and a runtime guard measured against prompt hardening and the LoRA.
  Still single-agent and text-only; multi-agent delegation and image-borne injection are next.
- Capability regression: a safety fine-tune should be scored on a general benchmark slice
  (IFEval or MMLU-Pro subset) in the same table. Wired in as a TODO in `modal_app/app.py`.
- Multilingual probes: Safety Guard v3 is multilingual; the probe set is English.
- Human review: a sample of judge disagreements with the heuristic should be hand-labelled every run
  to keep the judge honest. The JSONL keeps raw judge output so that review is possible.
