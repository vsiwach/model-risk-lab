"""Modal app: run the whole harness on rented GPUs with one command each.

    pip install modal && modal setup                      # once, on your machine
    modal run modal_app/app.py::evaluate --system base        # base model
    modal run modal_app/app.py::evaluate --system rails       # + content-safety rails
    modal run modal_app/app.py::build_sft                 # build the safety SFT set (self-distilled under rails)
    modal run modal_app/app.py::train                     # QLoRA safety fine-tune -> volume + lora/out
    modal run modal_app/app.py::evaluate --system lora --adapter nemotron-nano-8b-safety-lora
    modal run modal_app/app.py::agentic --system base               # retail-agent vertical, then --harden, --guard, --adapter
    incident sft --out mitigate/incident_sft.jsonl                  # oracle-labelled packets (hermetic, no GPU)
    modal run modal_app/app.py::incident_eval --system base         # the use case: base, --harden, --guard phrouros
    modal run modal_app/app.py::incident_train                      # QLoRA: resist injected ops actions, keep MTTR
    modal run modal_app/app.py::incident_eval --system lora --adapter nemotron-nano-8b-incident-lora
    govern gate --incident results/inc_lora.jsonl --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --mitigation lora
    nmr report results/base.jsonl results/rails.jsonl results/lora.jsonl --out results/report.md

Cost guide (Modal list prices, Nov 2026): L4 for inference (~$0.80/h), A100-40GB for training (~$2.80/h).
A 190-probe eval is a few minutes per system; the QLoRA job is roughly an hour. The whole study fits
inside about $15 of credit.

Models (Hugging Face):
  target: nvidia/Llama-3.1-Nemotron-Nano-8B-v1              (Llama 3.1 community licence)
  judge:  nvidia/Nemotron-3.5-Content-Safety (default; NMR_JUDGE=sgv3|nemoguard|nemotron3|csr4b|llamaguard4 to bake off)
Set a HF token as the Modal secret `huggingface` (HF_TOKEN=...) if either repo asks for acceptance.
"""


import json
import os
import sys
import time
from pathlib import Path

import modal

APP = "model-risk-lab"
TARGET_MODEL = os.environ.get("NMR_TARGET", "nvidia/Llama-3.1-Nemotron-Nano-8B-v1")
GUARD_KEY = os.environ.get("NMR_JUDGE", "nemotron35")   # judge registry key, see nmr/judge.py JUDGES
VOL = modal.Volume.from_name(f"{APP}-vol", create_if_missing=True)
VOL_PATH = "/vol"

ROOT = Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "vllm>=0.11.0,<0.21",
        "transformers>=4.55",
        "peft>=0.17",
        "trl>=0.21",
        "bitsandbytes>=0.46",
        "accelerate>=1.0",
        "datasets>=3.0",
        "openai>=1.40",
        "pandas",
        "numpy",
        "matplotlib",
        "pyyaml",
        "hf_transfer",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HOME": f"{VOL_PATH}/hf", "VLLM_USE_V1": "1"})
    .add_local_dir(str(ROOT / "harness" / "nmr"), remote_path="/root/nmr")
    .add_local_dir(str(ROOT / "target" / "incident"), remote_path="/root/incident")
    .add_local_dir(str(ROOT / "mitigate"), remote_path="/root/mitigate")
)

app = modal.App(APP, image=image)
# set NMR_HF_SECRET=1 to attach a Modal secret named "huggingface" (HF_TOKEN) for gated repos; off by default
secrets = [modal.Secret.from_name("huggingface", required_keys=[])] if os.environ.get("NMR_HF_SECRET", "0") == "1" else []


# --------------------------------------------------------------------------------------- inference


@app.cls(gpu="L4", volumes={VOL_PATH: VOL}, secrets=secrets, timeout=60 * 60, scaledown_window=120)
class Target:
    """The model under test, served with vLLM. Optional LoRA adapter from the volume."""

    adapter: str = modal.parameter(default="")

    @modal.enter()
    def load(self):
        from vllm import LLM

        kw = dict(model=TARGET_MODEL, dtype="bfloat16", max_model_len=4096, gpu_memory_utilization=0.90,
                  enforce_eager=True)
        if self.adapter:
            kw.update(enable_lora=True, max_lora_rank=64)
        self.llm = LLM(**kw)
        self.lora = None
        if self.adapter:
            from vllm.lora.request import LoRARequest

            path = f"{VOL_PATH}/adapters/{self.adapter}"
            self.lora = LoRARequest("safety", 1, path)

    @modal.method()
    def chat(self, pairs: list[tuple[str, str]], max_tokens: int = 512) -> list[dict]:
        msgs = [[{"role": "system", "content": s}, {"role": "user", "content": u}] for s, u in pairs]
        return self.chat_multi(msgs, max_tokens)

    @modal.method()
    def chat_multi(self, msgs: list[list[dict]], max_tokens: int = 512) -> list[dict]:
        from vllm import SamplingParams

        sp = SamplingParams(temperature=0.0, max_tokens=max_tokens)
        t0 = time.perf_counter()
        outs = self.llm.chat(msgs, sp, lora_request=self.lora, use_tqdm=False)
        dt = (time.perf_counter() - t0) / max(1, len(pairs))
        return [{"text": o.outputs[0].text, "prompt_tokens": len(o.prompt_token_ids),
                 "completion_tokens": len(o.outputs[0].token_ids), "latency_s": dt} for o in outs]


@app.cls(gpu="L4", volumes={VOL_PATH: VOL}, secrets=secrets, timeout=60 * 60, scaledown_window=120)
class Guard:
    """A Nemotron-family safety judge served with vLLM; returns raw verdicts the harness parses.

    judge keys and prompt styles come from nmr.judge.JUDGES so the Modal path and the NIM path score
    identically. Nemotron 3.5 Content Safety is a 4B Gemma-3 model with a 128K context that accepts a
    custom natural-language policy through chat_template_kwargs.
    """

    judge: str = modal.parameter(default=GUARD_KEY)

    @modal.enter()
    def load(self):
        from vllm import LLM

        sys.path.insert(0, "/root")
        from nmr.judge import JUDGES

        self.spec = JUDGES[self.judge]
        if self.spec.get("nim_only"):
            raise RuntimeError(f"judge {self.judge} is adapter-only on a gated base; use it through NIM, not Modal")
        self.llm = LLM(model=self.spec["model"], dtype="bfloat16", max_model_len=8192,
                       gpu_memory_utilization=0.90, enforce_eager=True)

    @modal.method()
    def check(self, pairs: list[tuple[str, str]], custom_policy: str = "") -> list[str]:
        from vllm import SamplingParams

        sys.path.insert(0, "/root")
        from nmr.judge import guard_prompt

        style = self.spec["style"]
        thinking = bool(self.spec.get("thinking"))
        sp = SamplingParams(temperature=0.0, max_tokens=600 if thinking else 120)
        if style == "aegis_json":
            msgs = [[{"role": "user", "content": guard_prompt(u, r)}] for u, r in pairs]
            outs = self.llm.chat(msgs, sp, use_tqdm=False)
        else:
            msgs = []
            for u, r in pairs:
                m = [{"role": "user", "content": u}]
                if r:
                    m.append({"role": "assistant", "content": r})
                msgs.append(m)
            kw = {"request_categories": "/categories", "enable_thinking": thinking}
            if custom_policy:
                kw["custom_policy"] = custom_policy
            outs = self.llm.chat(msgs, sp, use_tqdm=False, chat_template_kwargs=kw)
        return [o.outputs[0].text.split("</think>")[-1] for o in outs]


# --------------------------------------------------------------------------------------- eval


@app.local_entrypoint()
def evaluate(system: str = "base", probes: str = "results/probes.jsonl", adapter: str = "",
         out: str = "", batch: int = 32, max_tokens: int = 512):
    """Generate + rails (optional) + judge for one system, writing results/<system>.jsonl locally."""
    sys.path.insert(0, str(ROOT))
    from nmr.backends import DEFAULT_SYSTEM
    from nmr.judge import verdict_from_guard
    from nmr.rails import HARDENING, SAFE_REFUSAL
    from nmr.types import Generation, Record, read_probes, write_records

    plist = read_probes(Path(probes))
    out_path = Path(out or f"results/{system}.jsonl")
    rails = system.startswith("rails")
    target = Target(adapter=adapter)
    guard = Guard()

    systems = [(p.meta.get("system") or DEFAULT_SYSTEM) + (HARDENING if rails else "") for p in plist]
    users = [p.prompt for p in plist]
    responses: list[dict] = [None] * len(plist)  # type: ignore
    rails_info: list[dict] = [{} for _ in plist]

    # input rail
    todo = list(range(len(plist)))
    if rails:
        verdicts = []
        for i in range(0, len(plist), batch):
            verdicts += guard.check.remote([(u, "") for u in users[i:i + batch]])
        from nmr.judge import parse_guard

        todo = []
        for i, raw in enumerate(verdicts):
            parsed = parse_guard(raw)
            if parsed and parsed[0]:
                responses[i] = {"text": SAFE_REFUSAL, "prompt_tokens": 0, "completion_tokens": 0, "latency_s": 0.0}
                rails_info[i] = {"input_blocked": True, "categories": parsed[2]}
            else:
                todo.append(i)
        print(f"input rail blocked {len(plist) - len(todo)}/{len(plist)}")

    # generation
    for s in range(0, len(todo), batch):
        idx = todo[s:s + batch]
        res = target.chat.remote([(systems[i], users[i]) for i in idx], max_tokens=max_tokens)
        for i, r in zip(idx, res):
            responses[i] = r
        print(f"generated {min(s + batch, len(todo))}/{len(todo)}")

    # output rail
    if rails and todo:
        raws = []
        for s in range(0, len(todo), batch):
            idx = todo[s:s + batch]
            raws += guard.check.remote([(users[i], responses[i]["text"]) for i in idx])
        from nmr.judge import parse_guard

        blocked = 0
        for i, raw in zip(todo, raws):
            parsed = parse_guard(raw)
            if parsed and parsed[1]:
                responses[i]["text"] = SAFE_REFUSAL
                rails_info[i] = {"output_blocked": True, "categories": parsed[2]}
                blocked += 1
        print(f"output rail blocked {blocked}/{len(todo)}")

    # judge (always the guard model, so systems are scored identically)
    raws = []
    for i in range(0, len(plist), batch):
        raws += guard.check.remote([(users[j], responses[j]["text"]) for j in range(i, min(i + batch, len(plist)))])

    records = []
    for p, r, raw, ri in zip(plist, responses, raws, rails_info):
        g = Generation(probe_id=p.id, system=system, response=r["text"], latency_s=r["latency_s"],
                       prompt_tokens=r["prompt_tokens"], completion_tokens=r["completion_tokens"], rails=ri)
        records.append(Record(p, g, verdict_from_guard(p, g, raw)))
    n = write_records(out_path, records)
    from nmr.metrics import summarize

    s = summarize(records)
    print(f"wrote {n} records to {out_path}")
    print(f"{system}: ASR overall {s.asr_overall.as_pct()}, over-refusal {s.over_refusal.as_pct()}, "
          f"canary leak {s.canary_leak.as_pct()}")


# --------------------------------------------------------------------------------------- SFT data


@app.local_entrypoint()
def build_sft(n_harmful: int = 1200, n_benign: int = 1200, seed: int = 7, out: str = "lora/sft.jsonl"):
    """Self-distilled safety SFT set.

    harmful prompts (Aegis 2.0 train, unsafe) -> response generated by the base model behind the rails
    (the rails' refusal when blocked, the model's own safe completion otherwise, re-checked by the guard);
    benign prompts (XSTest safe + a general instruct slice) -> the base model's own answer, kept only if the
    guard calls it safe. Training on the model's own safe outputs keeps helpfulness; the harmful half
    teaches the refusal boundary the rails enforce at runtime.
    """
    import random

    import datasets

    sys.path.insert(0, str(ROOT))
    from nmr.backends import DEFAULT_SYSTEM
    from nmr.judge import parse_guard
    from nmr.rails import HARDENING, SAFE_REFUSAL

    rng = random.Random(seed)
    aegis = datasets.load_dataset("nvidia/Aegis-AI-Content-Safety-Dataset-2.0", split="train")
    harmful = [r["prompt"] for r in aegis if r["prompt_label"] == "unsafe" and r["prompt"] and len(r["prompt"]) < 1500]
    rng.shuffle(harmful)
    harmful = harmful[:n_harmful]

    xs = datasets.load_dataset("natolambert/xstest-v2-copy", split="prompts")
    benign = [r["prompt"] for r in xs if not str(r["type"]).startswith("contrast_")]
    try:
        gen = datasets.load_dataset("HuggingFaceH4/no_robots", split="train")
        benign += [r["prompt"] for r in gen if len(r["prompt"]) < 1200][: n_benign]
    except Exception as e:
        print("no_robots unavailable:", e)
    rng.shuffle(benign)
    benign = benign[:n_benign]

    target, guard = Target(), Guard()
    system = DEFAULT_SYSTEM + HARDENING
    rows = []

    def run_batch(prompts: list[str], label: str):
        out = []
        for i in range(0, len(prompts), 32):
            chunk = prompts[i:i + 32]
            in_raw = guard.check.remote([(u, "") for u in chunk])
            gens = target.chat.remote([(system, u) for u in chunk], max_tokens=400)
            out_raw = guard.check.remote([(u, g["text"]) for u, g in zip(chunk, gens)])
            for u, g, ir, orr in zip(chunk, gens, in_raw, out_raw):
                pi, po = parse_guard(ir) or (False, False, []), parse_guard(orr) or (False, False, [])
                if label == "harmful":
                    resp = SAFE_REFUSAL if (pi[0] or po[1]) else g["text"]
                    rows.append({"prompt": u, "response": resp, "label": label})
                else:
                    if not po[1]:
                        rows.append({"prompt": u, "response": g["text"], "label": label})
            print(f"{label}: {min(i + 32, len(prompts))}/{len(prompts)}")

    run_batch(harmful, "harmful")
    run_batch(benign, "benign")
    rng.shuffle(rows)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} SFT rows to {out}")


# --------------------------------------------------------------------------------------- QLoRA


@app.function(gpu="A100-40GB", volumes={VOL_PATH: VOL}, secrets=secrets, timeout=3 * 60 * 60)
def _train(sft_jsonl: str, name: str, epochs: float, lr: float, rank: int, max_len: int) -> str:
    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    rows = [json.loads(l) for l in sft_jsonl.splitlines() if l.strip()]
    tok = AutoTokenizer.from_pretrained(TARGET_MODEL)
    tok.pad_token = tok.pad_token or tok.eos_token

    # conversational prompt/completion format: loss on the assistant turn only (trl default for this shape)
    def to_pc(r):
        if "messages" in r:
            m = r["messages"]
            return {"prompt": m[:-1], "completion": [m[-1]]}
        return {"prompt": [{"role": "user", "content": r["prompt"]}],
                "completion": [{"role": "assistant", "content": r["response"]}]}

    ds = Dataset.from_list([to_pc(r) for r in rows]).train_test_split(test_size=0.05, seed=7)

    from transformers import AutoModelForCausalLM

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(TARGET_MODEL, quantization_config=bnb, dtype=torch.bfloat16,
                                                 device_map={"": 0})
    peft_cfg = LoraConfig(r=rank, lora_alpha=2 * rank, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                          target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    out_dir = f"{VOL_PATH}/adapters/{name}"
    cfg = SFTConfig(
        output_dir=out_dir, num_train_epochs=epochs, learning_rate=lr, lr_scheduler_type="cosine",
        warmup_ratio=0.03, per_device_train_batch_size=4, gradient_accumulation_steps=4, bf16=True,
        logging_steps=10, eval_strategy="steps", eval_steps=50, save_strategy="no", max_length=max_len,
        gradient_checkpointing=True, report_to=[], packing=False,
    )
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds["train"], eval_dataset=ds["test"],
                         processing_class=tok, peft_config=peft_cfg)
    trainer.train()
    metrics = trainer.evaluate()
    trainer.model.save_pretrained(out_dir)
    tok.save_pretrained(out_dir)
    with open(f"{out_dir}/train_metrics.json", "w") as f:
        json.dump({"eval": metrics, "rows": len(rows), "epochs": epochs, "lr": lr, "rank": rank}, f, indent=2)
    VOL.commit()
    return json.dumps(metrics)


@app.local_entrypoint()
def train(sft: str = "lora/sft.jsonl", name: str = "nemotron-nano-8b-safety-lora", epochs: float = 2.0,
          lr: float = 1e-4, rank: int = 32, max_len: int = 1024, download: str = "lora/out"):
    """QLoRA safety fine-tune on the SFT set; adapter saved to the volume and copied to lora/out."""
    text = Path(sft).read_text(encoding="utf-8")
    print("training on", len(text.splitlines()), "rows")
    print("eval:", _train.remote(text, name, epochs, lr, rank, max_len))
    dst = Path(download) / name
    dst.mkdir(parents=True, exist_ok=True)
    for entry in VOL.listdir(f"/adapters/{name}"):
        if entry.type == modal.volume.FileEntryType.FILE:
            with open(dst / Path(entry.path).name, "wb") as f:
                for chunk in VOL.read_file(entry.path):
                    f.write(chunk)
    print(f"adapter downloaded to {dst}; evaluate with: modal run modal_app/app.py::evaluate --system lora --adapter {name}")


# --------------------------------------------------------------------------------------- agentic vertical


@app.local_entrypoint()
def agentic(system: str = "base", adapter: str = "", harden: bool = False, guard: bool = False,
            out: str = "", max_indirect: int = 60, workers: int = 8):
    """Agentic cybersecurity vertical on the real model: modal run modal_app/app.py::agentic --system guard --guard"""
    sys.path.insert(0, str(ROOT))
    from nmr.agentic import build_scenarios, run_agentic
    from nmr.agentic.metrics import summarize_agentic

    target = Target(adapter=adapter)

    class Remote:
        name = f"modal:{TARGET_MODEL}" + (f"+{adapter}" if adapter else "")

        def chat_messages(self, messages):
            r = target.chat_multi.remote([messages], 400)[0]
            return r["text"], r["prompt_tokens"], r["completion_tokens"]

    scenarios = build_scenarios(max_indirect=max_indirect)
    eps = run_agentic(Remote(), scenarios, system_name=system, hardened=harden, guard=guard,
                      out_path=Path(out or f"results/agentic_{system}.jsonl"), workers=workers)
    s = summarize_agentic(eps)
    print(f"{system}: attack success {s.attack_success.as_pct()}, unauthorized {s.unauthorized_action.as_pct()}, "
          f"exfil {s.exfiltration.as_pct()}, blocked {s.attempted_blocked.as_pct()}, benign task success {s.task_success.as_pct()}")


# --------------------------------------------------------------------------------------- judge bake-off


@app.local_entrypoint()
def bakeoff(judges: str = "nemotron35,sgv3,nemoguard", n: int = 300, out: str = "results/calibration.md"):
    """Score several Nemotron-family judges against Aegis 2.0 human labels: modal run modal_app/app.py::bakeoff"""
    sys.path.insert(0, str(ROOT))
    from nmr.calibrate import Calibration, load_labelled
    from nmr.judge import verdict_from_guard

    triples = load_labelled(n=n)
    rows = []
    for key in [k.strip() for k in judges.split(",") if k.strip()]:
        g = Guard(judge=key)
        raws = []
        for i in range(0, len(triples), 32):
            chunk = triples[i:i + 32]
            raws += g.check.remote([(p.prompt, gen.response) for p, gen, _ in chunk])
        tp = fp = tn = fn = 0
        for (p, gen, truth), raw in zip(triples, raws):
            pred = verdict_from_guard(p, gen, raw, judge_name=key).response_unsafe
            tp += pred and truth; fp += pred and not truth; tn += (not pred) and (not truth); fn += (not pred) and truth
        rows.append(Calibration(judge=key, n=len(triples), tp=tp, fp=fp, tn=tn, fn=fn))
        print(rows[-1].markdown())
    md = "## Judge bake-off (Aegis 2.0 test, human response labels)\n\n" + rows[0].markdown()
    for r in rows[1:]:
        md += r.markdown().splitlines()[-1] + "\n"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(md, encoding="utf-8")
    print("wrote", out)


# --------------------------------------------------------------------------------------- incident agent (the use case)


@app.local_entrypoint()
def incident_eval(system: str = "base", adapter: str = "", harden: bool = False, guard: str = "",
                  out: str = "", max_injection: int = 72, workers: int = 8):
    """Incident agent on the real model: modal run modal_app/app.py::incident_eval --system base
       then --harden, --guard invariants|phrouros, --adapter <lora name>."""
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "target"))
    from incident.llm import LLMPolicy
    from incident.metrics import summarize_incident
    from incident.runner import run_scenarios
    from incident.scenarios import build_scenarios

    target = Target(adapter=adapter)

    class Remote:
        name = f"modal:{TARGET_MODEL}" + (f"+{adapter}" if adapter else "")

        def chat_messages(self, messages):
            r = target.chat_multi.remote([messages], 200)[0]
            return r["text"], r["prompt_tokens"], r["completion_tokens"]

    be = Remote()
    eps = run_scenarios(lambda: LLMPolicy(be, hardened=harden), build_scenarios(max_injection=max_injection),
                        system_name=system, guard=(guard or False), out_path=Path(out or f"results/inc_{system}.jsonl"),
                        workers=workers)
    s = summarize_incident(eps)
    print(f"{system}: attack success {s.attack_success.as_pct()}, unsafe executed {s.unsafe_executed.as_pct()}, "
          f"blocked {s.blocked.as_pct()}, MTTR x{s.mttr_ratio:.2f}, false positives {s.false_positive.as_pct()}")


@app.local_entrypoint()
def incident_train(sft: str = "mitigate/incident_sft.jsonl", name: str = "nemotron-nano-8b-incident-lora",
                   epochs: float = 2.0, lr: float = 1e-4, rank: int = 32, max_len: int = 2048,
                   download: str = "mitigate/out"):
    """QLoRA on the oracle-labelled incident packets (build them first: `incident sft`)."""
    train(sft=sft, name=name, epochs=epochs, lr=lr, rank=rank, max_len=max_len, download=download)


# --------------------------------------------------------------------------------------- detached orchestration
#
# The local entrypoints above drive the loop from the laptop. These run the same loops *inside* Modal
# and write to the volume, so `modal run --detach modal_app/app.py::job --stage incident --system base`
# survives the client going away. Fetch results with `modal volume get model-risk-lab-vol results/<file> results/`.


@app.function(timeout=4 * 60 * 60, volumes={VOL_PATH: VOL})
def _job(stage: str, system: str, adapter: str, harden: bool, guard: str, judges: str, n: int,
         max_injection: int, probes_jsonl: str) -> str:
    sys.path.insert(0, "/root")
    out_dir = Path(f"{VOL_PATH}/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    if stage == "bakeoff":
        from nmr.calibrate import Calibration, load_labelled
        from nmr.judge import verdict_from_guard

        triples = load_labelled(n=n)
        rows = []
        for key in [k.strip() for k in judges.split(",") if k.strip()]:
            g = Guard(judge=key)
            raws = []
            for i in range(0, len(triples), 32):
                chunk = triples[i:i + 32]
                raws += g.check.remote([(p.prompt, gen.response) for p, gen, _ in chunk])
            tp = fp = tn = fn = 0
            for (p, gen, truth), raw in zip(triples, raws):
                pred = verdict_from_guard(p, gen, raw, judge_name=key).response_unsafe
                tp += pred and truth; fp += pred and not truth; tn += (not pred) and (not truth); fn += (not pred) and truth
            rows.append(Calibration(judge=key, n=len(triples), tp=tp, fp=fp, tn=tn, fn=fn))
        md = "## Judge bake-off (Aegis 2.0 test, human response labels)\n\n" + rows[0].markdown()
        for r in rows[1:]:
            md += r.markdown().splitlines()[-1] + "\n"
        (out_dir / "calibration.md").write_text(md)
        VOL.commit()
        return md
    if stage == "incident":
        from incident.llm import LLMPolicy
        from incident.metrics import summarize_incident
        from incident.runner import run_scenarios
        from incident.scenarios import build_scenarios

        target = Target(adapter=adapter)

        class Remote:
            name = f"modal:{TARGET_MODEL}" + (f"+{adapter}" if adapter else "")

            def chat_messages(self, messages):
                r = target.chat_multi.remote([messages], 200)[0]
                return r["text"], r["prompt_tokens"], r["completion_tokens"]

        be = Remote()
        eps = run_scenarios(lambda: LLMPolicy(be, hardened=harden), build_scenarios(max_injection=max_injection),
                            system_name=system, guard=(guard or False), out_path=out_dir / f"inc_{system}.jsonl", workers=8)
        VOL.commit()
        s = summarize_incident(eps)
        return (f"{system}: attack success {s.attack_success.as_pct()}, unsafe executed {s.unsafe_executed.as_pct()}, "
                f"blocked {s.blocked.as_pct()}, MTTR x{s.mttr_ratio:.2f}, false positives {s.false_positive.as_pct()}")
    if stage == "breadth":
        from nmr.backends import DEFAULT_SYSTEM
        from nmr.judge import parse_guard, verdict_from_guard
        from nmr.metrics import summarize
        from nmr.rails import HARDENING, SAFE_REFUSAL
        from nmr.types import Generation, Probe, Record, write_records
        import json as _json

        plist = [Probe(**_json.loads(l)) for l in probes_jsonl.splitlines() if l.strip()]
        rails = system.startswith("rails")
        target, guard_ = Target(adapter=adapter), Guard()
        systems = [(p.meta.get("system") or DEFAULT_SYSTEM) + (HARDENING if rails else "") for p in plist]
        users = [p.prompt for p in plist]
        responses = [None] * len(plist)
        rails_info = [{} for _ in plist]
        todo = list(range(len(plist)))
        if rails:
            verdicts = []
            for i in range(0, len(plist), 32):
                verdicts += guard_.check.remote([(u, "") for u in users[i:i + 32]])
            todo = []
            for i, raw in enumerate(verdicts):
                parsed = parse_guard(raw)
                if parsed and parsed[0]:
                    responses[i] = {"text": SAFE_REFUSAL, "prompt_tokens": 0, "completion_tokens": 0, "latency_s": 0.0}
                    rails_info[i] = {"input_blocked": True, "categories": parsed[2]}
                else:
                    todo.append(i)
        for s0 in range(0, len(todo), 32):
            idx = todo[s0:s0 + 32]
            for i, r in zip(idx, target.chat.remote([(systems[i], users[i]) for i in idx], max_tokens=512)):
                responses[i] = r
        if rails and todo:
            raws = []
            for s0 in range(0, len(todo), 32):
                idx = todo[s0:s0 + 32]
                raws += guard_.check.remote([(users[i], responses[i]["text"]) for i in idx])
            for i, raw in zip(todo, raws):
                parsed = parse_guard(raw)
                if parsed and parsed[1]:
                    responses[i]["text"] = SAFE_REFUSAL
                    rails_info[i] = {"output_blocked": True, "categories": parsed[2]}
        raws = []
        for i in range(0, len(plist), 32):
            raws += guard_.check.remote([(users[j], responses[j]["text"]) for j in range(i, min(i + 32, len(plist)))])
        records = []
        for p, r, raw, ri in zip(plist, responses, raws, rails_info):
            g = Generation(probe_id=p.id, system=system, response=r["text"], latency_s=r["latency_s"],
                           prompt_tokens=r["prompt_tokens"], completion_tokens=r["completion_tokens"], rails=ri)
            records.append(Record(p, g, verdict_from_guard(p, g, raw)))
        write_records(out_dir / f"{system}.jsonl", records)
        VOL.commit()
        sm = summarize(records)
        return f"{system}: ASR overall {sm.asr_overall.as_pct()}, over-refusal {sm.over_refusal.as_pct()}, canary leak {sm.canary_leak.as_pct()}"
    raise ValueError(stage)


@app.local_entrypoint()
def job(stage: str = "incident", system: str = "base", adapter: str = "", harden: bool = False, guard: str = "",
        judges: str = "nemotron35,sgv3", n: int = 200, max_injection: int = 72, probes: str = "results/probes.jsonl"):
    """Detached job runner. Example: modal run --detach modal_app/app.py::job --stage incident --system base"""
    pj = Path(probes).read_text() if (stage == "breadth" and Path(probes).exists()) else ""
    call = _job.spawn(stage, system, adapter, harden, guard, judges, n, max_injection, pj)
    print(f"spawned {stage}/{system}: call id {call.object_id}; results land in volume {APP}-vol under results/")


# --------------------------------------------------------------------------------------- single-container stages
#
# One GPU container loads the target and the judge in-process and runs a whole stage, writing to the volume.
# No cross-function calls, nothing depends on the client staying alive:
#   modal run --detach modal_app/app.py::stage --name incident --system base
#   modal run --detach modal_app/app.py::stage --name bakeoff
#   modal run --detach modal_app/app.py::stage --name breadth --system base --probes results/probes.jsonl


class _LocalLLM:
    """Thread-safe wrapper over an in-process vLLM engine with the harness backend interface."""

    def __init__(self, llm, name: str, lora=None, max_tokens: int = 400, chat_kwargs: dict | None = None):
        import threading

        self.llm, self.name, self.lora, self.max_tokens, self.chat_kwargs = llm, name, lora, max_tokens, chat_kwargs
        self._lock = threading.Lock()

    def chat_many(self, msgs: list[list[dict]], max_tokens: int | None = None) -> list[str]:
        from vllm import SamplingParams

        sp = SamplingParams(temperature=0.0, max_tokens=max_tokens or self.max_tokens)
        kw = {"chat_template_kwargs": self.chat_kwargs} if self.chat_kwargs else {}
        with self._lock:
            outs = self.llm.chat(msgs, sp, lora_request=self.lora, use_tqdm=False, **kw)
        return [o.outputs[0].text for o in outs]

    def chat_messages(self, messages: list[dict]):
        return self.chat_many([messages])[0], 0, 0

    def chat(self, system: str, user: str):
        return self.chat_messages([{"role": "system", "content": system}, {"role": "user", "content": user}])


@app.function(gpu="A100-40GB", volumes={VOL_PATH: VOL}, secrets=secrets, timeout=3 * 60 * 60)
def _stage(name: str, system: str, adapter: str, harden: bool, guard: str, judge: str, n: int,
           max_injection: int, probes_jsonl: str, heldout: bool = False) -> str:
    import json as _json
    from vllm import LLM

    sys.path.insert(0, "/root")
    from nmr.judge import JUDGES, guard_prompt, parse_guard, verdict_from_guard

    out_dir = Path(f"{VOL_PATH}/results")
    out_dir.mkdir(parents=True, exist_ok=True)

    def load_judge(key: str, util: float = 0.85):
        spec = JUDGES[key]
        llm = LLM(model=spec["model"], dtype="bfloat16", max_model_len=8192, gpu_memory_utilization=util,
                  enforce_eager=True)
        style = spec["style"]
        kw = None if style == "aegis_json" else {"request_categories": "/categories",
                                                  "enable_thinking": bool(spec.get("thinking"))}
        return _LocalLLM(llm, key, max_tokens=120, chat_kwargs=kw), style

    def judge_raw(j, style, pairs):
        if style == "aegis_json":
            msgs = [[{"role": "user", "content": guard_prompt(u, r)}] for u, r in pairs]
        else:
            msgs = [[{"role": "user", "content": u}] + ([{"role": "assistant", "content": r}] if r else []) for u, r in pairs]
        return [t.split("</think>")[-1] for t in j.chat_many(msgs, max_tokens=120)]

    if name == "bakeoff":
        from nmr.calibrate import Calibration, load_labelled

        triples = load_labelled(n=n)
        rows = []
        for key in [k.strip() for k in judge.split(",") if k.strip()]:
            j, style = load_judge(key)
            raws = []
            for i in range(0, len(triples), 64):
                raws += judge_raw(j, style, [(p.prompt, g.response) for p, g, _ in triples[i:i + 64]])
            tp = fp = tn = fn = 0
            unparsed = 0
            for (p, g, truth), raw in zip(triples, raws):
                parsed = parse_guard(raw)          # the judge's own verdict on the response, nothing layered on top
                if parsed is None:
                    unparsed += 1
                pred = bool(parsed and parsed[1])
                tp += pred and truth; fp += pred and not truth; tn += (not pred) and (not truth); fn += (not pred) and truth
            rows.append(Calibration(judge=key, n=len(triples), tp=tp, fp=fp, tn=tn, fn=fn))
            print(rows[-1].markdown(), f"unparsed={unparsed}")
            del j.llm, j
            import gc, torch
            gc.collect(); torch.cuda.empty_cache()
        md = "## Judge bake-off (Aegis 2.0 test, human response labels)\n\n" + rows[0].markdown()
        for r in rows[1:]:
            md += r.markdown().splitlines()[-1] + "\n"
        (out_dir / "calibration.md").write_text(md)
        VOL.commit()
        return md

    # target model (+ optional LoRA) for the other stages
    kw = dict(model=TARGET_MODEL, dtype="bfloat16", max_model_len=4096, gpu_memory_utilization=0.55, enforce_eager=True)
    lora = None
    if adapter:
        from vllm.lora.request import LoRARequest

        kw.update(enable_lora=True, max_lora_rank=64)
        lora = LoRARequest("safety", 1, f"{VOL_PATH}/adapters/{adapter}")
    target = _LocalLLM(LLM(**kw), f"modal:{TARGET_MODEL}" + (f"+{adapter}" if adapter else ""), lora=lora)

    if name == "incident":
        from incident.llm import LLMPolicy
        from incident.metrics import summarize_incident
        from incident.runner import run_scenarios
        from incident.scenarios import build_scenarios

        target.max_tokens = 200
        eps = run_scenarios(lambda: LLMPolicy(target, hardened=harden),
                            build_scenarios(max_injection=max_injection, heldout=heldout),
                            system_name=system, guard=(guard or False), out_path=out_dir / f"inc_{system}.jsonl", workers=1)
        VOL.commit()
        s = summarize_incident(eps)
        msg = (f"{system}: attack success {s.attack_success.as_pct()}, unsafe executed {s.unsafe_executed.as_pct()}, "
               f"blocked {s.blocked.as_pct()}, MTTR x{s.mttr_ratio:.2f}, false positives {s.false_positive.as_pct()}")
        (out_dir / f"inc_{system}.txt").write_text(msg)
        VOL.commit()
        return msg

    if name == "breadth":
        from nmr.backends import DEFAULT_SYSTEM
        from nmr.metrics import summarize
        from nmr.rails import HARDENING, SAFE_REFUSAL
        from nmr.types import Generation, Probe, Record, write_records

        j, style = load_judge((judge or DEFAULT_JUDGE_KEY).split(",")[0], util=0.38)   # beside the target (0.55)
        plist = [Probe(**_json.loads(l)) for l in probes_jsonl.splitlines() if l.strip()]
        rails = system.startswith("rails")
        systems = [(p.meta.get("system") or DEFAULT_SYSTEM) + (HARDENING if rails else "") for p in plist]
        users = [p.prompt for p in plist]
        texts = [None] * len(plist)
        info = [{} for _ in plist]
        todo = list(range(len(plist)))
        if rails:
            raws = judge_raw(j, style, [(u, "") for u in users])
            todo = []
            for i, raw in enumerate(raws):
                parsed = parse_guard(raw)
                if parsed and parsed[0]:
                    texts[i], info[i] = SAFE_REFUSAL, {"input_blocked": True, "categories": parsed[2]}
                else:
                    todo.append(i)
        for s0 in range(0, len(todo), 64):
            idx = todo[s0:s0 + 64]
            outs = target.chat_many([[{"role": "system", "content": systems[i]}, {"role": "user", "content": users[i]}] for i in idx], 512)
            for i, t in zip(idx, outs):
                texts[i] = t
        if rails and todo:
            raws = judge_raw(j, style, [(users[i], texts[i]) for i in todo])
            for i, raw in zip(todo, raws):
                parsed = parse_guard(raw)
                if parsed and parsed[1]:
                    texts[i], info[i] = SAFE_REFUSAL, {"output_blocked": True, "categories": parsed[2]}
        raws = judge_raw(j, style, [(users[i], texts[i]) for i in range(len(plist))])
        records = []
        for p, t, raw, ri in zip(plist, texts, raws, info):
            g = Generation(probe_id=p.id, system=system, response=t, latency_s=0.0, rails=ri)
            records.append(Record(p, g, verdict_from_guard(p, g, raw, judge_name=j.name)))
        write_records(out_dir / f"{system}.jsonl", records)
        VOL.commit()
        sm = summarize(records)
        return f"{system}: ASR overall {sm.asr_overall.as_pct()}, over-refusal {sm.over_refusal.as_pct()}, canary leak {sm.canary_leak.as_pct()}"
    raise ValueError(name)


DEFAULT_JUDGE_KEY = "nemotron35"


@app.local_entrypoint()
def stage(name: str = "incident", system: str = "base", adapter: str = "", harden: bool = False, guard: str = "",
          judge: str = "nemotron35,sgv3", n: int = 200, max_injection: int = 72, probes: str = "results/probes.jsonl",
          heldout: bool = False):
    pj = Path(probes).read_text() if (name == "breadth" and Path(probes).exists()) else ""
    call = _stage.spawn(name, system, adapter, harden, guard, judge, n, max_injection, pj, heldout)
    print(f"spawned stage {name}/{system}: {call.object_id}")
