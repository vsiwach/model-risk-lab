"""incident CLI: run | report | sft

  incident run    --system rules                                   # the MTTR baseline
  incident run    --system base --backend mock                     # mock LLM policy
  incident run    --system guard --backend mock --guard            # + deny-by-default guard
  incident run    --system base --backend openai --model nvidia/llama-3.1-nemotron-nano-8b-v1
  incident run    --system lora --backend hf --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --adapter mitigate/out/<name>
  incident report results/inc_rules.jsonl results/inc_base.jsonl results/inc_guard.jsonl
  incident sft    --out mitigate/incident_sft.jsonl                 # oracle-labelled episodes for the LoRA
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path


def _backend(args):
    from nmr.backends import HFLocal, OpenAICompatible

    if args.backend == "openai":
        return OpenAICompatible(model=args.model, base_url=args.base_url, max_tokens=args.max_tokens)
    if args.backend == "hf":
        return HFLocal(model_id=args.model, adapter=args.adapter, max_new_tokens=args.max_tokens)
    raise SystemExit(f"unknown backend {args.backend}")


def cmd_run(args) -> None:
    from .metrics import summarize_incident
    from .runner import run_scenarios
    from .scenarios import build_scenarios

    scenarios = build_scenarios(seed=args.seed, max_injection=args.max_injection)
    if args.limit:
        scenarios = scenarios[: args.limit]
    if args.system == "rules" or args.backend == "rules":
        from .rules import RulePolicy

        factory = lambda: RulePolicy()  # noqa: E731
    elif args.backend == "mock":
        from .mock import MockBackend, MockLLMPolicy

        factory = lambda: MockLLMPolicy(MockBackend(compliance=args.mock_compliance), hardened=args.harden)  # noqa: E731
    else:
        from .llm import LLMPolicy

        be = _backend(args)
        factory = lambda: LLMPolicy(be, hardened=args.harden)  # noqa: E731
    eps = run_scenarios(factory, scenarios, system_name=args.system, guard=args.guard, out_path=Path(args.out),
                        workers=args.workers)
    s = summarize_incident(eps)
    print(f"{args.system}: attack success {s.attack_success.as_pct()}, unsafe executed {s.unsafe_executed.as_pct()}, "
          f"blocked {s.blocked.as_pct()}, MTTR x{s.mttr_ratio:.2f}, false positives {s.false_positive.as_pct()}")


def cmd_report(args) -> None:
    from .metrics import markdown_incident, summarize_incident
    from .runner import read_episodes

    sums = [summarize_incident(read_episodes(Path(p))) for p in args.results]
    md = markdown_incident(sums)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    print(md)


def cmd_sft(args) -> None:
    from .sft import build_sft

    n = build_sft(Path(args.out), seed=args.seed, max_injection=args.max_injection, hardened=args.harden)
    print(f"wrote {n} SFT rows to {args.out}")


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="incident", description="incident-remediation agent target")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--system", required=True)
    r.add_argument("--backend", choices=["rules", "mock", "openai", "hf"], default="mock")
    r.add_argument("--model", default="nvidia/llama-3.1-nemotron-nano-8b-v1")
    r.add_argument("--base-url", default="https://integrate.api.nvidia.com/v1")
    r.add_argument("--adapter", default=None)
    r.add_argument("--max-tokens", type=int, default=200)
    r.add_argument("--harden", action="store_true")
    r.add_argument("--guard", nargs="?", const="invariants", default=False,
                   help="runtime guard: 'invariants' (default when given) or 'phrouros' (deny-by-default policy + approvals + egress)")
    r.add_argument("--mock-compliance", type=float, default=0.5)
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--max-injection", type=int, default=72)
    r.add_argument("--limit", type=int, default=0)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("report")
    c.add_argument("results", nargs="+")
    c.add_argument("--out", default="results/incident_report.md")
    c.set_defaults(fn=cmd_report)

    s = sub.add_parser("sft")
    s.add_argument("--out", default="mitigate/incident_sft.jsonl")
    s.add_argument("--seed", type=int, default=11)
    s.add_argument("--max-injection", type=int, default=96)
    s.add_argument("--harden", action="store_true")
    s.set_defaults(fn=cmd_sft)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
