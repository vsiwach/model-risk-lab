"""Command line interface.

  nmr probes  --out results/probes.jsonl [--n 40] [--offline]
  nmr run     --probes results/probes.jsonl --system base  --backend openai --model nvidia/llama-3.1-nemotron-nano-8b-v1 \
              --base-url https://integrate.api.nvidia.com/v1 --judge guard --out results/base.jsonl
  nmr run     ... --system rails --rails                         # same backend wrapped in guardrails
  nmr run     ... --system lora  --backend hf --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --adapter lora/out
  nmr report  results/base.jsonl results/rails.jsonl results/lora.jsonl --out results/report.md
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .metrics import summarize
from .probes import build_probe_set
from .report import chart, markdown
from .runner import run
from .types import read_probes, read_records, write_probes


def _backend(args):
    from .backends import HFLocal, Mock, OpenAICompatible

    if args.backend == "mock":
        return Mock(compliance=args.mock_compliance)
    if args.backend == "openai":
        return OpenAICompatible(model=args.model, base_url=args.base_url, max_tokens=args.max_tokens)
    if args.backend == "hf":
        return HFLocal(model_id=args.model, adapter=args.adapter, max_new_tokens=args.max_tokens)
    raise SystemExit(f"unknown backend {args.backend}")


def _guard(args):
    """The guard model behind the rails: same registry as the judges (default: the --rails-guard key)."""
    from .judge import make_judge
    from .rails import MockGuard

    key = getattr(args, "rails_guard", None) or args.judge
    if args.backend == "mock" or key == "heuristic":
        return MockGuard()
    return make_judge(key, base_url=args.guard_base_url or args.base_url)


def _judge(args):
    from .judge import make_judge

    key = args.judge
    if key == "guard":          # old spelling
        key = "sgv3"
    if key == "rubric":
        key = f"rubric:{args.judge_model or args.model}"
    return make_judge(key, base_url=args.guard_base_url or args.base_url)


def cmd_probes(args) -> None:
    probes = build_probe_set(n_per_category=args.n, seed=args.seed, offline=args.offline)
    n = write_probes(Path(args.out), probes)
    by = {}
    for p in probes:
        by[p.category] = by.get(p.category, 0) + 1
    print(f"wrote {n} probes to {args.out}: {by}")


def cmd_run(args) -> None:
    probes = read_probes(Path(args.probes))
    if args.limit:
        probes = probes[: args.limit]
    backend = _backend(args)
    if args.rails:
        from .rails import GuardedBackend

        backend = GuardedBackend(inner=backend, guard=_guard(args))
    judge = _judge(args)
    recs = run(backend, judge, probes, system_name=args.system, out_path=Path(args.out), workers=args.workers)
    s = summarize(recs)
    print(f"{args.system}: ASR overall {s.asr_overall.as_pct()}, over-refusal {s.over_refusal.as_pct()}, "
          f"canary leak {s.canary_leak.as_pct()}, p50 {s.latency_p50:.2f}s")


def cmd_report(args) -> None:
    sums = [summarize(read_records(Path(p))) for p in args.results]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    png = chart(sums, out.with_suffix(".png"))
    md = markdown(sums, title=args.title) + f"\n![chart]({png.name})\n"
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"wrote {out} and {png}")


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="nmr", description="Nemotron model-risk evaluation harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probes", help="build the probe set")
    p.add_argument("--out", default="results/probes.jsonl")
    p.add_argument("--n", type=int, default=40, help="probes per category from each sampled source")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--offline", action="store_true", help="bundled probes only, no downloads")
    p.set_defaults(fn=cmd_probes)

    r = sub.add_parser("run", help="generate and judge")
    r.add_argument("--probes", default="results/probes.jsonl")
    r.add_argument("--system", required=True, help="label: base | rails | lora | ...")
    r.add_argument("--backend", choices=["openai", "hf", "mock"], default="openai")
    r.add_argument("--model", default="nvidia/llama-3.1-nemotron-nano-8b-v1")
    r.add_argument("--base-url", default="https://integrate.api.nvidia.com/v1")
    r.add_argument("--adapter", default=None, help="PEFT adapter dir (hf backend)")
    r.add_argument("--max-tokens", type=int, default=512)
    r.add_argument("--rails", action="store_true", help="wrap the backend in content-safety rails")
    r.add_argument("--judge", default="nemotron35",
                   help="judge key: nemotron35 (default) | nemotron3 | csr4b | sgv3 | nemoguard | llamaguard4 | heuristic | rubric")
    r.add_argument("--rails-guard", default=None, help="guard model behind --rails (judge key); defaults to --judge")
    r.add_argument("--guard-base-url", default=None, help="endpoint for judge/guard models; defaults to --base-url")
    r.add_argument("--judge-model", default=None, help="rubric judge model")
    r.add_argument("--mock-compliance", type=float, default=0.6)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--limit", type=int, default=0)
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("report", help="compare result files")
    c.add_argument("results", nargs="+")
    c.add_argument("--out", default="results/report.md")
    c.add_argument("--title", default="Nemotron model risk evaluation")
    c.set_defaults(fn=cmd_report)

    _add_agentic(sub)
    _add_calibrate(sub)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main(sys.argv[1:])


def cmd_agentic(args) -> None:
    """Run the agentic cybersecurity vertical for one system."""
    from pathlib import Path as _P

    from .agentic import build_scenarios, run_agentic
    from .agentic.metrics import summarize_agentic

    scenarios = build_scenarios(seed=args.seed, max_indirect=args.max_indirect)
    if args.backend == "mock":
        from .agentic.mock import MockAgent

        backend = MockAgent(compliance=args.mock_compliance)
    else:
        backend = _backend(args)
    pj = None
    if args.policy_judge:
        from .agentic.policy_judge import PolicyJudge

        pj = PolicyJudge(key=args.policy_judge, base_url=args.guard_base_url or args.base_url)
    eps = run_agentic(backend, scenarios, system_name=args.system, hardened=args.harden, guard=args.guard,
                      out_path=_P(args.out), workers=args.workers, policy_judge=pj)
    s = summarize_agentic(eps)
    print(f"{args.system}: attack success {s.attack_success.as_pct()}, unauthorized {s.unauthorized_action.as_pct()}, "
          f"exfil {s.exfiltration.as_pct()}, blocked {s.attempted_blocked.as_pct()}, benign task success {s.task_success.as_pct()}")


def cmd_agentic_report(args) -> None:
    from pathlib import Path as _P

    from .agentic.metrics import markdown_agentic, summarize_agentic
    from .agentic.runner import read_episodes

    sums = [summarize_agentic(read_episodes(_P(p))) for p in args.results]
    md = markdown_agentic(sums)
    out = _P(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)


def _add_agentic(sub) -> None:
    a = sub.add_parser("agentic", help="agentic cybersecurity vertical: run one system")
    a.add_argument("--system", required=True, help="label: base | hardened | guard | hardened+guard | lora")
    a.add_argument("--backend", choices=["openai", "hf", "mock"], default="openai")
    a.add_argument("--model", default="nvidia/llama-3.1-nemotron-nano-8b-v1")
    a.add_argument("--base-url", default="https://integrate.api.nvidia.com/v1")
    a.add_argument("--adapter", default=None)
    a.add_argument("--max-tokens", type=int, default=400)
    a.add_argument("--harden", action="store_true", help="prompt hardening + <data> wrapping of tool results")
    a.add_argument("--guard", action="store_true", help="ToolPolicyGuard blocks policy-violating tool calls")
    a.add_argument("--policy-judge", default=None, help="judge key for the model-based second opinion, e.g. nemotron35")
    a.add_argument("--guard-base-url", default=None)
    a.add_argument("--mock-compliance", type=float, default=0.5)
    a.add_argument("--seed", type=int, default=7)
    a.add_argument("--max-indirect", type=int, default=60)
    a.add_argument("--workers", type=int, default=4)
    a.add_argument("--out", required=True)
    a.set_defaults(fn=cmd_agentic)

    r = sub.add_parser("agentic-report", help="compare agentic result files")
    r.add_argument("results", nargs="+")
    r.add_argument("--out", default="results/agentic_report.md")
    r.set_defaults(fn=cmd_agentic_report)


def cmd_calibrate(args) -> None:
    from pathlib import Path as _P

    from .calibrate import calibrate, load_labelled

    from .judge import make_judge

    triples = load_labelled(n=args.n, seed=args.seed)
    keys = [k.strip() for k in args.judges.split(",") if k.strip()]
    if "heuristic" not in keys:
        keys.append("heuristic")
    rows = []
    for key in keys:
        try:
            judge = make_judge(key, base_url=args.guard_base_url or args.base_url)
            rows.append(calibrate(judge, triples, workers=args.workers))
        except Exception as e:  # a judge that is not served on this endpoint
            print(f"{key}: skipped ({e})")
    md = "## Judge bake-off (Aegis 2.0 test, human response labels)\n\n" + rows[0].markdown()
    for r in rows[1:]:
        md += r.markdown().splitlines()[-1] + "\n"
    md += ("\nPick the judge with the best F1 on *your* policy, then keep it fixed across base, rails and lora "
           "so the comparison is apples to apples. A judge's FP rate is the floor on measurable over-refusal; "
           "its FN rate is the ceiling on measurable attack success.\n")
    print(md)
    if args.out:
        _P(args.out).parent.mkdir(parents=True, exist_ok=True)
        _P(args.out).write_text(md, encoding="utf-8")


def _add_calibrate(sub) -> None:
    k = sub.add_parser("calibrate", help="score the judge against human labels before trusting it")
    k.add_argument("--n", type=int, default=300)
    k.add_argument("--seed", type=int, default=7)
    k.add_argument("--judges", default="nemotron35,sgv3,nemoguard",
                   help="comma-separated judge keys to bake off (heuristic is always added)")
    k.add_argument("--guard-base-url", default=None)
    k.add_argument("--base-url", default="https://integrate.api.nvidia.com/v1")
    k.add_argument("--model", default="nvidia/llama-3.1-nemotron-nano-8b-v1")
    k.add_argument("--judge-model", default=None)
    k.add_argument("--workers", type=int, default=4)
    k.add_argument("--out", default="results/calibration.md")
    k.set_defaults(fn=cmd_calibrate)
