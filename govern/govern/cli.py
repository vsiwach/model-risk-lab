"""govern CLI: gate | verify | ledger

  govern gate --incident results/inc_lora.jsonl --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 \
              --mitigation lora --mitigation guard --out results/certificate.json
  govern verify results/certificate.json
  govern verify --ledger results/temporal/ledger.jsonl          # walk the signed chain; exit 1 if broken
  govern ledger export --ledger results/temporal/ledger.jsonl --workflow-id <id> --out results/temporal/export/<id>
  govern ledger stats  --ledger results/temporal/ledger.jsonl    # verdict counts, decision-time percentiles
  govern ledger check  --ledger results/temporal/ledger.jsonl    # action records vs activity tasks in history
"""

from __future__ import annotations

import argparse
import json
from importlib import resources
from pathlib import Path

from .gate import evaluate_gate, sign_certificate, verify_certificate


def _default_policy() -> Path:
    return Path(str(resources.files("govern").joinpath("risk-policy.yaml")))


def cmd_gate(args) -> None:
    policy = Path(args.policy) if args.policy else _default_policy()
    g = evaluate_gate(policy, incident_results=Path(args.incident) if args.incident else None,
                      breadth_results=Path(args.breadth) if args.breadth else None,
                      calibration_md=Path(args.calibration) if args.calibration else None, system=args.system)
    print(g.markdown())
    cert = sign_certificate(g, policy, model=args.model, mitigations=args.mitigation or [])
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(cert, indent=2))
    Path(args.out).with_suffix(".md").write_text(g.markdown())
    print(f"certificate ({cert['verdict']}) written to {args.out}, expires {cert['expires_at']}")
    raise SystemExit(0 if g.passed else 2)


def cmd_verify(args) -> None:
    if args.ledger:
        from .ledger import Ledger, verify

        ok, bad = verify(Path(args.ledger), key=args.key)
        n = sum(1 for _ in Ledger.iter_lines(args.ledger))
        if ok:
            print(f"VALID: {args.ledger}, {n} records, chain intact")
            raise SystemExit(0)
        print(f"INVALID: {args.ledger}, chain breaks at line {bad} of {n}")
        raise SystemExit(1)
    if not args.certificate:
        raise SystemExit("govern verify: give a certificate path or --ledger")
    cert = json.loads(Path(args.certificate).read_text())
    ok = verify_certificate(cert)
    print(f"{'VALID' if ok else 'INVALID'}: {cert['model']} {cert['verdict']} issued {cert['issued_at']} expires {cert['expires_at']}")
    raise SystemExit(0 if ok else 2)


def cmd_ledger_export(args) -> None:
    from .ledger import export_bundle

    out = Path(args.out) if args.out else Path(args.ledger).parent / "export" / args.workflow_id
    m = export_bundle(Path(args.ledger), args.workflow_id, out, key=args.key, blob_dir=args.blob_dir)
    print(f"exported {m['records']} records for {args.workflow_id} to {out} "
          f"(chain {'verified' if m['chain_verified'] else 'BROKEN'}, {m['chain_lines']} proof hashes, {len(m['blobs'])} blobs)")
    raise SystemExit(0 if m["chain_verified"] else 1)


def cmd_ledger_stats(args) -> None:
    """Verdict counts and guard decision-time percentiles from the action records."""
    from .ledger import Ledger

    recs = Ledger.read(args.ledger)
    actions = [r["body"] for r in recs if r["kind"] == "action"]
    kinds = {}
    for r in recs:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    verdicts = {}
    for b in actions:
        verdicts[b["verdict"]] = verdicts.get(b["verdict"], 0) + 1
    ms = sorted(float(b.get("decision_ms", 0.0)) for b in actions)

    def pct(q: float) -> float:
        return ms[min(len(ms) - 1, int(q * len(ms)))] if ms else float("nan")

    print(f"records: {len(recs)} " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print("action verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())))
    print(f"guard decision_ms over {len(ms)} action records: p50 {pct(0.5):.3f}, p95 {pct(0.95):.3f}, "
          f"p99 {pct(0.99):.3f}, max {ms[-1] if ms else float('nan'):.3f}")
    wfs = {b["workflow_id"] for b in actions}
    print(f"workflows: {len(wfs)}")


def cmd_ledger_check(args) -> None:
    """Ledger completeness: kind=action records per workflow against activity tasks scheduled in Temporal history."""
    import asyncio

    from .ledger import Ledger, verify

    async def main() -> int:
        from temporalio.api.enums.v1 import EventType
        from temporalio.client import Client

        actions = [r["body"] for r in Ledger.read(args.ledger, kind="action")]
        by_wf: dict[str, int] = {}
        for b in actions:
            by_wf[b["workflow_id"]] = by_wf.get(b["workflow_id"], 0) + 1
        client = await Client.connect(args.address)
        total_hist, mismatched = 0, []
        for wf_id, n in sorted(by_wf.items()):
            h = 0
            async for e in client.get_workflow_handle(wf_id).fetch_history_events():
                if e.event_type == EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED:
                    h += 1
            total_hist += h
            if h != n:
                mismatched.append((wf_id, n, h))
        ok, bad = verify(args.ledger, key=args.key)
        share = (100.0 * len(actions) / total_hist) if total_hist else float("nan")
        print(f"workflows in ledger: {len(by_wf)}; action records: {len(actions)}; activity tasks in history: {total_hist}; "
              f"completeness {share:.1f}%; workflows with a mismatch: {len(mismatched)}")
        for wf_id, n, h in mismatched[:10]:
            print(f"  {wf_id}: ledger {n} vs history {h}")
        print(f"chain: {'VALID' if ok else f'INVALID at line {bad}'}")
        return 0 if (ok and not mismatched and total_hist == len(actions)) else 1

    raise SystemExit(asyncio.run(main()))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="govern")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--policy", default=None)
    g.add_argument("--incident", default=None)
    g.add_argument("--breadth", default=None)
    g.add_argument("--calibration", default=None)
    g.add_argument("--system", default="candidate")
    g.add_argument("--model", required=True)
    g.add_argument("--mitigation", action="append")
    g.add_argument("--out", default="results/certificate.json")
    g.set_defaults(fn=cmd_gate)
    v = sub.add_parser("verify", help="verify a certificate, or a signed ledger with --ledger")
    v.add_argument("certificate", nargs="?", default=None)
    v.add_argument("--ledger", default=None)
    v.add_argument("--key", default=None, help="ledger key (default PHROUROS_LEDGER_KEY)")
    v.set_defaults(fn=cmd_verify)
    led = sub.add_parser("ledger", help="signed ledger tools")
    lsub = led.add_subparsers(dest="ledger_cmd", required=True)
    ex = lsub.add_parser("export", help="bundle one workflow's records, chain proof and referenced blobs")
    ex.add_argument("--ledger", default="results/temporal/ledger.jsonl")
    ex.add_argument("--workflow-id", required=True)
    ex.add_argument("--out", default=None)
    ex.add_argument("--blob-dir", default="results/temporal/blobs")
    ex.add_argument("--key", default=None)
    ex.set_defaults(fn=cmd_ledger_export)
    st = lsub.add_parser("stats", help="verdict counts and guard decision-time percentiles")
    st.add_argument("--ledger", default="results/temporal/ledger.jsonl")
    st.set_defaults(fn=cmd_ledger_stats)
    ck = lsub.add_parser("check", help="action records vs activity tasks in Temporal history (needs the server)")
    ck.add_argument("--ledger", default="results/temporal/ledger.jsonl")
    ck.add_argument("--address", default="localhost:7233")
    ck.add_argument("--key", default=None)
    ck.set_defaults(fn=cmd_ledger_check)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
