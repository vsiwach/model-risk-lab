"""govern CLI: gate | verify | ledger

  govern gate --incident results/inc_lora.jsonl --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 \
              --mitigation lora --mitigation guard --out results/certificate.json
  govern verify results/certificate.json
  govern verify --ledger results/temporal/ledger.jsonl          # walk the signed chain; exit 1 if broken
  govern ledger export --ledger results/temporal/ledger.jsonl --workflow-id <id> --out results/temporal/export/<id>
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
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
