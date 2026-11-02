"""govern CLI: gate | verify

  govern gate --incident results/inc_lora.jsonl --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 \
              --mitigation lora --mitigation guard --out results/certificate.json
  govern verify results/certificate.json
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
    cert = json.loads(Path(args.certificate).read_text())
    ok = verify_certificate(cert)
    print(f"{'VALID' if ok else 'INVALID'}: {cert['model']} {cert['verdict']} issued {cert['issued_at']} expires {cert['expires_at']}")
    raise SystemExit(0 if ok else 2)


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
    v = sub.add_parser("verify")
    v.add_argument("certificate")
    v.set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
