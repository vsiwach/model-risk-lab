from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


@dataclass
class Check:
    name: str
    value: float
    threshold: float
    op: str          # "<=" or ">="
    passed: bool

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"{mark}  {self.name}: {self.value:.3f} {self.op} {self.threshold:.3f}"


@dataclass
class GateResult:
    policy: str
    system: str
    passed: bool
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def markdown(self) -> str:
        head = f"## Release gate: {self.system} against policy '{self.policy}': {'PASS' if self.passed else 'FAIL'}\n\n"
        body = "```\n" + "\n".join(c.line() for c in self.checks) + "\n```\n"
        return head + body + ("\n".join(f"- {n}" for n in self.notes) + "\n" if self.notes else "")


def _chk(name, value, threshold, op) -> Check:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return Check(name, float("nan"), threshold, op, False)
    ok = value <= threshold if op == "<=" else value >= threshold
    return Check(name, float(value), float(threshold), op, bool(ok))


def evaluate_gate(policy_path: Path, incident_results: Path | None = None, breadth_results: Path | None = None,
                  calibration_md: Path | None = None, system: str = "candidate") -> GateResult:
    pol = yaml.safe_load(Path(policy_path).read_text())
    res = GateResult(policy=pol["name"], system=system, passed=True)
    if incident_results:
        from incident.metrics import summarize_incident
        from incident.runner import read_episodes

        s = summarize_incident(read_episodes(incident_results))
        t = pol["incident"]
        res.checks += [
            _chk("incident.attack_success", s.attack_success.rate, t["attack_success_max"], "<="),
            _chk("incident.exfiltration", s.exfiltration.rate, t["exfiltration_max"], "<="),
            _chk("incident.service_down", s.service_down.rate, t["service_down_max"], "<="),
            _chk("incident.mttr_ratio", s.mttr_ratio, t["mttr_ratio_max"], "<="),
            _chk("incident.false_positive", s.false_positive.rate, t["false_positive_max"], "<="),
            _chk("incident.resolved", s.resolved.rate, t["resolved_min"], ">="),
        ]
    if breadth_results:
        from nmr.metrics import summarize
        from nmr.types import read_records

        b = summarize(read_records(breadth_results))
        t = pol["breadth"]
        res.checks += [_chk("breadth.asr_overall", b.asr_overall.rate, t["asr_overall_max"], "<="),
                       _chk("breadth.over_refusal", b.over_refusal.rate, t["over_refusal_max"], "<=")]
    if calibration_md:
        f1 = _f1_from_markdown(Path(calibration_md).read_text())
        res.checks.append(_chk("judge.f1", f1, pol["judge"]["f1_min"], ">="))
    if not res.checks:
        res.notes.append("no results supplied; nothing to gate")
        res.passed = False
    res.passed = res.passed and all(c.passed for c in res.checks)
    return res


def _f1_from_markdown(md: str) -> float | None:
    for line in md.splitlines():
        if line.startswith("|") and "%" in line and not line.startswith("| Judge"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            try:
                return float(cells[5].rstrip("%")) / 100.0
            except (IndexError, ValueError):
                continue
    return None


def sign_certificate(gate: GateResult, policy_path: Path, model: str, mitigations: list[str],
                     key: str | None = None, valid_days: int | None = None) -> dict:
    pol = yaml.safe_load(Path(policy_path).read_text())
    key = key or os.environ.get("MRL_CERT_KEY", "dev-key-change-me")
    days = valid_days or int(pol.get("certificate", {}).get("valid_days", 90))
    now = datetime.now(timezone.utc)
    body = {
        "issuer": pol.get("certificate", {}).get("issuer", "model-risk-lab"),
        "policy": pol["name"], "policy_version": pol.get("version", 1),
        "policy_sha256": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest(),
        "model": model, "mitigations": mitigations, "system": gate.system,
        "verdict": "PASS" if gate.passed else "FAIL",
        "checks": [asdict(c) for c in gate.checks],
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(days=days)).isoformat(timespec="seconds"),
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    sig = base64.b64encode(hmac.new(key.encode(), payload, hashlib.sha256).digest()).decode()
    return {**body, "signature": sig, "algorithm": "HMAC-SHA256"}


def verify_certificate(cert: dict, key: str | None = None) -> bool:
    key = key or os.environ.get("MRL_CERT_KEY", "dev-key-change-me")
    body = {k: v for k, v in cert.items() if k not in ("signature", "algorithm")}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expected = base64.b64encode(hmac.new(key.encode(), payload, hashlib.sha256).digest()).decode()
    not_expired = datetime.fromisoformat(cert["expires_at"]) > datetime.now(timezone.utc)
    return hmac.compare_digest(expected, cert.get("signature", "")) and not_expired
