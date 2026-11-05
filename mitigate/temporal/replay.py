"""Replay a signed ledger through a candidate policy: the verdict diff is the policy change's test suite.

For every `kind=action` record, rebuild the `ActionRecord` and the recorded simulator snapshot, call
`PhrourosGuard.authorize_record` under the candidate policy, and compare with the verdict recorded at run
time. No activity runs; nothing is written.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from govern.ledger import Ledger
from mitigate.phrouros_guard import ActionRecord, PhrourosGuard

RECORD_FIELDS = ("workflow_id", "run_id", "activity_id", "attempt", "activity_type", "args_hash", "args_summary",
                 "step_index", "t_start")


def _normalize(verdict: str) -> str:
    """Collapse the ledger's lifecycle verdicts onto the guard's four kinds."""
    return {"pending": "approval", "allowed_with_approval": "allow", "expired": "approval"}.get(verdict, verdict)


@dataclass
class ReplayDiff:
    ledger: str
    policy: str
    candidate_version: int
    total: int = 0
    pairs: Counter = field(default_factory=Counter)             # (recorded, candidate) -> count
    newly_blocked: int = 0                                      # recorded allow -> candidate deny/egress_deny/approval
    newly_allowed: int = 0                                      # recorded deny/egress_deny/approval -> candidate allow
    by_activity: Counter = field(default_factory=Counter)       # activity label -> number of changed verdicts
    changed: list[dict] = field(default_factory=list)           # first few changed records, for a hand check

    @property
    def unchanged(self) -> int:
        return sum(n for (a, b), n in self.pairs.items() if a == b)


def _label(body: dict) -> str:
    s = body.get("args_summary") or {}
    if body.get("activity_type") == "sim_act":
        return f"sim_act:{s.get('action')}"
    return str(body.get("activity_type"))


def replay_ledger(ledger_path: Path, policy_path: Path, key: str | None = None, keep: int = 10) -> ReplayDiff:
    guard = PhrourosGuard(policy_path=Path(policy_path), key=key)
    diff = ReplayDiff(ledger=str(ledger_path), policy=str(policy_path), candidate_version=guard.policy_version)
    for rec in Ledger.read(ledger_path, kind="action"):
        b = rec["body"]
        recorded = _normalize(str(b.get("verdict")))
        ar = ActionRecord(**{k: b.get(k) for k in RECORD_FIELDS})
        v = guard.authorize_record(ar, b.get("sim_state"))
        candidate = v.kind
        diff.total += 1
        diff.pairs[(recorded, candidate)] += 1
        if recorded != candidate:
            diff.by_activity[_label(b)] += 1
            if recorded == "allow":
                diff.newly_blocked += 1
            elif candidate == "allow":
                diff.newly_allowed += 1
            if len(diff.changed) < keep:
                diff.changed.append({"record_id": rec["record_id"], "workflow_id": b["workflow_id"],
                                     "activity": _label(b), "args": b.get("args_summary"), "recorded": recorded,
                                     "candidate": candidate, "clause": v.clause, "reasons": v.reasons})
    return diff


def render_table(d: ReplayDiff) -> str:
    L = [f"Replay of {d.ledger} under {d.policy} (candidate policy version {d.candidate_version})", "",
         f"{d.total} action records; {d.unchanged} unchanged, {d.newly_blocked} newly blocked, {d.newly_allowed} newly allowed", "",
         "| recorded | candidate | count |", "|---|---|---:|"]
    for (a, b), n in sorted(d.pairs.items(), key=lambda kv: (-kv[1], kv[0])):
        L.append(f"| {a} | {b} | {n} |")
    L += ["", "Most affected activity types:", "", "| activity | changed verdicts |", "|---|---:|"]
    for label, n in d.by_activity.most_common(10):
        L.append(f"| {label} | {n} |")
    if not d.by_activity:
        L.append("| (none) | 0 |")
    if d.changed:
        L += ["", "First changed records:", ""]
        for c in d.changed:
            L.append(f"- {c['workflow_id']} {c['activity']} {c['args']}: {c['recorded']} -> {c['candidate']} ({c['clause']})")
    return "\n".join(L) + "\n"
