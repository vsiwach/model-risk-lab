"""Mitigation: phrouros enforce as the runtime guardian for the incident agent.

Composes three checks before any action executes:
  1. phrouros `Policy.authorize(agent_id, tool, approval_token)`: identity registered, tool granted,
     state-changing tools need a single-use approval token (deny by default).
  2. phrouros egress allowlist on the escalation channel (only `pagerduty:*`).
  3. the lab's invariant engine (`incident.policy.check_action`), which plays the human approver:
     an approval token is minted only when the invariants pass.

Two entry points share those checks:

  * `filter(sim, decision)`: the in-process guard the lab runner calls (unchanged behaviour).
  * `authorize_record(record, sim_state)`: the step-level verdict the Temporal interceptor calls with an
    `ActionRecord` built from the activity's arguments. It adds the `approval` verdict (a clause marked in
    the policy's `approvals:` list ends in a human decision instead of a deny) and the approval token
    scheme bound to the argument hash (`mint_approval` / `verify_approval`, HMAC with the ledger key).

`phrouros` is imported when installed (pip install -e <path-to-phrouros>); otherwise a small
API-compatible shim (`phrouros_compat.py`, same YAML format and semantics) keeps the lab hermetic.
Provenance: github.com/vsiwach/phrouros, phrouros/enforce/policy.py.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from govern.ledger import canonical_json, ledger_key
from incident.policy import CANARY_RE, Violation, check_action
from incident.sim import PAGER, Simulator

try:  # real phrouros if present
    from phrouros.enforce.policy import Policy  # type: ignore
    PHROUROS = "phrouros"
except Exception:  # pragma: no cover
    from .phrouros_compat import Policy  # type: ignore
    PHROUROS = "compat"

DEFAULT_POLICY = Path(__file__).with_name("phrouros-policy.yaml")
STRICT_POLICY = Path(__file__).with_name("phrouros-policy-strict.yaml")
SIM_ACTIVITY = "sim_act"


@dataclass
class ActionRecord:
    """What the interceptor knows about one activity attempt before it runs."""

    workflow_id: str
    run_id: str
    activity_id: str
    attempt: int
    activity_type: str
    args_hash: str
    args_summary: dict = field(default_factory=dict)   # action, pool_id, channel, message | prompt_sha256, packet_bytes
    step_index: int = 0
    t_start: float = 0.0

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    kind: str                     # allow | deny | approval | egress_deny
    clause: str                   # the policy clause or invariant that decided
    reasons: list[str] = field(default_factory=list)
    approval_id: str | None = None
    host: str | None = None
    decision_ms: float = 0.0
    policy_version: int = 0

    @property
    def allowed(self) -> bool:
        return self.kind == "allow"


def args_hash_of(args: Any) -> str:
    return hashlib.sha256(canonical_json(args).encode("utf-8")).hexdigest()


@dataclass
class PhrourosGuard:
    agent_id: str = "incident-remediator"
    policy_path: Path = DEFAULT_POLICY
    key: str | None = None                          # approval-token key; defaults to the ledger key
    blocked: list = field(default_factory=list)
    ledger: list = field(default_factory=list)      # intent + decision + outcome, in order (in-process path)

    def __post_init__(self) -> None:
        self.policy_path = Path(self.policy_path)
        self.policy = Policy.from_yaml(self.policy_path)
        raw = yaml.safe_load(self.policy_path.read_text()) or {}
        self.policy_version = int(raw.get("version", 1))
        self.policy_sha256 = hashlib.sha256(self.policy_path.read_bytes()).hexdigest()
        inv = raw.get("invariants") or {}
        self.probes_to_reinstate = int(inv.get("probes_to_reinstate", 2))
        self.approval_clauses: list[dict] = list(raw.get("approvals") or [])
        self.key = ledger_key(self.key)

    # ---- in-process path (unchanged) --------------------------------------------------------------

    def filter(self, sim: Simulator, d: dict) -> tuple[dict, list[Violation]]:
        tool = d.get("action", "wait")
        invariants = check_action(sim, d, probes_to_reinstate=self.probes_to_reinstate)
        token = None
        if tool in self.policy.state_changing_tools and not invariants:
            token = self.policy.mint_approval(approver="invariant-engine", agent_id=self.agent_id, tool=tool)
        decision = self.policy.authorize(self.agent_id, tool, approval_token=token)
        egress_ok = True
        if tool == "escalate":
            egress_ok = self.policy.egress_allowed(str(d.get("channel", "")))
        reasons = [v.detail for v in invariants]
        if not decision.allowed:
            reasons.append(f"{decision.code}: {decision.detail}")
        if not egress_ok:
            reasons.append(f"egress denied for channel {d.get('channel')!r}")
        entry = {"tick": sim.tick, "agent": self.agent_id, "intent": {k: v for k, v in d.items() if not k.startswith("_")},
                 "decision": "deny" if reasons else "allow", "reasons": reasons}
        self.ledger.append(entry)
        if reasons:
            self.blocked.append(entry)
            return ({"action": "wait", "pool_id": d.get("pool_id"),
                     "rationale": "blocked by phrouros policy: " + "; ".join(reasons)},
                    invariants or [Violation("unsafe_action", "; ".join(reasons))])
        return d, []

    # ---- step-level path (Temporal interceptor, replay) --------------------------------------------

    def _approval_clause(self, tool: str, condition: str) -> str | None:
        for c in self.approval_clauses:
            if c.get("tool") == tool and c.get("when") == condition:
                return str(c.get("clause", f"{tool}.{condition}"))
        return None

    def approval_id_for(self, record: ActionRecord) -> str:
        raw = "|".join([record.workflow_id, record.activity_type, record.args_hash, str(self.policy_version)])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def authorize_record(self, record: ActionRecord, sim_state: dict | None, approval_token: str | None = None) -> Verdict:
        """One verdict per activity attempt: allow | deny | approval | egress_deny. Pure function of the
        record, the simulator snapshot and the token; the caller writes the ledger."""
        t0 = time.perf_counter()
        v = self._authorize(record, sim_state, approval_token)
        v.decision_ms = (time.perf_counter() - t0) * 1000.0
        v.policy_version = self.policy_version
        return v

    def _authorize(self, record: ActionRecord, sim_state: dict | None, approval_token: str | None) -> Verdict:
        summary = record.args_summary or {}
        if record.activity_type != SIM_ACTIVITY:
            decision = self.policy.authorize(self.agent_id, record.activity_type)
            if not decision.allowed:
                return Verdict("deny", decision.code, [decision.detail])
            return Verdict("allow", "tool_grant")
        tool = str(summary.get("action") or "wait")
        d = {k: summary[k] for k in ("action", "pool_id", "channel", "message") if k in summary}
        d.setdefault("action", tool)
        if tool == "escalate":
            text = " ".join(str(d.get(k, "")) for k in ("message", "channel"))
            if CANARY_RE.search(text):
                return Verdict("deny", "exfiltration", ["admin token in an outbound field"])
            channel = str(d.get("channel", PAGER))
            if not self.policy.egress_allowed(channel):
                clause = self._approval_clause("escalate", "channel_not_allowlisted")
                if clause is None:
                    return Verdict("egress_deny", "egress_allowlist", [f"egress denied for channel {channel!r}"], host=channel)
                approval_id = self.approval_id_for(record)
                if approval_token and self.verify_approval(approval_token, approval_id, record.args_hash):
                    return Verdict("allow", clause, ["approved"], approval_id=approval_id, host=channel)
                if approval_token:
                    return Verdict("deny", clause, ["approval token does not match this approval id and argument hash"],
                                   approval_id=approval_id, host=channel)
                return Verdict("approval", clause, [f"escalation to {channel!r} needs a human decision"],
                               approval_id=approval_id, host=channel)
        if sim_state is None:
            return Verdict("deny", "no_state", ["no simulator state to evaluate the invariants against"])
        from incident.temporal_worker import simulator_from_state

        sim = simulator_from_state(sim_state)
        invariants = check_action(sim, d, probes_to_reinstate=self.probes_to_reinstate)
        if invariants:
            return Verdict("deny", "invariant:" + invariants[0].rule, [x.detail for x in invariants])
        token = None
        if tool in self.policy.state_changing_tools:
            token = self.policy.mint_approval(approver="invariant-engine", agent_id=self.agent_id, tool=tool)
        decision = self.policy.authorize(self.agent_id, tool, approval_token=token)
        if not decision.allowed:
            return Verdict("deny", decision.code, [decision.detail])
        return Verdict("allow", "tool_grant")

    # ---- approval tokens -----------------------------------------------------------------------------

    def mint_approval(self, approval_id: str, args_hash: str) -> str:
        """token = HMAC-SHA256(key, approval_id + args_hash): bound to the exact arguments approved."""
        return hmac.new(self.key.encode("utf-8"), (approval_id + args_hash).encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_approval(self, token: str, approval_id: str, args_hash: str) -> bool:
        return hmac.compare_digest(self.mint_approval(approval_id, args_hash), str(token))
