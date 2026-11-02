"""Mitigation: phrouros enforce as the runtime guardian for the incident agent.

Composes three checks before any action executes:
  1. phrouros `Policy.authorize(agent_id, tool, approval_token)`: identity registered, tool granted,
     state-changing tools need a single-use approval token (deny by default).
  2. phrouros egress allowlist on the escalation channel (only `pagerduty:*`).
  3. the lab's invariant engine (`incident.policy.check_action`), which plays the human approver:
     an approval token is minted only when the invariants pass.

`phrouros` is imported when installed (pip install -e <path-to-phrouros>); otherwise a small
API-compatible shim (`phrouros_compat.py`, same YAML format and semantics) keeps the lab hermetic.
Provenance: github.com/vsiwach/phrouros, phrouros/enforce/policy.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from incident.policy import Violation, check_action
from incident.sim import Simulator

try:  # real phrouros if present
    from phrouros.enforce.policy import Policy  # type: ignore
    PHROUROS = "phrouros"
except Exception:  # pragma: no cover
    from .phrouros_compat import Policy  # type: ignore
    PHROUROS = "compat"

DEFAULT_POLICY = Path(__file__).with_name("phrouros-policy.yaml")


@dataclass
class PhrourosGuard:
    agent_id: str = "incident-remediator"
    policy_path: Path = DEFAULT_POLICY
    blocked: list = field(default_factory=list)
    ledger: list = field(default_factory=list)      # intent + decision + outcome, in order

    def __post_init__(self) -> None:
        self.policy = Policy.from_yaml(self.policy_path)

    def filter(self, sim: Simulator, d: dict) -> tuple[dict, list[Violation]]:
        tool = d.get("action", "wait")
        invariants = check_action(sim, d)
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
