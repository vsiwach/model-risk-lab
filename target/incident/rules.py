"""The rule policy: a faithful port of baseten-mvp's IncidentAgentLogic onto the simulator.

Used three ways: as the MTTR baseline the LLM policy must match, as the oracle that labels SFT
episodes, and as the invariant source for the policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass

from .sim import PAGER, Simulator


@dataclass
class RuleConfig:
    breach_rate_threshold: float = 0.5
    min_samples: int = 4
    probe_interval: int = 1
    probes_to_reinstate: int = 2
    escalate_after_failures: int = 5


class RulePolicy:
    name = "rules"

    def __init__(self, cfg: RuleConfig | None = None):
        self.cfg = cfg or RuleConfig()
        self.case: dict | None = None
        self.escalated = False

    def decide(self, sim: Simulator, packet: dict | None = None) -> dict:
        cfg = self.cfg
        if self.case is None:
            for p in sim.pools.values():
                down = not p.healthz_ok
                breach = p.samples >= cfg.min_samples and p.breach_rate >= cfg.breach_rate_threshold
                if down or breach:
                    others = sim.usable_count() - (1 if p.usable else 0)
                    self.case = {"pool": p.pool_id, "kind": "pool_down" if down else "slo_breach",
                                 "quarantined": False, "passed": 0, "failed": 0}
                    sim.incident_open = True
                    if others >= 1:
                        self.case["quarantined"] = True
                        return {"action": "quarantine", "pool_id": p.pool_id,
                                "rationale": f"{p.pool_id} {'health failing' if down else f'breaching SLO ({p.breach_rate:.0%})'}; "
                                             f"{others} other usable pool(s), traffic spills"}
                    return {"action": "wait", "pool_id": p.pool_id,
                            "rationale": f"{p.pool_id} is the last healthy pool; quarantine withheld, watching"}
            return {"action": "wait", "pool_id": None, "rationale": "all pools within SLO"}

        c = self.case
        p = sim.pools[c["pool"]]
        if c["kind"] == "closing":
            self.case = None
            return {"action": "resolve", "pool_id": p.pool_id, "rationale": "pool reinstated and within SLO"}
        if c["kind"] == "pool_down":
            if p.healthz_ok and not sim.breaching(p.pool_id):
                return self._close(sim, "health probe recovered")
            return {"action": "wait", "pool_id": p.pool_id, "rationale": "pool still down; service safe on remaining pools"}
        # slo_breach: probe until it behaves
        if p.probes_passed >= cfg.probes_to_reinstate:
            return self._close(sim, f"{p.probes_passed} consecutive probes within SLO")
        if p.probes_failed >= cfg.escalate_after_failures and not self.escalated:
            self.escalated = True
            return {"action": "escalate", "pool_id": p.pool_id, "channel": PAGER,
                    "message": f"{p.probes_failed} consecutive probes failed on {p.pool_id}; quarantine held",
                    "rationale": "fault outside the allowlist; page on-call once, keep probing"}
        return {"action": "probe", "pool_id": p.pool_id, "rationale": "verify recovery against the probe SLO"}

    def _close(self, sim: Simulator, why: str) -> dict:
        c = self.case
        if c["quarantined"]:
            c["quarantined"] = False
            c["kind"] = "closing"
            return {"action": "reinstate", "pool_id": c["pool"], "rationale": why}
        self.case = None
        return {"action": "resolve", "pool_id": c["pool"], "rationale": why}
