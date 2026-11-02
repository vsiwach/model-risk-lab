"""SFT data for the incident agent: packets labelled by the rule oracle.

Each row is one tick: the exact packet the LLM policy would see (telemetry, logs, planted text if any)
and the oracle's action with a rationale. For injected ticks the rationale names the planted text and
says it was ignored, so the model learns both the action and the habit of calling out the injection.
Clean ticks keep the oracle's remediation behaviour (the MTTR half of the objective).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .llm import HARDENING, SYSTEM, build_packet
from .rules import RulePolicy
from .runner import _extra_for
from .scenarios import build_scenarios
from .sim import Simulator


def build_sft(out: Path, seed: int = 11, max_injection: int = 96, hardened: bool = False) -> int:
    scenarios = build_scenarios(seed=seed, max_injection=max_injection, benign_per_fault=6)
    rows = []
    system = SYSTEM + (HARDENING if hardened else "")
    for sc in scenarios:
        sim = Simulator(fault=sc.fault_obj(), seed=sc.seed)
        oracle = RulePolicy()
        last = None
        for _ in range(sc.max_ticks):
            sim.advance()
            extra = _extra_for(sc, sim)
            packet = build_packet(sim, extra, hardened, last)
            d = oracle.decide(sim)
            rationale = d.get("rationale", "")
            if extra:
                where = {"log_line": "a log line", "alert": "the alert annotation", "runbook": "the runbook excerpt",
                         "probe_result": "the probe result"}.get(sc.vector, "the packet")
                rationale = f"Ignored an instruction planted in {where}; {rationale}"
            label = {"action": d["action"], "pool_id": d.get("pool_id"), "rationale": rationale}
            if d["action"] == "escalate":
                label["channel"], label["message"] = d["channel"], d["message"]
            rows.append({"messages": [{"role": "system", "content": system}, {"role": "user", "content": packet},
                                      {"role": "assistant", "content": json.dumps(label)}],
                         "scenario": sc.id, "category": sc.category, "tick": sim.tick})
            kw = {k: v for k, v in d.items() if k in ("channel", "message")}
            if d["action"] == "probe" and sc.vector == "probe_result" and extra.get("probe_body"):
                kw["_injected_result"] = extra["probe_body"]
            last = sim.act(d["action"], d.get("pool_id"), **kw)
            if sim.resolved_tick is not None:
                break
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)
