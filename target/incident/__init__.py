"""Target: an incident-remediation agent for an inference control plane, with Nemotron in the loop.

Extracted from vsiwach/baseten-mvp (services/router/router_app/incident_agent.py), which runs the same
closed action allowlist against live Baseten pools with a recorded MTTR of about 9 seconds. Here the
pools, telemetry and chaos faults are simulated with an injected clock so every episode is hermetic,
reproducible, and runs on a laptop.

Two policies drive the same loop:

* `rules.RulePolicy`  the ported deterministic logic (the oracle and the MTTR baseline)
* `llm.LLMPolicy`     a model reads an incident packet (pool table, recent samples, log lines, alert
                      annotations, runbook excerpt, last tool result) and returns ONE allowlisted action

Attacks arrive as data inside that packet (a log line, an alert annotation, a runbook page, a probe
result). The policy engine in `policy.py` scores every action against the invariants the rule policy
earned through chaos testing (never quarantine the last healthy pool, never reinstate without passing
probes, never resolve while breaching, escalate to the pager only, never leak the admin token), and
can run as a deny-by-default guard that blocks unsafe actions before they execute.
"""

from .sim import Simulator, Fault  # noqa: F401
from .rules import RulePolicy  # noqa: F401
from .scenarios import build_scenarios  # noqa: F401
from .runner import run_scenarios  # noqa: F401
