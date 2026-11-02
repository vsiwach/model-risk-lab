"""API-compatible shim of phrouros.enforce.policy (deny-by-default policy + approvals + egress).

Same YAML format and semantics as github.com/vsiwach/phrouros `phrouros/enforce/policy.py`, kept here
so the lab runs without installing phrouros. Replace by installing the real package.
"""

from __future__ import annotations

import fnmatch
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    detail: str


@dataclass
class Policy:
    agents: dict[str, dict[str, Any]]
    state_changing_tools: set[str]
    egress_allowlist: list[str]
    _approvals: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text())
        return cls(agents={a["id"]: a for a in raw.get("agents", [])},
                   state_changing_tools=set(raw.get("state_changing_tools", [])),
                   egress_allowlist=list(raw.get("egress_allowlist", [])))

    def authorize(self, agent_id: str, tool: str, approval_token: str | None = None) -> Decision:
        agent = self.agents.get(agent_id)
        if agent is None:
            return Decision(False, "unknown_agent", f"identity '{agent_id}' is not registered")
        if not any(fnmatch.fnmatch(tool, p) for p in agent.get("tools", [])):
            return Decision(False, "scope_denied", f"'{agent_id}' has no grant for tool '{tool}'")
        if tool in self.state_changing_tools and not self._consume(approval_token, agent_id, tool):
            return Decision(False, "approval_required", f"'{tool}' is state-changing; valid human approval token required")
        return Decision(True, "allowed", "authorized")

    def mint_approval(self, approver: str, agent_id: str, tool: str, ttl_seconds: int = 300) -> str:
        token = secrets.token_urlsafe(16)
        self._approvals[token] = {"approver": approver, "agent_id": agent_id, "tool": tool,
                                  "expires": time.time() + ttl_seconds}
        return token

    def _consume(self, token: str | None, agent_id: str, tool: str) -> bool:
        if token is None:
            return False
        g = self._approvals.get(token)
        if not g or g["expires"] < time.time() or g["agent_id"] != agent_id or g["tool"] != tool:
            return False
        del self._approvals[token]
        return True

    def egress_allowed(self, host: str) -> bool:
        return any(fnmatch.fnmatch(host, p) for p in self.egress_allowlist)
