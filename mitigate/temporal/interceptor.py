"""PhrourosInterceptor: authorize every activity before it runs, record it in the signed ledger after.

Per activity attempt, in order:
  1. build an `ActionRecord` (workflow id, run id, activity id, attempt, type, sha256 of the canonical
     JSON of the arguments, a short summary, step index, start time);
  2. `PhrourosGuard.authorize_record(record, sim_state, token)` -> allow | deny | approval | egress_deny;
  3. allow: run the activity, hash the result, append `verdict=allow` (or `allowed_with_approval`);
  4. deny / egress_deny: append the record, raise `ApplicationError(type="PolicyDenied")`, non-retryable;
  5. approval: a valid `x-phrouros-approval` header bound to the argument hash counts as allow; missing or
     mismatched: append `verdict=pending` and raise `ApplicationError(type="ApprovalRequired")`.

Public interface meant to survive registration as a Temporal Agent Harness policy later:
`PhrourosGuard.authorize_record`, `mint_approval`, `verify_approval` (see docs/temporal-spike.md,
"Harness compatibility").
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Any

import temporalio.converter
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
    WorkflowInboundInterceptor,
    WorkflowInterceptorClassInput,
)

from govern.ledger import Ledger, get_ledger
from mitigate.phrouros_guard import DEFAULT_POLICY, ActionRecord, PhrourosGuard, Verdict, args_hash_of

from .headers import APPROVAL_ARG, APPROVAL_HEADER, SIM_ACTIVITY, workflow_interceptor_class

log = logging.getLogger(__name__)

DEFAULT_LEDGER = Path("results/temporal/ledger.jsonl")
LLM_ACTIVITY = "llm_decide"


def payload_hashes_of(args: list[Any]) -> list[str]:
    """sha256 of each argument's payload bytes as the default converter serializes it: the same hash the
    claim-check codec records, so a ledger action record can be joined to its payload records."""
    conv = temporalio.converter.default().payload_converter
    out = []
    for a in args:
        try:
            out.append(hashlib.sha256(conv.to_payloads([a])[0].data).hexdigest())
        except Exception:  # pragma: no cover
            out.append(args_hash_of(a))
    return out


def summarize_args(activity_type: str, args: list[Any]) -> dict:
    if activity_type == SIM_ACTIVITY and len(args) >= 4:
        kw = args[3] if isinstance(args[3], dict) else {}
        s = {"action": args[1], "pool_id": args[2]}
        for k in ("channel", "message"):
            if k in kw:
                s[k] = kw[k]
        return s
    if activity_type == LLM_ACTIVITY and len(args) >= 2 and isinstance(args[1], str):
        return {"prompt_sha256": hashlib.sha256(args[1].encode("utf-8")).hexdigest(), "packet_bytes": len(args[1].encode("utf-8"))}
    return {}


def result_hash_of(result: Any) -> str:
    return args_hash_of(result)


class PhrourosInterceptor(Interceptor):
    """Worker interceptor. Register with `Worker(..., interceptors=[PhrourosInterceptor(guard, ledger)])`."""

    def __init__(self, guard: PhrourosGuard, ledger: Ledger) -> None:
        self.guard = guard
        self.ledger = ledger
        self._steps: dict[str, int] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_paths(cls, ledger_path: Path | None = None, policy_path: Path | None = None,
                   key: str | None = None) -> "PhrourosInterceptor":
        guard = PhrourosGuard(policy_path=Path(policy_path or DEFAULT_POLICY), key=key)
        return cls(guard, get_ledger(Path(ledger_path or DEFAULT_LEDGER), key))

    def next_step(self, workflow_id: str) -> int:
        with self._lock:
            n = self._steps.get(workflow_id, 0)
            self._steps[workflow_id] = n + 1
            return n

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        return _PhrourosActivityInbound(next, self)

    def workflow_interceptor_class(self, input: WorkflowInterceptorClassInput) -> type[WorkflowInboundInterceptor] | None:
        return workflow_interceptor_class(input)


def _sim_state_for(activity_type: str, args: list[Any]) -> dict | None:
    if activity_type != SIM_ACTIVITY or not args:
        return None
    from incident.temporal_worker import _RUNS, snapshot

    run = _RUNS.get(str(args[0]))
    return snapshot(run.sim) if run else None


def _token_from(input: ExecuteActivityInput, args: list[Any]) -> tuple[str | None, list[Any]]:
    token = None
    hdr = input.headers.get(APPROVAL_HEADER) if input.headers else None
    if hdr is not None:
        token = str(temporalio.converter.default().payload_converter.from_payloads([hdr])[0])
    if len(args) >= 4 and isinstance(args[3], dict) and APPROVAL_ARG in args[3]:   # belt and braces
        kw = dict(args[3])
        token = token or str(kw.pop(APPROVAL_ARG))
        kw.pop(APPROVAL_ARG, None)
        args = [*args[:3], kw, *args[4:]]
    return token, args


class _PhrourosActivityInbound(ActivityInboundInterceptor):
    def __init__(self, next: ActivityInboundInterceptor, owner: PhrourosInterceptor) -> None:
        super().__init__(next)
        self.owner = owner

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        info = activity.info()
        token, args = _token_from(input, list(input.args))
        record = ActionRecord(workflow_id=info.workflow_id, run_id=info.workflow_run_id, activity_id=info.activity_id,
                              attempt=info.attempt, activity_type=info.activity_type, args_hash=args_hash_of(args),
                              args_summary=summarize_args(info.activity_type, args),
                              step_index=self.owner.next_step(info.workflow_id), t_start=time.time())
        sim_state = _sim_state_for(info.activity_type, args)
        verdict: Verdict = self.owner.guard.authorize_record(record, sim_state, approval_token=token)
        body = {**record.as_dict(), "task_queue": info.task_queue, "policy_version": verdict.policy_version,
                "policy_sha256": self.owner.guard.policy_sha256, "clause": verdict.clause, "reasons": verdict.reasons,
                "decision_ms": round(verdict.decision_ms, 4), "approval_id": verdict.approval_id, "host": verdict.host,
                "sim_state": sim_state, "payload_hashes": payload_hashes_of(args)}
        if verdict.kind in ("deny", "egress_deny"):
            body["verdict"] = verdict.kind
            self.owner.ledger.append("action", body)
            raise ApplicationError(f"PolicyDenied: {verdict.clause}", verdict.clause, type="PolicyDenied",
                                   non_retryable=True)
        if verdict.kind == "approval":
            body["verdict"] = "pending"
            self.owner.ledger.append("action", body)
            raise ApplicationError(f"ApprovalRequired: {verdict.approval_id}", verdict.approval_id,
                                   type="ApprovalRequired", non_retryable=True)
        body["verdict"] = "allowed_with_approval" if token else "allow"
        t0 = time.perf_counter()
        try:
            result = await self.next.execute_activity(dataclasses.replace(input, args=args))
        except Exception as e:
            body.update(duration_ms=round((time.perf_counter() - t0) * 1000, 3), error_type=type(e).__name__)
            self.owner.ledger.append("action", body)
            raise
        body.update(duration_ms=round((time.perf_counter() - t0) * 1000, 3), result_hash=result_hash_of(result),
                    result_payload_hash=payload_hashes_of([result])[0])
        self.owner.ledger.append("action", body)
        return result
