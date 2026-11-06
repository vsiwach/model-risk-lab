"""Workflow-side half of the interceptor: moves an approval token from the activity arguments into the
`x-phrouros-approval` header. Kept in its own module with only `temporalio` imports so the workflow
sandbox can load it without pulling the guard, the ledger or yaml into workflow code."""

from __future__ import annotations

from typing import Any

import temporalio.converter
from temporalio.worker import (
    StartActivityInput,
    WorkflowInboundInterceptor,
    WorkflowInterceptorClassInput,
    WorkflowOutboundInterceptor,
)

APPROVAL_HEADER = "x-phrouros-approval"
APPROVAL_ARG = "_approval_token"
SIM_ACTIVITY = "sim_act"


def _activity_name(activity: Any) -> str:
    if isinstance(activity, str):
        return activity
    defn = getattr(activity, "__temporal_activity_definition", None)
    return getattr(defn, "name", None) or getattr(activity, "__name__", str(activity))


class ApprovalHeaderOutbound(WorkflowOutboundInterceptor):
    def start_activity(self, input: StartActivityInput):
        args = list(input.args)
        if _activity_name(input.activity) == SIM_ACTIVITY and len(args) >= 4 and isinstance(args[3], dict) \
                and APPROVAL_ARG in args[3]:
            kwargs = dict(args[3])
            token = str(kwargs.pop(APPROVAL_ARG))
            args[3] = kwargs
            input.args = args
            payload = temporalio.converter.default().payload_converter.to_payload(token)
            input.headers = {**dict(input.headers), APPROVAL_HEADER: payload}
        return super().start_activity(input)


class ApprovalHeaderInbound(WorkflowInboundInterceptor):
    def init(self, outbound: WorkflowOutboundInterceptor) -> None:
        super().init(ApprovalHeaderOutbound(outbound))


def workflow_interceptor_class(_: WorkflowInterceptorClassInput) -> type[WorkflowInboundInterceptor]:
    return ApprovalHeaderInbound
