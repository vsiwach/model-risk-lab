"""Approval test client: find a pending approval in the ledger, mint the token bound to its argument hash,
signal the waiting workflow. In v1 this is a Slack or PagerDuty approver; in v0 it is a CLI and an
async loop the test harness runs beside the worker."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from temporalio.client import Client, WorkflowHandle

from govern.ledger import Ledger
from mitigate.phrouros_guard import DEFAULT_POLICY, PhrourosGuard

DEFAULT_LEDGER = Path("results/temporal/ledger.jsonl")


def pending_args_hash(ledger_path: Path, approval_id: str) -> str | None:
    """The argument hash recorded with the `pending` action record for this approval id."""
    found = None
    for rec in Ledger.read(ledger_path, kind="action"):
        b = rec["body"]
        if b.get("approval_id") == approval_id and b.get("verdict") == "pending":
            found = b["args_hash"]
    return found


async def approve_async(client: Client, workflow_id: str, approval_id: str, ledger_path: Path = DEFAULT_LEDGER,
                        policy_path: Path = DEFAULT_POLICY, key: str | None = None) -> str:
    args_hash = pending_args_hash(ledger_path, approval_id)
    if args_hash is None:
        raise SystemExit(f"no pending record for approval {approval_id} in {ledger_path}")
    token = PhrourosGuard(policy_path=policy_path, key=key).mint_approval(approval_id, args_hash)
    await client.get_workflow_handle(workflow_id).signal("approve", args=[approval_id, token])
    return token


def approve_once(workflow_id: str, approval_id: str, address: str = "localhost:7233",
                 ledger_path: Path = DEFAULT_LEDGER, key: str | None = None) -> str:
    async def main() -> str:
        client = await Client.connect(address)
        return await approve_async(client, workflow_id, approval_id, ledger_path=ledger_path, key=key)

    return asyncio.run(main())


def auto_approver(ledger_path: Path | None = None, ledger_key: str | None = None, poll_s: float = 0.2,
                  policy_path: Path = DEFAULT_POLICY):
    """An approver loop for `run_temporal_async(approver=...)`: polls the workflow's pending approvals and
    signals a token for each (an approver that says yes to everything, which is what the acceptance test
    for the approval path needs; a real approver reads the record first)."""
    ledger_path = Path(ledger_path or DEFAULT_LEDGER)
    guard = PhrourosGuard(policy_path=policy_path, key=ledger_key)

    async def loop(handle: WorkflowHandle, client: Client) -> None:
        # The approval id is a function of (workflow, activity type, argument hash, policy version), so the
        # same step asked again later in the episode gets the same id: signal whenever it is pending.
        while True:
            try:
                ids = await handle.query("pending_approvals")
            except Exception:
                ids = []
            for approval_id in ids:
                args_hash = pending_args_hash(ledger_path, approval_id)
                if args_hash is None:
                    continue
                token = guard.mint_approval(approval_id, args_hash)
                await handle.signal("approve", args=[approval_id, token])
            await asyncio.sleep(poll_s)

    return loop


def describe_pending(ledger_path: Path = DEFAULT_LEDGER) -> list[dict]:
    """Pending approvals in a ledger with their arguments, for a human reading the CLI."""
    out = []
    for rec in Ledger.read(ledger_path, kind="action"):
        b = rec["body"]
        if b.get("verdict") == "pending":
            out.append({"workflow_id": b["workflow_id"], "approval_id": b["approval_id"],
                        "args": b.get("args_summary"), "clause": b.get("clause")})
    return out


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(describe_pending(), indent=1))
