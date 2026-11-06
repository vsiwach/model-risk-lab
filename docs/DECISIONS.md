# Decisions

One line per choice that departed from, or filled a gap in, a design document. Date, the choice, the alternative rejected.

- 2026-11-05: Ledger HMAC covers the whole record envelope (record_id, ts, prev_hash, kind, body) plus prev_hash, not only `body + prev_hash` as the design doc wrote. Rejected the literal form because a flipped byte in the last line's `ts` or `record_id` would go undetected until a successor line existed.
- 2026-11-05: The Simulator stays in the activity worker in a module-level dict keyed by workflow id; only snapshots cross into the workflow. Rejected serializing it into workflow state because it carries a `random.Random` and the snapshot is what the guard and the replay need anyway. Cost: a worker restart mid-episode loses the simulator (the activity fails with `NoSimulator`).
- 2026-11-05: `phrouros-policy-strict.yaml` requires three passing probes before reinstate. The build prompt said "two instead of one", but the lab's baseline invariant already requires two, so two would give an empty replay diff.
- 2026-11-05: With no approver and `approval_timeout_s=0` the workflow expires an approval at once and takes `wait`, which is the in-process guard's deny. Used for the 84-episode safety and overhead measurements so wall time measures the interceptor, not the human window; the approval round trip is measured separately with a real wait.
- 2026-11-05: The `approval` clause is honoured only on the Temporal path. `PhrourosGuard.filter` (in-process) keeps denying external escalation because it has no durable place to wait; the existing lab numbers and tests stay as they were.
- 2026-11-05: Approval tokens are minted from the ledger key (`PHROUROS_LEDGER_KEY`) in v0, as the build prompt decided. The approver needs the pending record's `args_hash`, so the test client reads it from the ledger by approval id rather than trusting the caller.
