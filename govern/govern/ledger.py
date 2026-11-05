"""Signed ledger: append-only JSONL with a hash chain and an HMAC per record.

One line per record:

    {"record_id": uuid, "ts": iso8601, "prev_hash": sha256(previous line), "kind": action|payload|approval,
     "body": {...}, "hmac": HMAC-SHA256(key, canonical_json(envelope) + prev_hash)}

where `envelope` is the record without `hmac` (record_id, ts, prev_hash, kind, body). The design doc
signs `body + prev_hash`; signing the whole envelope is a superset that also pins the id and timestamp,
so a flipped byte in the last line's `ts` is caught without a successor line (docs/DECISIONS.md).
`prev_hash` ties each record to the exact bytes of the one before it, so changing any byte of any line
breaks every record after it; the HMAC ties the record to a key the editor does not hold. In v0 the key
comes from `PHROUROS_LEDGER_KEY` (a dev constant by default) and the worker signs its own records, which
proves integrity against later edits, not against a compromised worker (the v1 ledger service closes that).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_KEY = "phrouros-dev-key-change-me"
GENESIS = "0" * 64
KINDS = ("action", "payload", "approval")


def ledger_key(key: str | None = None) -> str:
    return key or os.environ.get("PHROUROS_LEDGER_KEY", DEFAULT_KEY)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sign_record(key: str, envelope: dict) -> str:
    """HMAC over the canonical record envelope (everything but `hmac`) plus its prev_hash."""
    env = {k: v for k, v in envelope.items() if k != "hmac"}
    return hmac.new(key.encode("utf-8"), (canonical_json(env) + env["prev_hash"]).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _line_bytes(record: dict) -> bytes:
    return (canonical_json(record) + "\n").encode("utf-8")


class Ledger:
    """Append-only, thread-safe JSONL ledger. Several `Ledger` objects on one file must not share a process
    unless they share this instance; the chain head is cached in memory after the first append."""

    def __init__(self, path: str | Path, key: str | None = None) -> None:
        self.path = Path(path)
        self.key = ledger_key(key)
        self._lock = threading.Lock()
        self._head: str | None = None       # sha256 of the last line written, None until read

    # ---- write -------------------------------------------------------------------------------

    def _load_head(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = b""
        with self.path.open("rb") as f:
            for raw in f:
                if raw.strip():
                    last = raw
        return sha256_hex(last) if last else GENESIS

    def append(self, kind: str, body: dict) -> dict:
        if kind not in KINDS:
            raise ValueError(f"unknown ledger kind {kind!r}")
        with self._lock:
            if self._head is None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._head = self._load_head()
            rec = {"record_id": str(uuid.uuid4()), "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "prev_hash": self._head, "kind": kind, "body": body}
            rec["hmac"] = sign_record(self.key, rec)
            line = _line_bytes(rec)
            with self.path.open("ab") as f:
                f.write(line)
                f.flush()
            self._head = sha256_hex(line)
        return rec

    @property
    def head(self) -> str:
        with self._lock:
            if self._head is None:
                self._head = self._load_head()
            return self._head

    # ---- read ----------------------------------------------------------------------------------

    @staticmethod
    def iter_lines(path: str | Path) -> Iterator[tuple[int, bytes]]:
        with Path(path).open("rb") as f:
            for i, raw in enumerate(f, 1):
                if raw.strip():
                    yield i, raw

    @staticmethod
    def read(path: str | Path, kind: str | None = None) -> list[dict]:
        out = []
        for _, raw in Ledger.iter_lines(path):
            rec = json.loads(raw)
            if kind is None or rec.get("kind") == kind:
                out.append(rec)
        return out


_LEDGERS: dict[Path, Ledger] = {}
_LEDGERS_LOCK = threading.Lock()


def get_ledger(path: str | Path, key: str | None = None) -> Ledger:
    """One `Ledger` per file per process, so the interceptor and the payload codec share the chain head."""
    p = Path(path).resolve()
    with _LEDGERS_LOCK:
        led = _LEDGERS.get(p)
        if led is None:
            led = _LEDGERS[p] = Ledger(p, key)
        return led


def verify(path: str | Path, key: str | None = None) -> tuple[bool, int | None]:
    """Walk the chain. Returns (ok, first_bad_line) with 1-based line numbers; (True, None) when intact."""
    key = ledger_key(key)
    prev = GENESIS
    for lineno, raw in Ledger.iter_lines(path):
        try:
            rec = json.loads(raw)
            rec_prev, sig = rec["prev_hash"], rec["hmac"]
            expected = sign_record(key, rec)
        except (ValueError, KeyError, TypeError):
            return False, lineno
        if rec_prev != prev or not hmac.compare_digest(expected, sig):
            return False, lineno
        prev = sha256_hex(raw)
    return True, None


def export_bundle(path: str | Path, workflow_id: str, out_dir: str | Path, key: str | None = None,
                  blob_dir: str | Path | None = None) -> dict:
    """Write the records for one workflow, the chain proof up to the last matching record, and the blobs
    they reference. Returns a small manifest (also written as manifest.json)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ok, bad = verify(path, key)
    matching: list[dict] = []
    proof: list[dict] = []
    last_match = 0
    payload_hashes: set[str] = set()
    for lineno, raw in Ledger.iter_lines(path):
        rec = json.loads(raw)
        proof.append({"line": lineno, "prev_hash": rec["prev_hash"], "sha256": sha256_hex(raw)})
        body = rec.get("body", {})
        if body.get("workflow_id") == workflow_id:
            matching.append(rec)
            last_match = lineno
            payload_hashes.update(body.get("payload_hashes", []))
            if body.get("result_payload_hash"):
                payload_hashes.add(body["result_payload_hash"])
    proof = proof[:last_match]
    with (out / "records.jsonl").open("w", encoding="utf-8") as f:
        for rec in matching:
            f.write(canonical_json(rec) + "\n")
    (out / "chain_proof.json").write_text(json.dumps({"ledger": str(path), "verified": ok, "first_bad_line": bad,
                                                       "genesis": GENESIS, "hashes": proof}, indent=1))
    copied = []
    if blob_dir:
        bdir = out / "blobs"
        for h in sorted(payload_hashes):
            src = Path(blob_dir) / h
            if src.exists():
                bdir.mkdir(exist_ok=True)
                shutil.copyfile(src, bdir / h)
                copied.append(h)
    manifest = {"workflow_id": workflow_id, "records": len(matching), "chain_lines": len(proof),
                "chain_verified": ok, "blobs": copied}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return manifest
