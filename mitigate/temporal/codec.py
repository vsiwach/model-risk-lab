"""PhrourosCodec: hash every payload crossing the Temporal boundary and claim-check the ones that are
large or sensitive.

encode: for each payload compute sha256(data) and append a ledger record of kind `payload`
`{hash, size, type, claimcheck}`. If the payload is over `size_cap` bytes or matches a sensitivity rule
(the router admin token, AWS access key ids, email addresses) the serialized payload is written to
`blob_dir/<hash>` and replaced in history by `{"$ref": hash, "size": n}` with metadata
`encoding=phrouros/claimcheck`.

decode: resolve `$ref` from the blob dir, verify the hash of the restored payload data, fail loudly on a
mismatch or a missing blob. Nothing is silently substituted.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

import temporalio.converter
from govern.ledger import Ledger, get_ledger
from incident.sim import ADMIN_TOKEN
from temporalio.api.common.v1 import Payload
from temporalio.converter import DataConverter, PayloadCodec

CLAIMCHECK_ENCODING = b"phrouros/claimcheck"
DEFAULT_SIZE_CAP = 32 * 1024
DEFAULT_BLOB_DIR = Path("results/temporal/blobs")
DEFAULT_LEDGER = Path("results/temporal/ledger.jsonl")
SENSITIVE_RE = re.compile(
    rb"(" + re.escape(ADMIN_TOKEN.encode()) + rb"|AKIA[0-9A-Z]{16}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)


class ClaimCheckError(ValueError):
    """A `$ref` could not be resolved or the stored blob does not hash to its reference."""


class PhrourosCodec(PayloadCodec):
    def __init__(self, blob_dir: Path | str = DEFAULT_BLOB_DIR, ledger: Ledger | None = None,
                 size_cap: int = DEFAULT_SIZE_CAP, sensitive: re.Pattern[bytes] = SENSITIVE_RE) -> None:
        self.blob_dir = Path(blob_dir)
        self.ledger = ledger
        self.size_cap = size_cap
        self.sensitive = sensitive

    def _sensitive(self, data: bytes) -> bool:
        return len(data) > self.size_cap or bool(self.sensitive.search(data))

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") == CLAIMCHECK_ENCODING:
                out.append(p)
                continue
            h = hashlib.sha256(p.data).hexdigest()
            check = self._sensitive(p.data)
            if self.ledger is not None:
                self.ledger.append("payload", {"hash": h, "size": len(p.data),
                                               "type": p.metadata.get("encoding", b"").decode("utf-8", "replace"),
                                               "claimcheck": check})
            if not check:
                out.append(p)
                continue
            self.blob_dir.mkdir(parents=True, exist_ok=True)
            (self.blob_dir / h).write_bytes(p.SerializeToString())
            ref = json.dumps({"$ref": h, "size": len(p.data)}, separators=(",", ":")).encode()
            out.append(Payload(metadata={"encoding": CLAIMCHECK_ENCODING}, data=ref))
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != CLAIMCHECK_ENCODING:
                out.append(p)
                continue
            ref = json.loads(p.data)
            h = ref["$ref"]
            path = self.blob_dir / h
            if not path.exists():
                raise ClaimCheckError(f"claim-check blob {h} is missing from {self.blob_dir}")
            inner = Payload()
            inner.ParseFromString(path.read_bytes())
            if hashlib.sha256(inner.data).hexdigest() != h:
                raise ClaimCheckError(f"claim-check blob {h} does not hash to its reference")
            out.append(inner)
        return out


def phrouros_data_converter(blob_dir: Path | str | None = None, ledger_path: Path | str | None = None,
                            key: str | None = None, size_cap: int = DEFAULT_SIZE_CAP) -> DataConverter:
    ledger = get_ledger(Path(ledger_path or DEFAULT_LEDGER), key)
    codec = PhrourosCodec(blob_dir=Path(blob_dir or DEFAULT_BLOB_DIR), ledger=ledger, size_cap=size_cap)
    return dataclasses.replace(temporalio.converter.default(), payload_codec=codec)


def refs_in(payloads: Iterable[Payload]) -> list[str]:
    """The `$ref` hashes among a set of payloads (used by the tests against workflow history)."""
    out = []
    for p in payloads:
        if p.metadata.get("encoding") == CLAIMCHECK_ENCODING:
            out.append(json.loads(p.data)["$ref"])
    return out
