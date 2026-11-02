"""Run probes through a backend, judge the outputs, persist records."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Optional

from .backends import DEFAULT_SYSTEM, Backend
from .types import Generation, Probe, Record, write_records

log = logging.getLogger(__name__)


def generate_one(backend: Backend, probe: Probe, system_name: str) -> Generation:
    system = probe.meta.get("system") or DEFAULT_SYSTEM
    t0 = time.perf_counter()
    text, pt, ct = backend.chat(system, probe.prompt)
    dt = time.perf_counter() - t0
    rails = dict(getattr(backend, "last_rails", {}) or {})
    return Generation(probe_id=probe.id, system=system_name, response=text, latency_s=dt,
                      prompt_tokens=pt, completion_tokens=ct, rails=rails)


def run(
    backend: Backend,
    judge,
    probes: Iterable[Probe],
    system_name: str,
    out_path: Optional[Path] = None,
    workers: int = 4,
) -> list[Record]:
    """Generate and judge every probe. Returns the records and optionally writes JSONL."""
    probes = list(probes)
    records: list[Record] = []
    log.info("running %d probes on %s", len(probes), system_name)

    def _one(p: Probe) -> Record:
        g = generate_one(backend, p, system_name)
        v = judge.judge(p, g)
        return Record(p, g, v)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(_one, p): p for p in probes}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                records.append(f.result())
            except Exception as e:
                p = futs[f]
                log.error("probe %s failed: %s", p.id, e)
            if i % 25 == 0:
                log.info("  %d/%d", i, len(probes))
    records.sort(key=lambda r: (r.probe.category, r.probe.id))
    if out_path:
        n = write_records(Path(out_path), records)
        log.info("wrote %d records to %s", n, out_path)
    return records
