"""Core data types shared across the harness."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional


# Risk categories tracked by the harness. These map onto the Nemotron model-risk
# portfolio named in the role: cybersecurity, content moderation, data protection,
# plus prompt injection (the agentic risk) and a benign control set.
CATEGORIES = (
    "cybersecurity",
    "content_safety",
    "data_protection",
    "prompt_injection",
    "benign",
)


@dataclass(frozen=True)
class Probe:
    """One red-team (or benign control) prompt."""

    id: str
    category: str          # one of CATEGORIES
    prompt: str
    source: str            # dataset or 'bundled'
    expected: str          # 'refuse' for harmful probes, 'comply' for benign controls
    meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category {self.category!r}")
        if self.expected not in ("refuse", "comply"):
            raise ValueError(f"expected must be 'refuse' or 'comply', got {self.expected!r}")


@dataclass
class Generation:
    """A target model's answer to a probe."""

    probe_id: str
    system: str
    response: str
    latency_s: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    rails: dict = field(default_factory=dict)   # what the rails did, if any


@dataclass
class Verdict:
    """The judge's decision on one generation."""

    probe_id: str
    system: str
    response_unsafe: bool          # judge says the response is unsafe
    refused: bool                  # response reads as a refusal / safe completion
    categories: list[str] = field(default_factory=list)
    judge: str = ""
    raw: str = ""


@dataclass
class Record:
    """Probe + generation + verdict, one row of the results file."""

    probe: Probe
    generation: Generation
    verdict: Verdict

    def to_json(self) -> str:
        return json.dumps(
            {"probe": asdict(self.probe), "generation": asdict(self.generation), "verdict": asdict(self.verdict)},
            ensure_ascii=False,
        )

    @staticmethod
    def from_json(line: str) -> "Record":
        d = json.loads(line)
        return Record(Probe(**d["probe"]), Generation(**d["generation"]), Verdict(**d["verdict"]))


def write_records(path: Path, records: Iterable[Record]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(r.to_json() + "\n")
            n += 1
    return n


def read_records(path: Path) -> Iterator[Record]:
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield Record.from_json(line)


def write_probes(path: Path, probes: Iterable[Probe]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for p in probes:
            f.write(json.dumps(asdict(p), ensure_ascii=False) + "\n")
            n += 1
    return n


def read_probes(path: Path) -> list[Probe]:
    out: list[Probe] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(Probe(**json.loads(line)))
    return out
