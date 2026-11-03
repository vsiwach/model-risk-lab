"""Judge calibration: how much should you trust the judge?

Idea borrowed from vsiwach/agentops-sdk (`validate_auditors.py`: benchmark candidate auditor models on a
ground-truth set before letting one certify agents). Here the ground truth is the human-labelled
`response_label` in the Aegis 2.0 test split, and the judge under test is whatever `nmr run` would use
(Safety Guard, rubric, or heuristic). Report accuracy, precision, recall and F1 on "response unsafe",
plus the confusion matrix, so every ASR number in the report carries its judge's error bars with it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .types import Generation, Probe


@dataclass
class Calibration:
    judge: str
    n: int
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / max(1, self.n)

    @property
    def precision(self) -> float:
        return self.tp / max(1, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return self.tp / max(1, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(1e-9, p + r)

    def markdown(self) -> str:
        return (f"| Judge | n | Accuracy | Precision (unsafe) | Recall (unsafe) | F1 | FP | FN |\n|---|---|---|---|---|---|---|---|\n"
                f"| {self.judge} | {self.n} | {100*self.accuracy:.1f}% | {100*self.precision:.1f}% | "
                f"{100*self.recall:.1f}% | {100*self.f1:.1f}% | {self.fp} | {self.fn} |\n")


def load_labelled(n: int = 300, seed: int = 7) -> list[tuple[Probe, Generation, bool]]:
    """(probe, generation, human_says_response_unsafe) triples from Aegis 2.0 test."""
    import datasets

    ds = datasets.load_dataset("nvidia/Aegis-AI-Content-Safety-Dataset-2.0", split="test")
    rows = [r for r in ds if r["response"] and r["response_label"] in ("safe", "unsafe") and r["prompt"]]
    rng = random.Random(seed)
    rng.shuffle(rows)
    # balance the two classes so accuracy is not dominated by the majority label
    unsafe = [r for r in rows if r["response_label"] == "unsafe"][: n // 2]
    safe = [r for r in rows if r["response_label"] == "safe"][: n - len(unsafe)]
    out = []
    for r in unsafe + safe:
        p = Probe(id="cal-" + r["id"][:10], category="content_safety", prompt=r["prompt"], source="aegis-test",
                  expected="refuse" if r["prompt_label"] == "unsafe" else "comply")
        g = Generation(probe_id=p.id, system="aegis", response=r["response"], latency_s=0.0)
        out.append((p, g, r["response_label"] == "unsafe"))
    return out


def calibrate(judge, triples, workers: int = 4) -> Calibration:
    from concurrent.futures import ThreadPoolExecutor

    def one(t):
        p, g, truth = t
        raw_fn = getattr(judge, "raw_verdict", None)
        if raw_fn is not None:                      # model judge: score its own verdict, nothing layered on top
            from .judge import parse_guard

            parsed = parse_guard(raw_fn(p.prompt, g.response))
            return bool(parsed and parsed[1]), truth
        return judge.judge(p, g).response_unsafe, truth

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        preds = list(ex.map(one, triples))
    tp = sum(1 for pr, tr in preds if pr and tr)
    fp = sum(1 for pr, tr in preds if pr and not tr)
    tn = sum(1 for pr, tr in preds if not pr and not tr)
    fn = sum(1 for pr, tr in preds if not pr and tr)
    return Calibration(judge=getattr(judge, "name", "judge"), n=len(preds), tp=tp, fp=fp, tn=tn, fn=fn)
