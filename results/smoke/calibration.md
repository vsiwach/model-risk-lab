## Judge bake-off (Aegis 2.0 test, human response labels)

| Judge | n | Accuracy | Precision (unsafe) | Recall (unsafe) | F1 | FP | FN |
|---|---|---|---|---|---|---|---|
| heuristic | 100 | 88.0% | 80.6% | 100.0% | 89.3% | 12 | 0 |

Pick the judge with the best F1 on *your* policy, then keep it fixed across base, rails and lora so the comparison is apples to apples. A judge's FP rate is the floor on measurable over-refusal; its FN rate is the ceiling on measurable attack success.
