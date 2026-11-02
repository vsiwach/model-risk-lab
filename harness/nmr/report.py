"""Report: compare systems (base, rails, lora) side by side as Markdown plus one PNG chart."""

from __future__ import annotations

from pathlib import Path

from .metrics import HARMFUL, Summary

# Fixed categorical order (validated light-surface palette): base, rails, lora.
SERIES_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
CAT_LABELS = {
    "cybersecurity": "Cybersecurity",
    "content_safety": "Content safety",
    "data_protection": "Data protection",
    "prompt_injection": "Prompt injection",
}


def markdown(summaries: list[Summary], title: str = "Model risk evaluation") -> str:
    lines = [f"# {title}", ""]
    lines.append("Attack success rate (ASR) = share of harmful probes whose response the judge marked unsafe. "
                 "Lower is better. Over-refusal = share of benign control prompts the system refused. "
                 "Lower is better. Brackets are 95% bootstrap intervals.")
    lines.append("")
    head = "| Metric | " + " | ".join(s.system for s in summaries) + " |"
    lines.append(head)
    lines.append("|---|" + "---|" * len(summaries))
    for c in HARMFUL:
        lines.append(f"| ASR {CAT_LABELS[c]} | " + " | ".join(s.asr[c].as_pct() for s in summaries) + " |")
    lines.append("| **ASR overall (harmful)** | " + " | ".join(f"**{s.asr_overall.as_pct()}**" for s in summaries) + " |")
    lines.append("| Canary leak (injection) | " + " | ".join(s.canary_leak.as_pct() for s in summaries) + " |")
    lines.append("| Over-refusal (benign) | " + " | ".join(s.over_refusal.as_pct() for s in summaries) + " |")
    lines.append("| Latency p50 / p95 (s) | " + " | ".join(f"{s.latency_p50:.2f} / {s.latency_p95:.2f}" for s in summaries) + " |")
    lines.append("| Mean output tokens | " + " | ".join(f"{s.tokens_out_mean:.0f}" for s in summaries) + " |")
    lines.append("| Probes | " + " | ".join(str(s.n) for s in summaries) + " |")
    lines.append("")
    lines.append("Reading the table: a mitigation earns its place only if ASR falls **and** over-refusal stays "
                 "flat. Guardrails usually buy the largest ASR drop at the cost of latency and some over-refusal; "
                 "a safety fine-tune keeps latency flat and should hold over-refusal, which is the tradeoff to "
                 "watch when the two are stacked.")
    return "\n".join(lines) + "\n"


def chart(summaries: list[Summary], out_png: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cats = list(HARMFUL) + ["benign"]
    labels = [CAT_LABELS.get(c, "Over-refusal (benign)") for c in cats]
    n_sys = len(summaries)
    width = 0.8 / n_sys
    fig, ax = plt.subplots(figsize=(9, 4.2), dpi=150)
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")
    for i, s in enumerate(summaries):
        vals, los, his = [], [], []
        for c in cats:
            st = s.over_refusal if c == "benign" else s.asr[c]
            vals.append(100 * st.rate)
            los.append(100 * (st.rate - st.lo))
            his.append(100 * (st.hi - st.rate))
        xs = [j + (i - (n_sys - 1) / 2) * width for j in range(len(cats))]
        ax.bar(xs, vals, width=width * 0.92, color=SERIES_COLORS[i % len(SERIES_COLORS)], label=s.system,
               yerr=[los, his], error_kw={"ecolor": "#6b6b66", "elinewidth": 1, "capsize": 2}, linewidth=0)
        for x, v in zip(xs, vals):
            ax.text(x, v + 2.5, f"{v:.0f}", ha="center", va="bottom", fontsize=7.5, color="#3c3c38")
    ax.set_xticks(range(len(cats)), labels, fontsize=9, color="#3c3c38")
    ax.set_ylim(0, 105)
    ax.set_ylabel("rate (%)", fontsize=9, color="#6b6b66")
    ax.set_title("Attack success rate by risk category, and over-refusal on benign controls",
                 fontsize=10.5, loc="left", color="#1f1f1d")
    ax.yaxis.grid(True, color="#e6e5e0", linewidth=0.8)
    ax.set_axisbelow(True)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.spines["bottom"].set_color("#c9c8c1")
    ax.tick_params(axis="y", colors="#6b6b66", length=0)
    ax.legend(frameon=False, fontsize=8.5, loc="upper right", ncol=min(n_sys, 3))
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png)
    plt.close(fig)
    return out_png
