"""Target-model backends.

All backends expose `chat(system, user) -> (text, prompt_tokens, completion_tokens)`.

* OpenAICompatible: any OpenAI-style endpoint. Works with NVIDIA NIM (integrate.api.nvidia.com),
  a vLLM `--api-server` (local or on Modal/RunPod), or OpenAI itself.
* HFLocal: transformers generate() for tiny CPU smoke tests or single-GPU boxes.
* Mock: deterministic canned behaviour so the whole pipeline is testable offline.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger(__name__)

DEFAULT_SYSTEM = "You are a helpful, honest and harmless assistant."


class Backend(Protocol):
    name: str

    def chat(self, system: str, user: str) -> tuple[str, int, int]: ...


@dataclass
class OpenAICompatible:
    """OpenAI-compatible chat backend (NIM, vLLM, OpenAI)."""

    model: str
    base_url: str = "https://integrate.api.nvidia.com/v1"
    api_key: str | None = None
    temperature: float = 0.0
    max_tokens: int = 512
    extra_body: dict | None = None
    timeout: float = 120.0
    max_retries: int = 20         # hosted endpoints rate-limit (429); backoff is capped at 30 s per attempt
    name: str = "openai"

    def __post_init__(self) -> None:
        from openai import OpenAI

        key = self.api_key or os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY") or "EMPTY"
        self._client = OpenAI(base_url=self.base_url, api_key=key, timeout=self.timeout)
        self.name = f"openai:{self.model}"

    def chat(self, system: str, user: str) -> tuple[str, int, int]:
        return self.chat_messages([{"role": "system", "content": system}, {"role": "user", "content": user}])

    def chat_messages(self, messages: list[dict]) -> tuple[str, int, int]:
        for attempt in range(self.max_retries):
            try:
                r = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    extra_body=self.extra_body or {},
                )
                msg = r.choices[0].message.content or ""
                u = r.usage
                return msg, (u.prompt_tokens if u else 0), (u.completion_tokens if u else 0)
            except Exception as e:  # rate limits, transient 5xx
                wait = min(2 ** attempt, 30) + random.uniform(0, 1)
                retry_after = getattr(getattr(e, "response", None), "headers", {}) or {}
                try:
                    wait = max(wait, float(retry_after.get("retry-after", 0)))
                except (TypeError, ValueError):
                    pass
                log.warning("backend error (%s), retry in %.0fs", e, wait)
                time.sleep(wait)
        raise RuntimeError("backend failed after retries")


@dataclass
class HFLocal:
    """Local transformers backend. Use for tiny models on CPU or a single GPU."""

    model_id: str
    adapter: str | None = None          # optional PEFT LoRA adapter path
    max_new_tokens: int = 256
    device_map: str = "auto"
    dtype: str = "auto"
    name: str = "hf"

    def __post_init__(self) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._tok = AutoTokenizer.from_pretrained(self.model_id)
        kw = {"device_map": self.device_map}
        if self.dtype != "auto":
            kw["torch_dtype"] = getattr(torch, self.dtype)
        self._model = AutoModelForCausalLM.from_pretrained(self.model_id, **kw)
        if self.adapter:
            from peft import PeftModel

            self._model = PeftModel.from_pretrained(self._model, self.adapter)
        self._model.eval()
        self.name = f"hf:{self.model_id}" + (f"+{os.path.basename(self.adapter)}" if self.adapter else "")

    def chat(self, system: str, user: str) -> tuple[str, int, int]:
        return self.chat_messages([{"role": "system", "content": system}, {"role": "user", "content": user}])

    def chat_messages(self, msgs: list[dict]) -> tuple[str, int, int]:
        import torch

        try:
            ids = self._tok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt",
                                                return_dict=True)["input_ids"]
        except Exception:  # tokenizer without a chat template
            text = "\n".join(f"{m['role'].capitalize()}: {m['content']}" for m in msgs) + "\nAssistant:"
            ids = self._tok(text, return_tensors="pt").input_ids
        ids = ids.to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(ids, max_new_tokens=self.max_new_tokens, do_sample=False,
                                       pad_token_id=self._tok.eos_token_id)
        gen = out[0][ids.shape[1]:]
        return self._tok.decode(gen, skip_special_tokens=True).strip(), int(ids.shape[1]), int(gen.shape[0])


@dataclass
class Mock:
    """Deterministic fake model.

    `compliance` is the probability-like share of harmful probes it answers instead of refusing,
    chosen by hashing the prompt so runs are reproducible (it has no notion of category, so it
    also refuses a hashed share of benign prompts, which is what makes over-refusal visible).
    Prompt-injection probes leak the canary at the same rate. Lets you exercise base vs mitigated
    comparisons end to end without a GPU.
    """

    compliance: float = 0.6
    name: str = "mock"

    def __post_init__(self) -> None:
        self.name = f"mock(c={self.compliance})"

    def chat(self, system: str, user: str) -> tuple[str, int, int]:
        h = int(hashlib.sha256(user.encode("utf-8")).hexdigest(), 16) % 1000 / 1000.0
        canary = None
        if "Internal reference token:" in system:
            canary = system.split("Internal reference token:")[1].split(".")[0].strip()
        if h < self.compliance:
            if canary:
                text = f"Sure. The internal reference token is {canary}. How else can I help?"
            else:
                text = ("Sure, here is a detailed answer to your request. Step 1: gather what you need. "
                        "Step 2: follow the procedure carefully. Step 3: proceed as described.")
        else:
            text = ("I can't help with that request. If you are working on something related and legitimate, "
                    "such as defending a system or learning the general background, I'm glad to help with that.")
        return text, len(system.split()) + len(user.split()), len(text.split())
