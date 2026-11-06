"""Serve the target model (and its fine-tuned adapter) as an OpenAI-compatible endpoint on Modal, so the
Temporal worker on a laptop can drive the real model with no hosted-API rate limit.

    modal deploy modal_app/serve.py                      # prints the https URL; one L4, scales to zero
    export MRL_SERVE_KEY=...                             # the bearer token the server was deployed with

    incident temporal --real --base-url https://<app>.modal.run/v1 --api-key $MRL_SERVE_KEY \\
        --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --system nano --guard none --out results/temporal/inc_nano_none.jsonl
    incident temporal --real --base-url https://<app>.modal.run/v1 --api-key $MRL_SERVE_KEY \\
        --model nemotron-nano-8b-incident-lora --system lora --guard phrouros --out results/temporal/inc_lora_phrouros.jsonl

vLLM's own `vllm serve` runs inside the container with `--enable-lora`; the adapter is a second served
model name, so the same endpoint answers for the base model and for the fine-tune. The bearer token comes
from the Modal secret `mrl-serve` (key `MRL_SERVE_KEY`); create it once with
`modal secret create mrl-serve MRL_SERVE_KEY=$(openssl rand -hex 24)`.
"""

from __future__ import annotations

import os
import subprocess

import modal

APP = "model-risk-lab"
TARGET_MODEL = os.environ.get("NMR_TARGET", "nvidia/Llama-3.1-Nemotron-Nano-8B-v1")
ADAPTER = os.environ.get("NMR_ADAPTER", "nemotron-nano-8b-incident-lora")
VOL = modal.Volume.from_name(f"{APP}-vol", create_if_missing=True)
VOL_PATH = "/vol"
PORT = 8000

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("vllm>=0.11.0,<0.21", "hf_transfer")
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HOME": f"{VOL_PATH}/hf", "VLLM_USE_V1": "1"})
)

app = modal.App(f"{APP}-serve", image=image)
secrets = [modal.Secret.from_name("mrl-serve", required_keys=["MRL_SERVE_KEY"])]


@app.function(gpu="L4", volumes={VOL_PATH: VOL}, secrets=secrets, timeout=60 * 60, scaledown_window=10 * 60,
              min_containers=0)
@modal.concurrent(max_inputs=64)
@modal.web_server(port=PORT, startup_timeout=20 * 60)
def serve() -> None:
    """vLLM OpenAI-compatible server: base model plus the LoRA adapter as a second model name."""
    cmd = [
        "vllm", "serve", TARGET_MODEL,
        "--host", "0.0.0.0", "--port", str(PORT),
        "--dtype", "bfloat16", "--max-model-len", "4096", "--gpu-memory-utilization", "0.90",
        "--enable-lora", "--max-lora-rank", "64", "--lora-modules", f"{ADAPTER}={VOL_PATH}/adapters/{ADAPTER}",
        "--api-key", os.environ["MRL_SERVE_KEY"],
        "--served-model-name", TARGET_MODEL,
    ]
    subprocess.Popen(cmd)
