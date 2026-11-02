#!/usr/bin/env bash
# Security resilience the way NVIDIA's safety recipe measures it: the garak vulnerability scanner
# (https://github.com/NVIDIA/garak) against the same OpenAI-compatible endpoint the harness uses.
# Reports a resilience score per probe family; put the summary next to results/report.md.
#   pip install garak
#   export OPENAI_API_KEY=$NVIDIA_API_KEY OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1
#   bash scripts/garak.sh nvidia/llama-3.1-nemotron-nano-8b-v1
set -euo pipefail
MODEL="${1:-nvidia/llama-3.1-nemotron-nano-8b-v1}"
python -m garak --model_type openai.OpenAICompatible --model_name "$MODEL" \
  --probes promptinject,dan,encoding,leakreplay,malwaregen,xss,latentinjection \
  --report_prefix results/garak_$(echo "$MODEL" | tr '/' '_')
