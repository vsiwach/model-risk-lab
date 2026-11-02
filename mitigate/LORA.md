# LoRA safety fine-tune

`modal run modal_app/app.py::build_sft` writes `sft.jsonl` here (self-distilled under the rails:
harmful prompts -> refusal or guard-approved safe completion; benign prompts -> the base model's own
answer when the guard calls it safe). `modal run modal_app/app.py::train` runs QLoRA (nf4, r=32,
alpha=64, 2 epochs, lr 1e-4) on an A100-40GB and copies the adapter to `out/<name>/`.

Evaluate with `modal run modal_app/app.py::evaluate --system lora --adapter <name>` or locally with
`nmr run --backend hf --model nvidia/Llama-3.1-Nemotron-Nano-8B-v1 --adapter lora/out/<name> ...`.
