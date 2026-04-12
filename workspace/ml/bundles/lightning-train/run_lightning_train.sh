#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATASET_PATH="${DATASET_PATH:-$ROOT_DIR/data/cybertron_training_corpus.jsonl}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/outputs/bootstrap-risk-policy-threat}"
MODEL_NAME="${MODEL_NAME:-Qwen/Qwen2.5-7B-Instruct}"
MAX_STEPS="${MAX_STEPS:-0}"
NUM_TRAIN_EPOCHS="${NUM_TRAIN_EPOCHS:-6}"
PER_DEVICE_BATCH_SIZE="${PER_DEVICE_BATCH_SIZE:-1}"
GRADIENT_ACCUMULATION_STEPS="${GRADIENT_ACCUMULATION_STEPS:-16}"
MAX_LENGTH="${MAX_LENGTH:-1536}"
LORA_RANK="${LORA_RANK:-32}"
LORA_ALPHA="${LORA_ALPHA:-64}"
LORA_DROPOUT="${LORA_DROPOUT:-0.05}"
SAVE_STEPS="${SAVE_STEPS:-50}"
WARMUP_RATIO="${WARMUP_RATIO:-0.05}"

echo "== Lightning training run =="
echo "ROOT_DIR=$ROOT_DIR"
echo "DATASET_PATH=$DATASET_PATH"
echo "OUTPUT_DIR=$OUTPUT_DIR"
echo "MODEL_NAME=$MODEL_NAME"
echo "MAX_STEPS=$MAX_STEPS"
echo "NUM_TRAIN_EPOCHS=$NUM_TRAIN_EPOCHS"

python -m pip install --upgrade pip
pip install -r "$ROOT_DIR/requirements.txt"

python - <<'PY'
import json
import torch

report = {
    "gpuReady": torch.cuda.is_available(),
    "deviceCount": torch.cuda.device_count(),
    "deviceName": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
    "cudaVersion": torch.version.cuda,
}
print(json.dumps(report, indent=2))

if not torch.cuda.is_available():
    raise SystemExit("No CUDA GPU detected. Stop here instead of burning time on CPU.")
PY

python "$ROOT_DIR/train_cybertron_lora.py" \
  --dataset "$DATASET_PATH" \
  --model-name "$MODEL_NAME" \
  --output-dir "$OUTPUT_DIR" \
  --max-steps "$MAX_STEPS" \
  --num-train-epochs "$NUM_TRAIN_EPOCHS" \
  --per-device-batch-size "$PER_DEVICE_BATCH_SIZE" \
  --gradient-accumulation-steps "$GRADIENT_ACCUMULATION_STEPS" \
  --max-length "$MAX_LENGTH" \
  --lora-rank "$LORA_RANK" \
  --lora-alpha "$LORA_ALPHA" \
  --lora-dropout "$LORA_DROPOUT" \
  --save-steps "$SAVE_STEPS" \
  --warmup-ratio "$WARMUP_RATIO"

tar -czf "$OUTPUT_DIR.tar.gz" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"

echo "Training finished."
echo "Adapter directory: $OUTPUT_DIR"
echo "Packed archive: $OUTPUT_DIR.tar.gz"
