#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$ROOT_DIR/.." && pwd)"
VENV_DIR="${VENV_DIR:-$WORKSPACE_DIR/.venv-cybertron-ml}"
HF_HOME="${HF_HOME:-$WORKSPACE_DIR/.cache/huggingface}"
BOOTSTRAP_DATASET="$ROOT_DIR/data/cybertron_bootstrap_sft.jsonl"
REVIEWED_DATASET="$ROOT_DIR/data/cybertron_enterprise_training_corpus.jsonl"
DEFAULT_DATASET="$ROOT_DIR/data/cybertron_training_corpus.jsonl"
USER_DATASET_PATH="${DATASET_PATH:-}"
DATASET_PATH="${USER_DATASET_PATH:-}"
USE_CURRENT_ENV="${USE_CURRENT_ENV:-0}"

if [[ -z "$DATASET_PATH" && -f "$REVIEWED_DATASET" ]]; then
  DATASET_PATH="$REVIEWED_DATASET"
fi

if [[ -z "$DATASET_PATH" && -f "$DEFAULT_DATASET" ]]; then
  DATASET_PATH="$DEFAULT_DATASET"
fi

if [[ -z "$DATASET_PATH" || ! -f "$DATASET_PATH" ]]; then
  DATASET_PATH="$BOOTSTRAP_DATASET"
fi

MODEL_NAME="${MODEL_NAME:-Qwen/Qwen2.5-3B-Instruct}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/outputs/cybertron-qwen25-3b-lora}"
NUM_TRAIN_EPOCHS="${NUM_TRAIN_EPOCHS:-6}"
MAX_STEPS="${MAX_STEPS:-0}"
PER_DEVICE_BATCH_SIZE="${PER_DEVICE_BATCH_SIZE:-2}"
GRADIENT_ACCUMULATION_STEPS="${GRADIENT_ACCUMULATION_STEPS:-8}"
LEARNING_RATE="${LEARNING_RATE:-2e-4}"
MAX_LENGTH="${MAX_LENGTH:-1024}"
LORA_RANK="${LORA_RANK:-32}"
LORA_ALPHA="${LORA_ALPHA:-64}"
LORA_DROPOUT="${LORA_DROPOUT:-0.05}"
LOGGING_STEPS="${LOGGING_STEPS:-5}"
SAVE_STEPS="${SAVE_STEPS:-25}"
SAVE_TOTAL_LIMIT="${SAVE_TOTAL_LIMIT:-2}"
WARMUP_RATIO="${WARMUP_RATIO:-0.03}"

mkdir -p "$HF_HOME" "$WORKSPACE_DIR/.cache"

if [[ "$USE_CURRENT_ENV" != "1" ]]; then
  if python -m venv --system-site-packages "$VENV_DIR"; then
    source "$VENV_DIR/bin/activate"
  else
    echo "Venv creation failed; reusing the current Python environment instead." >&2
  fi
fi

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "$ROOT_DIR/requirements-h100.txt"

echo "== Cybertron H100 training =="
echo "dataset: $DATASET_PATH"
echo "model:   $MODEL_NAME"
echo "output:  $OUTPUT_DIR"

ARGS=(
  "$ROOT_DIR/train_cybertron_lora.py"
  --dataset "$DATASET_PATH"
  --model-name "$MODEL_NAME"
  --output-dir "$OUTPUT_DIR"
  --per-device-batch-size "$PER_DEVICE_BATCH_SIZE"
  --gradient-accumulation-steps "$GRADIENT_ACCUMULATION_STEPS"
  --learning-rate "$LEARNING_RATE"
  --max-length "$MAX_LENGTH"
  --lora-rank "$LORA_RANK"
  --lora-alpha "$LORA_ALPHA"
  --lora-dropout "$LORA_DROPOUT"
  --logging-steps "$LOGGING_STEPS"
  --save-steps "$SAVE_STEPS"
  --save-total-limit "$SAVE_TOTAL_LIMIT"
  --warmup-ratio "$WARMUP_RATIO"
)

if [[ "${NUM_TRAIN_EPOCHS}" != "0" ]]; then
  ARGS+=(--num-train-epochs "$NUM_TRAIN_EPOCHS")
else
  ARGS+=(--max-steps "$MAX_STEPS")
fi

python "${ARGS[@]}"
