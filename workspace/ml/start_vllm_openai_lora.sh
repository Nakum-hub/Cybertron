#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$ROOT_DIR/.." && pwd)"
HF_HOME="${HF_HOME:-$WORKSPACE_DIR/.cache/huggingface}"
CONTAINER_NAME="${CONTAINER_NAME:-cybertron-vllm}"
DOCKER_IMAGE="${DOCKER_IMAGE:-vllm/vllm-openai:latest}"
DEFAULT_1_5B_MODEL="Qwen/Qwen2.5-1.5B-Instruct"
DEFAULT_3B_MODEL="Qwen/Qwen2.5-3B-Instruct"
DEFAULT_14B_MODEL="Qwen/Qwen2.5-14B-Instruct"
DEFAULT_1_5B_ADAPTER="$ROOT_DIR/outputs/cybertron-qwen25-1_5b-t4-lora"
DEFAULT_3B_ADAPTER="$ROOT_DIR/outputs/cybertron-qwen25-3b-lora"
DEFAULT_14B_ADAPTER="$ROOT_DIR/outputs/cybertron-qwen25-14b-lora"

detect_gpu_memory_mib() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    return 1
  fi

  nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -n 1
}

GPU_MEMORY_MIB="${GPU_MEMORY_MIB:-}"
if [[ -z "$GPU_MEMORY_MIB" ]]; then
  GPU_MEMORY_MIB="$(detect_gpu_memory_mib || true)"
fi

prefer_t4_adapter="0"
if [[ -n "$GPU_MEMORY_MIB" ]] && [[ "$GPU_MEMORY_MIB" =~ ^[0-9]+$ ]] && (( GPU_MEMORY_MIB <= 24576 )); then
  prefer_t4_adapter="1"
fi

if [[ -n "${ADAPTER_PATH:-}" ]]; then
  SELECTED_ADAPTER_PATH="$ADAPTER_PATH"
elif [[ "$prefer_t4_adapter" == "1" && -d "$DEFAULT_1_5B_ADAPTER" ]]; then
  SELECTED_ADAPTER_PATH="$DEFAULT_1_5B_ADAPTER"
elif [[ -d "$DEFAULT_14B_ADAPTER" ]]; then
  SELECTED_ADAPTER_PATH="$DEFAULT_14B_ADAPTER"
elif [[ -d "$DEFAULT_3B_ADAPTER" ]]; then
  SELECTED_ADAPTER_PATH="$DEFAULT_3B_ADAPTER"
else
  SELECTED_ADAPTER_PATH="$DEFAULT_1_5B_ADAPTER"
fi

if [[ -n "${BASE_MODEL:-}" ]]; then
  SELECTED_BASE_MODEL="$BASE_MODEL"
elif [[ "$SELECTED_ADAPTER_PATH" == "$DEFAULT_14B_ADAPTER" ]]; then
  SELECTED_BASE_MODEL="$DEFAULT_14B_MODEL"
elif [[ "$SELECTED_ADAPTER_PATH" == "$DEFAULT_3B_ADAPTER" ]]; then
  SELECTED_BASE_MODEL="$DEFAULT_3B_MODEL"
else
  SELECTED_BASE_MODEL="$DEFAULT_1_5B_MODEL"
fi

BASE_MODEL="$SELECTED_BASE_MODEL"
ADAPTER_PATH="$SELECTED_ADAPTER_PATH"
ADAPTER_ALIAS="${ADAPTER_ALIAS:-cybertron}"
SERVED_MODEL_NAME="${SERVED_MODEL_NAME:-cybertron-local}"
VLLM_PORT="${VLLM_PORT:-8000}"
if [[ -n "${MAX_MODEL_LEN:-}" ]]; then
  MAX_MODEL_LEN="$MAX_MODEL_LEN"
elif [[ "$ADAPTER_PATH" == "$DEFAULT_14B_ADAPTER" ]]; then
  MAX_MODEL_LEN="8192"
elif [[ "$ADAPTER_PATH" == "$DEFAULT_1_5B_ADAPTER" ]]; then
  MAX_MODEL_LEN="4096"
else
  MAX_MODEL_LEN="16384"
fi
MAX_LORA_RANK="${MAX_LORA_RANK:-64}"
OPENAI_API_KEY="${OPENAI_API_KEY:-cybertron-local-key}"
GPU_MEMORY_UTILIZATION="${GPU_MEMORY_UTILIZATION:-}"
MAX_NUM_SEQS="${MAX_NUM_SEQS:-}"
ENFORCE_EAGER="${ENFORCE_EAGER:-0}"

if [[ "$ADAPTER_PATH" == "$DEFAULT_1_5B_ADAPTER" ]] || [[ "$prefer_t4_adapter" == "1" ]]; then
  if [[ -z "$GPU_MEMORY_UTILIZATION" ]]; then
    GPU_MEMORY_UTILIZATION="0.82"
  fi
  if [[ -z "$MAX_NUM_SEQS" ]]; then
    MAX_NUM_SEQS="8"
  fi
  if [[ "${ENFORCE_EAGER:-0}" != "1" ]]; then
    ENFORCE_EAGER="1"
  fi
fi

if [[ ! -d "$ADAPTER_PATH" ]]; then
  echo "Adapter directory not found: $ADAPTER_PATH" >&2
  echo "Run 'npm run ml:train:h100 --prefix workspace' first or set ADAPTER_PATH." >&2
  exit 1
fi

mkdir -p "$HF_HOME"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "== Cybertron local vLLM server =="
echo "image:   $DOCKER_IMAGE"
echo "model:   $BASE_MODEL"
echo "adapter: $ADAPTER_PATH"
echo "listen:  http://127.0.0.1:${VLLM_PORT}/v1"
echo "served:  $SERVED_MODEL_NAME"
echo "lora-rk: $MAX_LORA_RANK"
echo "ctx-len: $MAX_MODEL_LEN"
if [[ -n "$GPU_MEMORY_MIB" ]]; then
  echo "gpu-mem: ${GPU_MEMORY_MIB} MiB"
fi
if [[ -n "$GPU_MEMORY_UTILIZATION" ]]; then
  echo "gpu-util: $GPU_MEMORY_UTILIZATION"
fi
if [[ -n "$MAX_NUM_SEQS" ]]; then
  echo "max-seqs: $MAX_NUM_SEQS"
fi
if [[ "$ENFORCE_EAGER" == "1" ]]; then
  echo "eager:   enabled"
fi

VLLM_ARGS=(
  --model "$BASE_MODEL"
  --served-model-name "$SERVED_MODEL_NAME"
  --api-key "$OPENAI_API_KEY"
  --host 0.0.0.0
  --port 8000
  --max-model-len "$MAX_MODEL_LEN"
  --max-lora-rank "$MAX_LORA_RANK"
  --enable-lora
  --lora-modules "${ADAPTER_ALIAS}=/adapters/cybertron-lora"
)

if [[ -n "$GPU_MEMORY_UTILIZATION" ]]; then
  VLLM_ARGS+=(--gpu-memory-utilization "$GPU_MEMORY_UTILIZATION")
fi
if [[ -n "$MAX_NUM_SEQS" ]]; then
  VLLM_ARGS+=(--max-num-seqs "$MAX_NUM_SEQS")
fi
if [[ "$ENFORCE_EAGER" == "1" ]]; then
  VLLM_ARGS+=(--enforce-eager)
fi

exec docker run \
  --rm \
  --gpus all \
  --ipc=host \
  --name "$CONTAINER_NAME" \
  -p "${VLLM_PORT}:8000" \
  -e HUGGING_FACE_HUB_TOKEN="${HUGGING_FACE_HUB_TOKEN:-}" \
  -v "$HF_HOME:/root/.cache/huggingface" \
  -v "$ADAPTER_PATH:/adapters/cybertron-lora:ro" \
  "$DOCKER_IMAGE" \
  "${VLLM_ARGS[@]}"
