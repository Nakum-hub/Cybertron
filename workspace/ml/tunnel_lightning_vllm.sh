#!/usr/bin/env bash
set -euo pipefail

LIGHTNING_SSH_TARGET="${LIGHTNING_SSH_TARGET:-${SSH_TARGET:-}}"
LIGHTNING_SSH_KEY_PATH="${LIGHTNING_SSH_KEY_PATH:-${SSH_KEY_PATH:-}}"
LOCAL_PORT="${LOCAL_PORT:-18000}"
REMOTE_VLLM_HOST="${REMOTE_VLLM_HOST:-127.0.0.1}"
REMOTE_VLLM_PORT="${REMOTE_VLLM_PORT:-8000}"

if [[ -z "$LIGHTNING_SSH_TARGET" ]]; then
  echo "Missing LIGHTNING_SSH_TARGET (or SSH_TARGET)." >&2
  echo "Example: export LIGHTNING_SSH_TARGET=user@your-lightning-host" >&2
  exit 1
fi

SSH_ARGS=(
  -N
  -L "${LOCAL_PORT}:${REMOTE_VLLM_HOST}:${REMOTE_VLLM_PORT}"
  -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=3
)

if [[ -n "$LIGHTNING_SSH_KEY_PATH" ]]; then
  SSH_ARGS+=(-i "$LIGHTNING_SSH_KEY_PATH")
fi

echo "== Cybertron Lightning vLLM tunnel =="
echo "ssh target:  ${LIGHTNING_SSH_TARGET}"
echo "remote vLLM: ${REMOTE_VLLM_HOST}:${REMOTE_VLLM_PORT}"
echo "local bind:  127.0.0.1:${LOCAL_PORT}"
echo
echo "After the tunnel is up, point Cybertron at the GPU-backed endpoint:"
echo "  export LLM_PROVIDER=openai"
echo "  export OPENAI_BASE_URL=http://127.0.0.1:${LOCAL_PORT}/v1"
echo "  export OPENAI_API_KEY=<same token used by the remote vLLM server>"
echo "  export OPENAI_MODEL=cybertron-local"
echo
echo "Cybertron Threat Command will then report the runtime as self_hosted_tunnel"
echo "from /v1/threat-intel/ai/runtime when the endpoint is reachable."

exec ssh "${SSH_ARGS[@]}" "$LIGHTNING_SSH_TARGET"
