#!/usr/bin/env bash
# Starts both inference servers natively (Metal GPU), with all state inside the repo.
#   ollama        -> http://127.0.0.1:11434   (provider "ollama")
#   llama-server  -> http://127.0.0.1:8081    (provider "llamacpp")
# Logs: local/tmp/ollama.log, local/tmp/llama-server.log. Stop with: scripts/run_llm_runtimes.sh stop
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/local/tools"
MODELS="$ROOT/local/models"
LOGS="$ROOT/local/tmp"
mkdir -p "$LOGS"

if [[ "${1:-start}" == "stop" ]]; then
  pkill -f "$TOOLS/ollama/ollama serve" || true
  pkill -f "$TOOLS/llama.cpp/llama-server" || true
  exit 0
fi

# Docker containers reach the host via host.docker.internal, so listen on all interfaces.
HOME="$TOOLS/ollama/home" OLLAMA_MODELS="$MODELS/ollama" OLLAMA_HOST=0.0.0.0:11434 \
  nohup "$TOOLS/ollama/ollama" serve >"$LOGS/ollama.log" 2>&1 &

GGUF="$(ls "$MODELS"/gguf/*.gguf | head -1)"
nohup "$TOOLS/llama.cpp/llama-server" -m "$GGUF" --alias llama-3.2-3b-instruct \
  --host 0.0.0.0 --port 8081 -c 8192 -ngl 99 --jinja >"$LOGS/llama-server.log" 2>&1 &

for _ in $(seq 1 60); do
  if curl -fs http://127.0.0.1:11434/api/version >/dev/null && curl -fs http://127.0.0.1:8081/health >/dev/null; then
    echo "ollama and llama-server are up"; exit 0
  fi
  sleep 1
done
echo "servers did not come up; see $LOGS" >&2
exit 1
