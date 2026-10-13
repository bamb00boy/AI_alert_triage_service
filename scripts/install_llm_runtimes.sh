#!/usr/bin/env bash
# Installs Ollama and llama.cpp (portable macOS builds) and one model for each, entirely
# inside this repo: binaries in local/tools/, models in local/models/. Nothing is written
# to Homebrew, ~/.ollama or ~/Library/Caches.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/local/tools"
MODELS="$ROOT/local/models"
OLLAMA_VERSION="${OLLAMA_VERSION:-v0.40.3}"
LLAMACPP_BUILD="${LLAMACPP_BUILD:-b11572}"
OLLAMA_MODEL="${TRIAGE_OLLAMA_MODEL:-qwen3:4b-instruct}"
GGUF_URL="${GGUF_URL:-https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf}"

mkdir -p "$TOOLS/ollama" "$TOOLS/llama.cpp" "$MODELS/ollama" "$MODELS/gguf"

if [[ ! -x "$TOOLS/ollama/ollama" ]]; then
  echo "ollama $OLLAMA_VERSION"
  curl -fsSL "https://github.com/ollama/ollama/releases/download/$OLLAMA_VERSION/ollama-darwin.tgz" | tar xz -C "$TOOLS/ollama"
fi

if [[ ! -x "$TOOLS/llama.cpp/llama-server" ]]; then
  echo "llama.cpp $LLAMACPP_BUILD"
  curl -fsSL "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMACPP_BUILD/llama-$LLAMACPP_BUILD-bin-macos-arm64.tar.gz" \
    | tar xz -C "$TOOLS/llama.cpp" --strip-components=1
fi

GGUF="$MODELS/gguf/$(basename "$GGUF_URL")"
if [[ ! -s "$GGUF" ]]; then
  echo "gguf $(basename "$GGUF")"
  curl -fL --retry 3 -o "$GGUF.part" "$GGUF_URL" && mv "$GGUF.part" "$GGUF"
fi

# Pull the Ollama model with a throwaway server whose HOME and model dir are inside the repo.
export HOME="$TOOLS/ollama/home" OLLAMA_MODELS="$MODELS/ollama" OLLAMA_HOST=127.0.0.1:11434
mkdir -p "$HOME"
"$TOOLS/ollama/ollama" serve >/dev/null 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -fs http://127.0.0.1:11434/api/version >/dev/null && break; sleep 1; done
"$TOOLS/ollama/ollama" pull "$OLLAMA_MODEL"
echo "done: $(du -sh "$ROOT/local" | cut -f1) in local/"
