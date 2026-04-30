#!/usr/bin/env bash
# scripts/ollama_import_gguf.sh — import a GGUF embedding model into the
# running Ollama container as a named model.
#
# Why: ION's case-embedding background task talks to Ollama and asks for
# whatever ``ION_EMBEDDING_MODEL`` resolves to (default: nomic-embed-text).
# Some sites want to pin to a specific Hugging Face GGUF build (e.g. the
# v1.5 release with longer context + task-prefix support) rather than
# whatever Ollama's library ships. This script downloads the GGUF and
# registers it as a named Ollama model via ``ollama create``.
#
# Air-gapped use:
#   1. On a connected box, run with --download-only to fetch the GGUF.
#   2. Copy the .gguf file across to the air-gapped network.
#   3. On the air-gapped box, run with --gguf <path> to skip the download
#      and only register the model.
#
# Usage:
#   ./scripts/ollama_import_gguf.sh                          # default v1.5 Q4_K_M
#   ./scripts/ollama_import_gguf.sh --quant Q8_0             # higher quality (~140 MB)
#   ./scripts/ollama_import_gguf.sh --gguf /path/to/file.gguf
#   ./scripts/ollama_import_gguf.sh --download-only --out /tmp/nomic.gguf
#   ./scripts/ollama_import_gguf.sh --name my-embed --gguf /path/to/file.gguf
#
# Defaults:
#   model name in Ollama:  nomic-embed-text-v1.5
#   GGUF source URL:       huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF
#   quant:                 Q4_K_M (~81 MiB)
#   ollama container:      ion-ollama (overridable with ION_OLLAMA_CONTAINER)
#
# Set ION_EMBEDDING_MODEL=nomic-embed-text-v1.5 (or whatever --name you
# pass) in .env after import so the embedding service picks it up.

set -euo pipefail

# Stop Git Bash on Windows from mangling /tmp/... into C:/Users/.../Temp/...
# inside `docker exec` arguments. No-op on Linux/macOS — defensive.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

MODEL_NAME="nomic-embed-text-v1.5"
QUANT="Q4_K_M"
GGUF_PATH=""
DOWNLOAD_ONLY=0
OUT_PATH=""
HF_REPO="nomic-ai/nomic-embed-text-v1.5-GGUF"
OLLAMA_CTR="${ION_OLLAMA_CONTAINER:-ion-ollama}"

usage() {
  sed -n '2,30p' "$0"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --name)            MODEL_NAME="$2"; shift 2 ;;
    --quant)           QUANT="$2"; shift 2 ;;
    --gguf)            GGUF_PATH="$2"; shift 2 ;;
    --download-only)   DOWNLOAD_ONLY=1; shift ;;
    --out)             OUT_PATH="$2"; shift 2 ;;
    --repo)            HF_REPO="$2"; shift 2 ;;
    -h|--help)         usage ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ── Step 1: locate or download the GGUF ───────────────────────────────────
if [ -z "$GGUF_PATH" ]; then
  GGUF_FILENAME="nomic-embed-text-v1.5.${QUANT}.gguf"
  GGUF_URL="https://huggingface.co/${HF_REPO}/resolve/main/${GGUF_FILENAME}"
  GGUF_PATH="${OUT_PATH:-/tmp/${GGUF_FILENAME}}"

  if [ -f "$GGUF_PATH" ]; then
    echo "Using existing file: $GGUF_PATH ($(du -h "$GGUF_PATH" | cut -f1))"
  else
    echo "Downloading $GGUF_FILENAME from Hugging Face..."
    echo "  Source: $GGUF_URL"
    echo "  Target: $GGUF_PATH"
    if command -v curl >/dev/null 2>&1; then
      curl -L --fail --progress-bar -o "$GGUF_PATH" "$GGUF_URL"
    elif command -v wget >/dev/null 2>&1; then
      wget --progress=bar:force -O "$GGUF_PATH" "$GGUF_URL"
    else
      echo "Neither curl nor wget found; install one or pass --gguf <path>" >&2
      exit 1
    fi
    echo "Downloaded: $(du -h "$GGUF_PATH" | cut -f1)"
  fi
fi

if [ "$DOWNLOAD_ONLY" -eq 1 ]; then
  echo "--download-only: GGUF available at $GGUF_PATH"
  echo "Re-run without --download-only on the target host (with --gguf $GGUF_PATH) to register."
  exit 0
fi

# ── Step 2: confirm the Ollama container is running ───────────────────────
if ! docker inspect "$OLLAMA_CTR" >/dev/null 2>&1; then
  echo "Ollama container '$OLLAMA_CTR' not found." >&2
  echo "Start it (typically: docker compose --profile ai up -d ollama)" >&2
  echo "or override: ION_OLLAMA_CONTAINER=<name> $0" >&2
  exit 1
fi

# ── Step 3: copy GGUF into the Ollama container + write a Modelfile ──────
echo "Copying GGUF into ${OLLAMA_CTR}:/tmp/import.gguf..."
docker cp "$GGUF_PATH" "${OLLAMA_CTR}:/tmp/import.gguf"

# Modelfile for an embedding model — stays minimal; nomic-embed-text-v1.5
# does its own task-prefix handling on the input side.
MODELFILE_BODY='FROM /tmp/import.gguf'
echo "Writing Modelfile..."
docker exec -i "$OLLAMA_CTR" sh -c 'cat > /tmp/Modelfile' <<<"$MODELFILE_BODY"

# ── Step 4: ollama create — register under MODEL_NAME ────────────────────
echo "Registering as Ollama model: $MODEL_NAME"
docker exec "$OLLAMA_CTR" ollama create "$MODEL_NAME" -f /tmp/Modelfile

# ── Step 5: cleanup + sanity check ───────────────────────────────────────
docker exec "$OLLAMA_CTR" rm -f /tmp/import.gguf /tmp/Modelfile

echo
echo "Models now registered in Ollama:"
docker exec "$OLLAMA_CTR" ollama list | head -20

echo
echo "Done. Set the following in .env so ION uses the imported model:"
echo "  ION_EMBEDDING_ENABLED=true"
echo "  ION_EMBEDDING_MODEL=${MODEL_NAME}"
echo
echo "Then restart the ion service:"
echo "  docker compose up -d --force-recreate ion"
