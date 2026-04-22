#!/bin/bash
# =============================================================================
# ION - Load Offline Deployment Bundle (air-gapped side)
# =============================================================================
# Run this on the air-gapped target after transferring an offline bundle
# built with scripts/build-offline-package.sh.
#
# Usage: run from inside the bundle directory
#   chmod +x load.sh && ./load.sh
#
# What it does:
#   1. Verifies MANIFEST.sha256
#   2. docker loads each image tarball (ION, pgvector, Ollama)
#   3. Restores the Ollama models volume (chat model + nomic-embed-text)
#   4. Idempotent — safe to re-run
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "=============================================="
echo "ION Offline Bundle Loader"
echo "=============================================="
echo "Bundle dir: ${SCRIPT_DIR}"
echo ""

# ----- Step 1: Integrity check -----
echo "[1/4] Verifying MANIFEST.sha256..."
if [ ! -f MANIFEST.sha256 ]; then
    echo "  ERROR: MANIFEST.sha256 not found in bundle."
    echo "  Was this bundle built with build-offline-package.sh v0.10.9+?"
    exit 1
fi
if ! sha256sum -c --status MANIFEST.sha256; then
    echo "  ERROR: checksum mismatch. Bundle is corrupted or tampered."
    echo "  Re-run to see which files failed:"
    echo "    sha256sum -c MANIFEST.sha256 | grep -v OK"
    exit 1
fi
echo "  OK"

# ----- Step 2: Load Docker images -----
echo ""
echo "[2/4] Loading Docker images..."
for img in images/*.tar.gz; do
    echo "  - ${img}"
    gunzip -c "${img}" | docker load | tail -1
done

# ----- Step 3: Restore Ollama models volume -----
echo ""
echo "[3/4] Restoring Ollama models volume..."

# Determine compose project name (directory name by default)
# The ollama-models volume will be <project>_ollama-models.
PROJECT_NAME="$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')"
# Allow override via env (matches compose's COMPOSE_PROJECT_NAME behaviour)
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${PROJECT_NAME}}"
OLLAMA_VOL="${PROJECT_NAME}_ollama-models"

echo "  Target volume: ${OLLAMA_VOL}"

# Create volume if missing (idempotent — existing volume keeps its contents
# unless overwritten by the tar extract below)
docker volume create "${OLLAMA_VOL}" > /dev/null

if [ -f models/ollama-models.tar.gz ]; then
    # Guard against clobbering an existing, larger models volume with an
    # older bundle. If the volume already has data, warn and ask.
    HAS_EXISTING=$(docker run --rm -v "${OLLAMA_VOL}":/check:ro alpine \
        sh -c "find /check -type f | head -1" 2>/dev/null || true)
    if [ -n "${HAS_EXISTING}" ]; then
        echo "  NOTE: ${OLLAMA_VOL} already has data."
        echo "        This bundle will extract ON TOP of it (tar merge)."
        echo "        If you want a clean restore, docker volume rm ${OLLAMA_VOL}"
        echo "        and re-run this script."
    fi
    docker run --rm \
        -v "${OLLAMA_VOL}":/dest \
        -v "$(pwd)/models":/backup:ro \
        alpine tar xzf /backup/ollama-models.tar.gz -C /dest
    echo "  OK — models restored"
else
    echo "  WARNING: models/ollama-models.tar.gz not found; skipping"
fi

# ----- Step 4: Print next-step commands -----
echo ""
echo "[4/4] Done"
echo ""
echo "=============================================="
echo "Next steps"
echo "=============================================="
echo ""
echo "1. Review/edit .env (admin password, feature flags, integrations)"
echo "2. Start the stack:"
echo "     docker compose --profile ai up -d"
echo "3. Watch the health come up:"
echo "     docker compose ps"
echo "     curl -s http://localhost:8000/api/health"
echo "4. Login: admin / \$ION_ADMIN_PASSWORD"
echo ""
echo "If you want case similarity + KB RAG turned on, uncomment these in .env:"
echo "   ION_EMBEDDING_ENABLED=true"
echo "   ION_FEW_SHOT_EXEMPLARS_ENABLED=true"
echo "   ION_KB_RAG_ENABLED=true"
echo "(The ${EMBED_MODEL:-nomic-embed-text} model is already in the bundle.)"
echo ""
