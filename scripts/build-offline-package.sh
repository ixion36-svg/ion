#!/bin/bash
# =============================================================================
# ION - Build Offline Deployment Package (v0.10.9+)
# =============================================================================
# Run this script on a machine WITH internet access to create an air-gapped
# deployment bundle that can be transferred to the secure environment.
#
# Usage:
#   ./scripts/build-offline-package.sh [ion_version] [chat_model] [pg_version]
#
# Examples:
#   ./scripts/build-offline-package.sh 0.10.9
#   ./scripts/build-offline-package.sh 0.10.9 llama3.1:8b pg17
#
# What this bundles (v0.10.4+ needs these — previous script missed them):
#   - ixion36/ion:<VERSION>     Application image
#   - pgvector/pgvector:<PG>    Postgres + pgvector (not plain postgres!)
#   - ollama/ollama:latest      LLM host
#   - Chat model                Bob's reasoning (default llama3.1:8b)
#   - nomic-embed-text          Embeddings for case similarity + KB RAG
#                               (NEW in v0.10.4 — silent-fail without it)
# =============================================================================

set -e

VERSION="${1:-0.10.16}"
CHAT_MODEL="${2:-llama3.1:8b}"
PG_VERSION="${3:-pg16}"
EMBED_MODEL="nomic-embed-text"
PACKAGE_NAME="ion-offline-${VERSION}"
OUTPUT_DIR="./dist/${PACKAGE_NAME}"

echo "=============================================="
echo "ION Offline Bundle Builder"
echo "=============================================="
echo "  ION version : ${VERSION}"
echo "  Chat model  : ${CHAT_MODEL}"
echo "  Embed model : ${EMBED_MODEL}  (required for case similarity + KB RAG)"
echo "  PG major    : ${PG_VERSION}   (pgvector/pgvector:${PG_VERSION})"
echo "=============================================="

# ----- Output layout -----
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/images"
mkdir -p "${OUTPUT_DIR}/models"
mkdir -p "${OUTPUT_DIR}/deploy"
mkdir -p "${OUTPUT_DIR}/deploy/nginx"
mkdir -p "${OUTPUT_DIR}/deploy/ssl"

# ----- Step 1: ION image -----
echo ""
echo "[1/7] Pulling ION application image..."
docker pull "ixion36/ion:${VERSION}"
docker save "ixion36/ion:${VERSION}" | gzip > "${OUTPUT_DIR}/images/ion-${VERSION}.tar.gz"

# ----- Step 2: Postgres (pgvector) image -----
echo ""
echo "[2/7] Pulling Postgres (pgvector/pgvector:${PG_VERSION})..."
docker pull "pgvector/pgvector:${PG_VERSION}"
docker save "pgvector/pgvector:${PG_VERSION}" | gzip > "${OUTPUT_DIR}/images/pgvector-${PG_VERSION}.tar.gz"

# ----- Step 3: Ollama image -----
echo ""
echo "[3/7] Pulling Ollama image..."
docker pull ollama/ollama:latest
docker save ollama/ollama:latest | gzip > "${OUTPUT_DIR}/images/ollama-latest.tar.gz"

# ----- Step 4: Pre-populate Ollama models (chat + embedding) -----
echo ""
echo "[4/7] Pre-populating Ollama models (${CHAT_MODEL} + ${EMBED_MODEL})..."

TEMP_OLLAMA_VOL="ion-ollama-prep-$(date +%s)"
docker volume create "${TEMP_OLLAMA_VOL}" > /dev/null

docker run -d --name ion-ollama-prep \
  -v "${TEMP_OLLAMA_VOL}":/root/.ollama \
  ollama/ollama:latest > /dev/null
sleep 4

echo "      Pulling chat model: ${CHAT_MODEL}..."
docker exec ion-ollama-prep ollama pull "${CHAT_MODEL}"
echo "      Pulling embed model: ${EMBED_MODEL}..."
docker exec ion-ollama-prep ollama pull "${EMBED_MODEL}"

echo "      Exporting models volume..."
docker run --rm \
  -v "${TEMP_OLLAMA_VOL}":/source:ro \
  -v "$(pwd)/${OUTPUT_DIR}/models":/dest \
  alpine tar czf /dest/ollama-models.tar.gz -C /source .

docker stop ion-ollama-prep > /dev/null
docker rm ion-ollama-prep > /dev/null
docker volume rm "${TEMP_OLLAMA_VOL}" > /dev/null

# ----- Step 5: Copy deployment files -----
echo ""
echo "[5/7] Copying deployment files..."
cp docker-compose.yml "${OUTPUT_DIR}/"
cp .env.example "${OUTPUT_DIR}/.env" 2>/dev/null || touch "${OUTPUT_DIR}/.env"
cp SETUP.md "${OUTPUT_DIR}/" 2>/dev/null || true
cp README.md "${OUTPUT_DIR}/" 2>/dev/null || true
cp CHANGELOG.md "${OUTPUT_DIR}/" 2>/dev/null || true
cp -r deploy/* "${OUTPUT_DIR}/deploy/" 2>/dev/null || true

# Stamp the .env with the versions this bundle was built for so the air-gap
# load step can't drift (compose default + bundled image must match).
{
  echo ""
  echo "# Stamped by build-offline-package.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ION_VERSION=${VERSION}"
  echo "PG_VERSION=${PG_VERSION}"
  echo "ION_OLLAMA_MODEL=${CHAT_MODEL}"
  echo "ION_EMBEDDING_MODEL=${EMBED_MODEL}"
  echo "# Opt-in feature flags — flip to true after load if you want them:"
  echo "# ION_EMBEDDING_ENABLED=true"
  echo "# ION_FEW_SHOT_EXEMPLARS_ENABLED=true"
  echo "# ION_KB_RAG_ENABLED=true"
} >> "${OUTPUT_DIR}/.env"

# Copy the load script into the bundle so the air-gap side has it.
cp scripts/load-offline-package.sh "${OUTPUT_DIR}/load.sh" 2>/dev/null || \
  echo "WARNING: scripts/load-offline-package.sh not found — bundle won't have a load helper"
chmod +x "${OUTPUT_DIR}/load.sh" 2>/dev/null || true

# ----- Step 6: README.txt -----
cat > "${OUTPUT_DIR}/README.txt" << README_EOF
================================================================================
ION Offline Deployment Bundle
  ION:    ixion36/ion:${VERSION}
  PG:     pgvector/pgvector:${PG_VERSION}
  Ollama: ollama/ollama:latest  +  ${CHAT_MODEL}  +  ${EMBED_MODEL}
================================================================================

CONTENTS

  images/
    ion-${VERSION}.tar.gz          — ION application
    pgvector-${PG_VERSION}.tar.gz            — Postgres + pgvector
    ollama-latest.tar.gz         — Ollama LLM host
  models/
    ollama-models.tar.gz         — ${CHAT_MODEL} + ${EMBED_MODEL}
  deploy/                         — nginx + HTTPS compose overrides
  docker-compose.yml              — v${VERSION} compose
  .env                            — stamped with ION_VERSION / PG_VERSION
  load.sh                         — Air-gapped-side loader
  MANIFEST.sha256                 — Integrity manifest
  README.txt                      — This file

DEPLOY (AIR-GAPPED SIDE)

  1. Copy this directory to the target machine.
  2. Verify integrity:
       sha256sum -c MANIFEST.sha256
  3. Run the loader:
       chmod +x load.sh && ./load.sh
  4. Start:
       docker compose --profile ai up -d
  5. Access http://localhost:8000 — login admin / <ION_ADMIN_PASSWORD in .env>.

OPT-IN FEATURES (uncomment in .env)

  # Case-similarity embeddings (pgvector-backed)
  ION_EMBEDDING_ENABLED=true

  # Few-shot gold exemplars in Bob's prompt
  ION_FEW_SHOT_EXEMPLARS_ENABLED=true

  # KB RAG grounding (embeds the ~392 seeded KB articles)
  ION_KB_RAG_ENABLED=true

All three require ${EMBED_MODEL} — already in this bundle.

WHY A BUNDLE REBUILD IS NEEDED TO UPGRADE

  ION's v0.10.4+ stack has THREE images that cross the gap (ION, pgvector,
  Ollama) and TWO models that must live inside the Ollama volume (chat +
  embedding). A pure ION-image update without re-loading the pgvector image
  and/or the models volume will leave you with a silent partial upgrade:
  the app runs but Similar Cases is empty and KB RAG contributes nothing.

README_EOF

# ----- Step 7: Manifest -----
echo ""
echo "[6/7] Writing MANIFEST.sha256..."
(cd "${OUTPUT_DIR}" && \
  find . -type f ! -name 'MANIFEST.sha256' -print0 | \
  xargs -0 sha256sum > MANIFEST.sha256)

echo ""
echo "[7/7] Bundle ready"

ION_SIZE=$(du -h "${OUTPUT_DIR}/images/ion-${VERSION}.tar.gz" | cut -f1)
PG_SIZE=$(du -h "${OUTPUT_DIR}/images/pgvector-${PG_VERSION}.tar.gz" | cut -f1)
OLLAMA_SIZE=$(du -h "${OUTPUT_DIR}/images/ollama-latest.tar.gz" | cut -f1)
MODEL_SIZE=$(du -h "${OUTPUT_DIR}/models/ollama-models.tar.gz" | cut -f1)
TOTAL_SIZE=$(du -sh "${OUTPUT_DIR}" | cut -f1)

echo ""
echo "=============================================="
echo "  Bundle: ${OUTPUT_DIR}"
echo "  Sizes:"
echo "    ION image        ${ION_SIZE}"
echo "    pgvector (${PG_VERSION}) ${PG_SIZE}"
echo "    Ollama image     ${OLLAMA_SIZE}"
echo "    Models (chat+embed)  ${MODEL_SIZE}"
echo "    Total            ${TOTAL_SIZE}"
echo "=============================================="
echo ""
echo "Transfer '${OUTPUT_DIR}' to the air-gapped target."
echo "On the target: chmod +x load.sh && ./load.sh"
echo ""
