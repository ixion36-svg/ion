#!/bin/bash
# =============================================================================
# IXION - Ollama Model Setup Script
# =============================================================================
# This script pulls the recommended models for IXION's AI assistant
# Run this after starting the Docker containers
# =============================================================================

set -e

OLLAMA_HOST="${OLLAMA_HOST:-localhost}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_URL="http://${OLLAMA_HOST}:${OLLAMA_PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "IXION - Ollama Model Setup"
echo "=============================================="
echo ""

# Check if Ollama is available
echo -n "Checking Ollama connection... "
if curl -s "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "Could not connect to Ollama at ${OLLAMA_URL}"
    echo "Make sure the Ollama container is running:"
    echo "  docker-compose up -d ollama"
    exit 1
fi

echo ""

# Function to pull a model
pull_model() {
    local model=$1
    local description=$2

    echo -e "${YELLOW}Pulling ${model}${NC} - ${description}"

    # Check if model already exists
    if curl -s "${OLLAMA_URL}/api/tags" | grep -q "\"name\":\"${model}\""; then
        echo -e "  ${GREEN}Already installed${NC}"
        return 0
    fi

    # Pull the model
    curl -s -X POST "${OLLAMA_URL}/api/pull" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${model}\"}" | while read -r line; do
        status=$(echo "$line" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$status" ]; then
            echo -ne "  ${status}...\r"
        fi
    done
    echo -e "  ${GREEN}Done${NC}              "
}

# Parse command line argument for model size
MODEL_SIZE="${1:-testing}"

case "$MODEL_SIZE" in
    testing|test|small)
        echo "Installing testing models (minimal RAM usage)..."
        echo ""
        pull_model "qwen2.5:0.5b" "Tiny model for testing (~400MB RAM)"
        ;;

    production|prod|full)
        echo "Installing production models (requires 8GB+ RAM)..."
        echo ""
        pull_model "qwen2.5:0.5b" "Tiny model for testing (~400MB RAM)"
        pull_model "qwen2.5-coder:7b" "Full coding model (~5GB RAM)"
        ;;

    all)
        echo "Installing all recommended models..."
        echo ""
        pull_model "qwen2.5:0.5b" "Tiny model for testing (~400MB RAM)"
        pull_model "qwen2.5-coder:7b" "Full coding model (~5GB RAM)"
        pull_model "llama3:8b" "General purpose model (~5GB RAM)"
        pull_model "phi3:mini" "Lightweight model (~2GB RAM)"
        ;;

    *)
        echo "Custom model: $MODEL_SIZE"
        echo ""
        pull_model "$MODEL_SIZE" "Custom model"
        ;;
esac

echo ""
echo "=============================================="
echo -e "${GREEN}Setup complete!${NC}"
echo "=============================================="
echo ""
echo "Available models:"
curl -s "${OLLAMA_URL}/api/tags" | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | while read -r model; do
    echo "  - $model"
done
echo ""
echo "To use a different model, update IXION_OLLAMA_MODEL in your .env file"
echo ""
