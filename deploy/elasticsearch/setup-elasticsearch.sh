#!/bin/bash
# =============================================================================
# DocForge - Elasticsearch Setup Script
# =============================================================================
# Sets up ILM policy, ingest pipeline, and index template for DocForge logs.
#
# Usage: ./setup-elasticsearch.sh [ELASTICSEARCH_URL]
# Example: ./setup-elasticsearch.sh http://localhost:9200
# =============================================================================

set -e

ELASTICSEARCH_URL="${1:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "DocForge Elasticsearch Setup"
echo "=============================================="
echo "Elasticsearch URL: ${ELASTICSEARCH_URL}"
echo ""

# Wait for Elasticsearch to be ready
echo "[1/5] Waiting for Elasticsearch..."
until curl -s "${ELASTICSEARCH_URL}/_cluster/health" > /dev/null 2>&1; do
    echo "  Waiting for Elasticsearch to start..."
    sleep 5
done
echo "  Elasticsearch is ready!"

# Create ILM policy
echo ""
echo "[2/5] Creating ILM policy..."
curl -X PUT "${ELASTICSEARCH_URL}/_ilm/policy/docforge-policy" \
    -H "Content-Type: application/json" \
    -d @"${SCRIPT_DIR}/ilm-policy.json"
echo ""

# Create ingest pipeline
echo ""
echo "[3/5] Creating ingest pipeline..."
curl -X PUT "${ELASTICSEARCH_URL}/_ingest/pipeline/docforge-pipeline" \
    -H "Content-Type: application/json" \
    -d @"${SCRIPT_DIR}/ingest-pipeline.json"
echo ""

# Create index template
echo ""
echo "[4/5] Creating index template..."
curl -X PUT "${ELASTICSEARCH_URL}/_index_template/docforge" \
    -H "Content-Type: application/json" \
    -d '{
  "index_patterns": ["docforge-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "docforge-policy",
      "index.lifecycle.rollover_alias": "docforge",
      "index.default_pipeline": "docforge-pipeline",
      "index.codec": "best_compression"
    },
    "mappings": {
      "dynamic_templates": [
        {
          "strings_as_keywords": {
            "match_mapping_type": "string",
            "mapping": {
              "type": "keyword",
              "ignore_above": 1024
            }
          }
        }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "message": { "type": "text" },
        "log.level": { "type": "keyword" },
        "log.logger": { "type": "keyword" },
        "service.name": { "type": "keyword" },
        "service.version": { "type": "keyword" },
        "service.environment": { "type": "keyword" },
        "trace.id": { "type": "keyword" },
        "transaction.id": { "type": "keyword" },
        "span.id": { "type": "keyword" },
        "user.id": { "type": "keyword" },
        "user.name": { "type": "keyword" },
        "client.ip": { "type": "ip" },
        "client.geo": { "type": "object" },
        "http.request.method": { "type": "keyword" },
        "url.path": { "type": "keyword" },
        "http.response.status_code": { "type": "integer" },
        "event.duration": { "type": "long" },
        "event.action": { "type": "keyword" },
        "event.category": { "type": "keyword" },
        "event.type": { "type": "keyword" },
        "event.outcome": { "type": "keyword" },
        "error.type": { "type": "keyword" },
        "error.message": { "type": "text" },
        "error.stack_trace": { "type": "text" },
        "host.name": { "type": "keyword" },
        "host.hostname": { "type": "keyword" },
        "container.id": { "type": "keyword" },
        "container.name": { "type": "keyword" }
      }
    }
  },
  "priority": 200,
  "composed_of": [],
  "version": 1,
  "_meta": {
    "description": "DocForge ECS-compliant log template"
  }
}'
echo ""

# Create initial index with rollover alias
echo ""
echo "[5/5] Creating initial index with rollover alias..."
# Check if alias already exists
if curl -s "${ELASTICSEARCH_URL}/_alias/docforge" | grep -q "docforge"; then
    echo "  Alias 'docforge' already exists, skipping..."
else
    curl -X PUT "${ELASTICSEARCH_URL}/docforge-000001" \
        -H "Content-Type: application/json" \
        -d '{
      "aliases": {
        "docforge": {
          "is_write_index": true
        }
      }
    }'
fi
echo ""

echo ""
echo "=============================================="
echo "Setup complete!"
echo "=============================================="
echo ""
echo "Index template: docforge"
echo "ILM policy: docforge-policy"
echo "Ingest pipeline: docforge-pipeline"
echo "Write alias: docforge"
echo ""
echo "Logs will be indexed to: docforge-*"
echo "Retention policy: 90 days"
echo ""
