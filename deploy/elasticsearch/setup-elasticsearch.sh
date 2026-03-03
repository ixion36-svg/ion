#!/bin/bash
# =============================================================================
# ION - Elasticsearch Setup Script
# =============================================================================
# Sets up ILM policy, ingest pipeline, and index template for ION logs.
#
# Usage: ./setup-elasticsearch.sh [ELASTICSEARCH_URL]
# Example: ./setup-elasticsearch.sh http://localhost:9200
# =============================================================================

set -e

ELASTICSEARCH_URL="${1:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "ION Elasticsearch Setup"
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
curl -X PUT "${ELASTICSEARCH_URL}/_ilm/policy/ion-policy" \
    -H "Content-Type: application/json" \
    -d @"${SCRIPT_DIR}/ilm-policy.json"
echo ""

# Create ingest pipeline
echo ""
echo "[3/5] Creating ingest pipeline..."
curl -X PUT "${ELASTICSEARCH_URL}/_ingest/pipeline/ion-pipeline" \
    -H "Content-Type: application/json" \
    -d @"${SCRIPT_DIR}/ingest-pipeline.json"
echo ""

# Create index template
echo ""
echo "[4/5] Creating index template..."
curl -X PUT "${ELASTICSEARCH_URL}/_index_template/ion" \
    -H "Content-Type: application/json" \
    -d '{
  "index_patterns": ["ion-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "ion-policy",
      "index.lifecycle.rollover_alias": "ion",
      "index.default_pipeline": "ion-pipeline",
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
    "description": "ION ECS-compliant log template"
  }
}'
echo ""

# Create initial index with rollover alias
echo ""
echo "[5/5] Creating initial index with rollover alias..."
# Check if alias already exists
if curl -s "${ELASTICSEARCH_URL}/_alias/ion" | grep -q "ion"; then
    echo "  Alias 'ion' already exists, skipping..."
else
    curl -X PUT "${ELASTICSEARCH_URL}/ion-000001" \
        -H "Content-Type: application/json" \
        -d '{
      "aliases": {
        "ion": {
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
echo "Index template: ion"
echo "ILM policy: ion-policy"
echo "Ingest pipeline: ion-pipeline"
echo "Write alias: ion"
echo ""
echo "Logs will be indexed to: ion-*"
echo "Retention policy: 90 days"
echo ""
