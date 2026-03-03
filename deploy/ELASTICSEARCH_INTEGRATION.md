# ION Elasticsearch Integration Guide

This guide explains how to configure ION to send ECS-compliant logs to Elasticsearch using Filebeat.

## Overview

ION produces structured JSON logs that comply with the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html). These logs can be shipped to Elasticsearch using Filebeat for centralized log management, searching, and visualization in Kibana.

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    ION     │────▶│    Filebeat     │────▶│  Elasticsearch  │
│  (Application)  │     │  (Log Shipper)  │     │    (Storage)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                               │
        │ JSON logs                                     │
        ▼                                               ▼
  /var/log/ion/                            ┌─────────────────┐
     app.log                                    │     Kibana      │
                                                │ (Visualization) │
                                                └─────────────────┘
```

## ECS Log Fields

ION logs include the following ECS-compliant fields:

### Core Fields

| Field | Description | Example |
|-------|-------------|---------|
| `@timestamp` | Event timestamp (ISO 8601) | `2024-01-15T10:30:00.000Z` |
| `message` | Log message | `Authentication login: success` |
| `log.level` | Log level | `info`, `warning`, `error` |
| `log.logger` | Logger name | `ion.auth.service` |

### Service Fields

| Field | Description | Example |
|-------|-------------|---------|
| `service.name` | Application name | `ion` |
| `service.version` | Application version | `1.0.0` |
| `service.environment` | Deployment environment | `production` |

### Trace Fields (Request Tracking)

| Field | Description | Example |
|-------|-------------|---------|
| `trace.id` | Distributed trace ID | `abc123-def456` |
| `transaction.id` | Request/transaction ID | `req-789xyz` |

### User Fields

| Field | Description | Example |
|-------|-------------|---------|
| `user.id` | User ID | `42` |
| `user.name` | Username | `admin` |

### HTTP Fields

| Field | Description | Example |
|-------|-------------|---------|
| `http.request.method` | HTTP method | `GET`, `POST` |
| `http.response.status_code` | Response status | `200`, `404` |
| `url.path` | Request path | `/api/templates/1` |

### Event Fields

| Field | Description | Example |
|-------|-------------|---------|
| `event.category` | Event category | `authentication`, `database`, `web` |
| `event.action` | Specific action | `login`, `create`, `http_request` |
| `event.outcome` | Result | `success`, `failure` |
| `event.duration` | Duration (nanoseconds) | `150000000` |

### Error Fields

| Field | Description | Example |
|-------|-------------|---------|
| `error.type` | Exception type | `ValueError` |
| `error.message` | Error message | `Invalid template ID` |
| `error.stack_trace` | Stack trace | `Traceback (most recent call last)...` |

## Quick Start

### 1. Configure ION Logging

Set environment variables in your deployment:

```bash
# Enable JSON logging (required for Elasticsearch)
ION_LOG_JSON=true

# Use full ECS format
ION_LOG_ECS=true

# Set log level
ION_LOG_LEVEL=INFO

# Write logs to file (for Filebeat)
ION_LOG_FILE=/var/log/ion/app.log

# Service identification
ION_SERVICE_NAME=ion
ION_VERSION=1.0.0
ION_ENVIRONMENT=production
```

### 2. Deploy with Filebeat

Use the provided Docker Compose configuration:

```bash
cd deploy

# Set Elasticsearch connection
export ELASTICSEARCH_HOSTS='["http://elasticsearch:9200"]'
export ELASTICSEARCH_USERNAME=elastic
export ELASTICSEARCH_PASSWORD=changeme

# Start ION with Filebeat
docker-compose -f docker-compose.elk.yml up -d
```

### 3. Setup Elasticsearch Indices

Run the setup script to create ILM policy, ingest pipeline, and index template:

```bash
cd deploy/elasticsearch
chmod +x setup-elasticsearch.sh
./setup-elasticsearch.sh http://elasticsearch:9200
```

## Detailed Configuration

### Filebeat Configuration

The Filebeat configuration (`deploy/filebeat/filebeat.yml`) is pre-configured for ION:

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/ion/*.log
    json.keys_under_root: true
    json.overwrite_keys: true

output.elasticsearch:
  hosts: ${ELASTICSEARCH_HOSTS}
  index: "ion-%{[environment]}-%{+yyyy.MM.dd}"
  ilm.enabled: true
  ilm.policy_name: "ion-policy"
```

### Index Lifecycle Management (ILM)

The default ILM policy provides:

| Phase | Age | Actions |
|-------|-----|---------|
| Hot | 0 days | Rollover at 1 day or 10GB |
| Warm | 7 days | Shrink to 1 shard, force merge |
| Cold | 30 days | Freeze index |
| Delete | 90 days | Delete index |

To customize, edit `deploy/elasticsearch/ilm-policy.json`:

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_primary_shard_size": "10gb"
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": { "delete": {} }
      }
    }
  }
}
```

### Ingest Pipeline

The ingest pipeline (`deploy/elasticsearch/ingest-pipeline.json`) enriches logs with:

- **GeoIP**: Adds geographic data from client IP addresses
- **User Agent**: Parses user agent strings
- **Timestamp normalization**: Ensures consistent date formats

## Elasticsearch Authentication

### Basic Authentication

```bash
export ELASTICSEARCH_USERNAME=elastic
export ELASTICSEARCH_PASSWORD=your-password
```

### API Key Authentication

1. Create API key in Elasticsearch:
```bash
curl -X POST "localhost:9200/_security/api_key" -H "Content-Type: application/json" -d '{
  "name": "ion-filebeat",
  "role_descriptors": {
    "ion_writer": {
      "cluster": ["monitor", "manage_index_templates", "manage_ilm"],
      "index": [
        {
          "names": ["ion-*"],
          "privileges": ["write", "create_index", "manage"]
        }
      ]
    }
  }
}'
```

2. Configure Filebeat:
```yaml
output.elasticsearch:
  api_key: "id:api_key_value"
```

### TLS/SSL

For HTTPS connections:

```bash
export ELASTICSEARCH_SSL_ENABLED=true
export ELASTICSEARCH_CA_PATH=/path/to/ca.crt
export ELASTICSEARCH_SSL_VERIFY=full  # or 'none' for self-signed
```

## Kibana Setup

### Import Dashboards

1. Open Kibana
2. Go to **Stack Management** → **Saved Objects**
3. Import the dashboard file (if provided)

### Create Index Pattern

1. Go to **Stack Management** → **Index Patterns**
2. Create pattern: `ion-*`
3. Select `@timestamp` as the time field

### Useful Queries

**Authentication failures:**
```
event.category: "authentication" AND event.outcome: "failure"
```

**Slow requests (>1 second):**
```
event.duration > 1000000000
```

**Errors by user:**
```
log.level: "error" | stats count() by user.name
```

**HTTP 5xx errors:**
```
http.response.status_code >= 500
```

## Air-Gapped Deployment

For environments without internet access:

### 1. Download Filebeat Image

On a machine with internet:
```bash
docker pull docker.elastic.co/beats/filebeat:9.3.0
docker save docker.elastic.co/beats/filebeat:9.3.0 | gzip > filebeat.tar.gz
```

### 2. Transfer and Load

On the air-gapped machine:
```bash
gunzip -c filebeat.tar.gz | docker load
```

### 3. Deploy

```bash
docker-compose -f docker-compose.elk.yml up -d
```

## Troubleshooting

### Logs Not Appearing in Elasticsearch

1. **Check Filebeat status:**
   ```bash
   docker logs ion-filebeat
   ```

2. **Verify log file exists:**
   ```bash
   docker exec ion ls -la /var/log/ion/
   ```

3. **Test Elasticsearch connectivity:**
   ```bash
   docker exec ion-filebeat filebeat test output
   ```

4. **Check Filebeat registry:**
   ```bash
   docker exec ion-filebeat cat /usr/share/filebeat/data/registry/filebeat/log.json
   ```

### Invalid JSON Logs

If logs aren't parsing correctly:

1. **Verify JSON format:**
   ```bash
   docker exec ion tail -1 /var/log/ion/app.log | jq .
   ```

2. **Check for multiline issues:**
   Stack traces may span multiple lines. The Filebeat config handles this with multiline patterns.

### Index Not Created

1. **Check ILM policy:**
   ```bash
   curl -X GET "localhost:9200/_ilm/policy/ion-policy"
   ```

2. **Check index template:**
   ```bash
   curl -X GET "localhost:9200/_index_template/ion"
   ```

3. **Re-run setup:**
   ```bash
   ./setup-elasticsearch.sh http://localhost:9200
   ```

## Environment Variables Reference

### ION Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `ION_LOG_JSON` | `true` | Output JSON format |
| `ION_LOG_ECS` | `true` | Use full ECS schema |
| `ION_LOG_FILE` | - | File path for log output |
| `ION_SERVICE_NAME` | `ion` | Service name in logs |
| `ION_VERSION` | `1.0.0` | Version in logs |
| `ION_ENVIRONMENT` | `production` | Environment tag |

### Filebeat

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_HOSTS` | `["http://elasticsearch:9200"]` | Elasticsearch hosts |
| `ELASTICSEARCH_USERNAME` | - | Basic auth username |
| `ELASTICSEARCH_PASSWORD` | - | Basic auth password |
| `ELASTICSEARCH_SSL_ENABLED` | `false` | Enable TLS |
| `ELASTICSEARCH_CA_PATH` | - | CA certificate path |
| `KIBANA_HOST` | `http://kibana:5601` | Kibana URL |
| `ENVIRONMENT` | `production` | Environment tag |
| `MONITORING_ENABLED` | `false` | Enable Filebeat monitoring |

## Sample Log Output

### Authentication Event
```json
{
  "@timestamp": "2024-01-15T10:30:00.000Z",
  "log": {
    "level": "info",
    "logger": "ion.auth.service"
  },
  "message": "Authentication login: success",
  "service": {
    "name": "ion",
    "version": "1.0.0",
    "environment": "production"
  },
  "event": {
    "category": "authentication",
    "action": "login",
    "outcome": "success"
  },
  "user": {
    "name": "admin"
  },
  "client": {
    "ip": "192.168.1.100"
  },
  "trace": {
    "id": "abc123"
  },
  "ecs": {
    "version": "9.3.0"
  }
}
```

### HTTP Request
```json
{
  "@timestamp": "2024-01-15T10:30:01.000Z",
  "log": {
    "level": "info",
    "logger": "ion.web.logging_middleware"
  },
  "message": "GET /api/templates 200 45ms",
  "http": {
    "request": {
      "method": "GET"
    },
    "response": {
      "status_code": 200
    }
  },
  "url": {
    "path": "/api/templates"
  },
  "event": {
    "category": "web",
    "action": "http_request",
    "outcome": "success",
    "duration": 45000000
  },
  "user": {
    "id": "1",
    "name": "admin"
  }
}
```

## Alert Investigation Integration

ION includes a built-in alert investigation page (`/alerts`) that queries Elasticsearch for security alerts and provides triage, case management, and analytics.

### Supported Alert Indices

The alert investigation module searches across these index patterns:
- `.alerts-*` (Kibana default SIEM alerts)
- `.watcher-history-*` (Elasticsearch Watcher)
- `alerts-*` (Custom alert indices)

### ECS Fields Used by Alert Investigation

The alert parser extracts data from these ECS fields:

| Category | Fields | Used For |
|----------|--------|----------|
| **Timestamp** | `@timestamp`, `timestamp`, `kibana.alert.start` | Alert time ordering |
| **Title/Rule** | `kibana.alert.rule.name`, `signal.rule.name`, `rule.name` | Alert title and rule name |
| **Severity** | `kibana.alert.severity`, `event.severity`, `signal.rule.severity` | Severity classification |
| **Status** | `kibana.alert.status`, `status`, `state` | Alert status |
| **Host** | `host.name`, `host.hostname`, `agent.hostname` | Affected host identification |
| **User** | `user.name`, `user_name`, `winlog.user.name` | Affected user identification |
| **Source IP** | `source.ip`, `source.address` | Observable extraction |
| **Destination IP** | `destination.ip`, `destination.address` | Observable extraction |
| **URL** | `url.full`, `url.original` | Observable extraction |
| **Domain** | `url.domain`, `dns.question.name`, `destination.domain` | Observable extraction |

### GeoIP Data for Analytics

The analytics dashboard's geographic map visualization uses ECS geo fields from the alert's raw data:

- `source.geo.location` (lat/lon)
- `destination.geo.location` (lat/lon)
- `client.geo.location` (lat/lon)
- `server.geo.location` (lat/lon)
- `host.geo.location` (lat/lon)

These fields are populated by Elasticsearch's **GeoIP ingest processor**. To enable geographic data in alerts:

1. Ensure the GeoIP ingest processor is installed and configured in your Elasticsearch cluster
2. Alert ingest pipelines should include a GeoIP processor step for IP fields
3. The MaxMind GeoLite2 database (bundled with Elasticsearch) provides the geographic mapping

If no geo data is present in alerts, the map displays an informational message instead.

### Configuring Elasticsearch for Alerts

```bash
# Required environment variables
ION_ELASTICSEARCH_ENABLED=true
ION_ELASTICSEARCH_HOSTS=https://elasticsearch:9200
ION_ELASTICSEARCH_USERNAME=elastic
ION_ELASTICSEARCH_PASSWORD=changeme

# Optional: Custom alert index pattern
ION_ELASTICSEARCH_ALERT_INDEX=.alerts-*
```

## Security Considerations

1. **Credential Management**: Store Elasticsearch credentials securely (environment variables, secrets manager)
2. **Network Security**: Use TLS for Elasticsearch connections in production
3. **Log Retention**: Configure ILM policy according to your compliance requirements
4. **Access Control**: Use Elasticsearch RBAC to limit who can read logs
5. **PII in Logs**: Be mindful of logging sensitive user data

## Support

For issues with:
- **ION logging**: Check application logs and configuration
- **Filebeat**: See [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- **Elasticsearch**: See [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
