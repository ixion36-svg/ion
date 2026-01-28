# DocForge OpenCTI Integration Guide

This guide explains how to configure DocForge to enrich alert observables (IPs, domains, hashes, URLs) against an OpenCTI threat intelligence platform.

## Overview

DocForge integrates with [OpenCTI](https://www.opencti.io/) via its GraphQL API to provide IOC enrichment directly from the alert investigation page. When an analyst clicks "Enrich via OpenCTI", DocForge queries OpenCTI for matching observables, indicators, threat actors, and labels, displaying results inline alongside the alert.

### Architecture

```
+-----------------+     GraphQL API     +-----------------+
|    DocForge     |-------------------->|     OpenCTI     |
|  Alert Triage   |<--------------------|   Platform      |
+-----------------+    Enrichment       +-----------------+
        |              Results                  |
        v                                       v
  /alerts page                          STIX 2.1 Data
  Enrich button                         (Indicators,
  Inline results                         Observables,
                                         Threat Actors)
```

### What Gets Enriched

| Observable Type | STIX Type | Example |
|-----------------|-----------|---------|
| IPv4 Address | `IPv4-Addr` | `37.120.198.100` |
| IPv6 Address | `IPv6-Addr` | `2001:db8::1` |
| Domain Name | `Domain-Name` | `evil-login.example.com` |
| URL | `Url` | `https://evil.com/callback` |
| SHA-256 Hash | `StixFile` | `e3b0c44298fc1c14...` |
| SHA-1 Hash | `StixFile` | `da39a3ee5e6b4b0d...` |
| MD5 Hash | `StixFile` | `d41d8cd98f00b204...` |
| Email Address | `Email-Addr` | `attacker@evil.com` |

### Enrichment Results

For each matched observable, DocForge returns:

- **Score**: OpenCTI threat score (0-100)
- **Indicators**: Linked STIX indicators with names, descriptions, patterns, and scores
- **Threat Actors**: Threat actor groups linked via `indicates` relationships
- **Labels**: Tags applied to the observable or its indicators

## Configuration

### Via Web UI

1. Navigate to the alerts page
2. OpenCTI settings are managed via the API (see below) or config file

### Via Config File

Add to `.docforge/config.json`:

```json
{
    "opencti_enabled": true,
    "opencti_url": "http://localhost:8888",
    "opencti_token": "your-api-token-uuid",
    "opencti_verify_ssl": true
}
```

### Via Environment Variables

```bash
DOCFORGE_OPENCTI_ENABLED=true
DOCFORGE_OPENCTI_URL=https://opencti.example.com
DOCFORGE_OPENCTI_TOKEN=5b3d8e6f-2a1c-4b9d-8e7f-3c6a9d4b2e1f
DOCFORGE_OPENCTI_VERIFY_SSL=true
```

### Via API

```bash
# Configure (admin only)
curl -X POST http://localhost:8000/api/opencti/config \
  -H "Content-Type: application/json" \
  -d '{
    "opencti_url": "https://opencti.example.com",
    "opencti_token": "your-api-token-uuid",
    "opencti_verify_ssl": true
  }'

# Test connection
curl http://localhost:8000/api/opencti/test

# Disable
curl -X DELETE http://localhost:8000/api/opencti/config
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/opencti/config` | GET | Get integration status (URL, enabled state; token not exposed) |
| `/api/opencti/config` | POST | Configure OpenCTI settings (admin only) |
| `/api/opencti/config` | DELETE | Disable OpenCTI integration (admin only) |
| `/api/opencti/test` | GET | Test connection (returns user info) |
| `/api/opencti/enrich` | POST | Enrich a single observable |
| `/api/opencti/enrich/batch` | POST | Enrich multiple observables |

### Enrich Request

```bash
# Single observable
curl -X POST http://localhost:8000/api/opencti/enrich \
  -H "Content-Type: application/json" \
  -d '{"type": "ipv4-addr", "value": "37.120.198.100"}'

# Batch
curl -X POST http://localhost:8000/api/opencti/enrich/batch \
  -H "Content-Type: application/json" \
  -d '[
    {"type": "ipv4-addr", "value": "37.120.198.100"},
    {"type": "domain-name", "value": "evil.example.com"},
    {"type": "file-sha256", "value": "e3b0c44298fc1c14..."}
  ]'
```

### Enrich Response

```json
{
  "found": true,
  "type": "ipv4-addr",
  "value": "37.120.198.100",
  "observable": {
    "id": "f3850c20-...",
    "type": "IPv4-Addr",
    "value": "37.120.198.100",
    "description": "Primary C2 address used by APT-TEST-1",
    "score": 95,
    "created_by": null
  },
  "indicators": [
    {
      "id": "24e9e60d-...",
      "name": "Primary C2 IP - 37.120.198.100",
      "description": "Primary command-and-control address...",
      "pattern": "[ipv4-addr:value = '37.120.198.100']",
      "score": 95,
      "labels": []
    }
  ],
  "threat_actors": [
    {
      "id": "d264f513-...",
      "name": "APT-TEST-1",
      "description": "Financially motivated APT group...",
      "types": ["crime-syndicate"],
      "relationship": "indicates"
    }
  ],
  "labels": [],
  "reports": [],
  "error": null
}
```

## Test Instance

A Docker Compose stack is provided for local development and testing.

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ with `httpx` (`pip install httpx`)

### Start OpenCTI

```bash
cd test-opencti
docker compose up -d
```

This starts 6 services:

| Service | Port | Purpose |
|---------|------|---------|
| OpenCTI Platform | 8888 | GraphQL API + Web UI |
| OpenCTI Worker | -- | Background processing |
| Elasticsearch | 9201 | OpenCTI data store (9201 to avoid clash with DocForge ES on 9200) |
| Redis | 6379 | Cache and event stream |
| MinIO | 9002 | S3-compatible object storage |
| RabbitMQ | 5672 / 15672 | Message broker |

Test credentials:
- **Admin email**: `admin@opencti.io`
- **Admin password**: `OpenCTITest123!`
- **API token**: `5b3d8e6f-2a1c-4b9d-8e7f-3c6a9d4b2e1f`

OpenCTI takes 1-2 minutes to start. The seed script will wait automatically.

### Seed Test Data

```bash
cd test-opencti
python seed_opencti.py
```

This creates threat intelligence objects matching the seed alerts:

| Type | Count | Details |
|------|-------|---------|
| Threat Actors | 3 | APT-TEST-1, ShadowNet Collective, RansomCrew |
| Malware | 2 | SvcHostUpdate Backdoor, InvoiceQ4 Dropper |
| IP Indicators | 10 | All source IPs from seed alerts (with auto-created observables) |
| Domain Indicators | 5 | 4 DGA domains + 1 phishing domain |
| File Hash Indicators | 3 | SHA-256 hashes for malware samples |
| URL Indicators | 1 | C2 callback URL |
| Relationships | 21+ | indicates, uses, based-on (auto-created) |

Each indicator includes a threat score (60-95) and is linked to its threat actor via `indicates` relationships.

### Verify

```bash
# Test OpenCTI API directly
curl -X POST http://localhost:8888/graphql \
  -H "Authorization: Bearer 5b3d8e6f-2a1c-4b9d-8e7f-3c6a9d4b2e1f" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ me { name } }"}'

# Test DocForge enrichment
curl -X POST http://localhost:8000/api/opencti/enrich \
  -H "Content-Type: application/json" \
  -d '{"type": "ipv4-addr", "value": "37.120.198.100"}'
```

### Stop

```bash
cd test-opencti
docker compose down        # stop and remove containers
docker compose down -v     # also remove volumes (full reset)
```

## OpenCTI Token Setup

For production OpenCTI instances:

1. Log in to OpenCTI web UI
2. Go to **Settings** > **Security** > **Users**
3. Select your user (or create a dedicated API user)
4. Under **API access**, copy the **API key** (UUID format)
5. The user needs at least read access to observables, indicators, and threat actors

## Supported Observable Type Aliases

The enrichment endpoint accepts both STIX type names and convenience aliases:

| Alias | Maps To |
|-------|---------|
| `ip`, `source_ip`, `destination_ip` | `ipv4-addr` |
| `domain`, `hostname` | `domain-name` |
| `ipv4-addr` | `IPv4-Addr` |
| `ipv6-addr` | `IPv6-Addr` |
| `domain-name` | `Domain-Name` |
| `url` | `Url` |
| `file-sha256` | `StixFile` (filtered by `hashes.SHA-256`) |
| `file-sha1` | `StixFile` (filtered by `hashes.SHA-1`) |
| `file-md5` | `StixFile` (filtered by `hashes.MD5`) |
| `email-addr` | `Email-Addr` |

## Troubleshooting

### "OpenCTI integration is not enabled"

OpenCTI is not configured. Set `opencti_enabled: true` in config.json or via the API.

### "Failed to connect to OpenCTI"

- Verify OpenCTI is running: `curl http://localhost:8888/graphql`
- Check the URL in config matches the OpenCTI address
- For Docker setups, ensure network connectivity between DocForge and OpenCTI

### Enrichment returns "found: false" for known indicators

- Verify the observable exists in OpenCTI (check the OpenCTI web UI)
- Ensure the indicator was created with `createObservables: true` so the observable (SCO) exists alongside the indicator (SDO)
- Check that the observable type matches (e.g., use `file-sha256` not `file` for hash lookups)

### Test connection succeeds but enrichment fails

- The API token may have insufficient permissions. Ensure the user has read access to `stixCyberObservables`, `indicators`, and `stixCoreRelationships`
- Check DocForge server logs for detailed GraphQL error messages
