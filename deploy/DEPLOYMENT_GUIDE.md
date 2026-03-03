# IXION Deployment Guide

## Air-Gapped / Secure Environment Deployment

This guide covers deploying IXION in environments without internet access.

### Features Included in Docker Image

- Full NLP processing (NLTK data pre-downloaded)
- SOC entity detection (18 pattern types: IPs, CVEs, hashes, etc.)
- AI-assisted alert triage (observable extraction, MITRE mapping, analysis, contextual chat)
- Multi-alert pattern detection with auto-triggered investigation playbooks
- Playbook execution: action recording, outcome classification, and auto-generated investigation reports
- Spell checking with technical term awareness
- Rewrite suggestions (professional, concise, formal, technical styles)
- Table detection (Markdown, CSV, TSV)
- Folder organization with auto-assignment
- Role-based access control
- Optional Keycloak/OIDC SSO

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building the Offline Package](#building-the-offline-package)
3. [Transferring to Secure Environment](#transferring-to-secure-environment)
4. [Deployment Options](#deployment-options)
   - [Option A: HTTP Only (Development/Testing)](#option-a-http-only)
   - [Option B: HTTPS with Nginx (Production)](#option-b-https-with-nginx)
5. [Configuration](#configuration)
6. [Post-Deployment Setup](#post-deployment-setup)
7. [Operations](#operations)
8. [Troubleshooting](#troubleshooting)
9. [Security Checklist](#security-checklist)

---

## Prerequisites

### Build Machine (with internet access)

- Docker Engine 20.10+
- Docker Compose v2+
- 2GB free disk space
- Internet access (to pull base images)

### Target Machine (air-gapped)

- Docker Engine 20.10+
- Docker Compose v2+
- 800MB free disk space (for image with NLP data)
- 100MB+ free disk space (for data)
- 1GB RAM recommended (for NLP processing)

---

## Building the Offline Package

Run these commands on a machine **with internet access**.

### Windows

```cmd
cd C:\Projects\ixion
scripts\build-offline-package.bat 1.0.0
```

### Linux/Mac

```bash
cd /path/to/ixion
chmod +x scripts/build-offline-package.sh
./scripts/build-offline-package.sh 1.0.0
```

### Output

The build creates `dist/ixion-offline-1.0.0/` containing:

```
ixion-offline-1.0.0/
├── ixion-image-1.0.0.zip    # Docker image (~150-200MB)
├── docker-compose.yml           # Basic deployment config
├── deploy.sh                    # Deployment script
└── README.txt                   # Quick reference
```

For HTTPS deployment, also copy the `deploy/` folder:

```
deploy/
├── docker-compose.https.yml    # HTTPS deployment config
├── nginx/
│   └── nginx.conf              # Nginx configuration
├── generate-certs.sh           # Certificate generation script
└── DEPLOYMENT_GUIDE.md         # This guide
```

---

## Transferring to Secure Environment

1. Copy the offline package to approved transfer media (USB, DVD, etc.)
2. Follow your organization's security procedures for media transfer
3. Copy files to the target machine

**Recommended directory structure on target:**

```
/opt/ixion/
├── ixion-image-1.0.0.zip
├── docker-compose.yml           # or docker-compose.https.yml
├── deploy.sh
├── nginx/
│   └── nginx.conf
└── ssl/
    ├── server.crt               # Your TLS certificate
    └── server.key               # Your TLS private key
```

---

## Deployment Options

### Option A: HTTP Only

**Use for:** Development, testing, or when TLS is handled by external load balancer.

```bash
cd /opt/ixion

# Load Docker image
unzip -p ixion-image-*.zip | docker load
# Or for .tar.gz: gunzip -c ixion-image-*.tar.gz | docker load

# Deploy
./deploy.sh
docker-compose up -d

# Verify
docker-compose ps
curl http://localhost:8000/api/stats
```

**Access:** http://localhost:8000

---

### Option B: HTTPS with Nginx

**Use for:** Production deployments requiring encrypted connections.

#### Step 1: Prepare TLS Certificates

**Option 1: Use organization-provided certificates**

Place your certificates in the `ssl/` directory:
```
ssl/
├── server.crt    # Certificate (PEM format)
└── server.key    # Private key (PEM format)
```

**Option 2: Generate self-signed certificates (testing only)**

```bash
cd /opt/ixion
chmod +x generate-certs.sh
./generate-certs.sh ixion.yourdomain.com
```

#### Step 2: Load Docker Images

```bash
# Load IXION image
unzip -p ixion-image-*.zip | docker load

# Pull nginx image (if not included in offline package)
# If no internet, you'll need to also export/import nginx:1.25-alpine
docker pull nginx:1.25-alpine
docker save nginx:1.25-alpine | gzip > nginx-image.tar.gz
# Transfer and load on target:
gunzip -c nginx-image.tar.gz | docker load
```

#### Step 3: Deploy with HTTPS

```bash
cd /opt/ixion

# Initialize database (first time only)
./deploy.sh

# Start with HTTPS
docker-compose -f docker-compose.https.yml up -d

# Verify
docker-compose -f docker-compose.https.yml ps
curl -k https://localhost/api/stats
```

**Access:** https://localhost (or your configured hostname)

---

## Configuration

### Environment Variables

Configure in `docker-compose.yml` or `docker-compose.https.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `IXION_HOST` | `0.0.0.0` | Bind address |
| `IXION_PORT` | `8000` | Application port |
| `IXION_COOKIE_SECURE` | `false` | Set `true` for HTTPS |
| `IXION_ADMIN_PASSWORD` | `changeme` | Initial admin password |
| `IXION_OIDC_ENABLED` | `true` | Enable Keycloak SSO |
| `IXION_OIDC_KEYCLOAK_URL` | - | Keycloak server URL |
| `IXION_OIDC_REALM` | - | Keycloak realm |
| `IXION_OIDC_CLIENT_ID` | - | OIDC client ID |
| `IXION_OIDC_CLIENT_SECRET` | - | OIDC client secret |
| `IXION_OLLAMA_ENABLED` | `true` | Enable Ollama AI integration |
| `IXION_OLLAMA_URL` | `http://ollama:11434` | Ollama service URL |
| `IXION_OLLAMA_MODEL` | `qwen2.5:7b` | Default AI model |
| `IXION_GITLAB_ENABLED` | `true` | Enable GitLab integration |
| `IXION_GITLAB_URL` | - | GitLab server URL |
| `IXION_GITLAB_TOKEN` | - | GitLab Personal Access Token |
| `IXION_GITLAB_PROJECT_ID` | - | GitLab project ID or path |

### Example: Production HTTPS Configuration

```yaml
environment:
  - IXION_COOKIE_SECURE=true
  - IXION_ADMIN_PASSWORD=YourSecurePassword123!
```

### Example: With Keycloak SSO

```yaml
environment:
  - IXION_COOKIE_SECURE=true
  - IXION_OIDC_ENABLED=true
  - IXION_OIDC_KEYCLOAK_URL=https://keycloak.internal.company.com
  - IXION_OIDC_REALM=ixion
  - IXION_OIDC_CLIENT_ID=ixion-app
  - IXION_OIDC_CLIENT_SECRET=your-client-secret-here
```

### Example: With GitLab Integration

```yaml
environment:
  - IXION_COOKIE_SECURE=true
  - IXION_GITLAB_ENABLED=true
  - IXION_GITLAB_URL=https://gitlab.internal.company.com
  - IXION_GITLAB_TOKEN=glpat-xxxxxxxxxxxx
  - IXION_GITLAB_PROJECT_ID=security/documentation
```

**Note:** The GitLab token requires the `api` scope. Create a Personal Access Token in GitLab > User Settings > Access Tokens.

---

## Post-Deployment Setup

### 1. Change Admin Password

**CRITICAL:** Change the default admin password immediately!

1. Navigate to https://your-server/login
2. Login with: `admin` / `changeme` (or your configured password)
3. Go to Profile → Change Password
4. Set a strong password

### 2. Create Additional Users

1. Login as admin
2. Navigate to Users
3. Create users with appropriate roles:
   - **Analyst**: Alerts, cases, playbooks, templates, documents, AI chat
   - **Lead**: Analyst + topology, security dashboards
   - **Engineering**: Lead + integrations, system settings
   - **Admin**: Full system access

### 3. Set Up AI Model (If Using Ollama)

```bash
# Pull the default AI model into the Ollama sidecar (first time only)
docker exec -it ixion-ollama ollama pull qwen2.5:7b

# Verify AI is available
curl http://localhost:8000/api/ai/status
# Should return: {"available": true, "default_model": "qwen2.5:7b", ...}
```

Once available, AI assist buttons (Analyze, Extract, Suggest, Discuss) will appear automatically in the alert investigation UI.

### 4. Configure Roles (Optional)

Default roles and permissions are pre-configured. Customize via the admin interface if needed.

---

## Operations

### Starting Services

```bash
# HTTP
docker-compose up -d

# HTTPS
docker-compose -f docker-compose.https.yml up -d
```

### Stopping Services

```bash
docker-compose down
# or
docker-compose -f docker-compose.https.yml down
```

### Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ixion
docker-compose logs -f nginx
```

### Checking Status

```bash
docker-compose ps
docker-compose -f docker-compose.https.yml ps
```

### Backup

```bash
# Backup data volume
docker run --rm \
  -v ixion-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/ixion-backup-$(date +%Y%m%d).tar.gz -C /data .

# Backup includes:
# - Database (ixion.db)
# - Configuration (config.json)
```

### Restore

```bash
# Stop services first
docker-compose down

# Restore data
docker run --rm \
  -v ixion-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/ixion-backup-YYYYMMDD.tar.gz -C /data"

# Restart services
docker-compose up -d
```

### Updating IXION

1. Build new offline package with updated version
2. Transfer to secure environment
3. Load new image:
   ```bash
   unzip -p ixion-image-NEW.zip | docker load
   ```
4. Update image tag in docker-compose.yml if needed
5. Restart:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs ixion

# Common issues:
# - Database initialization failed
# - Permission issues on /data volume
```

### Can't connect to web interface

```bash
# Check if containers are running
docker-compose ps

# Check nginx logs (HTTPS deployment)
docker-compose logs nginx

# Test internal connectivity
docker exec ixion-app curl -s http://localhost:8000/api/stats
```

### Certificate errors (HTTPS)

```bash
# Verify certificate files exist
ls -la ssl/

# Check certificate validity
openssl x509 -in ssl/server.crt -noout -dates

# Check certificate matches key
openssl x509 -in ssl/server.crt -noout -modulus | md5sum
openssl rsa -in ssl/server.key -noout -modulus | md5sum
# (Both should match)
```

### Database issues

```bash
# Check database exists
docker exec ixion-app ls -la /data/.ixion/

# Reset database (WARNING: deletes all data!)
docker-compose down -v
./deploy.sh
docker-compose up -d
```

### Permission denied errors

```bash
# Fix volume permissions
docker run --rm -v ixion-data:/data alpine chown -R 1000:1000 /data
```

---

## Security Checklist

Before going to production, verify:

- [ ] Changed default admin password
- [ ] Using HTTPS with valid TLS certificates
- [ ] `IXION_COOKIE_SECURE=true` is set
- [ ] Firewall configured (only ports 80/443 open if needed)
- [ ] Regular backups scheduled
- [ ] Log monitoring configured
- [ ] User accounts reviewed and appropriate roles assigned
- [ ] Self-signed certificates replaced with CA-signed (if applicable)
- [ ] Rate limiting configured appropriately in nginx.conf
- [ ] Resource limits set in docker-compose.yml

---

## Quick Reference

| Task | Command |
|------|---------|
| Start (HTTP) | `docker-compose up -d` |
| Start (HTTPS) | `docker-compose -f docker-compose.https.yml up -d` |
| Stop | `docker-compose down` |
| Logs | `docker-compose logs -f` |
| Status | `docker-compose ps` |
| Backup | See [Backup](#backup) section |
| Shell access | `docker exec -it ixion-app /bin/bash` |

---

## Support

For issues and questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review container logs
- Consult your organization's Docker/security team
