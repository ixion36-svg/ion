# DocForge Setup Instructions

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Initialize database
docforge init

# Upgrade database schema
docforge upgrade

# Seed default users
docforge seed-users --admin-password YourPassword123

# Start web server
docforge web
```

Access at: http://localhost:8000

---

## Air-Gapped Deployment

For deploying to secure environments without internet access.

### 1. Build Offline Package (on machine with internet)

**Windows:**
```cmd
scripts\build-offline-package.bat 1.0.0
```

**Linux/Mac:**
```bash
./scripts/build-offline-package.sh 1.0.0
```

### 2. Transfer to Secure Environment

Copy `dist/docforge-offline-1.0.0/` to the target machine.

### 3. Deploy

**HTTP (Development/Testing):**
```bash
cd docforge-offline-1.0.0
./deploy.sh
docker-compose up -d
```

**HTTPS (Production):**
```bash
cd docforge-offline-1.0.0
# Place certificates in ssl/server.crt and ssl/server.key
./deploy.sh
docker-compose -f docker-compose.https.yml up -d
```

### 4. Login

- URL: http://localhost:8000 (or https://localhost for HTTPS)
- Username: `admin`
- Password: `changeme` (CHANGE THIS!)

---

## Deployment Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Docker image build |
| `docker-compose.yml` | HTTP deployment |
| `deploy/docker-compose.https.yml` | HTTPS deployment with nginx |
| `deploy/nginx/nginx.conf` | Nginx reverse proxy config |
| `deploy/generate-certs.sh` | Generate self-signed certs |
| `deploy/DEPLOYMENT_GUIDE.md` | Comprehensive deployment guide |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCFORGE_COOKIE_SECURE` | `false` | Set `true` for HTTPS |
| `DOCFORGE_ADMIN_PASSWORD` | `changeme` | Initial admin password |
| `DOCFORGE_OIDC_ENABLED` | `false` | Enable Keycloak SSO |
| `DOCFORGE_OIDC_KEYCLOAK_URL` | - | Keycloak server URL |
| `DOCFORGE_OIDC_REALM` | - | Keycloak realm name |
| `DOCFORGE_OIDC_CLIENT_ID` | - | OIDC client ID |
| `DOCFORGE_OIDC_CLIENT_SECRET` | - | OIDC client secret |

### Config File

Located at `.docforge/config.json`:

```json
{
  "db_path": ".docforge/docforge.db",
  "default_format": "markdown",
  "auto_save": true,
  "cookie_secure": true,
  "oidc_enabled": false,
  "oidc_keycloak_url": "",
  "oidc_realm": "",
  "oidc_client_id": "",
  "oidc_client_secret": ""
}
```

---

## CLI Commands

### System
```bash
docforge init              # Initialize database
docforge upgrade           # Upgrade database schema
docforge seed-users        # Create default roles and admin user
docforge status            # Show system status
docforge web               # Start web server
```

### Templates
```bash
docforge template list
docforge template create "My Template" --format markdown
docforge template show 1
docforge template edit 1
docforge template delete 1
docforge template search "keyword"
docforge template import template.md
docforge template export 1 -o output.md
```

### Collections
```bash
docforge collection list
docforge collection create "My Collection" -d "Description"
docforge collection show 1
docforge collection add 1 5      # Add template 5 to collection 1
docforge collection remove 5     # Remove template from collection
docforge collection delete 1
```

### Rendering
```bash
docforge render preview 1 -d '{"name": "Value"}'
docforge render run 1 -f data.json -o output.md
docforge render validate-data 1 -d '{"name": "Value"}'
docforge render batch 1 data.csv --name-field "title"
```

### Versions
```bash
docforge version list 1
docforge version show 1 2
docforge version diff 1 1 2
docforge version checkpoint 1 "Release v1.0"
docforge version rollback 1 2
```

### Documents
```bash
docforge document list
docforge document show 1
docforge document export 1 -o output.md
docforge document delete 1
```

---

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user info
- `POST /api/auth/change-password` - Change password

### Collections
- `GET /api/collections` - List collections
- `POST /api/collections` - Create collection
- `GET /api/collections/{id}` - Get collection
- `PUT /api/collections/{id}` - Update collection
- `DELETE /api/collections/{id}` - Delete collection

### Templates
- `GET /api/templates` - List templates
- `POST /api/templates` - Create template
- `GET /api/templates/{id}` - Get template
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template
- `POST /api/templates/{id}/validate` - Validate data
- `POST /api/templates/{id}/preview` - Preview render
- `POST /api/templates/{id}/render` - Render document
- `POST /api/templates/{id}/batch-render` - Batch render

### Documents
- `GET /api/documents` - List documents
- `GET /api/documents/{id}` - Get document
- `DELETE /api/documents/{id}` - Delete document

---

## Default Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access to all resources |
| **Editor** | Create/edit templates and documents |
| **Viewer** | Read-only access |

---

## Security Features

- Session-based authentication with secure cookies
- OIDC/Keycloak SSO support
- Role-based access control (RBAC)
- Rate limiting on authentication endpoints
- Security headers (CSP, HSTS, X-Frame-Options)
- Timing-attack resistant login
- Sandboxed Jinja2 template rendering
- CSRF protection for OIDC flows
- Audit logging

---

## Backup & Restore

### Backup (Docker)
```bash
docker run --rm -v docforge-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/docforge-backup.tar.gz -C /data .
```

### Restore (Docker)
```bash
docker-compose down
docker run --rm -v docforge-data:/data -v $(pwd):/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/docforge-backup.tar.gz -C /data"
docker-compose up -d
```

### Backup (Local)
```bash
cp -r .docforge .docforge-backup-$(date +%Y%m%d)
```

---

## Troubleshooting

### Common Issues

**"Template not found"**
- Verify the template ID exists: `docforge template list`

**"Permission denied"**
- Check user has required role
- Verify authentication token is valid

**"Database locked"**
- Only one process should access the database at a time
- Restart the web server if needed

**Container won't start**
```bash
docker-compose logs docforge
```

For detailed troubleshooting, see `deploy/DEPLOYMENT_GUIDE.md`.
