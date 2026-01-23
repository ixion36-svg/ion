#!/bin/bash
# =============================================================================
# DocForge - Build Offline Deployment Package
# =============================================================================
# Run this script on a machine WITH internet access to create an air-gapped
# deployment package that can be transferred to the secure environment.
#
# Usage: ./scripts/build-offline-package.sh [version]
# Example: ./scripts/build-offline-package.sh 1.0.0
# =============================================================================

set -e

VERSION="${1:-latest}"
PACKAGE_NAME="docforge-offline-${VERSION}"
OUTPUT_DIR="./dist/${PACKAGE_NAME}"

echo "=============================================="
echo "Building DocForge Offline Package v${VERSION}"
echo "=============================================="

# Create output directory
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Step 1: Build Docker image
echo ""
echo "[1/4] Building Docker image..."
docker build -t docforge:${VERSION} -t docforge:latest .

# Step 2: Save Docker image as tar
echo ""
echo "[2/4] Exporting Docker image..."
docker save docforge:${VERSION} | gzip > "${OUTPUT_DIR}/docforge-image-${VERSION}.tar.gz"

# Step 3: Copy deployment files
echo ""
echo "[3/4] Copying deployment files..."
cp docker-compose.yml "${OUTPUT_DIR}/"
cp SETUP.md "${OUTPUT_DIR}/" 2>/dev/null || true

# Copy HTTPS deployment files
mkdir -p "${OUTPUT_DIR}/nginx"
mkdir -p "${OUTPUT_DIR}/ssl"
cp deploy/docker-compose.https.yml "${OUTPUT_DIR}/" 2>/dev/null || true
cp deploy/nginx/nginx.conf "${OUTPUT_DIR}/nginx/" 2>/dev/null || true
cp deploy/generate-certs.sh "${OUTPUT_DIR}/" 2>/dev/null || true
cp deploy/DEPLOYMENT_GUIDE.md "${OUTPUT_DIR}/" 2>/dev/null || true
chmod +x "${OUTPUT_DIR}/generate-certs.sh" 2>/dev/null || true

# Copy Elasticsearch/Filebeat deployment files
mkdir -p "${OUTPUT_DIR}/filebeat"
mkdir -p "${OUTPUT_DIR}/elasticsearch"
cp deploy/docker-compose.elk.yml "${OUTPUT_DIR}/" 2>/dev/null || true
cp deploy/filebeat/filebeat.yml "${OUTPUT_DIR}/filebeat/" 2>/dev/null || true
cp deploy/elasticsearch/ilm-policy.json "${OUTPUT_DIR}/elasticsearch/" 2>/dev/null || true
cp deploy/elasticsearch/ingest-pipeline.json "${OUTPUT_DIR}/elasticsearch/" 2>/dev/null || true
cp deploy/elasticsearch/setup-elasticsearch.sh "${OUTPUT_DIR}/elasticsearch/" 2>/dev/null || true
cp deploy/ELASTICSEARCH_INTEGRATION.md "${OUTPUT_DIR}/" 2>/dev/null || true
chmod +x "${OUTPUT_DIR}/elasticsearch/setup-elasticsearch.sh" 2>/dev/null || true

# Create deployment script
cat > "${OUTPUT_DIR}/deploy.sh" << 'DEPLOY_EOF'
#!/bin/bash
# DocForge Offline Deployment Script
# Run this on the air-gapped target machine

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_FILE=$(ls "${SCRIPT_DIR}"/docforge-image-*.tar.gz 2>/dev/null | head -1)

if [ -z "$IMAGE_FILE" ]; then
    echo "ERROR: No Docker image file found!"
    exit 1
fi

echo "=============================================="
echo "DocForge Offline Deployment"
echo "=============================================="

# Step 1: Load Docker image
echo ""
echo "[1/3] Loading Docker image..."
echo "      This may take a few minutes..."
gunzip -c "$IMAGE_FILE" | docker load

# Step 2: Initialize database
echo ""
echo "[2/3] Initializing database..."
docker run --rm -v docforge-data:/data docforge:latest \
    python -c "
from pathlib import Path
from docforge.storage.database import init_db
from docforge.core.config import Config

data_dir = Path('/data/.docforge')
data_dir.mkdir(parents=True, exist_ok=True)
db_path = data_dir / 'docforge.db'

if not db_path.exists():
    print('Creating database...')
    init_db(db_path)
    config = Config(db_path=db_path, cookie_secure=False)
    config.to_file(data_dir / 'config.json')
    print('Database created successfully!')
else:
    print('Database already exists.')
"

# Step 3: Seed default users
echo ""
echo "[3/3] Setting up authentication..."
docker run --rm -v docforge-data:/data docforge:latest \
    python -c "
from pathlib import Path
from docforge.storage.database import get_engine, get_session_factory
from docforge.auth.service import AuthService

db_path = Path('/data/.docforge/docforge.db')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

auth = AuthService(session)
auth.seed_permissions()
auth.seed_roles()
admin = auth.seed_admin_user(password='changeme')
session.commit()

if admin:
    print('Admin user ready: admin / changeme')
    print('WARNING: Change this password immediately!')
"

echo ""
echo "=============================================="
echo "Deployment complete!"
echo "=============================================="
echo ""
echo "To start DocForge:"
echo "  docker-compose up -d"
echo ""
echo "Access the web UI at: http://localhost:8000"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: changeme"
echo ""
echo "IMPORTANT: Change the admin password after first login!"
echo ""
DEPLOY_EOF

chmod +x "${OUTPUT_DIR}/deploy.sh"

# Step 4: Create README
cat > "${OUTPUT_DIR}/README.txt" << 'README_EOF'
================================================================================
DocForge Offline Deployment Package
================================================================================

CONTENTS:
  - docforge-image-*.tar.gz   : Docker image (compressed)
  - docker-compose.yml        : HTTP deployment config
  - docker-compose.https.yml  : HTTPS deployment config (production)
  - docker-compose.elk.yml    : Elasticsearch logging config
  - deploy.sh                 : Deployment script
  - nginx/nginx.conf          : Nginx reverse proxy config
  - filebeat/filebeat.yml     : Filebeat log shipper config
  - elasticsearch/            : Elasticsearch setup files (ILM, pipeline)
  - generate-certs.sh         : Generate self-signed TLS certificates
  - DEPLOYMENT_GUIDE.md       : Comprehensive deployment guide
  - ELASTICSEARCH_INTEGRATION.md : Elasticsearch/logging guide
  - SETUP.md                  : Quick setup reference

REQUIREMENTS:
  - Docker Engine 20.10+
  - Docker Compose v2+
  - ~500MB disk space for image
  - ~100MB disk space for data

================================================================================
OPTION A: HTTP DEPLOYMENT (Development/Testing)
================================================================================

  1. chmod +x deploy.sh && ./deploy.sh
  2. docker-compose up -d
  3. Access: http://localhost:8000

================================================================================
OPTION B: HTTPS DEPLOYMENT (Production)
================================================================================

  1. Place TLS certificates:
     - ssl/server.crt  (certificate)
     - ssl/server.key  (private key)

     Or generate self-signed certs (testing only):
       chmod +x generate-certs.sh
       ./generate-certs.sh your-hostname.com

  2. Load nginx image (if not already available):
     docker pull nginx:1.25-alpine  # On machine with internet
     docker save nginx:1.25-alpine | gzip > nginx.tar.gz
     # Transfer and load:
     gunzip -c nginx.tar.gz | docker load

  3. Deploy:
     chmod +x deploy.sh && ./deploy.sh
     docker-compose -f docker-compose.https.yml up -d

  4. Access: https://localhost

================================================================================
DEFAULT CREDENTIALS
================================================================================

  Username: admin
  Password: changeme

  *** CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN! ***

================================================================================
OPTION C: ELASTICSEARCH LOGGING
================================================================================

  1. Ensure Elasticsearch is accessible from the deployment machine

  2. Download Filebeat image (on machine with internet):
     docker pull docker.elastic.co/beats/filebeat:8.11.0
     docker save docker.elastic.co/beats/filebeat:8.11.0 | gzip > filebeat.tar.gz
     # Transfer and load:
     gunzip -c filebeat.tar.gz | docker load

  3. Setup Elasticsearch indices:
     chmod +x elasticsearch/setup-elasticsearch.sh
     ./elasticsearch/setup-elasticsearch.sh http://elasticsearch:9200

  4. Configure and deploy:
     export ELASTICSEARCH_HOSTS='["http://elasticsearch:9200"]'
     docker-compose -f docker-compose.elk.yml up -d

  See ELASTICSEARCH_INTEGRATION.md for detailed configuration options.

================================================================================
CONFIGURATION
================================================================================

Edit docker-compose.yml or docker-compose.https.yml:

  environment:
    - DOCFORGE_COOKIE_SECURE=true        # Required for HTTPS
    - DOCFORGE_ADMIN_PASSWORD=SecurePwd  # Initial admin password
    - DOCFORGE_OIDC_ENABLED=true         # Enable Keycloak SSO
    - DOCFORGE_OIDC_KEYCLOAK_URL=https://keycloak.example.com
    - DOCFORGE_OIDC_REALM=docforge
    - DOCFORGE_OIDC_CLIENT_ID=docforge-app
    - DOCFORGE_OIDC_CLIENT_SECRET=secret

================================================================================
OPERATIONS
================================================================================

  Start:    docker-compose up -d
  Stop:     docker-compose down
  Logs:     docker-compose logs -f
  Status:   docker-compose ps

  Backup:
    docker run --rm -v docforge-data:/data -v $(pwd):/backup \
      alpine tar czf /backup/docforge-backup.tar.gz -C /data .

  Restore:
    docker run --rm -v docforge-data:/data -v $(pwd):/backup \
      alpine tar xzf /backup/docforge-backup.tar.gz -C /data

================================================================================
For detailed instructions, see DEPLOYMENT_GUIDE.md
================================================================================
README_EOF

# Calculate sizes
IMAGE_SIZE=$(du -h "${OUTPUT_DIR}/docforge-image-${VERSION}.tar.gz" | cut -f1)
TOTAL_SIZE=$(du -sh "${OUTPUT_DIR}" | cut -f1)

echo ""
echo "[4/4] Package created successfully!"
echo ""
echo "Package location: ${OUTPUT_DIR}"
echo "Image size: ${IMAGE_SIZE}"
echo "Total size: ${TOTAL_SIZE}"
echo ""
echo "Contents:"
ls -la "${OUTPUT_DIR}"
echo ""
echo "To deploy:"
echo "  1. Copy '${OUTPUT_DIR}' to the air-gapped machine"
echo "  2. Run: cd ${PACKAGE_NAME} && ./deploy.sh"
echo "  3. Run: docker-compose up -d"
echo ""
