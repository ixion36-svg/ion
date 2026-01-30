#!/bin/bash
# =============================================================================
# IXION - Build Offline Deployment Package
# =============================================================================
# Run this script on a machine WITH internet access to create an air-gapped
# deployment package that can be transferred to the secure environment.
#
# Usage: ./scripts/build-offline-package.sh [version] [model]
# Example: ./scripts/build-offline-package.sh 1.0.0 qwen2.5:0.5b
# =============================================================================

set -e

VERSION="${1:-latest}"
OLLAMA_MODEL="${2:-qwen2.5:0.5b}"
PACKAGE_NAME="ixion-offline-${VERSION}"
OUTPUT_DIR="./dist/${PACKAGE_NAME}"

echo "=============================================="
echo "Building IXION Offline Package v${VERSION}"
echo "Including Ollama model: ${OLLAMA_MODEL}"
echo "=============================================="

# Create output directory
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/images"
mkdir -p "${OUTPUT_DIR}/models"

# Step 1: Build IXION Docker image
echo ""
echo "[1/6] Building IXION Docker image..."
docker build -t ixion:${VERSION} -t ixion:latest .

# Step 2: Save IXION Docker image as tar
echo ""
echo "[2/6] Exporting IXION Docker image..."
docker save ixion:${VERSION} | gzip > "${OUTPUT_DIR}/images/ixion-${VERSION}.tar.gz"

# Step 3: Pull and save Ollama image
echo ""
echo "[3/6] Pulling Ollama Docker image..."
docker pull ollama/ollama:latest
docker save ollama/ollama:latest | gzip > "${OUTPUT_DIR}/images/ollama-latest.tar.gz"

# Step 4: Pull Ollama model and export it
echo ""
echo "[4/6] Pulling Ollama model: ${OLLAMA_MODEL}..."
# Start a temporary Ollama container to pull the model
docker run -d --name ixion-ollama-temp -v ixion-ollama-temp:/root/.ollama ollama/ollama:latest
sleep 5

# Pull the model
docker exec ixion-ollama-temp ollama pull ${OLLAMA_MODEL}

# Export the model data
echo "Exporting model data..."
docker run --rm -v ixion-ollama-temp:/source -v "$(pwd)/${OUTPUT_DIR}/models":/dest alpine \
    sh -c "cd /source && tar czf /dest/ollama-models.tar.gz ."

# Cleanup temp container
docker stop ixion-ollama-temp
docker rm ixion-ollama-temp
docker volume rm ixion-ollama-temp

# Step 5: Copy deployment files
echo ""
echo "[5/6] Copying deployment files..."
cp docker-compose.yml "${OUTPUT_DIR}/"
cp .env.example "${OUTPUT_DIR}/.env"
cp SETUP.md "${OUTPUT_DIR}/" 2>/dev/null || true
cp README.md "${OUTPUT_DIR}/" 2>/dev/null || true

# Copy HTTPS deployment files
mkdir -p "${OUTPUT_DIR}/deploy"
mkdir -p "${OUTPUT_DIR}/deploy/nginx"
mkdir -p "${OUTPUT_DIR}/deploy/ssl"
cp -r deploy/* "${OUTPUT_DIR}/deploy/" 2>/dev/null || true

# Create deployment script
cat > "${OUTPUT_DIR}/deploy.sh" << 'DEPLOY_EOF'
#!/bin/bash
# IXION Offline Deployment Script
# Run this on the air-gapped target machine

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "IXION Offline Deployment"
echo "=============================================="

# Step 1: Load Docker images
echo ""
echo "[1/4] Loading Docker images..."
echo "      Loading IXION image..."
gunzip -c "${SCRIPT_DIR}/images/ixion-"*.tar.gz | docker load

echo "      Loading Ollama image..."
gunzip -c "${SCRIPT_DIR}/images/ollama-latest.tar.gz" | docker load

# Step 2: Load Ollama models
echo ""
echo "[2/4] Loading Ollama models..."
docker volume create ixion_ollama-models 2>/dev/null || true
docker run --rm -v ixion_ollama-models:/dest -v "${SCRIPT_DIR}/models":/source alpine \
    sh -c "cd /dest && tar xzf /source/ollama-models.tar.gz"
echo "      Models loaded successfully!"

# Step 3: Initialize database
echo ""
echo "[3/4] Initializing database..."
docker volume create ixion_ixion-data 2>/dev/null || true
docker run --rm -v ixion_ixion-data:/data ixion:latest \
    python -c "
from pathlib import Path
from ixion.storage.database import init_db
from ixion.core.config import Config

data_dir = Path('/data/.ixion')
data_dir.mkdir(parents=True, exist_ok=True)
db_path = data_dir / 'ixion.db'

if not db_path.exists():
    print('Creating database...')
    init_db(db_path)
    config = Config(db_path=db_path, cookie_secure=False)
    config.to_file(data_dir / 'config.json')
    print('Database created successfully!')
else:
    print('Database already exists.')
"

# Step 4: Seed default users
echo ""
echo "[4/4] Setting up authentication..."
docker run --rm -v ixion_ixion-data:/data ixion:latest \
    python -c "
from pathlib import Path
from ixion.storage.database import get_engine, get_session_factory
from ixion.auth.service import AuthService
import os

db_path = Path('/data/.ixion/ixion.db')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

auth = AuthService(session)
auth.seed_permissions()
auth.seed_roles()
admin_password = os.environ.get('IXION_ADMIN_PASSWORD', 'changeme')
admin = auth.seed_admin_user(password=admin_password)
session.commit()

if admin:
    print('Admin user ready: admin / ' + admin_password)
    print('WARNING: Change this password immediately!')
"

echo ""
echo "=============================================="
echo "Deployment complete!"
echo "=============================================="
echo ""
echo "To start IXION:"
echo "  cd ${SCRIPT_DIR}"
echo "  docker-compose up -d"
echo ""
echo "Access the web UI at: http://localhost:8000"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: changeme (or value of IXION_ADMIN_PASSWORD)"
echo ""
echo "IMPORTANT: Change the admin password after first login!"
echo ""
DEPLOY_EOF

chmod +x "${OUTPUT_DIR}/deploy.sh"

# Step 6: Create README
cat > "${OUTPUT_DIR}/README.txt" << README_EOF
================================================================================
IXION Offline Deployment Package v${VERSION}
Intelligence eXchange & Integration Operations Network
================================================================================

CONTENTS:
  images/
    - ixion-${VERSION}.tar.gz    : IXION Docker image
    - ollama-latest.tar.gz       : Ollama LLM service image
  models/
    - ollama-models.tar.gz       : Pre-downloaded Ollama model (${OLLAMA_MODEL})
  deploy/
    - nginx/                     : Nginx reverse proxy configs
    - ssl/                       : SSL certificate directory
    - docker-compose.https.yml   : HTTPS deployment config
  - docker-compose.yml           : Main deployment config
  - .env                         : Environment configuration
  - deploy.sh                    : Deployment script
  - SETUP.md                     : Quick setup reference
  - README.md                    : Full documentation

REQUIREMENTS:
  - Docker Engine 20.10+
  - Docker Compose v2+
  - 8GB+ RAM recommended (for Ollama)
  - ~2GB disk space for images
  - ~500MB disk space for models

================================================================================
QUICK START
================================================================================

  1. chmod +x deploy.sh && ./deploy.sh
  2. Edit .env to configure integrations (GitLab, OpenCTI, Elasticsearch)
  3. docker-compose up -d
  4. Access: http://localhost:8000
  5. Login: admin / changeme

================================================================================
HTTPS DEPLOYMENT (Production)
================================================================================

  1. Place TLS certificates in deploy/ssl/:
     - server.crt (certificate)
     - server.key (private key)

  2. Update .env:
     IXION_COOKIE_SECURE=true

  3. Deploy:
     docker-compose -f deploy/docker-compose.https.yml up -d

  4. Access: https://localhost

================================================================================
INTEGRATION CONFIGURATION
================================================================================

Edit .env before starting:

  # GitLab
  IXION_GITLAB_ENABLED=true
  IXION_GITLAB_URL=https://gitlab.example.com
  IXION_GITLAB_TOKEN=your-token
  IXION_GITLAB_PROJECT_ID=1

  # OpenCTI
  IXION_OPENCTI_ENABLED=true
  IXION_OPENCTI_URL=https://opencti.example.com
  IXION_OPENCTI_TOKEN=your-token

  # Elasticsearch
  IXION_ELASTICSEARCH_ENABLED=true
  IXION_ELASTICSEARCH_URL=https://elasticsearch.example.com:9200
  IXION_ELASTICSEARCH_USERNAME=elastic
  IXION_ELASTICSEARCH_PASSWORD=your-password

================================================================================
AI ASSISTANT
================================================================================

The Ollama model (${OLLAMA_MODEL}) is pre-loaded and ready to use.

To use a different model:
  1. Update IXION_OLLAMA_MODEL in .env
  2. Ensure the model is available in the models/ archive

================================================================================
OPERATIONS
================================================================================

  Start:    docker-compose up -d
  Stop:     docker-compose down
  Logs:     docker-compose logs -f
  Status:   docker-compose ps

  Backup:
    docker run --rm -v ixion_ixion-data:/data -v \$(pwd):/backup \\
      alpine tar czf /backup/ixion-backup.tar.gz -C /data .

  Restore:
    docker-compose down
    docker run --rm -v ixion_ixion-data:/data -v \$(pwd):/backup \\
      alpine sh -c "rm -rf /data/* && tar xzf /backup/ixion-backup.tar.gz -C /data"
    docker-compose up -d

================================================================================
README_EOF

# Calculate sizes
IXION_SIZE=$(du -h "${OUTPUT_DIR}/images/ixion-${VERSION}.tar.gz" | cut -f1)
OLLAMA_SIZE=$(du -h "${OUTPUT_DIR}/images/ollama-latest.tar.gz" | cut -f1)
MODEL_SIZE=$(du -h "${OUTPUT_DIR}/models/ollama-models.tar.gz" | cut -f1)
TOTAL_SIZE=$(du -sh "${OUTPUT_DIR}" | cut -f1)

echo ""
echo "[6/6] Package created successfully!"
echo ""
echo "Package location: ${OUTPUT_DIR}"
echo ""
echo "Sizes:"
echo "  IXION image:  ${IXION_SIZE}"
echo "  Ollama image: ${OLLAMA_SIZE}"
echo "  Ollama model: ${MODEL_SIZE}"
echo "  Total:        ${TOTAL_SIZE}"
echo ""
echo "To deploy on air-gapped machine:"
echo "  1. Copy '${OUTPUT_DIR}' to the target machine"
echo "  2. Run: cd ${PACKAGE_NAME} && ./deploy.sh"
echo "  3. Edit .env to configure integrations"
echo "  4. Run: docker-compose up -d"
echo ""
