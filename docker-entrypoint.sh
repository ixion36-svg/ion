#!/bin/bash
# =============================================================================
# IXION Docker Entrypoint
# Intelligence eXchange & Integration Operations Network
# =============================================================================
# Handles initialization, configuration, and startup
# =============================================================================

set -e

# Configuration from environment variables
DATA_DIR="${IXION_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.ixion"
DB_PATH="${CONFIG_DIR}/ixion.db"
CONFIG_PATH="${CONFIG_DIR}/config.json"

HOST="${IXION_HOST:-0.0.0.0}"
PORT="${IXION_PORT:-8000}"

echo "IXION starting..."
echo "  Data directory: ${DATA_DIR}"
echo "  Database: ${DB_PATH}"

# Create config directory if needed
mkdir -p "${CONFIG_DIR}"

# Initialize database if it doesn't exist
if [ ! -f "${DB_PATH}" ]; then
    echo "Initializing database..."
    python -c "
from pathlib import Path
from ixion.storage.database import init_db
from ixion.core.config import Config
import os

db_path = Path('${DB_PATH}')
init_db(db_path)

# Create config from environment
config = Config(
    db_path=db_path,
    cookie_secure=os.environ.get('IXION_COOKIE_SECURE', 'false').lower() == 'true',
    oidc_enabled=os.environ.get('IXION_OIDC_ENABLED', 'false').lower() == 'true',
    oidc_keycloak_url=os.environ.get('IXION_OIDC_KEYCLOAK_URL', ''),
    oidc_realm=os.environ.get('IXION_OIDC_REALM', ''),
    oidc_client_id=os.environ.get('IXION_OIDC_CLIENT_ID', ''),
    oidc_client_secret=os.environ.get('IXION_OIDC_CLIENT_SECRET', ''),
    gitlab_enabled=os.environ.get('IXION_GITLAB_ENABLED', 'false').lower() == 'true',
    gitlab_url=os.environ.get('IXION_GITLAB_URL', ''),
    gitlab_token=os.environ.get('IXION_GITLAB_TOKEN', ''),
    gitlab_project_id=os.environ.get('IXION_GITLAB_PROJECT_ID', ''),
    opencti_enabled=os.environ.get('IXION_OPENCTI_ENABLED', 'false').lower() == 'true',
    opencti_url=os.environ.get('IXION_OPENCTI_URL', ''),
    opencti_token=os.environ.get('IXION_OPENCTI_TOKEN', ''),
    elasticsearch_enabled=os.environ.get('IXION_ELASTICSEARCH_ENABLED', 'false').lower() == 'true',
    elasticsearch_url=os.environ.get('IXION_ELASTICSEARCH_URL', ''),
    elasticsearch_username=os.environ.get('IXION_ELASTICSEARCH_USERNAME', ''),
    elasticsearch_password=os.environ.get('IXION_ELASTICSEARCH_PASSWORD', ''),
    elasticsearch_api_key=os.environ.get('IXION_ELASTICSEARCH_API_KEY', ''),
)
config.to_file(Path('${CONFIG_PATH}'))
print('Database initialized')
"

    # Seed default users
    echo "Setting up authentication..."
    python -c "
from pathlib import Path
from ixion.storage.database import get_engine, get_session_factory
from ixion.auth.service import AuthService
import os

db_path = Path('${DB_PATH}')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

auth = AuthService(session)
auth.seed_permissions()
auth.seed_roles()

# Use environment variable for initial admin password if set
admin_password = os.environ.get('IXION_ADMIN_PASSWORD', 'changeme')
auth.seed_admin_user(password=admin_password)
session.commit()
print('Authentication configured')
"
fi

# Update config from environment variables (in case they changed)
python -c "
from pathlib import Path
from ixion.core.config import Config
import os

config_path = Path('${CONFIG_PATH}')
if config_path.exists():
    config = Config.from_file(config_path)
else:
    config = Config(db_path=Path('${DB_PATH}'))

# Update from environment
if os.environ.get('IXION_COOKIE_SECURE'):
    config.cookie_secure = os.environ.get('IXION_COOKIE_SECURE', 'false').lower() == 'true'
if os.environ.get('IXION_OIDC_ENABLED'):
    config.oidc_enabled = os.environ.get('IXION_OIDC_ENABLED', 'false').lower() == 'true'
if os.environ.get('IXION_OIDC_KEYCLOAK_URL'):
    config.oidc_keycloak_url = os.environ.get('IXION_OIDC_KEYCLOAK_URL', '')
if os.environ.get('IXION_OIDC_REALM'):
    config.oidc_realm = os.environ.get('IXION_OIDC_REALM', '')
if os.environ.get('IXION_OIDC_CLIENT_ID'):
    config.oidc_client_id = os.environ.get('IXION_OIDC_CLIENT_ID', '')
if os.environ.get('IXION_OIDC_CLIENT_SECRET'):
    config.oidc_client_secret = os.environ.get('IXION_OIDC_CLIENT_SECRET', '')
if os.environ.get('IXION_GITLAB_ENABLED'):
    config.gitlab_enabled = os.environ.get('IXION_GITLAB_ENABLED', 'false').lower() == 'true'
if os.environ.get('IXION_GITLAB_URL'):
    config.gitlab_url = os.environ.get('IXION_GITLAB_URL', '')
if os.environ.get('IXION_GITLAB_TOKEN'):
    config.gitlab_token = os.environ.get('IXION_GITLAB_TOKEN', '')
if os.environ.get('IXION_GITLAB_PROJECT_ID'):
    config.gitlab_project_id = os.environ.get('IXION_GITLAB_PROJECT_ID', '')
if os.environ.get('IXION_OPENCTI_ENABLED'):
    config.opencti_enabled = os.environ.get('IXION_OPENCTI_ENABLED', 'false').lower() == 'true'
if os.environ.get('IXION_OPENCTI_URL'):
    config.opencti_url = os.environ.get('IXION_OPENCTI_URL', '')
if os.environ.get('IXION_OPENCTI_TOKEN'):
    config.opencti_token = os.environ.get('IXION_OPENCTI_TOKEN', '')
if os.environ.get('IXION_ELASTICSEARCH_ENABLED'):
    config.elasticsearch_enabled = os.environ.get('IXION_ELASTICSEARCH_ENABLED', 'false').lower() == 'true'
if os.environ.get('IXION_ELASTICSEARCH_URL'):
    config.elasticsearch_url = os.environ.get('IXION_ELASTICSEARCH_URL', '')
if os.environ.get('IXION_ELASTICSEARCH_USERNAME'):
    config.elasticsearch_username = os.environ.get('IXION_ELASTICSEARCH_USERNAME', '')
if os.environ.get('IXION_ELASTICSEARCH_PASSWORD'):
    config.elasticsearch_password = os.environ.get('IXION_ELASTICSEARCH_PASSWORD', '')
if os.environ.get('IXION_ELASTICSEARCH_API_KEY'):
    config.elasticsearch_api_key = os.environ.get('IXION_ELASTICSEARCH_API_KEY', '')

config.to_file(config_path)
"

echo "Starting web server on ${HOST}:${PORT}..."

# Execute the main command
exec python -m uvicorn ixion.web.server:app \
    --host "${HOST}" \
    --port "${PORT}" \
    "$@"
