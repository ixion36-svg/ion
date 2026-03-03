#!/bin/bash
# =============================================================================
# ION Docker Entrypoint
# Intelligent Operating Network
# =============================================================================
# Handles initialization, configuration, and startup
# =============================================================================

set -e

# Configuration from environment variables
DATA_DIR="${ION_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.ion"
DB_PATH="${CONFIG_DIR}/ion.db"
CONFIG_PATH="${CONFIG_DIR}/config.json"

HOST="${ION_HOST:-0.0.0.0}"
PORT="${ION_PORT:-8000}"

echo "ION starting..."
echo "  Data directory: ${DATA_DIR}"
echo "  Database: ${DB_PATH}"

# Create config directory if needed
mkdir -p "${CONFIG_DIR}"

# Initialize database if it doesn't exist
if [ ! -f "${DB_PATH}" ]; then
    echo "Initializing database..."
    python -c "
from pathlib import Path
from ion.storage.database import init_db
from ion.core.config import Config
import os

db_path = Path('${DB_PATH}')
init_db(db_path)

# Create config from environment
config = Config(
    db_path=db_path,
    cookie_secure=os.environ.get('ION_COOKIE_SECURE', 'false').lower() == 'true',
    oidc_enabled=os.environ.get('ION_OIDC_ENABLED', 'false').lower() == 'true',
    oidc_keycloak_url=os.environ.get('ION_OIDC_KEYCLOAK_URL', ''),
    oidc_realm=os.environ.get('ION_OIDC_REALM', ''),
    oidc_client_id=os.environ.get('ION_OIDC_CLIENT_ID', ''),
    oidc_client_secret=os.environ.get('ION_OIDC_CLIENT_SECRET', ''),
    gitlab_enabled=os.environ.get('ION_GITLAB_ENABLED', 'false').lower() == 'true',
    gitlab_url=os.environ.get('ION_GITLAB_URL', ''),
    gitlab_token=os.environ.get('ION_GITLAB_TOKEN', ''),
    gitlab_project_id=os.environ.get('ION_GITLAB_PROJECT_ID', ''),
    opencti_enabled=os.environ.get('ION_OPENCTI_ENABLED', 'false').lower() == 'true',
    opencti_url=os.environ.get('ION_OPENCTI_URL', ''),
    opencti_token=os.environ.get('ION_OPENCTI_TOKEN', ''),
    elasticsearch_enabled=os.environ.get('ION_ELASTICSEARCH_ENABLED', 'false').lower() == 'true',
    elasticsearch_url=os.environ.get('ION_ELASTICSEARCH_URL', ''),
    elasticsearch_username=os.environ.get('ION_ELASTICSEARCH_USERNAME', ''),
    elasticsearch_password=os.environ.get('ION_ELASTICSEARCH_PASSWORD', ''),
    elasticsearch_api_key=os.environ.get('ION_ELASTICSEARCH_API_KEY', ''),
)
config.to_file(Path('${CONFIG_PATH}'))
print('Database initialized')
"

    # Seed default users
    echo "Setting up authentication..."
    python -c "
from pathlib import Path
from ion.storage.database import get_engine, get_session_factory
from ion.auth.service import AuthService
import os

db_path = Path('${DB_PATH}')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

auth = AuthService(session)
auth.seed_permissions()
auth.seed_roles()

# Use environment variable for initial admin password if set
admin_password = os.environ.get('ION_ADMIN_PASSWORD', 'changeme')
auth.seed_admin_user(password=admin_password)
session.commit()
print('Authentication configured')
"
fi

# config.json is only written on first run (above). Subsequent changes
# are made via the admin UI and persisted in config.json on the volume.
# To re-initialize from .env, delete /data/.ion/config.json and restart.

echo "Starting web server on ${HOST}:${PORT}..."

# Execute the main command
exec python -m uvicorn ion.web.server:app \
    --host "${HOST}" \
    --port "${PORT}" \
    "$@"
