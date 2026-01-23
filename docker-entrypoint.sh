#!/bin/bash
# =============================================================================
# DocForge Docker Entrypoint
# =============================================================================
# Handles initialization, configuration, and startup
# =============================================================================

set -e

# Configuration from environment variables
DATA_DIR="${DOCFORGE_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.docforge"
DB_PATH="${CONFIG_DIR}/docforge.db"
CONFIG_PATH="${CONFIG_DIR}/config.json"

HOST="${DOCFORGE_HOST:-0.0.0.0}"
PORT="${DOCFORGE_PORT:-8000}"

echo "DocForge starting..."
echo "  Data directory: ${DATA_DIR}"
echo "  Database: ${DB_PATH}"

# Create config directory if needed
mkdir -p "${CONFIG_DIR}"

# Initialize database if it doesn't exist
if [ ! -f "${DB_PATH}" ]; then
    echo "Initializing database..."
    python -c "
from pathlib import Path
from docforge.storage.database import init_db
from docforge.core.config import Config
import os

db_path = Path('${DB_PATH}')
init_db(db_path)

# Create config from environment
config = Config(
    db_path=db_path,
    cookie_secure=os.environ.get('DOCFORGE_COOKIE_SECURE', 'false').lower() == 'true',
    oidc_enabled=os.environ.get('DOCFORGE_OIDC_ENABLED', 'false').lower() == 'true',
    oidc_keycloak_url=os.environ.get('DOCFORGE_OIDC_KEYCLOAK_URL', ''),
    oidc_realm=os.environ.get('DOCFORGE_OIDC_REALM', ''),
    oidc_client_id=os.environ.get('DOCFORGE_OIDC_CLIENT_ID', ''),
    oidc_client_secret=os.environ.get('DOCFORGE_OIDC_CLIENT_SECRET', ''),
)
config.to_file(Path('${CONFIG_PATH}'))
print('Database initialized')
"

    # Seed default users
    echo "Setting up authentication..."
    python -c "
from pathlib import Path
from docforge.storage.database import get_engine, get_session_factory
from docforge.auth.service import AuthService
import os

db_path = Path('${DB_PATH}')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

auth = AuthService(session)
auth.seed_permissions()
auth.seed_roles()

# Use environment variable for initial admin password if set
admin_password = os.environ.get('DOCFORGE_ADMIN_PASSWORD', 'changeme')
auth.seed_admin_user(password=admin_password)
session.commit()
print('Authentication configured')
"
fi

# Update config from environment variables (in case they changed)
python -c "
from pathlib import Path
from docforge.core.config import Config
import os

config_path = Path('${CONFIG_PATH}')
if config_path.exists():
    config = Config.from_file(config_path)
else:
    config = Config(db_path=Path('${DB_PATH}'))

# Update from environment
if os.environ.get('DOCFORGE_COOKIE_SECURE'):
    config.cookie_secure = os.environ.get('DOCFORGE_COOKIE_SECURE', 'false').lower() == 'true'
if os.environ.get('DOCFORGE_OIDC_ENABLED'):
    config.oidc_enabled = os.environ.get('DOCFORGE_OIDC_ENABLED', 'false').lower() == 'true'
if os.environ.get('DOCFORGE_OIDC_KEYCLOAK_URL'):
    config.oidc_keycloak_url = os.environ.get('DOCFORGE_OIDC_KEYCLOAK_URL', '')
if os.environ.get('DOCFORGE_OIDC_REALM'):
    config.oidc_realm = os.environ.get('DOCFORGE_OIDC_REALM', '')
if os.environ.get('DOCFORGE_OIDC_CLIENT_ID'):
    config.oidc_client_id = os.environ.get('DOCFORGE_OIDC_CLIENT_ID', '')
if os.environ.get('DOCFORGE_OIDC_CLIENT_SECRET'):
    config.oidc_client_secret = os.environ.get('DOCFORGE_OIDC_CLIENT_SECRET', '')

config.to_file(config_path)
"

echo "Starting web server on ${HOST}:${PORT}..."

# Execute the main command
exec python -m uvicorn docforge.web.server:app \
    --host "${HOST}" \
    --port "${PORT}" \
    "$@"
