#!/bin/bash
# =============================================================================
# ION Docker Entrypoint
# Intelligent Operating Network
# =============================================================================
# Handles initialization, configuration, and startup
# Supports PostgreSQL (ION_DATABASE_URL) or SQLite (fallback)
# =============================================================================

set -e

# Configuration from environment variables
DATA_DIR="${ION_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.ion"
CONFIG_PATH="${CONFIG_DIR}/config.json"

HOST="${ION_HOST:-0.0.0.0}"
PORT="${ION_PORT:-8000}"

echo "ION starting..."
echo "  Data directory: ${DATA_DIR}"

# Create config directory if needed
mkdir -p "${CONFIG_DIR}"

# Determine database backend
if [ -n "${ION_DATABASE_URL}" ]; then
    echo "  Database: PostgreSQL"

    # Wait for PostgreSQL to be ready (in case healthcheck hasn't caught up)
    echo "Waiting for database..."
    python -c "
import time, os
from sqlalchemy import create_engine, text

url = os.environ['ION_DATABASE_URL']
for attempt in range(30):
    try:
        engine = create_engine(url)
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        print('Database ready')
        break
    except Exception as e:
        if attempt < 29:
            time.sleep(2)
        else:
            print(f'Database not ready after 60s: {e}')
            raise
"
else
    DB_PATH="${CONFIG_DIR}/ion.db"
    echo "  Database: SQLite (${DB_PATH})"
fi

# Initialize database and seed auth
echo "Initializing database..."
python -c "
from pathlib import Path
from ion.storage.database import init_db
from ion.core.config import Config
import os

# init_db reads ION_DATABASE_URL automatically if set
engine = init_db()

# Create config from environment (only if config.json doesn't exist)
config_path = Path('${CONFIG_PATH}')
if not config_path.exists():
    config = Config(
        db_path=Path('${CONFIG_DIR}/ion.db'),
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
    config.to_file(config_path)
    print('Config initialized from environment')

print('Database initialized')
"

# Seed authentication (idempotent — safe to run every startup)
echo "Setting up authentication..."
python -c "
from ion.storage.database import get_engine, get_session_factory
from ion.auth.service import AuthService
import os

engine = get_engine()
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

echo "Starting web server on ${HOST}:${PORT}..."

# Execute the main command
exec python -m uvicorn ion.web.server:app \
    --host "${HOST}" \
    --port "${PORT}" \
    "$@"
