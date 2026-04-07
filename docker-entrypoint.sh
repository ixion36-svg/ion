#!/bin/bash
# =============================================================================
# ION Docker Entrypoint
# Intelligent Operating Network
# =============================================================================
# PostgreSQL-only deployment. SQLite is for local dev only.
# =============================================================================

set -e

DATA_DIR="${ION_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.ion"
CONFIG_PATH="${CONFIG_DIR}/config.json"

HOST="${ION_HOST:-0.0.0.0}"
PORT="${ION_PORT:-8000}"

# Default to the compose PostgreSQL if not set
export ION_DATABASE_URL="${ION_DATABASE_URL:-postgresql://ion:ion2025@postgres:5432/ion}"

echo "ION starting..."
echo "  Data directory: ${DATA_DIR}"
echo "  Database: PostgreSQL"

mkdir -p "${CONFIG_DIR}"

# =============================================================================
# Fresh database option (ONE-SHOT)
# =============================================================================
FRESH_DB_MARKER="${CONFIG_DIR}/.fresh_db_done"

if [ "${ION_FRESH_DB:-false}" = "true" ] && [ ! -f "${FRESH_DB_MARKER}" ]; then
    echo ""
    echo "============================================"
    echo "  ION_FRESH_DB=true — wiping database"
    echo "============================================"
    echo "  Dropping all PostgreSQL tables..."
    python -c "
from sqlalchemy import create_engine, text, inspect
import os
url = os.environ['ION_DATABASE_URL']
engine = create_engine(url)
with engine.connect() as conn:
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if tables:
        conn.execute(text('DROP SCHEMA public CASCADE'))
        conn.execute(text('CREATE SCHEMA public'))
        conn.commit()
        print(f'  Dropped {len(tables)} tables')
    else:
        print('  No existing tables to drop')
" 2>/dev/null || echo "  (PostgreSQL not yet available — tables will be created fresh)"
    rm -f "${CONFIG_DIR}/.seeded"* "${CONFIG_DIR}/.fresh_db_done"
    echo "Wiped at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${FRESH_DB_MARKER}"
    echo "  Database wiped — starting fresh"
    echo ""
elif [ "${ION_FRESH_DB:-false}" = "true" ] && [ -f "${FRESH_DB_MARKER}" ]; then
    echo "  ION_FRESH_DB=true but already wiped — skipping"
fi

# =============================================================================
# Wait for PostgreSQL
# =============================================================================
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

# =============================================================================
# Initialize database (creates tables)
# =============================================================================
echo "Initializing database..."
python -c "
from pathlib import Path
from ion.storage.database import init_db
from ion.core.config import Config
import os

engine = init_db()

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
        elasticsearch_alert_index=os.environ.get('ION_ELASTICSEARCH_ALERT_INDEX', '.alerts-security.alerts-*,alerts-*'),
    )
    config.to_file(config_path)
    print('Config initialized from environment')

print('Database initialized')
"

# =============================================================================
# Seed authentication
# =============================================================================
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

admin_password = os.environ.get('ION_ADMIN_PASSWORD', 'changeme')
auth.seed_admin_user(password=admin_password)
session.commit()
print('Authentication configured')
"

echo "Starting web server on ${HOST}:${PORT}..."

exec python -m uvicorn ion.web.server:app \
    --host "${HOST}" \
    --port "${PORT}" \
    "$@"
