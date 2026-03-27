#!/bin/bash
# =============================================================================
# ION Docker Entrypoint
# Intelligent Operating Network
# =============================================================================
# Handles initialization, configuration, and startup
# Supports PostgreSQL (ION_DATABASE_URL) or SQLite (fallback)
# Auto-migrates from SQLite to PostgreSQL on first run if ion.db exists
# =============================================================================

set -e

# Configuration from environment variables
DATA_DIR="${ION_DATA_DIR:-/data}"
CONFIG_DIR="${DATA_DIR}/.ion"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SQLITE_DB="${CONFIG_DIR}/ion.db"
MIGRATED_MARKER="${CONFIG_DIR}/ion.db.migrated"

HOST="${ION_HOST:-0.0.0.0}"
PORT="${ION_PORT:-8000}"

echo "ION starting..."
echo "  Data directory: ${DATA_DIR}"

# Create config directory if needed
mkdir -p "${CONFIG_DIR}"

# =============================================================================
# Fresh database option: ION_FRESH_DB=true wipes existing data (ONE-SHOT)
# After wiping, a marker is written so it won't wipe again on restart.
# Delete /data/.ion/.fresh_db_done to allow another wipe.
# =============================================================================
FRESH_DB_MARKER="${CONFIG_DIR}/.fresh_db_done"

if [ "${ION_FRESH_DB:-false}" = "true" ] && [ ! -f "${FRESH_DB_MARKER}" ]; then
    echo ""
    echo "============================================"
    echo "  ION_FRESH_DB=true — wiping database"
    echo "  (one-shot: will NOT wipe on next restart)"
    echo "============================================"
    if [ -f "${SQLITE_DB}" ]; then
        echo "  Removing SQLite database: ${SQLITE_DB}"
        rm -f "${SQLITE_DB}"
    fi
    if [ -f "${MIGRATED_MARKER}" ]; then
        rm -f "${MIGRATED_MARKER}"
    fi
    # Drop and recreate PostgreSQL database if configured
    if [ -n "${ION_DATABASE_URL}" ]; then
        echo "  Dropping all PostgreSQL tables..."
        python -c "
from sqlalchemy import create_engine, text, inspect
import os
url = os.environ['ION_DATABASE_URL']
engine = create_engine(url)
with engine.connect() as conn:
    # Get all table names and drop them
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
    fi
    # Remove seeder marker so KB/playbooks get re-seeded
    rm -f "${CONFIG_DIR}/.seeded"*
    # Write marker so fresh DB wipe only happens once
    echo "Wiped at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${FRESH_DB_MARKER}"
    echo "  Database wiped — starting fresh"
    echo "  Marker written: ${FRESH_DB_MARKER}"
    echo "  To wipe again, remove ${FRESH_DB_MARKER} and restart."
    echo ""
elif [ "${ION_FRESH_DB:-false}" = "true" ] && [ -f "${FRESH_DB_MARKER}" ]; then
    echo "  ION_FRESH_DB=true but already wiped (marker: ${FRESH_DB_MARKER})"
    echo "  Skipping wipe. Remove marker to wipe again."
fi

# Determine database backend
if [ -n "${ION_DATABASE_URL}" ]; then
    echo "  Database: PostgreSQL"

    # Warn if SQLite database still exists alongside PostgreSQL
    if [ -f "${SQLITE_DB}" ]; then
        echo ""
        echo "  WARNING: SQLite database found at ${SQLITE_DB}"
        echo "  PostgreSQL is configured — SQLite will NOT be used."
        echo "  Set ION_FRESH_DB=true to remove it, or delete manually."
        echo ""
    fi

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
    echo "  Database: SQLite (${SQLITE_DB})"
fi

# Initialize database (creates tables)
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
        elasticsearch_alert_index=os.environ.get('ION_ELASTICSEARCH_ALERT_INDEX', '.alerts-security.alerts-*,alerts-*'),
    )
    config.to_file(config_path)
    print('Config initialized from environment')

print('Database initialized')
"

# =============================================================================
# Auto-migrate SQLite -> PostgreSQL (one-time, on first upgrade)
# =============================================================================
# If PostgreSQL is configured AND an old ion.db exists AND hasn't been
# migrated yet, automatically copy all data from SQLite to PostgreSQL.
# After migration, renames ion.db to ion.db.migrated so it won't run again.
# =============================================================================
if [ -n "${ION_DATABASE_URL}" ] && [ -f "${SQLITE_DB}" ] && [ ! -f "${MIGRATED_MARKER}" ]; then
    echo ""
    echo "============================================"
    echo "  SQLite database detected — auto-migrating"
    echo "  to PostgreSQL (one-time operation)..."
    echo "============================================"
    echo ""

    python /app/migrate_to_postgres.py "${SQLITE_DB}" "${ION_DATABASE_URL}"
    MIGRATE_EXIT=$?

    if [ $MIGRATE_EXIT -eq 0 ]; then
        # Rename the old database so migration doesn't run again
        mv "${SQLITE_DB}" "${MIGRATED_MARKER}"
        echo ""
        echo "Migration complete. Old database preserved at ${MIGRATED_MARKER}"
        echo ""
    else
        echo ""
        echo "WARNING: Migration failed (exit code ${MIGRATE_EXIT})."
        echo "ION will continue with a fresh PostgreSQL database."
        echo "The old SQLite database is still at ${SQLITE_DB}"
        echo "You can retry manually: python /app/migrate_to_postgres.py ${SQLITE_DB}"
        echo ""
    fi
fi

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
