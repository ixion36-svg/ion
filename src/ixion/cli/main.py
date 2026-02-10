"""Main CLI entry point for IXION."""

import typer
from rich.console import Console

from ixion.cli.template_commands import template_app
from ixion.cli.version_commands import version_app
from ixion.cli.render_commands import render_app
from ixion.cli.extract_commands import extract_app
from ixion.cli.document_commands import document_app
from ixion.cli.collection_commands import collection_app

app = typer.Typer(
    name="ixion",
    help="Documentation Template Management System",
    no_args_is_help=True,
)

console = Console()

# Add sub-commands
app.add_typer(template_app, name="template", help="Template management commands")
app.add_typer(collection_app, name="collection", help="Collection management commands")
app.add_typer(version_app, name="version", help="Version control commands")
app.add_typer(render_app, name="render", help="Template rendering commands")
app.add_typer(extract_app, name="extract", help="Template extraction commands")
app.add_typer(document_app, name="document", help="Document management commands")


@app.command()
def init(
    path: str = typer.Option(
        ".", "--path", "-p", help="Path to initialize IXION in"
    ),
) -> None:
    """Initialize IXION database in the current or specified directory."""
    from pathlib import Path
    from ixion.storage.database import init_db
    from ixion.core.config import Config

    target_path = Path(path).resolve()
    ixion_dir = target_path / ".ixion"
    db_path = ixion_dir / "ixion.db"

    # Create directory
    ixion_dir.mkdir(parents=True, exist_ok=True)

    # Initialize database
    init_db(db_path)

    # Create default config
    config = Config(db_path=db_path)
    config.to_file(ixion_dir / "config.json")

    console.print(f"[green]OK[/green] Initialized IXION in {ixion_dir}")
    console.print(f"  Database: {db_path}")
    console.print(f"  Config: {ixion_dir / 'config.json'}")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
) -> None:
    """Start the web UI server."""
    import uvicorn

    console.print(f"[bold]Starting IXION Web UI[/bold]")
    console.print(f"  URL: http://{host}:{port}")
    console.print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(
        "ixion.web.server:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def status() -> None:
    """Show IXION status and statistics."""
    from pathlib import Path
    from ixion.core.config import get_config
    from ixion.storage.database import get_session, get_engine
    from ixion.storage.template_repository import TemplateRepository
    from ixion.storage.document_repository import DocumentRepository

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]IXION not initialized.[/yellow]")
        console.print("Run 'ixion init' to initialize.")
        return

    console.print("[bold]IXION Status[/bold]")
    console.print(f"  Database: {config.db_path}")
    console.print(f"  Default format: {config.default_format}")
    console.print(f"  Auto-save: {config.auto_save}")

    # Get statistics
    try:
        engine = get_engine(config.db_path)
        session = next(get_session(engine))
        template_repo = TemplateRepository(session)
        document_repo = DocumentRepository(session)

        templates = template_repo.list_all()
        documents = document_repo.list_all()
        tags = template_repo.list_tags()

        console.print(f"\n[bold]Statistics[/bold]")
        console.print(f"  Templates: {len(templates)}")
        console.print(f"  Documents: {len(documents)}")
        console.print(f"  Tags: {len(tags)}")
    except Exception as e:
        console.print(f"\n[red]Error reading database: {e}[/red]")


@app.command()
def upgrade() -> None:
    """Upgrade the database schema to the latest version."""
    from sqlalchemy import text, inspect
    from ixion.core.config import get_config
    from ixion.storage.database import get_engine, init_db

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]IXION not initialized.[/yellow]")
        console.print("Run 'ixion init' to initialize.")
        return

    console.print("[bold]Upgrading IXION database...[/bold]")

    engine = get_engine(config.db_path)
    inspector = inspect(engine)

    migrations_applied = []

    with engine.connect() as conn:
        # Check if documents table exists
        if 'documents' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('documents')]

            # Add current_version column if missing
            if 'current_version' not in columns:
                console.print("  Adding 'current_version' column to documents...")
                conn.execute(text("ALTER TABLE documents ADD COLUMN current_version INTEGER DEFAULT 1 NOT NULL"))
                migrations_applied.append("documents.current_version")

            # Add status column if missing
            if 'status' not in columns:
                console.print("  Adding 'status' column to documents...")
                conn.execute(text("ALTER TABLE documents ADD COLUMN status VARCHAR(50) DEFAULT 'active' NOT NULL"))
                migrations_applied.append("documents.status")

            # Add updated_at column if missing
            if 'updated_at' not in columns:
                console.print("  Adding 'updated_at' column to documents...")
                conn.execute(text("ALTER TABLE documents ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
                migrations_applied.append("documents.updated_at")

        # Check if document_versions table exists
        if 'document_versions' not in inspector.get_table_names():
            console.print("  Creating 'document_versions' table...")
            conn.execute(text("""
                CREATE TABLE document_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id INTEGER NOT NULL,
                    version_number INTEGER NOT NULL,
                    rendered_content TEXT NOT NULL,
                    input_data TEXT,
                    amendment_reason VARCHAR(500),
                    amended_by VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (document_id) REFERENCES documents(id)
                )
            """))
            migrations_applied.append("document_versions table")

            # Create initial version records for existing documents
            console.print("  Creating initial version records for existing documents...")
            conn.execute(text("""
                INSERT INTO document_versions (document_id, version_number, rendered_content, input_data, amendment_reason)
                SELECT id, 1, rendered_content, input_data, 'Initial version (migration)'
                FROM documents
            """))
            migrations_applied.append("initial document versions")

        # =================================================================
        # Auth tables migration (RBAC)
        # =================================================================

        # Create users table if missing
        if 'users' not in inspector.get_table_names():
            console.print("  Creating 'users' table...")
            conn.execute(text("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    display_name VARCHAR(255),
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    last_login DATETIME,
                    must_change_password BOOLEAN NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            migrations_applied.append("users table")

        # Create roles table if missing
        if 'roles' not in inspector.get_table_names():
            console.print("  Creating 'roles' table...")
            conn.execute(text("""
                CREATE TABLE roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    description TEXT,
                    is_system BOOLEAN NOT NULL DEFAULT 0
                )
            """))
            migrations_applied.append("roles table")

        # Create permissions table if missing
        if 'permissions' not in inspector.get_table_names():
            console.print("  Creating 'permissions' table...")
            conn.execute(text("""
                CREATE TABLE permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    resource VARCHAR(100) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    description TEXT
                )
            """))
            migrations_applied.append("permissions table")

        # Create user_roles association table if missing
        if 'user_roles' not in inspector.get_table_names():
            console.print("  Creating 'user_roles' table...")
            conn.execute(text("""
                CREATE TABLE user_roles (
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (role_id) REFERENCES roles(id)
                )
            """))
            migrations_applied.append("user_roles table")

        # Create role_permissions association table if missing
        if 'role_permissions' not in inspector.get_table_names():
            console.print("  Creating 'role_permissions' table...")
            conn.execute(text("""
                CREATE TABLE role_permissions (
                    role_id INTEGER NOT NULL,
                    permission_id INTEGER NOT NULL,
                    PRIMARY KEY (role_id, permission_id),
                    FOREIGN KEY (role_id) REFERENCES roles(id),
                    FOREIGN KEY (permission_id) REFERENCES permissions(id)
                )
            """))
            migrations_applied.append("role_permissions table")

        # Create user_sessions table if missing
        if 'user_sessions' not in inspector.get_table_names():
            console.print("  Creating 'user_sessions' table...")
            conn.execute(text("""
                CREATE TABLE user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token VARCHAR(255) NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent VARCHAR(500),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_user_sessions_token ON user_sessions(session_token)"))
            migrations_applied.append("user_sessions table")

        # Create audit_logs table if missing
        if 'audit_logs' not in inspector.get_table_names():
            console.print("  Creating 'audit_logs' table...")
            conn.execute(text("""
                CREATE TABLE audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action VARCHAR(100) NOT NULL,
                    resource_type VARCHAR(100),
                    resource_id INTEGER,
                    details TEXT,
                    ip_address VARCHAR(45),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """))
            conn.execute(text("CREATE INDEX ix_audit_logs_timestamp ON audit_logs(timestamp)"))
            conn.execute(text("CREATE INDEX ix_audit_logs_user_action ON audit_logs(user_id, action)"))
            migrations_applied.append("audit_logs table")

        # =================================================================
        # Collections table migration
        # =================================================================

        # Create collections table if missing
        if 'collections' not in inspector.get_table_names():
            console.print("  Creating 'collections' table...")
            conn.execute(text("""
                CREATE TABLE collections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    description TEXT,
                    icon VARCHAR(50),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            migrations_applied.append("collections table")

        # Add collection_id column to templates if missing
        if 'templates' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('templates')]
            if 'collection_id' not in columns:
                console.print("  Adding 'collection_id' column to templates...")
                conn.execute(text("ALTER TABLE templates ADD COLUMN collection_id INTEGER REFERENCES collections(id)"))
                migrations_applied.append("templates.collection_id")

        # =================================================================
        # Saved Searches table migration
        # =================================================================

        if 'saved_searches' not in inspector.get_table_names():
            console.print("  Creating 'saved_searches' table...")
            conn.execute(text("""
                CREATE TABLE saved_searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    search_type VARCHAR(50) NOT NULL DEFAULT 'discover',
                    search_params JSON NOT NULL,
                    created_by_id INTEGER NOT NULL REFERENCES users(id),
                    is_shared BOOLEAN NOT NULL DEFAULT 0,
                    is_favorite BOOLEAN NOT NULL DEFAULT 0,
                    execution_count INTEGER NOT NULL DEFAULT 0,
                    last_executed_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text("CREATE INDEX ix_saved_searches_created_by ON saved_searches(created_by_id)"))
            conn.execute(text("CREATE INDEX ix_saved_searches_shared ON saved_searches(is_shared)"))
            migrations_applied.append("saved_searches table")

        # =================================================================
        # Playbooks tables migration
        # =================================================================

        if 'playbooks' not in inspector.get_table_names():
            console.print("  Creating 'playbooks' table...")
            conn.execute(text("""
                CREATE TABLE playbooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    description TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    trigger_conditions JSON NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    created_by_id INTEGER NOT NULL REFERENCES users(id),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text("CREATE INDEX ix_playbooks_active ON playbooks(is_active)"))
            conn.execute(text("CREATE INDEX ix_playbooks_priority ON playbooks(priority)"))
            migrations_applied.append("playbooks table")

        if 'playbook_steps' not in inspector.get_table_names():
            console.print("  Creating 'playbook_steps' table...")
            conn.execute(text("""
                CREATE TABLE playbook_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playbook_id INTEGER NOT NULL REFERENCES playbooks(id),
                    step_order INTEGER NOT NULL,
                    step_type VARCHAR(50) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    step_params JSON,
                    is_required BOOLEAN NOT NULL DEFAULT 0
                )
            """))
            conn.execute(text("CREATE INDEX ix_playbook_steps_playbook ON playbook_steps(playbook_id)"))
            migrations_applied.append("playbook_steps table")

        if 'playbook_executions' not in inspector.get_table_names():
            console.print("  Creating 'playbook_executions' table...")
            conn.execute(text("""
                CREATE TABLE playbook_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playbook_id INTEGER NOT NULL REFERENCES playbooks(id),
                    es_alert_id VARCHAR(500) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    started_at DATETIME,
                    completed_at DATETIME,
                    step_statuses JSON,
                    executed_by_id INTEGER REFERENCES users(id),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text("CREATE INDEX ix_playbook_executions_alert ON playbook_executions(es_alert_id)"))
            conn.execute(text("CREATE INDEX ix_playbook_executions_playbook ON playbook_executions(playbook_id)"))
            conn.execute(text("CREATE INDEX ix_playbook_executions_status ON playbook_executions(status)"))
            migrations_applied.append("playbook_executions table")

        # =================================================================
        # Unified Notes table (consolidates alert_comments + case_notes)
        # =================================================================

        if 'notes' not in inspector.get_table_names():
            console.print("  Creating 'notes' table...")
            conn.execute(text("""
                CREATE TABLE notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type VARCHAR(50) NOT NULL,
                    entity_id VARCHAR(500) NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text("CREATE INDEX ix_notes_entity ON notes(entity_type, entity_id)"))
            conn.execute(text("CREATE INDEX ix_notes_user_id ON notes(user_id)"))
            conn.execute(text("CREATE INDEX ix_notes_created_at ON notes(created_at)"))
            migrations_applied.append("notes table")

            # Migrate data from old tables if they exist
            if 'alert_comments' in inspector.get_table_names():
                console.print("  Migrating data from 'alert_comments' to 'notes'...")
                conn.execute(text("""
                    INSERT INTO notes (entity_type, entity_id, user_id, content, created_at)
                    SELECT 'alert', es_alert_id, user_id, content, created_at
                    FROM alert_comments
                """))
                migrations_applied.append("alert_comments data migration")

            if 'case_notes' in inspector.get_table_names():
                console.print("  Migrating data from 'case_notes' to 'notes'...")
                conn.execute(text("""
                    INSERT INTO notes (entity_type, entity_id, user_id, content, created_at)
                    SELECT 'case', CAST(case_id AS VARCHAR), user_id, content, created_at
                    FROM case_notes
                """))
                migrations_applied.append("case_notes data migration")

        # =================================================================
        # Unified Observable Links table (consolidates observable_alert_links,
        # observable_case_links, observable_sightings)
        # =================================================================

        if 'observable_links' not in inspector.get_table_names():
            console.print("  Creating 'observable_links' table...")
            conn.execute(text("""
                CREATE TABLE observable_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observable_id INTEGER NOT NULL REFERENCES observables(id) ON DELETE CASCADE,
                    link_type VARCHAR(50) NOT NULL,
                    entity_id INTEGER NOT NULL,
                    context VARCHAR(100) NOT NULL,
                    extracted_from VARCHAR(50) NOT NULL DEFAULT 'auto',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    UNIQUE(observable_id, link_type, entity_id, context)
                )
            """))
            conn.execute(text("CREATE INDEX ix_observable_links_observable_id ON observable_links(observable_id)"))
            conn.execute(text("CREATE INDEX ix_observable_links_link_type ON observable_links(link_type)"))
            conn.execute(text("CREATE INDEX ix_observable_links_entity_id ON observable_links(entity_id)"))
            conn.execute(text("CREATE INDEX ix_observable_links_created_at ON observable_links(created_at)"))
            migrations_applied.append("observable_links table")

            # Migrate data from old tables if they exist
            if 'observable_alert_links' in inspector.get_table_names():
                console.print("  Migrating data from 'observable_alert_links' to 'observable_links'...")
                conn.execute(text("""
                    INSERT INTO observable_links (observable_id, link_type, entity_id, context, extracted_from, created_at)
                    SELECT observable_id, 'alert', alert_triage_id, context, extracted_from, created_at
                    FROM observable_alert_links
                """))
                migrations_applied.append("observable_alert_links data migration")

            if 'observable_case_links' in inspector.get_table_names():
                console.print("  Migrating data from 'observable_case_links' to 'observable_links'...")
                conn.execute(text("""
                    INSERT INTO observable_links (observable_id, link_type, entity_id, context, extracted_from, created_at)
                    SELECT observable_id, 'case', case_id, context, 'manual', created_at
                    FROM observable_case_links
                """))
                migrations_applied.append("observable_case_links data migration")

            if 'observable_sightings' in inspector.get_table_names():
                console.print("  Migrating data from 'observable_sightings' to 'observable_links'...")
                conn.execute(text("""
                    INSERT INTO observable_links (observable_id, link_type, entity_id, context, extracted_from, created_at)
                    SELECT observable_id,
                           CASE source_type WHEN 'alert' THEN 'alert' WHEN 'case' THEN 'case' ELSE 'manual' END,
                           COALESCE(source_id, 0),
                           COALESCE(context, source_type),
                           'sighting',
                           seen_at
                    FROM observable_sightings
                """))
                migrations_applied.append("observable_sightings data migration")

        # =================================================================
        # Unified Integration Events table (consolidates webhook_logs,
        # integration_logs, integration_health_checks)
        # =================================================================

        if 'integration_events' not in inspector.get_table_names():
            console.print("  Creating 'integration_events' table...")
            conn.execute(text("""
                CREATE TABLE integration_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type VARCHAR(50) NOT NULL,
                    integration_type VARCHAR(50) NOT NULL,
                    action VARCHAR(100),
                    message TEXT,
                    details JSON,
                    error_message TEXT,
                    response_time_ms REAL,
                    level VARCHAR(50),
                    webhook_id INTEGER REFERENCES webhooks(id) ON DELETE SET NULL,
                    webhook_event_type VARCHAR(100),
                    payload JSON,
                    headers JSON,
                    source_ip VARCHAR(45),
                    status VARCHAR(50),
                    health_status VARCHAR(50),
                    user_id INTEGER REFERENCES users(id),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text("CREATE INDEX ix_integration_events_type ON integration_events(event_type)"))
            conn.execute(text("CREATE INDEX ix_integration_events_integration_type ON integration_events(integration_type)"))
            conn.execute(text("CREATE INDEX ix_integration_events_created_at ON integration_events(created_at)"))
            conn.execute(text("CREATE INDEX ix_integration_events_webhook_id ON integration_events(webhook_id)"))
            conn.execute(text("CREATE INDEX ix_integration_events_level ON integration_events(level)"))
            conn.execute(text("CREATE INDEX ix_integration_events_status ON integration_events(status)"))
            migrations_applied.append("integration_events table")

            # Migrate data from old tables if they exist
            if 'webhook_logs' in inspector.get_table_names():
                console.print("  Migrating data from 'webhook_logs' to 'integration_events'...")
                conn.execute(text("""
                    INSERT INTO integration_events (event_type, integration_type, webhook_id, webhook_event_type,
                                                     payload, headers, source_ip, status, error_message,
                                                     response_time_ms, created_at)
                    SELECT 'webhook',
                           COALESCE((SELECT source_type FROM webhooks WHERE id = webhook_logs.webhook_id), 'custom'),
                           webhook_id, event_type, payload, headers, source_ip, status,
                           error_message, processing_time_ms, created_at
                    FROM webhook_logs
                """))
                migrations_applied.append("webhook_logs data migration")

            if 'integration_logs' in inspector.get_table_names():
                console.print("  Migrating data from 'integration_logs' to 'integration_events'...")
                conn.execute(text("""
                    INSERT INTO integration_events (event_type, integration_type, level, action, message,
                                                     details, user_id, created_at)
                    SELECT 'activity', integration_type, level, action, message, details, user_id, timestamp
                    FROM integration_logs
                """))
                migrations_applied.append("integration_logs data migration")

            if 'integration_health_checks' in inspector.get_table_names():
                console.print("  Migrating data from 'integration_health_checks' to 'integration_events'...")
                conn.execute(text("""
                    INSERT INTO integration_events (event_type, integration_type, health_status,
                                                     response_time_ms, error_message, details, created_at)
                    SELECT 'health_check', integration_type, status, response_time_ms,
                           error_message, check_metadata, checked_at
                    FROM integration_health_checks
                """))
                migrations_applied.append("integration_health_checks data migration")

        conn.commit()

    if migrations_applied:
        console.print(f"\n[green]OK[/green] Applied {len(migrations_applied)} migration(s):")
        for m in migrations_applied:
            console.print(f"  - {m}")
    else:
        console.print("[green]OK[/green] Database is already up to date.")


@app.command("seed-users")
def seed_users(
    admin_password: str = typer.Option(
        "changeme", "--admin-password", "-p", help="Password for the admin user"
    ),
) -> None:
    """Seed default roles, permissions, and admin user."""
    from ixion.core.config import get_config
    from ixion.storage.database import get_engine, get_session_factory
    from ixion.auth.service import AuthService

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]IXION not initialized.[/yellow]")
        console.print("Run 'ixion init' first, then 'ixion upgrade'.")
        return

    console.print("[bold]Seeding auth data...[/bold]")

    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        auth_service = AuthService(session)

        # Seed permissions
        console.print("  Creating permissions...")
        permissions = auth_service.seed_permissions()
        console.print(f"    Created/found {len(permissions)} permissions")

        # Seed roles
        console.print("  Creating roles...")
        roles = auth_service.seed_roles()
        console.print(f"    Created/found {len(roles)} roles")
        for role in roles:
            console.print(f"      - {role.name}: {len(role.permissions)} permissions")

        # Seed admin user
        console.print("  Creating admin user...")
        admin = auth_service.seed_admin_user(password=admin_password)
        if admin:
            console.print(f"    Admin user: {admin.username}")
            console.print(f"    Email: {admin.email}")
            if admin.must_change_password:
                console.print("    [yellow]Password change required on first login[/yellow]")

        session.commit()
        console.print("\n[green]OK[/green] Auth data seeded successfully.")
        console.print("\n[bold]Default credentials:[/bold]")
        console.print(f"  Username: admin")
        console.print(f"  Password: {admin_password}")
        console.print("  [yellow]Please change the password after first login![/yellow]")

    except Exception as e:
        session.rollback()
        console.print(f"\n[red]Error seeding auth data: {e}[/red]")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    app()
