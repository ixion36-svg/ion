"""Main CLI entry point for DocForge."""

import typer
from rich.console import Console

from docforge.cli.template_commands import template_app
from docforge.cli.version_commands import version_app
from docforge.cli.render_commands import render_app
from docforge.cli.extract_commands import extract_app
from docforge.cli.document_commands import document_app

app = typer.Typer(
    name="docforge",
    help="Documentation Template Management System",
    no_args_is_help=True,
)

console = Console()

# Add sub-commands
app.add_typer(template_app, name="template", help="Template management commands")
app.add_typer(version_app, name="version", help="Version control commands")
app.add_typer(render_app, name="render", help="Template rendering commands")
app.add_typer(extract_app, name="extract", help="Template extraction commands")
app.add_typer(document_app, name="document", help="Document management commands")


@app.command()
def init(
    path: str = typer.Option(
        ".", "--path", "-p", help="Path to initialize DocForge in"
    ),
) -> None:
    """Initialize DocForge database in the current or specified directory."""
    from pathlib import Path
    from docforge.storage.database import init_db
    from docforge.core.config import Config

    target_path = Path(path).resolve()
    docforge_dir = target_path / ".docforge"
    db_path = docforge_dir / "docforge.db"

    # Create directory
    docforge_dir.mkdir(parents=True, exist_ok=True)

    # Initialize database
    init_db(db_path)

    # Create default config
    config = Config(db_path=db_path)
    config.to_file(docforge_dir / "config.json")

    console.print(f"[green]OK[/green] Initialized DocForge in {docforge_dir}")
    console.print(f"  Database: {db_path}")
    console.print(f"  Config: {docforge_dir / 'config.json'}")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
) -> None:
    """Start the web UI server."""
    import uvicorn

    console.print(f"[bold]Starting DocForge Web UI[/bold]")
    console.print(f"  URL: http://{host}:{port}")
    console.print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(
        "docforge.web.server:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def status() -> None:
    """Show DocForge status and statistics."""
    from pathlib import Path
    from docforge.core.config import get_config
    from docforge.storage.database import get_session, get_engine
    from docforge.storage.template_repository import TemplateRepository
    from docforge.storage.document_repository import DocumentRepository

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]DocForge not initialized.[/yellow]")
        console.print("Run 'docforge init' to initialize.")
        return

    console.print("[bold]DocForge Status[/bold]")
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
    from docforge.core.config import get_config
    from docforge.storage.database import get_engine, init_db

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]DocForge not initialized.[/yellow]")
        console.print("Run 'docforge init' to initialize.")
        return

    console.print("[bold]Upgrading DocForge database...[/bold]")

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
    from docforge.core.config import get_config
    from docforge.storage.database import get_engine, get_session_factory
    from docforge.auth.service import AuthService

    config = get_config()

    if not config.db_path.exists():
        console.print("[yellow]DocForge not initialized.[/yellow]")
        console.print("Run 'docforge init' first, then 'docforge upgrade'.")
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
