#!/usr/bin/env python3
"""One-time migration: SQLite -> PostgreSQL for ION.

Usage (inside Docker):
    # 1. Start the new stack (PostgreSQL + ION)
    docker compose up -d postgres
    # 2. Copy the old SQLite DB into the ION container
    docker cp /path/to/ion.db ion:/tmp/ion.db
    # 3. Run the migration
    docker exec ion python /app/migrate_to_postgres.py /tmp/ion.db

Usage (local):
    ION_DATABASE_URL=postgresql://ion:ion2025@localhost:5432/ion python migrate_to_postgres.py /path/to/ion.db

The script:
    - Reads all tables from the SQLite source
    - Creates tables in PostgreSQL via SQLAlchemy ORM
    - Copies all rows, preserving IDs
    - Resets PostgreSQL sequences to max(id)+1 so new inserts work
"""

import sys
import os
from pathlib import Path

# Add src to path when running from project dir
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sqlalchemy import create_engine, inspect, text, MetaData
from sqlalchemy.orm import Session


def migrate(sqlite_path: str, pg_url: str):
    """Migrate all data from SQLite to PostgreSQL."""
    print(f"Source:  SQLite  -> {sqlite_path}")
    print(f"Target:  PostgreSQL -> {pg_url.split('@')[-1] if '@' in pg_url else pg_url}")
    print()

    # Connect to both databases
    sqlite_engine = create_engine(f"sqlite:///{sqlite_path}")
    pg_engine = create_engine(pg_url)

    # Import models so Base.metadata knows all tables
    import ion.models  # noqa: F401
    from ion.models.base import Base

    # Create all tables in PostgreSQL
    print("Creating tables in PostgreSQL...")
    Base.metadata.create_all(pg_engine)
    print("  Tables created.")

    # Get table names from SQLite (in dependency order)
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)
    sqlite_inspector = inspect(sqlite_engine)
    table_names = sqlite_inspector.get_table_names()

    # Sort tables by foreign key dependencies (parents first)
    sorted_tables = _sort_by_dependencies(sqlite_meta, table_names)

    total_rows = 0

    with sqlite_engine.connect() as src_conn, pg_engine.connect() as dst_conn:
        for table_name in sorted_tables:
            if table_name not in sqlite_meta.tables:
                continue

            table = sqlite_meta.tables[table_name]

            # Read all rows from SQLite
            rows = src_conn.execute(table.select()).fetchall()
            if not rows:
                print(f"  {table_name}: 0 rows (skip)")
                continue

            # Get column names
            columns = [col.name for col in table.columns]

            # Clear target table first (in case of partial previous migration)
            dst_conn.execute(table.delete())

            # Insert in batches
            batch_size = 500
            for i in range(0, len(rows), batch_size):
                batch = rows[i:i + batch_size]
                row_dicts = [dict(zip(columns, row)) for row in batch]
                dst_conn.execute(table.insert(), row_dicts)

            dst_conn.commit()
            total_rows += len(rows)
            print(f"  {table_name}: {len(rows)} rows migrated")

        # Reset PostgreSQL sequences for all tables with auto-increment IDs
        print()
        print("Resetting PostgreSQL sequences...")
        pg_inspector = inspect(pg_engine)
        for table_name in sorted_tables:
            if table_name not in sqlite_meta.tables:
                continue
            pg_columns = {col["name"]: col for col in pg_inspector.get_columns(table_name)}
            if "id" in pg_columns:
                try:
                    result = dst_conn.execute(
                        text(f"SELECT MAX(id) FROM {table_name}")
                    ).scalar()
                    if result is not None:
                        seq_name = f"{table_name}_id_seq"
                        dst_conn.execute(
                            text(f"SELECT setval('{seq_name}', :val)")
                            , {"val": result}
                        )
                        dst_conn.commit()
                        print(f"  {table_name}_id_seq -> {result}")
                except Exception as e:
                    # Table might not have a sequence (e.g., association tables)
                    pass

    print()
    print(f"Migration complete! {total_rows} total rows migrated across {len(sorted_tables)} tables.")


def _sort_by_dependencies(metadata: MetaData, table_names: list) -> list:
    """Sort tables so that referenced tables come before referencing tables."""
    sorted_result = []
    visited = set()

    def visit(name):
        if name in visited or name not in metadata.tables:
            return
        visited.add(name)
        table = metadata.tables[name]
        for fk in table.foreign_keys:
            ref_table = fk.column.table.name
            if ref_table != name:  # skip self-references
                visit(ref_table)
        sorted_result.append(name)

    for name in table_names:
        visit(name)

    return sorted_result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python migrate_to_postgres.py <sqlite_db_path> [postgresql_url]")
        print()
        print("If postgresql_url is not provided, reads ION_DATABASE_URL from environment.")
        sys.exit(1)

    sqlite_path = sys.argv[1]
    if not Path(sqlite_path).exists():
        print(f"Error: SQLite database not found at {sqlite_path}")
        sys.exit(1)

    pg_url = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("ION_DATABASE_URL")
    if not pg_url:
        print("Error: No PostgreSQL URL provided. Set ION_DATABASE_URL or pass as second argument.")
        sys.exit(1)

    migrate(sqlite_path, pg_url)
