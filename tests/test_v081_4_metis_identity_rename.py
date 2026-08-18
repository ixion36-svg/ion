"""The AEGIS -> METIS rename has to reach ION's database, not just its source.

The companion threat-modelling product's ION identity is two rows — a service
user and a role, both literally named `aegis` — plus a bearer token bound to
the user's id with only its hash stored. A source-only rename leaves
`seed-metis` creating a second account beside the first, so an estate ends up
with two service identities and an operator has no way to tell which one the
running METIS is using.

Renaming in place is what keeps the token working. Deleting and re-seeding
would revoke a credential that cannot be reissued without going back to the
air-gapped instance to read it out again.
"""
import pytest
from sqlalchemy import create_engine, text

from ion.storage.database import rename_aegis_identities


@pytest.fixture
def conn():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
            "email TEXT, display_name TEXT)"))
        connection.execute(text(
            "CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT UNIQUE, "
            "description TEXT)"))
        yield connection


def _seed_old(connection):
    connection.execute(text(
        "INSERT INTO users (id, username, email, display_name) VALUES "
        "(3, 'aegis', 'aegis@ion.local', 'AEGIS Threat Modelling')"))
    connection.execute(text(
        "INSERT INTO roles (id, name, description) VALUES "
        "(12, 'aegis', 'AEGIS threat modelling integration (service)')"))


def test_both_identities_are_renamed(conn):
    _seed_old(conn)
    assert rename_aegis_identities(conn) == 2
    assert conn.execute(text("SELECT username FROM users")).scalar() == "metis"
    assert conn.execute(text("SELECT name FROM roles")).scalar() == "metis"


def test_the_row_ids_survive(conn):
    """The whole reason this is an UPDATE and not a delete-and-reseed: the
    bearer token is bound to the user id and only its hash is stored."""
    _seed_old(conn)
    rename_aegis_identities(conn)
    assert conn.execute(text("SELECT id FROM users WHERE username='metis'")).scalar() == 3
    assert conn.execute(text("SELECT id FROM roles WHERE name='metis'")).scalar() == 12


def test_the_display_strings_follow(conn):
    _seed_old(conn)
    rename_aegis_identities(conn)
    row = conn.execute(text("SELECT email, display_name FROM users")).first()
    assert row == ("metis@ion.local", "METIS Threat Modelling")
    assert conn.execute(text("SELECT description FROM roles")).scalar() == (
        "METIS threat modelling integration (service)")


def test_it_is_idempotent(conn):
    _seed_old(conn)
    assert rename_aegis_identities(conn) == 2
    assert rename_aegis_identities(conn) == 0


def test_a_deployment_that_never_had_aegis_is_untouched(conn):
    assert rename_aegis_identities(conn) == 0


def test_an_existing_metis_row_is_not_collided_with(conn):
    """The operator who ran seed-metis before upgrading. Renaming on top would
    violate the unique constraint and take startup down with it; leaving the
    stale row is the lesser problem, and it is visible in the user list."""
    _seed_old(conn)
    conn.execute(text(
        "INSERT INTO users (id, username) VALUES (9, 'metis')"))
    conn.execute(text("INSERT INTO roles (id, name) VALUES (20, 'metis')"))
    assert rename_aegis_identities(conn) == 0
    remaining = {row[0] for row in conn.execute(text("SELECT username FROM users"))}
    assert remaining == {"aegis", "metis"}


def test_one_side_already_migrated_still_migrates_the_other(conn):
    """A half-finished previous run, or a hand-edited database."""
    _seed_old(conn)
    conn.execute(text("UPDATE roles SET name='metis' WHERE name='aegis'"))
    assert rename_aegis_identities(conn) == 1
    assert conn.execute(text("SELECT username FROM users")).scalar() == "metis"
