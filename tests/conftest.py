"""Shared fixtures. Tests that use the `database` fixture run twice: against a
temporary SQLite file and against a real embedded Postgres (skipped if the
pixeltable-pgserver package isn't installed)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import db  # noqa: E402


@pytest.fixture(scope="session")
def _postgres(tmp_path_factory):
    try:
        import pixeltable_pgserver as pgserver
    except ImportError:
        pytest.skip("pixeltable-pgserver not installed")
    server = pgserver.get_server(tmp_path_factory.mktemp("pgdata"), cleanup_mode="stop")
    yield server.get_uri()
    server.cleanup()


@pytest.fixture(params=["sqlite", "postgres"])
def database(request, tmp_path, monkeypatch):
    """A clean, empty database of each kind, selected through the environment."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("USERS_DB_PATH", str(tmp_path / "app.db"))
    if request.param == "postgres":
        uri = request.getfixturevalue("_postgres")
        import psycopg

        with psycopg.connect(uri, autocommit=True) as conn:
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
        monkeypatch.setenv("DATABASE_URL", uri)
    db._ready.clear()
    yield request.param
    db._ready.clear()
