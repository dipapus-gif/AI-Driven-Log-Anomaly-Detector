"""Database access shared by accounts and the detection platform.

Uses Postgres (for example Neon) when DATABASE_URL is set, and a local SQLite
file otherwise. On serverless hosts the filesystem is wiped between runs, so
there a DATABASE_URL is required; without one the database is reported as
unavailable instead of silently losing data.

Queries are written once with `?` placeholders and work on both databases.
Rows come back as dicts.
"""

import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class StoreUnavailable(Exception):
    """The database could not be reached or used."""


class Conflict(Exception):
    """A unique constraint was violated."""


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "")


def sqlite_path() -> Path:
    return Path(os.environ.get("USERS_DB_PATH") or ROOT / "models" / "users.db")


def available() -> bool:
    """False on a serverless host that has no database configured."""
    return bool(database_url()) or not os.environ.get("VERCEL")


def _schema(postgres: bool):
    pk = "BIGSERIAL PRIMARY KEY" if postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
    blob = "BYTEA" if postgres else "BLOB"
    created = "TIMESTAMPTZ NOT NULL DEFAULT now()" if postgres else "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
    return [
        f"""CREATE TABLE IF NOT EXISTS users (
            id {pk}, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            created_at {created})""",
        f"""CREATE TABLE IF NOT EXISTS events (
            id {pk}, account_id BIGINT NOT NULL, ts DOUBLE PRECISION NOT NULL,
            src_ip TEXT, dst_ip TEXT, dst_port INTEGER, proto TEXT, bytes BIGINT,
            username TEXT, host TEXT, action TEXT, event_type TEXT, message TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_events_acct_ts ON events (account_id, ts)",
        "CREATE INDEX IF NOT EXISTS idx_events_acct_src ON events (account_id, src_ip, ts)",
        f"""CREATE TABLE IF NOT EXISTS incidents (
            id {pk}, account_id BIGINT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL,
            src_ip TEXT, username TEXT, host TEXT,
            window_start DOUBLE PRECISION, window_end DOUBLE PRECISION,
            risk_score DOUBLE PRECISION NOT NULL, status TEXT NOT NULL, severity TEXT,
            verdict TEXT, report TEXT, features TEXT, trace TEXT, agent_mode TEXT,
            dedupe_key TEXT NOT NULL, UNIQUE (account_id, dedupe_key))""",
        "CREATE INDEX IF NOT EXISTS idx_incidents_acct ON incidents (account_id, created_at)",
        f"""CREATE TABLE IF NOT EXISTS actions (
            id {pk}, account_id BIGINT NOT NULL, incident_id BIGINT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL, kind TEXT NOT NULL, target TEXT,
            status TEXT NOT NULL, detail TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions (account_id, incident_id)",
        f"""CREATE TABLE IF NOT EXISTS ingest_tokens (
            id {pk}, account_id BIGINT NOT NULL, label TEXT, prefix TEXT,
            token_hash TEXT NOT NULL UNIQUE,
            created_at DOUBLE PRECISION NOT NULL, last_used DOUBLE PRECISION)""",
        f"""CREATE TABLE IF NOT EXISTS models (
            account_id BIGINT PRIMARY KEY, trained_at DOUBLE PRECISION NOT NULL,
            n_windows INTEGER, blob {blob} NOT NULL, meta TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS email_tokens (
            id {pk}, user_id BIGINT NOT NULL, kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            expires_at DOUBLE PRECISION NOT NULL, used_at DOUBLE PRECISION,
            created_at DOUBLE PRECISION NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens (user_id, kind)",
        """CREATE TABLE IF NOT EXISTS account_config (
            account_id BIGINT PRIMARY KEY, config TEXT NOT NULL)""",
    ]


_NEW_USER_COLUMNS = [
    ("email", "TEXT"),
    ("email_verified", "INTEGER NOT NULL DEFAULT 0"),
    ("pw_version", "INTEGER NOT NULL DEFAULT 0"),
]


def _migrate(conn, postgres):
    """Add columns that older databases lack (CREATE TABLE IF NOT EXISTS never alters a table)."""
    if postgres:
        for name, decl in _NEW_USER_COLUMNS:
            conn.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {name} {decl}")
    else:
        have = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        for name, decl in _NEW_USER_COLUMNS:
            if name not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email)")


_ready = set()


def _connect():
    if database_url():
        import psycopg

        return psycopg.connect(database_url(), connect_timeout=10)
    path = sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path, timeout=10)


def _is_unique_violation(exc) -> bool:
    return isinstance(exc, sqlite3.IntegrityError) or getattr(exc, "sqlstate", None) == "23505"


def _prepare(conn, postgres, target):
    if target not in _ready:
        for statement in _schema(postgres):
            conn.execute(statement)
        _migrate(conn, postgres)
        _ready.add(target)


def _translate(sql, postgres):
    return sql.replace("?", "%s") if postgres else sql


def _open():
    try:
        return _connect()
    except Exception as exc:
        raise StoreUnavailable("Could not connect to the database.") from exc


def run(sql, params=(), fetch=None):
    """Run one statement.

    fetch=None   -> returns None
    fetch="one"  -> first row as a dict, or None
    fetch="all"  -> list of dict rows
    fetch="count"-> number of rows the statement changed
    """
    postgres = bool(database_url())
    target = database_url() or str(sqlite_path())
    conn = _open()
    try:
        with conn:  # commits on success, rolls back on error
            _prepare(conn, postgres, target)
            cur = conn.execute(_translate(sql, postgres), params)
            if fetch == "count":
                return cur.rowcount
            if fetch is None or cur.description is None:
                return None
            names = [d[0] for d in cur.description]
            if fetch == "one":
                row = cur.fetchone()
                return dict(zip(names, row)) if row else None
            return [dict(zip(names, row)) for row in cur.fetchall()]
    except Exception as exc:
        if _is_unique_violation(exc):
            raise Conflict(str(exc)) from exc
        raise StoreUnavailable("The database request failed.") from exc
    finally:
        conn.close()


def run_many(sql, rows):
    """Run one statement for many parameter tuples in a single transaction."""
    if not rows:
        return
    postgres = bool(database_url())
    target = database_url() or str(sqlite_path())
    conn = _open()
    try:
        with conn:
            _prepare(conn, postgres, target)
            cur = conn.cursor()
            cur.executemany(_translate(sql, postgres), rows)
    except Exception as exc:
        raise StoreUnavailable("The database request failed.") from exc
    finally:
        conn.close()
