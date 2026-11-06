"""Account storage for the web app.

Uses Postgres (for example Neon) when DATABASE_URL is set, and a local SQLite
file otherwise. On serverless hosts the filesystem is wiped between runs, so
there a DATABASE_URL is required; without one, accounts are reported as
unavailable instead of silently disappearing.

Only password hashes are stored, never passwords.
"""

import os
import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
MIN_PASSWORD = 10
MAX_PASSWORD = 128

_SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""
_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""

_schema_ready = set()


class UsernameTaken(Exception):
    pass


class StoreUnavailable(Exception):
    """The account database could not be reached or used."""


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "")


def sqlite_path() -> Path:
    return Path(os.environ.get("USERS_DB_PATH") or ROOT / "models" / "users.db")


def available() -> bool:
    """False on a serverless host that has no database configured."""
    return bool(database_url()) or not os.environ.get("VERCEL")


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def validate_signup(username: str, password: str):
    """Return a user-facing problem with these sign-up details, or None if fine."""
    if not USERNAME_RE.match(username):
        return (
            "Username must be 3 to 32 characters: letters, numbers, dots, "
            "dashes or underscores, starting with a letter or number."
        )
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(password) > MAX_PASSWORD:
        return f"Password must be at most {MAX_PASSWORD} characters."
    if password.lower() == username:
        return "Password can't be the same as the username."
    return None


def _connect():
    if database_url():
        import psycopg

        return psycopg.connect(database_url(), connect_timeout=10)
    path = sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path, timeout=10)


def _run(sql, params=()):
    """Run one statement; return the first row if it produces any."""
    postgres = bool(database_url())
    target = database_url() or str(sqlite_path())
    conn = _connect()
    try:
        with conn:  # commits on success, rolls back on error
            if target not in _schema_ready:
                conn.execute(_SCHEMA_POSTGRES if postgres else _SCHEMA_SQLITE)
                _schema_ready.add(target)
            cur = conn.execute(sql.replace("?", "%s") if postgres else sql, params)
            return cur.fetchone() if cur.description else None
    finally:
        conn.close()


def _is_unique_violation(exc) -> bool:
    return isinstance(exc, sqlite3.IntegrityError) or getattr(exc, "sqlstate", None) == "23505"


def create_user(username: str, password_hash: str) -> int:
    try:
        row = _run(
            "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
            (username, password_hash),
        )
    except Exception as exc:
        if _is_unique_violation(exc):
            raise UsernameTaken(username) from exc
        raise StoreUnavailable("Could not save the account.") from exc
    return int(row[0])


def get_user(username: str):
    """Return (id, password_hash) for a username, or None if there is no such user."""
    try:
        row = _run("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    except Exception as exc:
        raise StoreUnavailable("Could not look up the account.") from exc
    return (int(row[0]), row[1]) if row else None
