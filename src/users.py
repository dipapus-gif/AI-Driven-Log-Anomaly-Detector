"""Account storage for the web app (see db.py for the database itself).

Only password hashes are stored, never passwords.
"""

import re

import db
from db import StoreUnavailable, available  # noqa: F401  (re-exported for callers)

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
MIN_PASSWORD = 10
MAX_PASSWORD = 128


class UsernameTaken(Exception):
    pass


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


def create_user(username: str, password_hash: str) -> int:
    try:
        row = db.run(
            "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
            (username, password_hash),
            fetch="one",
        )
    except db.Conflict as exc:
        raise UsernameTaken(username) from exc
    return int(row["id"])


def get_user(username: str):
    """Return (id, password_hash) for a username, or None if there is no such user."""
    row = db.run("SELECT id, password_hash FROM users WHERE username = ?", (username,), fetch="one")
    return (int(row["id"]), row["password_hash"]) if row else None
