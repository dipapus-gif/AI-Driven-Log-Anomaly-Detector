"""Account storage for the web app (see db.py for the database itself).

Only password hashes are stored, never passwords.
"""

import hashlib
import re
import secrets
import time

import db
from db import StoreUnavailable, available  # noqa: F401  (re-exported for callers)

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
MIN_PASSWORD = 10
MAX_PASSWORD = 128
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERIFY_TTL, RESET_TTL = 24 * 3600, 3600


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


class EmailTaken(Exception):
    pass


def normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def validate_email(email: str):
    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    return None


def validate_password(password: str, username: str = ""):
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(password) > MAX_PASSWORD:
        return f"Password must be at most {MAX_PASSWORD} characters."
    if password.lower() == username:
        return "Password can't be the same as the username."
    return None


def create_user(username: str, password_hash: str, email=None) -> int:
    try:
        row = db.run(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?) RETURNING id",
            (username, password_hash, email),
            fetch="one",
        )
    except db.Conflict as exc:
        # Either unique column can trip this; tell them apart.
        if email and db.run("SELECT 1 AS x FROM users WHERE email = ?", (email,), fetch="one"):
            raise EmailTaken(email) from exc
        raise UsernameTaken(username) from exc
    return int(row["id"])


def get_user(username: str):
    """Return (id, password_hash) for a username, or None if there is no such user."""
    row = db.run("SELECT id, password_hash FROM users WHERE username = ?", (username,), fetch="one")
    return (int(row["id"]), row["password_hash"]) if row else None


def get_account(user_id: int):
    """Return {id, username, email, email_verified, pw_version} or None."""
    row = db.run(
        "SELECT id, username, email, email_verified, pw_version FROM users WHERE id = ?",
        (user_id,), fetch="one",
    )
    if row:
        row["email_verified"] = bool(row["email_verified"])
    return row


def get_by_email(email: str):
    row = db.run(
        "SELECT id, username, email, email_verified FROM users WHERE email = ?", (email,), fetch="one"
    )
    if row:
        row["email_verified"] = bool(row["email_verified"])
    return row


def set_email(user_id: int, email: str):
    """Attach an (unverified) email. Outstanding verification links stop working."""
    try:
        db.run("UPDATE users SET email = ?, email_verified = 0 WHERE id = ?", (email, user_id))
    except db.Conflict as exc:
        raise EmailTaken(email) from exc
    db.run("DELETE FROM email_tokens WHERE user_id = ? AND kind = 'verify'", (user_id,))


# ---- one-time email tokens -------------------------------------------------
# Only a SHA-256 of each token is stored, so a database leak does not yield usable links.

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(user_id: int, kind: str, now=None) -> str:
    now = now or time.time()
    token = secrets.token_urlsafe(32)
    ttl = VERIFY_TTL if kind == "verify" else RESET_TTL
    # A new link replaces older unused ones of the same kind.
    db.run("DELETE FROM email_tokens WHERE user_id = ? AND kind = ?", (user_id, kind))
    db.run(
        "INSERT INTO email_tokens (user_id, kind, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, kind, _hash(token), now + ttl, now),
    )
    return token


def consume_token(token: str, kind: str, now=None):
    """Use a token once. Returns its user_id, or None if unknown, expired or already used."""
    if not token or len(token) > 200:
        return None
    now = now or time.time()
    h = _hash(token)
    # One UPDATE decides the race: only one caller can flip used_at from NULL.
    changed = db.run(
        "UPDATE email_tokens SET used_at = ? WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?",
        (now, h, kind, now), fetch="count",
    )
    if changed != 1:
        return None
    row = db.run("SELECT user_id FROM email_tokens WHERE token_hash = ?", (h,), fetch="one")
    return int(row["user_id"]) if row else None


def mark_verified(user_id: int):
    db.run("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))


def set_password(user_id: int, password_hash: str):
    """Change the password and bump pw_version, which signs out every existing session."""
    db.run(
        "UPDATE users SET password_hash = ?, pw_version = pw_version + 1 WHERE id = ?",
        (password_hash, user_id),
    )
    db.run("DELETE FROM email_tokens WHERE user_id = ? AND kind = 'reset'", (user_id,))


def peek_token(token: str, kind: str, now=None):
    """The user_id a token would belong to if usable now, without using it."""
    if not token or len(token) > 200:
        return None
    row = db.run(
        "SELECT user_id FROM email_tokens WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?",
        (_hash(token), kind, now or time.time()), fetch="one",
    )
    return int(row["user_id"]) if row else None
