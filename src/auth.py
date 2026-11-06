"""Login support for the web app: password hashing, signed session cookies and a
small rate limiter. Standard library only. Accounts themselves live in users.py.

Configuration (environment variables):
  AUTH_SECRET      random signing key for session cookies, 32+ characters:
                   python src/auth.py secret
  SIGNUP_ENABLED   set to 0 to close sign-ups (default: open)
  AUTH_DISABLED=1  turn login off (local development only)

If AUTH_SECRET is missing and login is not disabled, the app refuses all access
(fail closed) rather than silently running open.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

COOKIE_NAME = "session"
SESSION_SECONDS = 8 * 60 * 60

# scrypt cost: 16 MB of memory, about 50 ms per check.
_N, _R, _P = 2**14, 8, 1

LOGIN_LIMIT, LOGIN_WINDOW = 5, 5 * 60          # failed logins per client
SIGNUP_LIMIT, SIGNUP_WINDOW = 5, 60 * 60       # sign-up attempts per client
_hits = {}  # key -> (count, window start). Per process, best effort.


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---- configuration ---------------------------------------------------------

def auth_disabled() -> bool:
    return os.environ.get("AUTH_DISABLED") == "1"


def signup_enabled() -> bool:
    return os.environ.get("SIGNUP_ENABLED", "1") != "0"


def _secret() -> bytes:
    return os.environ.get("AUTH_SECRET", "").encode()


def is_configured() -> bool:
    return len(_secret()) >= 32


# ---- passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(candidate, _unb64(digest))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password("not-a-real-password")


def check_login(password: str, stored_hash) -> bool:
    """Verify a password. When the user doesn't exist (stored_hash is None) it
    still does the expensive hash, so a wrong username takes as long as a
    wrong password and can't be told apart by timing."""
    ok = check_password(password, stored_hash or _DUMMY_HASH)
    return ok and stored_hash is not None


# ---- sessions --------------------------------------------------------------

def _sign(payload: str) -> str:
    return _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())


def make_session(username: str, user_id: int, now=None) -> str:
    claims = {"u": username, "id": user_id, "exp": int((now or time.time()) + SESSION_SECONDS)}
    body = _b64(json.dumps(claims).encode())
    return f"{body}.{_sign(body)}"


def read_session(token, now=None):
    """Return (username, user_id) for a valid, unexpired token, otherwise None."""
    if not token or not is_configured() or token.count(".") != 1:
        return None
    body, signature = token.split(".")
    if not hmac.compare_digest(signature, _sign(body)):
        return None
    try:
        claims = json.loads(_unb64(body))
        if claims["exp"] < (now or time.time()):
            return None
        return str(claims["u"]), int(claims["id"])
    except (ValueError, KeyError, TypeError):
        return None


# ---- rate limiting ---------------------------------------------------------

def blocked_for(key: str, limit: int, window: int, now=None) -> int:
    """Seconds until this client may try again, or 0 if it may try now."""
    now = now or time.time()
    count, started = _hits.get(key, (0, now))
    if now - started > window:
        _hits.pop(key, None)
        return 0
    return int(window - (now - started)) + 1 if count >= limit else 0


def record_hit(key: str, window: int, now=None):
    now = now or time.time()
    count, started = _hits.get(key, (0, now))
    if now - started > window:
        count, started = 0, now
    _hits[key] = (count + 1, started)


def clear_hits(key: str):
    _hits.pop(key, None)


def reset_rate_limits():
    _hits.clear()


# ---- command line helper ---------------------------------------------------

if __name__ == "__main__":
    if sys.argv[1:] == ["secret"]:
        print(secrets.token_urlsafe(48))
    else:
        raise SystemExit("Usage: python src/auth.py secret")
