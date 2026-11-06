import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402
import auth  # noqa: E402
import db  # noqa: E402
import users  # noqa: E402
from generate_data import generate  # noqa: E402
from test_api import PASSWORD, USER, anon_client, client, csv_file  # noqa: E402,F401  (fixtures)

PROTECTED = [
    ("get", "/api/session"),
    ("get", "/api/benchmark"),
    ("get", "/api/benchmark/roc.png"),
    ("get", "/api/sample.csv"),
    ("post", "/api/demo"),
]


def signup(c, username=USER, password=PASSWORD):
    return c.post("/api/signup", json={"username": username, "password": password})


def login(c, username=USER, password=PASSWORD):
    return c.post("/api/login", json={"username": username, "password": password})


# ---- access control --------------------------------------------------------

@pytest.mark.parametrize("method,path", PROTECTED)
def test_data_routes_need_a_session(anon_client, method, path):
    assert getattr(anon_client, method)(path).status_code == 401


def test_upload_routes_need_a_session(anon_client):
    files = csv_file(generate(rows=100))
    assert anon_client.post("/api/train", files=files).status_code == 401
    assert anon_client.post("/api/analyze", files=files).status_code == 401


def test_api_docs_are_not_exposed(anon_client):
    assert anon_client.get("/docs").status_code == 404
    assert anon_client.get("/openapi.json").status_code == 404


# ---- sign-up ---------------------------------------------------------------

def test_signup_creates_account_and_signs_in(anon_client):
    r = signup(anon_client)
    assert r.status_code == 200 and r.json()["user"] == USER
    assert anon_client.get("/api/session").json()["user"] == USER


def test_signup_stores_a_hash_not_the_password(anon_client):
    signup(anon_client)
    _, stored = users.get_user(USER)
    assert stored.startswith("scrypt$") and PASSWORD not in stored


def test_usernames_are_case_insensitive_and_unique(anon_client):
    assert signup(anon_client, "Alice").json()["user"] == "alice"
    other = TestClient(api.app)
    assert signup(other, "ALICE", "another long password").status_code == 409
    assert login(other, "aLiCe").status_code == 200  # same account, any casing


@pytest.mark.parametrize(
    "username,password",
    [
        ("ab", PASSWORD),                      # too short
        ("has space", PASSWORD),               # bad characters
        ("-leading-dash", PASSWORD),
        ("bob", "short"),                      # weak password
        ("bob", "x" * 200),                    # absurdly long (hashing DoS)
        ("sameaspass1", "sameaspass1"),        # password equals username
    ],
)
def test_signup_rejects_bad_details(anon_client, username, password):
    r = signup(anon_client, username, password)
    assert r.status_code == 400 and r.json()["detail"]
    assert users.get_user(username.strip().lower()) is None


def test_signup_can_be_closed(anon_client, monkeypatch):
    monkeypatch.setenv("SIGNUP_ENABLED", "0")
    assert anon_client.get("/api/auth/options").json()["signup_enabled"] is False
    assert signup(anon_client).status_code == 403
    assert users.get_user(USER) is None


def test_signup_is_rate_limited_per_client(anon_client):
    for i in range(auth.SIGNUP_LIMIT):
        assert signup(anon_client, f"user{i}1").status_code == 200
    blocked = signup(anon_client, "onetoomany")
    assert blocked.status_code == 429 and "Retry-After" in blocked.headers


# ---- login / logout --------------------------------------------------------

def test_login_after_logout_works_and_logout_ends_the_session(anon_client):
    signup(anon_client)
    anon_client.post("/api/logout")
    assert anon_client.get("/api/session").status_code == 401
    assert login(anon_client).status_code == 200
    assert anon_client.get("/api/session").status_code == 200


def test_wrong_password_and_unknown_user_get_the_same_answer(anon_client):
    signup(anon_client)
    other = TestClient(api.app)
    bad_pw = login(other, USER, "nope nope nope")
    bad_user = login(other, "nobody", PASSWORD)
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json()
    assert "session" not in other.cookies


def test_session_cookie_is_hardened(anon_client):
    r = signup(anon_client)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


def test_cookie_is_marked_secure_over_https(anon_client):
    r = anon_client.post(
        "/api/signup",
        json={"username": USER, "password": PASSWORD},
        headers={"x-forwarded-proto": "https"},
    )
    assert "secure" in r.headers["set-cookie"].lower()


def test_repeated_failed_logins_lock_out_even_the_right_password(anon_client):
    signup(anon_client)
    other = TestClient(api.app)
    for _ in range(auth.LOGIN_LIMIT):
        assert login(other, USER, "wrong wrong wrong").status_code == 401
    locked = login(other)
    assert locked.status_code == 429 and "Retry-After" in locked.headers


# ---- sessions --------------------------------------------------------------

def test_tampered_and_expired_sessions_are_rejected(anon_client, monkeypatch):
    token = auth.make_session(USER, 7)
    assert auth.read_session(token) == (USER, 7)
    body, sig = token.split(".")
    assert auth.read_session(f"{body}.{sig[:-2]}AA") is None            # bad signature
    assert auth.read_session(f"{auth._b64(b'{}')}.{sig}") is None       # changed payload
    assert auth.read_session(token, now=10**11) is None                 # expired
    monkeypatch.setenv("AUTH_SECRET", "y" * 48)                         # key rotated
    assert auth.read_session(token) is None
    anon_client.cookies.set("session", "garbage")
    assert anon_client.get("/api/session").status_code == 401


# ---- failing safe ----------------------------------------------------------

def test_fails_closed_without_a_signing_secret(anon_client, monkeypatch):
    monkeypatch.delenv("AUTH_SECRET")
    assert signup(anon_client).status_code == 503
    assert login(anon_client).status_code == 503
    assert anon_client.get("/api/benchmark").status_code == 503


def test_short_secret_counts_as_unconfigured(anon_client, monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "short")
    assert anon_client.get("/api/benchmark").status_code == 503


def test_serverless_without_a_database_refuses_rather_than_losing_accounts(anon_client, monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert signup(anon_client).status_code == 503
    assert users.available() is False


def test_database_outage_is_a_503_not_a_crash(anon_client, monkeypatch):
    signup(anon_client)

    def down():
        raise OSError("connection refused")

    monkeypatch.setattr(db, "_connect", down)
    other = TestClient(api.app)
    assert login(other).status_code == 503
    assert signup(other, "newuser1").status_code == 503


def test_auth_disabled_switch_opens_the_app_for_local_use(anon_client, monkeypatch):
    monkeypatch.setenv("AUTH_DISABLED", "1")
    body = anon_client.get("/api/session").json()
    assert body["user"] == "local" and body["auth_required"] is False
    assert anon_client.get("/api/benchmark").status_code == 200


def test_password_hashes_are_salted_and_verify():
    a, b = auth.hash_password("same password!"), auth.hash_password("same password!")
    assert a != b
    assert auth.check_password("same password!", a)
    assert not auth.check_password("other password", a)
    assert not auth.check_password("same password!", "not-a-hash")


# ---- accounts are isolated -------------------------------------------------

def test_each_account_has_its_own_model(client):
    client.post("/api/demo")
    assert client.get("/api/session").json()["model"] is not None

    second = TestClient(api.app)
    signup(second, "bob.smith", "bobs long password")
    assert second.get("/api/session").json()["model"] is None
    r = second.post("/api/analyze", files=csv_file(generate(rows=100)))
    assert r.status_code == 409  # bob can't use alice's model

    # and bob training doesn't disturb alice
    second.post("/api/demo?rows=300")
    assert client.get("/api/session").json()["model"]["trained_rows"] == 1000
