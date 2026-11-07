import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402
import auth  # noqa: E402
import mailer  # noqa: E402
import users  # noqa: E402
from test_api import PASSWORD, USER, anon_client  # noqa: E402,F401  (fixture)

EMAIL = "alice@example.com"
NEW_PASSWORD = "a brand new passphrase"


@pytest.fixture()
def outbox(anon_client, monkeypatch):
    """Turn email on and capture what would be sent."""
    monkeypatch.setenv("EMAIL_FROM", "noreply@example.com")
    monkeypatch.setenv("EMAIL_PROVIDER", "console")
    monkeypatch.setenv("APP_BASE_URL", "https://app.example.com")
    monkeypatch.setattr(api, "MIN_RESET_SECONDS", 0)
    sent = []
    monkeypatch.setattr(mailer, "send_email", lambda to, subject, text: sent.append((to, subject, text)))
    return sent


def token_in(message, kind):
    return re.search(rf"/#/{kind}/([\w-]+)", message[2]).group(1)


def signup(c, email=EMAIL, username=USER):
    return c.post("/api/signup", json={"username": username, "password": PASSWORD, "email": email})


def test_email_is_off_without_a_provider(anon_client):
    assert anon_client.get("/api/auth/options").json()["email_enabled"] is False
    assert anon_client.post("/api/password/forgot", json={"email": EMAIL}).status_code == 503


def test_email_needs_a_public_address_to_link_to(anon_client, monkeypatch):
    monkeypatch.setenv("EMAIL_FROM", "noreply@example.com")
    monkeypatch.setenv("EMAIL_PROVIDER", "console")
    monkeypatch.delenv("APP_BASE_URL", raising=False)
    assert mailer.configured() is False  # never falls back to the request's Host header


def test_signup_requires_email_and_sends_verification(anon_client, outbox):
    assert anon_client.get("/api/auth/options").json()["email_enabled"] is True
    assert anon_client.post("/api/signup", json={"username": USER, "password": PASSWORD}).status_code == 400
    assert signup(anon_client, "not-an-email").status_code == 400
    assert signup(anon_client).status_code == 200
    assert len(outbox) == 1 and outbox[0][0] == EMAIL
    assert "https://app.example.com/#/verify/" in outbox[0][2]


def test_unverified_user_is_gated_until_verified(anon_client, outbox):
    signup(anon_client)
    gated = anon_client.get("/api/benchmark")
    assert gated.status_code == 403 and gated.headers["x-auth-reason"] == "email_unverified"
    s = anon_client.get("/api/session").json()
    assert s["email_required"] is True and s["email_verified"] is False
    token = token_in(outbox[0], "verify")
    assert anon_client.post("/api/email/verify", json={"token": token}).status_code == 200
    assert anon_client.get("/api/benchmark").status_code == 200
    assert anon_client.get("/api/session").json()["email_verified"] is True


def test_verify_link_is_single_use_and_get_does_not_consume_it(anon_client, outbox):
    signup(anon_client)
    token = token_in(outbox[0], "verify")
    anon_client.get(f"/api/email/verify?token={token}")  # a link scanner
    assert anon_client.post("/api/email/verify", json={"token": token}).status_code == 200
    assert anon_client.post("/api/email/verify", json={"token": token}).status_code == 400


def test_verify_token_expires(anon_client, outbox, monkeypatch):
    signup(anon_client)
    token = token_in(outbox[0], "verify")
    real = time.time
    monkeypatch.setattr(users.time, "time", lambda: real() + users.VERIFY_TTL + 5)
    assert anon_client.post("/api/email/verify", json={"token": token}).status_code == 400


def test_garbage_token_is_rejected(anon_client, outbox):
    assert anon_client.post("/api/email/verify", json={"token": "nope"}).status_code == 400
    assert anon_client.post("/api/email/verify", json={"token": "x" * 5000}).status_code == 400


def test_resend_replaces_the_old_link_and_is_limited(anon_client, outbox):
    signup(anon_client)
    first = token_in(outbox[0], "verify")
    for _ in range(auth.MAIL_LIMIT):
        assert anon_client.post("/api/email/resend").status_code == 200
    assert anon_client.post("/api/email/resend").status_code == 429
    assert anon_client.post("/api/email/verify", json={"token": first}).status_code == 400
    assert anon_client.post("/api/email/verify", json={"token": token_in(outbox[-1], "verify")}).status_code == 200


def test_duplicate_email_is_rejected(anon_client, outbox):
    assert signup(anon_client).status_code == 200
    other = type(anon_client)(api.app)
    assert signup(other, EMAIL.upper(), "bob123").status_code == 409


def verified_account(c, outbox):
    signup(c)
    c.post("/api/email/verify", json={"token": token_in(outbox[0], "verify")})
    outbox.clear()


def test_forgot_password_does_not_reveal_whether_an_account_exists(anon_client, outbox):
    verified_account(anon_client, outbox)
    known = anon_client.post("/api/password/forgot", json={"email": EMAIL})
    unknown = anon_client.post("/api/password/forgot", json={"email": "nobody@example.com"})
    junk = anon_client.post("/api/password/forgot", json={"email": "junk"})
    assert known.status_code == unknown.status_code == junk.status_code == 200
    assert known.json() == unknown.json() == junk.json()
    assert len(outbox) == 1 and outbox[0][0] == EMAIL


def test_reset_link_only_goes_to_verified_addresses(anon_client, outbox):
    signup(anon_client)  # never verified
    outbox.clear()
    anon_client.post("/api/password/forgot", json={"email": EMAIL})
    assert outbox == []


def test_forgot_password_is_rate_limited_per_address(anon_client, outbox):
    verified_account(anon_client, outbox)
    for _ in range(6):
        assert anon_client.post("/api/password/forgot", json={"email": EMAIL}).status_code == 200
    assert len(outbox) == auth.MAIL_LIMIT


def test_reset_changes_password_signs_out_old_sessions_and_link_is_single_use(anon_client, outbox):
    verified_account(anon_client, outbox)
    other = type(anon_client)(api.app)
    assert other.post("/api/login", json={"username": USER, "password": PASSWORD}).status_code == 200
    assert other.get("/api/session").status_code == 200

    anon_client.post("/api/password/forgot", json={"email": EMAIL})
    token = token_in(outbox[0], "reset")
    weak = anon_client.post("/api/password/reset", json={"token": token, "password": "short"})
    assert weak.status_code == 400  # a typo doesn't burn the link
    ok = anon_client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD})
    assert ok.status_code == 200
    assert anon_client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD}).status_code == 400

    assert other.get("/api/session").status_code == 401  # old session is dead
    assert anon_client.get("/api/session").status_code == 401
    fresh = type(anon_client)(api.app)
    assert fresh.post("/api/login", json={"username": USER, "password": PASSWORD}).status_code == 401
    assert fresh.post("/api/login", json={"username": USER, "password": NEW_PASSWORD}).status_code == 200
    assert fresh.get("/api/session").status_code == 200


def test_reset_token_expires(anon_client, outbox, monkeypatch):
    verified_account(anon_client, outbox)
    anon_client.post("/api/password/forgot", json={"email": EMAIL})
    token = token_in(outbox[0], "reset")
    real = time.time
    monkeypatch.setattr(users.time, "time", lambda: real() + users.RESET_TTL + 5)
    assert anon_client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD}).status_code == 400


def test_verify_token_cannot_be_used_to_reset(anon_client, outbox):
    signup(anon_client)
    token = token_in(outbox[0], "verify")
    assert anon_client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD}).status_code == 400


def test_reset_also_verifies_the_address(anon_client, outbox):
    signup(anon_client)
    users.mark_verified(users.get_user(USER)[0])
    users.set_email(users.get_user(USER)[0], EMAIL)  # unverified again
    uid = users.get_user(USER)[0]
    token = users.issue_token(uid, "reset")
    assert anon_client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD}).status_code == 200
    assert users.get_account(uid)["email_verified"] is True


def test_existing_account_can_add_an_email_with_its_password(anon_client, monkeypatch):
    # An account created before email was enabled has no address.
    assert anon_client.post("/api/signup", json={"username": USER, "password": PASSWORD}).status_code == 200
    monkeypatch.setenv("EMAIL_FROM", "noreply@example.com")
    monkeypatch.setenv("EMAIL_PROVIDER", "console")
    monkeypatch.setenv("APP_BASE_URL", "https://app.example.com")
    sent = []
    monkeypatch.setattr(mailer, "send_email", lambda *a: sent.append(a))
    assert anon_client.get("/api/benchmark").status_code == 403  # gated until it has a verified address
    assert anon_client.post("/api/email/set", json={"email": EMAIL, "password": "wrong password!"}).status_code == 401
    assert anon_client.post("/api/email/set", json={"email": EMAIL, "password": PASSWORD}).status_code == 200
    token = re.search(r"/#/verify/([\w-]+)", sent[0][2]).group(1)
    assert anon_client.post("/api/email/verify", json={"token": token}).status_code == 200
    assert anon_client.get("/api/benchmark").status_code == 200


def test_tokens_are_stored_hashed(anon_client, outbox):
    signup(anon_client)
    token = token_in(outbox[0], "verify")
    import db
    rows = db.run("SELECT token_hash FROM email_tokens", fetch="all")
    assert rows and all(token not in r["token_hash"] for r in rows)
