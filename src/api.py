"""Web API and front end for the log anomaly detector.

Run:  uvicorn api:app --app-dir src --reload      (then open http://127.0.0.1:8000)
Docs: http://127.0.0.1:8000/docs   (only when login is disabled; see auth.py)

Every /api route except /api/health, /api/auth/options, /api/signup, /api/login, /api/logout
and /api/ingest (which uses an ingest token) needs a signed-in session. Each account has its own
data, trained models, incidents and settings. See platform_api.py for the detection platform.
"""

import io
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

import auth
import mailer
import platform_api
import soc
import users
from engine import LogAnomalyEngine
from generate_data import generate
from pipeline import (
    MAX_ROWS,
    ROC_PATH,
    InputError,
    benchmark_table,
    describe_engine,
    load_benchmark,
    summarize,
    train_engine,
    validate_logs,
)

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
# Serverless hosts (Vercel) have a read-only project directory; /tmp is writable.
MODEL_DIR = Path("/tmp") if os.environ.get("VERCEL") else ROOT / "models"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_CACHED_MODELS = 50

# The interactive API docs would show the whole API to anyone, so they are only
# served when login is switched off for local development.
_docs = auth.auth_disabled()
app = FastAPI(
    title="AI Log Anomaly Detector",
    version="1.2.0",
    docs_url="/docs" if _docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs else None,
)


# ---- per-account models ----------------------------------------------------

_models = OrderedDict()  # user id -> (engine, trained_rows), least recently used first
_models_lock = threading.Lock()


def _model_path(user_id: int) -> Path:
    return MODEL_DIR / f"anomaly_model_{user_id}.pkl"


def _get_model(user_id: int):
    """This account's (engine, trained_rows); (None, None) if it hasn't trained one."""
    with _models_lock:
        if user_id in _models:
            _models.move_to_end(user_id)
            return _models[user_id]
    path = _model_path(user_id)
    if path.exists():
        try:
            engine = LogAnomalyEngine.load(str(path))
        except Exception:  # corrupt or from an incompatible sklearn version
            return None, None
        _put_model(user_id, engine, None)
        return engine, None
    return None, None


def _put_model(user_id: int, engine, trained_rows):
    with _models_lock:
        _models[user_id] = (engine, trained_rows)
        _models.move_to_end(user_id)
        while len(_models) > MAX_CACHED_MODELS:
            _models.popitem(last=False)


def _set_model(user_id: int, engine, trained_rows):
    _put_model(user_id, engine, trained_rows)
    try:
        engine.save(str(_model_path(user_id)))
    except OSError:
        pass  # read-only filesystem: the in-memory model still works


def _require_engine(user_id: int):
    engine, _ = _get_model(user_id)
    if engine is None:
        raise HTTPException(409, "No model trained yet. Train one first or run the demo.")
    return engine


# ---- request helpers -------------------------------------------------------

def _read_csv(upload: UploadFile) -> pd.DataFrame:
    raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit {MAX_UPLOAD_BYTES // 2**20} MB).")
    try:
        return pd.read_csv(io.BytesIO(raw))
    except Exception:
        raise HTTPException(400, "Could not read that file as a CSV.")


@app.exception_handler(InputError)
async def _input_error(_request, exc):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(users.StoreUnavailable)
async def _store_unavailable(_request, _exc):
    return JSONResponse(
        status_code=503, content={"detail": "The account service is unavailable. Try again shortly."}
    )


# ---- accounts and sessions -------------------------------------------------

@dataclass(frozen=True)
class User:
    name: str
    id: int
    email: str = ""
    email_verified: bool = True


def _check_ready():
    if not auth.is_configured():
        raise HTTPException(503, "Login is not configured on this server.")
    if not users.available():
        raise HTTPException(503, "No account database is configured on this server.")


def current_user(request: Request) -> User:
    """The signed-in user, or a 401 (503 if login was never set up). Does not check email verification."""
    if auth.auth_disabled():
        return User("local", 0)
    _check_ready()
    claims = auth.session_claims(request.cookies.get(auth.COOKIE_NAME))
    if claims is None:
        raise HTTPException(401, "Not signed in.")
    account = users.get_account(claims["id"])
    # A deleted account, or a session from before the last password change, is signed out.
    if account is None or account["username"] != claims["u"] or account["pw_version"] != claims["pv"]:
        raise HTTPException(401, "Not signed in.")
    return User(account["username"], account["id"], account["email"] or "", account["email_verified"])


def require_user(request: Request) -> User:
    """Dependency for data routes: signed in and, when email is enabled, verified."""
    user = current_user(request)
    if mailer.configured() and not user.email_verified:
        raise HTTPException(403, "Confirm your email address to continue.", headers={"X-Auth-Reason": "email_unverified"})
    return user


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def _start_session(request: Request, name: str, user_id: int, pw_version: int = 0) -> JSONResponse:
    response = JSONResponse({"user": name, "auth_required": True})
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.make_session(name, user_id, pw_version=pw_version),
        max_age=auth.SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=_is_https(request),
        path="/",
    )
    return response


def _too_many(wait: int, what: str) -> HTTPException:
    return HTTPException(
        429,
        f"Too many {what}. Try again in {wait // 60 + 1} minutes.",
        headers={"Retry-After": str(wait)},
    )


class Credentials(BaseModel):
    username: str
    password: str
    email: str = ""


@app.get("/api/auth/options")
def auth_options():
    """Public: what the sign-in screen should offer."""
    return {
        "signup_enabled": auth.signup_enabled(),
        "auth_required": not auth.auth_disabled(),
        "email_enabled": mailer.configured() and not auth.auth_disabled(),
    }


@app.post("/api/signup")
def signup(creds: Credentials, request: Request):
    if auth.auth_disabled():
        raise HTTPException(400, "Login is disabled on this server.")
    _check_ready()
    if not auth.signup_enabled():
        raise HTTPException(403, "Sign-ups are closed.")
    key = "signup:" + _client_key(request)
    wait = auth.blocked_for(key, auth.SIGNUP_LIMIT, auth.SIGNUP_WINDOW)
    if wait:
        raise _too_many(wait, "sign-up attempts")
    auth.record_hit(key, auth.SIGNUP_WINDOW)

    username = users.normalize_username(creds.username)
    problem = users.validate_signup(username, creds.password)
    email = users.normalize_email(creds.email) or None
    if mailer.configured() and not email:
        problem = problem or "An email address is required."
    if email and not problem:
        problem = users.validate_email(email)
    if problem:
        raise HTTPException(400, problem)
    try:
        user_id = users.create_user(username, auth.hash_password(creds.password), email)
    except users.UsernameTaken:
        raise HTTPException(409, "That username is taken.")
    except users.EmailTaken:
        raise HTTPException(409, "An account with that email already exists.")
    if email and mailer.configured():
        _send_verification(user_id, email)
    return _start_session(request, username, user_id)


@app.post("/api/login")
def login(creds: Credentials, request: Request):
    if auth.auth_disabled():
        return {"user": "local", "auth_required": False}
    _check_ready()
    key = "login:" + _client_key(request)
    wait = auth.blocked_for(key, auth.LOGIN_LIMIT, auth.LOGIN_WINDOW)
    if wait:
        raise _too_many(wait, "failed attempts")
    username = users.normalize_username(creds.username)
    found = users.get_user(username)
    if not auth.check_login(creds.password, found[1] if found else None):
        auth.record_hit(key, auth.LOGIN_WINDOW)
        raise HTTPException(401, "Wrong username or password.")
    auth.clear_hits(key)
    account = users.get_account(found[0])
    return _start_session(request, username, found[0], account["pw_version"] if account else 0)


@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return response


@app.get("/api/health")
def health():
    """Public liveness check. Deliberately reveals nothing else."""
    return {"status": "ok"}


@app.get("/api/session")
def session(user: User = Depends(current_user)):
    """Who is signed in, plus this account's model status and email state."""
    email_on = mailer.configured() and not auth.auth_disabled()
    if email_on and not user.email_verified:
        return {
            "user": user.name, "auth_required": True, "email": user.email,
            "email_verified": False, "email_required": True, "model": None, "max_rows": MAX_ROWS,
        }
    engine, rows = _get_model(user.id)
    return {
        "user": user.name,
        "email": user.email,
        "email_verified": user.email_verified,
        "email_required": False,
        "auth_required": not auth.auth_disabled(),
        "model": describe_engine(engine, rows or 0) if engine else None,
        "max_rows": MAX_ROWS,
    }


# ---- email verification and password reset --------------------------------

MIN_RESET_SECONDS = 1.5  # forgot-password always takes about this long, so timing reveals nothing


def _require_email_enabled():
    if auth.auth_disabled() or not mailer.configured():
        raise HTTPException(503, "Email is not set up on this server.")


def _send_verification(user_id: int, email: str) -> bool:
    link = f"{mailer.base_url()}/#/verify/{users.issue_token(user_id, 'verify')}"
    try:
        mailer.send_email(email, *mailer.verify_message(link))
        return True
    except Exception:
        return False  # the account exists; the user can press "resend"


class TokenBody(BaseModel):
    token: str


class EmailBody(BaseModel):
    email: str


class SetEmailBody(BaseModel):
    email: str
    password: str


class ResetBody(BaseModel):
    token: str
    password: str


@app.post("/api/email/verify")
def verify_email(body: TokenBody, request: Request):
    """Confirm an address. Reached by a POST from the page (not a GET), so a mail scanner that
    pre-fetches links can't use up the token."""
    _require_email_enabled()
    key = "verify:" + _client_key(request)
    wait = auth.blocked_for(key, 20, 3600)
    if wait:
        raise _too_many(wait, "attempts")
    auth.record_hit(key, 3600)
    user_id = users.consume_token(body.token, "verify")
    if user_id is None:
        raise HTTPException(400, "This link is invalid or has expired. Request a new one.")
    users.mark_verified(user_id)
    return {"ok": True}


@app.post("/api/email/resend")
def resend_verification(user: User = Depends(current_user)):
    _require_email_enabled()
    if user.email_verified:
        return {"ok": True}
    if not user.email:
        raise HTTPException(400, "Add an email address first.")
    key = f"resend:{user.id}"
    wait = auth.blocked_for(key, auth.MAIL_LIMIT, auth.MAIL_WINDOW)
    if wait:
        raise _too_many(wait, "emails requested")
    auth.record_hit(key, auth.MAIL_WINDOW)
    if not _send_verification(user.id, user.email):
        raise HTTPException(502, "The email could not be sent. Try again shortly.")
    return {"ok": True}


@app.post("/api/email/set")
def set_account_email(body: SetEmailBody, user: User = Depends(current_user)):
    """Add or change the account's email. Needs the password, so a stolen session can't redirect resets."""
    _require_email_enabled()
    found = users.get_user(user.name)
    key = f"setemail:{user.id}"
    wait = auth.blocked_for(key, auth.LOGIN_LIMIT, auth.LOGIN_WINDOW)
    if wait:
        raise _too_many(wait, "attempts")
    if not found or not auth.check_password(body.password, found[1]):
        auth.record_hit(key, auth.LOGIN_WINDOW)
        raise HTTPException(401, "Wrong password.")
    email = users.normalize_email(body.email)
    problem = users.validate_email(email)
    if problem:
        raise HTTPException(400, problem)
    try:
        users.set_email(user.id, email)
    except users.EmailTaken:
        raise HTTPException(409, "An account with that email already exists.")
    if not _send_verification(user.id, email):
        raise HTTPException(502, "Saved, but the email could not be sent. Press resend in a moment.")
    return {"ok": True, "email": email}


@app.post("/api/password/forgot")
def forgot_password(body: EmailBody, request: Request):
    """Always answers the same way, whether or not the address has an account."""
    _require_email_enabled()
    started = time.monotonic()
    ip_key = "forgot:" + _client_key(request)
    wait = auth.blocked_for(ip_key, auth.RESET_IP_LIMIT, auth.MAIL_WINDOW)
    if wait:
        raise _too_many(wait, "reset requests")
    auth.record_hit(ip_key, auth.MAIL_WINDOW)
    email = users.normalize_email(body.email)
    if not users.validate_email(email):
        mail_key = "forgot-mail:" + email
        if not auth.blocked_for(mail_key, auth.MAIL_LIMIT, auth.MAIL_WINDOW):
            auth.record_hit(mail_key, auth.MAIL_WINDOW)
            account = users.get_by_email(email)
            # Only an address the owner has confirmed can receive a reset link.
            if account and account["email_verified"]:
                link = f"{mailer.base_url()}/#/reset/{users.issue_token(account['id'], 'reset')}"
                try:
                    mailer.send_email(email, *mailer.reset_message(link))
                except Exception:
                    pass
    left = MIN_RESET_SECONDS - (time.monotonic() - started)
    if left > 0:
        time.sleep(left)
    return {"ok": True, "message": "If that address belongs to an account, a reset link is on its way."}


@app.post("/api/password/reset")
def reset_password(body: ResetBody, request: Request):
    _require_email_enabled()
    key = "reset:" + _client_key(request)
    wait = auth.blocked_for(key, 20, 3600)
    if wait:
        raise _too_many(wait, "attempts")
    auth.record_hit(key, 3600)
    # Check the new password before using up the one-time link, so a typo doesn't waste it.
    peek = users.peek_token(body.token, "reset")
    if peek is None:
        raise HTTPException(400, "This link is invalid or has expired. Request a new one.")
    account = users.get_account(peek)
    problem = users.validate_password(body.password, account["username"] if account else "")
    if problem:
        raise HTTPException(400, problem)
    user_id = users.consume_token(body.token, "reset")
    if user_id is None:
        raise HTTPException(400, "This link is invalid or has expired. Request a new one.")
    users.set_password(user_id, auth.hash_password(body.password))
    users.mark_verified(user_id)  # they just proved they control the address
    response = JSONResponse({"ok": True})
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return response


# ---- the detector ----------------------------------------------------------

@app.post("/api/train")
def train(
    file: UploadFile = File(...),
    contamination: float = Form(0.05),
    user: User = Depends(require_user),
):
    """Fit a model on a CSV of (mostly) normal logs."""
    df = _read_csv(file)
    engine = train_engine(df, contamination)
    _set_model(user.id, engine, len(df))
    return describe_engine(engine, len(df))


@app.post("/api/analyze")
def analyze(file: UploadFile = File(...), user: User = Depends(require_user)):
    """Score a CSV of logs with this account's model."""
    df = validate_logs(_read_csv(file))
    engine = _require_engine(user.id)
    return summarize(engine.score(df), engine)


@app.post("/api/demo")
def demo(rows: int = 1000, attack_fraction: float = 0.05, user: User = Depends(require_user)):
    """Generate synthetic traffic with injected attacks, train on it, and analyze it."""
    if not 100 <= rows <= 20_000:
        raise HTTPException(400, "rows must be between 100 and 20,000.")
    if not 0.01 <= attack_fraction <= 0.3:
        raise HTTPException(400, "attack_fraction must be between 0.01 and 0.3.")
    df = generate(rows=rows, attack_fraction=attack_fraction)
    engine = train_engine(df, contamination=attack_fraction)
    _set_model(user.id, engine, len(df))
    return summarize(engine.score(df), engine)


@app.get("/api/sample.csv", dependencies=[Depends(require_user)])
def sample(rows: int = 500):
    """A small synthetic CSV you can download and upload back to try the tool."""
    rows = max(100, min(rows, 5000))
    csv = generate(rows=rows).to_csv(index=False)
    return Response(
        csv,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="sample_logs.csv"'},
    )


@app.get("/api/benchmark", dependencies=[Depends(require_user)])
def benchmark():
    """The saved NSL-KDD benchmark: detectors plus the supervised Random Forest reference."""
    results = load_benchmark()
    if results is None:
        raise HTTPException(404, "No benchmark results found. Run src/evaluate.py first.")
    return {
        "contamination": results["contamination"],
        "table": json.loads(benchmark_table(results).to_json(orient="records")),
        "roc_available": ROC_PATH.exists(),
    }


@app.get("/api/benchmark/roc.png", dependencies=[Depends(require_user)])
def roc_image():
    if not ROC_PATH.exists():
        raise HTTPException(404, "ROC image not found.")
    return FileResponse(ROC_PATH, media_type="image/png")


app.include_router(platform_api.create_router(require_user))


@app.exception_handler(soc.SocError)
async def _soc_error(_request, exc):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")
