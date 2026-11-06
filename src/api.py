"""Web API and front end for the log anomaly detector.

Run:  uvicorn api:app --app-dir src --reload      (then open http://127.0.0.1:8000)
Docs: http://127.0.0.1:8000/docs   (only when login is disabled; see auth.py)

Every /api route except /api/health, /api/auth/options, /api/signup, /api/login
and /api/logout needs a signed-in session. Each account has its own trained model.
"""

import io
import json
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

import auth
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


def _check_ready():
    if not auth.is_configured():
        raise HTTPException(503, "Login is not configured on this server.")
    if not users.available():
        raise HTTPException(503, "No account database is configured on this server.")


def require_user(request: Request) -> User:
    """Dependency: the signed-in user, or a 401 (503 if login was never set up)."""
    if auth.auth_disabled():
        return User("local", 0)
    _check_ready()
    session = auth.read_session(request.cookies.get(auth.COOKIE_NAME))
    if session is None:
        raise HTTPException(401, "Not signed in.")
    return User(*session)


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def _start_session(request: Request, name: str, user_id: int) -> JSONResponse:
    response = JSONResponse({"user": name, "auth_required": True})
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.make_session(name, user_id),
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


@app.get("/api/auth/options")
def auth_options():
    """Public: what the sign-in screen should offer."""
    return {"signup_enabled": auth.signup_enabled(), "auth_required": not auth.auth_disabled()}


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
    if problem:
        raise HTTPException(400, problem)
    try:
        user_id = users.create_user(username, auth.hash_password(creds.password))
    except users.UsernameTaken:
        raise HTTPException(409, "That username is taken.")
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
    return _start_session(request, username, found[0])


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
def session(user: User = Depends(require_user)):
    """Who is signed in, plus this account's model status."""
    engine, rows = _get_model(user.id)
    return {
        "user": user.name,
        "auth_required": not auth.auth_disabled(),
        "model": describe_engine(engine, rows or 0) if engine else None,
        "max_rows": MAX_ROWS,
    }


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
    """The saved NSL-KDD benchmark: Isolation Forest vs One-Class SVM."""
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


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")
