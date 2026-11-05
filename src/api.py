"""Web API and front end for the log anomaly detector.

Run:  uvicorn api:app --app-dir src --reload      (then open http://127.0.0.1:8000)
Docs: http://127.0.0.1:8000/docs

The trained model lives in memory (and is also saved to models/anomaly_model.pkl
so it survives restarts). One shared model per server process: this is a demo
service, not a multi-tenant one. On serverless hosts each warm instance has its
own model, so after a cold start you may need to train again.
"""

import io
import json
import os
import threading
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response

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
MODEL_PATH = (
    Path("/tmp/anomaly_model.pkl")
    if os.environ.get("VERCEL")
    else ROOT / "models" / "anomaly_model.pkl"
)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = FastAPI(title="AI Log Anomaly Detector", version="1.0.0")

_lock = threading.Lock()
_state = {"engine": None, "trained_rows": None}


def _load_saved_model():
    if MODEL_PATH.exists():
        try:
            _state["engine"] = LogAnomalyEngine.load(str(MODEL_PATH))
        except Exception:  # corrupt or from an incompatible sklearn version
            _state["engine"] = None


_load_saved_model()


def _set_model(engine, trained_rows):
    _state["engine"], _state["trained_rows"] = engine, trained_rows
    try:
        engine.save(str(MODEL_PATH))
    except OSError:
        pass  # read-only filesystem: the in-memory model still works


def _read_csv(upload: UploadFile) -> pd.DataFrame:
    raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit {MAX_UPLOAD_BYTES // 2**20} MB).")
    try:
        return pd.read_csv(io.BytesIO(raw))
    except Exception:
        raise HTTPException(400, "Could not read that file as a CSV.")


def _require_engine():
    engine = _state["engine"]
    if engine is None:
        raise HTTPException(409, "No model trained yet. Train one first or run the demo.")
    return engine


@app.exception_handler(InputError)
async def _input_error(_request, exc):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/api/health")
def health():
    engine = _state["engine"]
    return {
        "status": "ok",
        "model_loaded": engine is not None,
        "model": describe_engine(engine, _state["trained_rows"] or 0) if engine else None,
        "max_rows": MAX_ROWS,
    }


@app.post("/api/train")
def train(file: UploadFile = File(...), contamination: float = Form(0.05)):
    """Fit a model on a CSV of (mostly) normal logs."""
    df = _read_csv(file)
    with _lock:
        engine = train_engine(df, contamination)
        _set_model(engine, len(df))
    return describe_engine(engine, len(df))


@app.post("/api/analyze")
def analyze(file: UploadFile = File(...)):
    """Score a CSV of logs with the current model."""
    df = validate_logs(_read_csv(file))
    with _lock:
        engine = _require_engine()
        scored = engine.score(df)
    return summarize(scored, engine)


@app.post("/api/demo")
def demo(rows: int = 1000, attack_fraction: float = 0.05):
    """Generate synthetic traffic with injected attacks, train on it, and analyze it."""
    if not 100 <= rows <= 20_000:
        raise HTTPException(400, "rows must be between 100 and 20,000.")
    if not 0.01 <= attack_fraction <= 0.3:
        raise HTTPException(400, "attack_fraction must be between 0.01 and 0.3.")
    df = generate(rows=rows, attack_fraction=attack_fraction)
    with _lock:
        engine = train_engine(df, contamination=attack_fraction)
        _set_model(engine, len(df))
        scored = engine.score(df)
    return summarize(scored, engine)


@app.get("/api/sample.csv")
def sample(rows: int = 500):
    """A small synthetic CSV you can download and upload back to try the tool."""
    rows = max(100, min(rows, 5000))
    csv = generate(rows=rows).to_csv(index=False)
    return Response(
        csv,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="sample_logs.csv"'},
    )


@app.get("/api/benchmark")
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


@app.get("/api/benchmark/roc.png")
def roc_image():
    if not ROC_PATH.exists():
        raise HTTPException(404, "ROC image not found.")
    return FileResponse(ROC_PATH, media_type="image/png")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")
