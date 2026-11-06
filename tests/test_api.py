import io
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402
import auth  # noqa: E402
from generate_data import generate  # noqa: E402

USER = "alice"
PASSWORD = "correct horse battery"


@pytest.fixture()
def anon_client(database, tmp_path, monkeypatch):
    """A client against a fresh database (SQLite and Postgres), nobody signed in."""
    monkeypatch.setenv("AUTH_SECRET", "x" * 48)
    for name in ("AUTH_DISABLED", "SIGNUP_ENABLED", "VERCEL"):
        monkeypatch.delenv(name, raising=False)
    # Keep tests away from any real saved models and start with none loaded.
    monkeypatch.setattr(api, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(api, "_models", type(api._models)())
    auth.reset_rate_limits()
    return TestClient(api.app)


@pytest.fixture()
def client(anon_client):
    """A client signed in as a freshly created account."""
    r = anon_client.post("/api/signup", json={"username": USER, "password": PASSWORD})
    assert r.status_code == 200
    return anon_client


def csv_file(df):
    return {"file": ("logs.csv", df.to_csv(index=False).encode(), "text/csv")}


def test_index_is_public_and_health_reveals_nothing(anon_client):
    assert "Log Anomaly Detector" in anon_client.get("/").text
    assert anon_client.get("/api/health").json() == {"status": "ok"}


def test_session_reports_user_and_model_status(client):
    body = client.get("/api/session").json()
    assert body["user"] == USER and body["auth_required"] is True and body["model"] is None


def test_analyze_without_model_is_409(client):
    r = client.post("/api/analyze", files=csv_file(generate(rows=100)))
    assert r.status_code == 409


def test_train_then_analyze_catches_attacks(client):
    df = generate(rows=600, attack_fraction=0.05)
    r = client.post("/api/train", files=csv_file(df), data={"contamination": "0.05"})
    assert r.status_code == 200
    assert r.json()["trained_rows"] == 600
    assert client.get("/api/session").json()["model"]["trained_rows"] == 600

    out = client.post("/api/analyze", files=csv_file(df)).json()
    assert out["rows"] == 600
    assert sum(out["histogram"]) == 600
    assert out["label_metrics"]["recall"] >= 0.9
    risks = [row["risk_score"] for row in out["flagged_rows"]]
    assert risks == sorted(risks, reverse=True)


def test_demo_trains_and_returns_results(client):
    out = client.post("/api/demo").json()
    assert out["rows"] == 1000 and out["flagged"] > 0
    assert client.get("/api/session").json()["model"] is not None


def test_bad_inputs_are_400(client):
    wrong_cols = io.BytesIO(b"a,b\n1,2\n" * 1)
    r = client.post("/api/train", files={"file": ("x.csv", wrong_cols, "text/csv")})
    assert r.status_code == 400 and "expected columns" in r.json()["detail"]

    r = client.post("/api/train", files=csv_file(generate(rows=50)), data={"contamination": "0.9"})
    assert r.status_code == 400

    r = client.post("/api/train", files=csv_file(generate(rows=5)))
    assert r.status_code == 400  # too few rows to train on

    r = client.post("/api/train", files={"file": ("x.csv", b"\x00\x01\x02", "text/csv")})
    assert r.status_code == 400

    assert client.post("/api/demo?rows=5").status_code == 400


def test_sample_and_benchmark(client):
    sample = client.get("/api/sample.csv")
    assert sample.headers["content-type"].startswith("text/csv")
    assert sample.text.startswith("duration,")
    bench = client.get("/api/benchmark").json()
    assert len(bench["table"]) == 8  # 4 feature sets x 2 detectors
    assert client.get("/api/benchmark/roc.png").headers["content-type"] == "image/png"
