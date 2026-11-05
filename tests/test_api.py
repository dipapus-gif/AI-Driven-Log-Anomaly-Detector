import io
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402
from generate_data import generate  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Keep tests away from any real saved model and start with none loaded.
    monkeypatch.setattr(api, "MODEL_PATH", tmp_path / "model.pkl")
    monkeypatch.setitem(api._state, "engine", None)
    monkeypatch.setitem(api._state, "trained_rows", None)
    return TestClient(api.app)


def csv_file(df):
    return {"file": ("logs.csv", df.to_csv(index=False).encode(), "text/csv")}


def test_index_and_health(client):
    assert "Log Anomaly Detector" in client.get("/").text
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["model_loaded"] is False


def test_analyze_without_model_is_409(client):
    r = client.post("/api/analyze", files=csv_file(generate(rows=100)))
    assert r.status_code == 409


def test_train_then_analyze_catches_attacks(client):
    df = generate(rows=600, attack_fraction=0.05)
    r = client.post("/api/train", files=csv_file(df), data={"contamination": "0.05"})
    assert r.status_code == 200
    assert r.json()["trained_rows"] == 600
    assert client.get("/api/health").json()["model_loaded"] is True

    out = client.post("/api/analyze", files=csv_file(df)).json()
    assert out["rows"] == 600
    assert sum(out["histogram"]) == 600
    assert out["label_metrics"]["recall"] >= 0.9
    risks = [row["risk_score"] for row in out["flagged_rows"]]
    assert risks == sorted(risks, reverse=True)


def test_demo_trains_and_returns_results(client):
    out = client.post("/api/demo").json()
    assert out["rows"] == 1000 and out["flagged"] > 0
    assert client.get("/api/health").json()["model_loaded"] is True


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
