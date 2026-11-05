import os
import sys

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)
DASHBOARD = os.path.join(SRC, "dashboard.py")


def new_app():
    return AppTest.from_file(DASHBOARD, default_timeout=60).run()


def test_starts_with_helpful_empty_state():
    at = new_app()
    assert not at.exception
    assert any("Train & analyze" in i.value for i in at.info)


def test_demo_run_shows_metrics_and_labels():
    at = new_app()
    at.button[0].click().run()
    assert not at.exception
    labels = [m.label for m in at.metric]
    assert labels == ["Rows analyzed", "Flagged", "Flag rate", "Risk threshold"]
    assert at.metric[0].value == "1,000"
    assert any("attacks" in s.value for s in at.success)


def test_upload_mode_without_file_shows_error():
    at = new_app()
    at.sidebar.radio[0].set_value("Upload CSV").run()
    at.sidebar.button[0].click().run()
    assert not at.exception
    assert any("Upload a training CSV" in e.value for e in at.error)
