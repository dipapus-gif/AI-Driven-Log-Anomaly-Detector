"""Agent, response, ingestion, tailer and platform API tests. No network, no real LLM."""

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import agent  # noqa: E402
import api  # noqa: E402
import auth  # noqa: E402
import intel  # noqa: E402
import netguard  # noqa: E402
import respond  # noqa: E402
import soc  # noqa: E402
import store  # noqa: E402
import tailer  # noqa: E402


# ---- helpers ---------------------------------------------------------------

@pytest.fixture()
def app(database, tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "x" * 48)
    for name in ("AUTH_DISABLED", "SIGNUP_ENABLED", "VERCEL", "ANTHROPIC_API_KEY",
                 "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "RESPONSE_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(api, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(api, "_models", type(api._models)())
    auth.reset_rate_limits()
    return api.app


def signup(app, name):
    c = TestClient(app)
    assert c.post("/api/signup", json={"username": name, "password": "correct horse battery"}).status_code == 200
    return c


@pytest.fixture()
def alice(app):
    return signup(app, "alice")


class ScriptedLLM:
    """Plays back a fixed list of replies, like the Messages API would."""
    model = "scripted"

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def create(self, system, messages, tools, force_tool=None):
        self.calls.append({"force_tool": force_tool, "n": len(messages)})
        return "tool_use", self.replies.pop(0)


def tool(name, **inp):
    return [{"type": "tool_use", "id": f"t{name}", "name": name, "input": inp}]


# ---- netguard --------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://example.com/hook", "https://127.0.0.1/x", "https://169.254.169.254/latest",
    "https://10.0.0.5/x", "https://example.com:8443/x", "https://user:pw@example.com/x",
    "https://localhost/x", "https://db.internal/x", "ftp://example.com/x",
])
def test_webhook_urls_that_must_be_refused(url):
    assert netguard.check_webhook_url(url)


def test_public_https_webhook_url_is_accepted():
    assert netguard.check_webhook_url("https://hooks.example.com/services/abc") is None


def test_hostname_resolving_to_private_address_is_refused():
    resolver = lambda host, port, type=None: [(2, 1, 6, "", ("10.1.2.3", 443))]  # noqa: E731
    with pytest.raises(netguard.WebhookError):
        netguard.post_json("https://rebind.example.com/x", {}, resolver=resolver)


# ---- agent -----------------------------------------------------------------

def make_incident(**over):
    base = {"id": 1, "src_ip": "203.0.113.50", "risk_score": 88.0, "title": "x", "status": "new",
            "window_start": 1_000_000.0, "window_end": 1_000_900.0,
            "evidence": {"meta": {"user": "bob"}, "features": {"failed_logins": 40, "fail_ratio": 1.0,
                                                               "event_count": 40, "distinct_ports": 1},
                         "explanation": [], "threshold": 60}}
    base.update(over)
    return base


def test_normalize_drops_actions_aimed_at_unrelated_hosts():
    case = agent.Case(1, make_incident(), store.DEFAULT_CONFIG, events=[])
    raw = {"verdict": "true_positive", "confidence": 0.9, "severity": "high", "title": "t", "summary": "s",
           "root_cause": "r", "recommended_actions": [
               {"kind": "block_ip", "target": "203.0.113.50", "reason": "attacker"},
               {"kind": "isolate_host", "target": "198.51.100.99", "reason": "injected by a log line"}]}
    out = agent.normalize_verdict(case, raw)
    assert [a["target"] for a in out["recommended_actions"]] == ["203.0.113.50"]


def test_guardrail_refuses_dismissal_without_job_match_or_confidence():
    case = agent.Case(1, make_incident(risk_score=70), store.DEFAULT_CONFIG, events=[])
    v = {"verdict": "false_positive", "confidence": 0.6, "severity": "low", "guardrail_notes": [],
         "recommended_actions": []}
    assert agent.apply_guardrails(case, v, {}, [])["verdict"] == "needs_review"


def test_guardrail_never_dismisses_when_intel_says_malicious():
    case = agent.Case(1, make_incident(risk_score=60), store.DEFAULT_CONFIG, events=[])
    v = {"verdict": "false_positive", "confidence": 0.99, "severity": "low", "guardrail_notes": [],
         "recommended_actions": []}
    out = agent.apply_guardrails(case, v, {"203.0.113.50": {"reputation": "malicious"}}, [])
    assert out["verdict"] == "needs_review"


def test_llm_loop_calls_tools_then_submits_verdict(database):
    case = agent.Case(1, make_incident(), store.DEFAULT_CONFIG, events=[])
    llm = ScriptedLLM([
        tool("lookup_ip_reputation", ip="203.0.113.50"),
        tool("submit_verdict", verdict="true_positive", confidence=0.95, severity="high", title="Brute force",
             summary="s", root_cause="r",
             recommended_actions=[{"kind": "block_ip", "target": "203.0.113.50", "reason": "bad"}]),
    ])
    out = agent.investigate(case, intel.IntelClient(environ={}), llm)
    assert out["mode"] == "llm" and out["verdict"]["verdict"] == "true_positive"
    assert [t["type"] for t in out["trace"]].count("tool") >= 1


def test_llm_failure_falls_back_to_rules(database):
    class Broken:
        def create(self, *a, **k):
            raise RuntimeError("boom")

    case = agent.Case(1, make_incident(), store.DEFAULT_CONFIG, events=[])
    out = agent.investigate(case, intel.IntelClient(environ={}), Broken())
    assert out["mode"] == "rules" and out["verdict"]["verdict"] in ("true_positive", "needs_review")
    assert any("rules investigator" in t.get("text", "") for t in out["trace"])


def test_llm_that_never_submits_is_forced_on_the_last_step(database):
    case = agent.Case(1, make_incident(), store.DEFAULT_CONFIG, events=[])
    replies = [tool("get_window_events")] * (agent.MAX_STEPS - 1) + [
        tool("submit_verdict", verdict="needs_review", confidence=0.5, severity="medium", title="t",
             summary="s", root_cause="r", recommended_actions=[])]
    llm = ScriptedLLM(replies)
    agent.investigate(case, intel.IntelClient(environ={}), llm)
    assert llm.calls[-1]["force_tool"] == "submit_verdict" and llm.calls[0]["force_tool"] is None


# ---- intel -----------------------------------------------------------------

def test_private_ips_are_never_sent_to_external_services():
    seen = []
    client = intel.IntelClient(http=lambda *a, **k: seen.append(a) or {}, environ={"ABUSEIPDB_API_KEY": "k"})
    assert client.check_ip("10.0.0.7")["scope"] == "internal"
    assert seen == []


# ---- end to end through the HTTP API --------------------------------------

def test_platform_requires_login(app):
    c = TestClient(app)
    assert c.get("/api/platform/overview").status_code == 401
    assert c.get("/api/platform/incidents").status_code == 401


def test_demo_detects_attacks_and_gates_isolation(alice):
    since = alice.post("/api/platform/demo").json()["since"]
    first = alice.post(f"/api/platform/run?since={since}").json()
    while first.get("remaining"):
        first = alice.post(f"/api/platform/run?since={since}").json()
    incidents = alice.get("/api/platform/incidents").json()["incidents"]
    assert any(i["status"] == "confirmed" for i in incidents)
    actions = alice.get("/api/platform/actions").json()["actions"]
    isolating = [a for a in actions if a["kind"] == "isolate_host"]
    assert all(a["status"] in ("pending_approval", "recommended", "refused") for a in isolating)
    pending = [a for a in actions if a["status"] == "pending_approval"]
    if pending:
        r = alice.post(f"/api/platform/actions/{pending[0]['id']}/approve").json()
        assert r["status"] == "executed" and r["detail"]["connector"] == "dry-run"
        assert alice.post(f"/api/platform/actions/{pending[0]['id']}/approve").status_code == 409
    report = alice.get(f"/api/platform/incidents/{incidents[0]['id']}/report.md")
    assert report.status_code == 200 and "Incident" in report.text


def test_demo_requires_confirmation_to_replace_data(alice):
    alice.post("/api/platform/demo")
    assert alice.post("/api/platform/demo").status_code == 409
    assert alice.post("/api/platform/demo?reset=true").status_code == 200


def test_accounts_cannot_see_each_other(app):
    a, b = signup(app, "alice"), signup(app, "bobby")
    since = a.post("/api/platform/demo").json()["since"]
    a.post(f"/api/platform/run?since={since}")
    iid = a.get("/api/platform/incidents").json()["incidents"][0]["id"]
    assert b.get("/api/platform/incidents").json()["incidents"] == []
    assert b.get(f"/api/platform/incidents/{iid}").status_code == 404
    assert b.post(f"/api/platform/incidents/{iid}/status", json={"status": "resolved"}).status_code == 404
    assert b.get("/api/platform/events/recent").json()["total"] == 0


def test_protected_host_is_never_isolated(alice):
    since = alice.post("/api/platform/demo").json()["since"]
    cfg = alice.get("/api/platform/config").json()
    cfg["protected_hosts"] = ["203.0.113.0/24", "198.51.100.0/24"]
    assert alice.put("/api/platform/config", json=cfg).status_code == 200
    alice.post(f"/api/platform/run?since={since}")
    actions = alice.get("/api/platform/actions").json()["actions"]
    assert not [a for a in actions if a["kind"] in ("isolate_host", "block_ip") and a["status"] == "executed"]


def test_config_rejects_private_webhook(alice):
    cfg = alice.get("/api/platform/config").json()
    cfg["alert_webhook"] = "https://169.254.169.254/latest"
    assert alice.put("/api/platform/config", json=cfg).status_code == 400


# ---- ingest ---------------------------------------------------------------

def test_ingest_needs_a_valid_token_and_is_per_account(app):
    a, b = signup(app, "alice"), signup(app, "bobby")
    anon = TestClient(app)
    line = json.dumps({"ts": time.time(), "src_ip": "10.0.0.5", "user": "alice", "event": "login_ok"})
    assert anon.post("/api/ingest", content=line).status_code == 401
    assert anon.post("/api/ingest", content=line, headers={"Authorization": "Bearer nope"}).status_code == 401
    token = a.post("/api/platform/tokens", json={"label": "t"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    r = anon.post("/api/ingest", content=line, headers=h)
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert a.get("/api/platform/events/recent").json()["total"] == 1
    assert b.get("/api/platform/events/recent").json()["total"] == 0
    tid = a.get("/api/platform/tokens").json()["tokens"][0]["id"]
    assert "token" not in a.get("/api/platform/tokens").json()["tokens"][0]
    assert a.delete(f"/api/platform/tokens/{tid}").status_code == 200
    assert anon.post("/api/ingest", content=line, headers=h).status_code == 401


def test_ingest_size_cap_and_rate_limit(alice, monkeypatch):
    token = alice.post("/api/platform/tokens", json={}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    anon = TestClient(api.app)
    with monkeypatch.context() as m:
        m.setattr(soc, "MAX_INGEST_BYTES", 100)
        assert anon.post("/api/ingest", content=b"x" * 500, headers=h).status_code == 413
    import platform_api
    monkeypatch.setattr(platform_api, "INGEST_LIMIT", 2)
    codes = [anon.post("/api/ingest", content=b"", headers=h).status_code for _ in range(4)]
    assert 429 in codes


# ---- tailer ---------------------------------------------------------------

def test_follower_handles_partial_lines_rotation_and_truncation(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("old\n")
    f = tailer.FileFollower(str(p))
    assert f.read_lines() == []                       # starts at the end
    with open(p, "a") as fh:
        fh.write("one\ntw")
    assert f.read_lines() == ["one"]                  # partial line is held back
    with open(p, "a") as fh:
        fh.write("o\n")
    assert f.read_lines() == ["two"]
    p.rename(tmp_path / "a.log.1")
    p.write_text("fresh\n")
    assert f.read_lines() == ["fresh"]                # rotation
    p.write_text("")
    f.read_lines()
    p.write_text("again\n")
    assert f.read_lines() == ["again"]                # truncation


def test_tailer_ships_lines_and_retries(tmp_path):
    got = []

    class H(BaseHTTPRequestHandler):
        fail = [1]

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.fail:
                self.fail.pop()
                self.send_response(503)
                self.end_headers()
                return
            got.append((self.headers["Authorization"], body.decode()))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    p = tmp_path / "x.log"
    p.write_text("a\nb\n")
    url = f"http://127.0.0.1:{srv.server_port}/api/ingest"
    src = tailer.FileFollower(str(p), from_start=True).read_lines
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 3:          # retry delay, interval wait, then (after the successful retry) interval wait
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        tailer.run([src], url, "tok", sleep=sleep, log=lambda m: None)
    srv.shutdown()
    assert got == [("Bearer tok", "a\nb")]


def test_tailer_stops_on_bad_token():
    import urllib.error

    def opener(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "no", {}, None)

    with pytest.raises(tailer.FatalError):
        tailer.send_batch("http://x/api/ingest", "bad", ["a"], opener=opener)


def test_tailer_refuses_plain_http_to_remote_hosts():
    with pytest.raises(SystemExit):
        tailer.main(["--url", "http://example.com/api/ingest", "-"])
