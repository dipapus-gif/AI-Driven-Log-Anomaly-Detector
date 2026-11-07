"""Storage for the detection platform: events, models, ingest tokens, incidents,
response actions and per-account settings. Every query is scoped to an account id,
so accounts can never see each other's data."""

import hashlib
import json
import secrets
import time

import db
import netguard
from detector import ThreatDetector

MAX_EVENTS_PER_ACCOUNT = 50_000
MAX_TOKENS_PER_ACCOUNT = 10

DEFAULT_CONFIG = {
    "directory": {},
    "known_jobs": [],
    "protected_hosts": [],
    "thresholds": {"alert": 70, "isolate": 80},
    "alert_webhook": "",
}

_model_cache = {}  # account id -> (trained_at, detector)


# ---- settings --------------------------------------------------------------

def _is_str_list(value, limit, item_limit=100):
    return (
        isinstance(value, list) and len(value) <= limit
        and all(isinstance(v, str) and 0 < len(v) <= item_limit for v in value)
    )


def validate_config(cfg):
    """Check and normalize account settings; raises ValueError with a helpful message."""
    if not isinstance(cfg, dict):
        raise ValueError("Settings must be a JSON object.")
    unknown = set(cfg) - set(DEFAULT_CONFIG)
    if unknown:
        raise ValueError(f"Unknown setting(s): {', '.join(sorted(unknown))}.")
    out = {k: json.loads(json.dumps(v)) for k, v in DEFAULT_CONFIG.items()}

    directory = cfg.get("directory", {})
    if not isinstance(directory, dict) or len(directory) > 200:
        raise ValueError("directory must be an object with at most 200 users.")
    for name, info in directory.items():
        if not isinstance(name, str) or not isinstance(info, dict):
            raise ValueError("Each directory entry must map a username to an object.")
        groups = info.get("groups", [])
        if not _is_str_list(groups, 50):
            raise ValueError(f"groups for {name!r} must be a list of short strings.")
        out["directory"][name[:64]] = {"groups": groups, "service_account": bool(info.get("service_account", False))}

    jobs = cfg.get("known_jobs", [])
    if not isinstance(jobs, list) or len(jobs) > 50:
        raise ValueError("known_jobs must be a list of at most 50 jobs.")
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str) or not job["name"].strip():
            raise ValueError("Each known job needs a name.")
        hours = job.get("hours", [0, 24])
        if (not isinstance(hours, list) or len(hours) != 2
                or not all(isinstance(h, int) and 0 <= h <= 24 for h in hours)):
            raise ValueError(f"hours for {job['name']!r} must be [start, end] between 0 and 24 (UTC).")
        ports = job.get("dst_ports", [])
        if not (isinstance(ports, list) and len(ports) <= 50
                and all(isinstance(p, int) and 0 <= p <= 65535 for p in ports)):
            raise ValueError(f"dst_ports for {job['name']!r} must be a list of port numbers.")
        hosts = job.get("hosts", [])
        if not _is_str_list(hosts, 50):
            raise ValueError(f"hosts for {job['name']!r} must be a list of strings.")
        cap = job.get("max_bytes_per_window")
        if cap is not None and not (isinstance(cap, (int, float)) and cap > 0):
            raise ValueError(f"max_bytes_per_window for {job['name']!r} must be a positive number.")
        out["known_jobs"].append(
            {
                "name": job["name"].strip()[:100],
                "user": (str(job["user"])[:64] if job.get("user") else None),
                "hosts": hosts, "hours": hours, "dst_ports": ports,
                "internal_only": bool(job.get("internal_only", False)),
                "max_bytes_per_window": cap,
            }
        )

    protected = cfg.get("protected_hosts", [])
    if not _is_str_list(protected, 100):
        raise ValueError("protected_hosts must be a list of host names or addresses.")
    out["protected_hosts"] = protected

    webhook = cfg.get("alert_webhook", "")
    if webhook:
        problem = netguard.check_webhook_url(webhook)
        if problem:
            raise ValueError(problem)
    out["alert_webhook"] = webhook or ""

    thresholds = cfg.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be an object.")
    for key in ("alert", "isolate"):
        value = thresholds.get(key, out["thresholds"][key])
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
            raise ValueError(f"thresholds.{key} must be a number from 0 to 100.")
        out["thresholds"][key] = value
    if out["thresholds"]["alert"] > out["thresholds"]["isolate"]:
        raise ValueError("thresholds.alert can't be higher than thresholds.isolate.")
    return out


def get_config(account_id):
    row = db.run("SELECT config FROM account_config WHERE account_id = ?", (account_id,), fetch="one")
    if not row:
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        return validate_config(json.loads(row["config"]))
    except ValueError:
        return json.loads(json.dumps(DEFAULT_CONFIG))


def set_config(account_id, cfg):
    clean = validate_config(cfg)
    db.run(
        "INSERT INTO account_config (account_id, config) VALUES (?, ?) "
        "ON CONFLICT (account_id) DO UPDATE SET config = excluded.config",
        (account_id, json.dumps(clean)),
    )
    return clean


# ---- events ----------------------------------------------------------------

_EVENT_COLUMNS = "ts, src_ip, dst_ip, dst_port, proto, bytes, username, host, action, event_type, message"


def insert_events(account_id, events):
    db.run_many(
        f"INSERT INTO events (account_id, {_EVENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (account_id, e["ts"], e["src_ip"], e["dst_ip"], e["dst_port"], e["proto"], e["bytes"],
             e["username"], e["host"], e["action"], e["event_type"], e["message"])
            for e in events
        ],
    )


def prune_events(account_id, keep=MAX_EVENTS_PER_ACCOUNT):
    """Keep only the newest `keep` events."""
    total = db.run("SELECT COUNT(*) AS n FROM events WHERE account_id = ?", (account_id,), fetch="one")["n"]
    if total > keep:
        cutoff = db.run(
            "SELECT ts FROM events WHERE account_id = ? ORDER BY ts DESC LIMIT 1 OFFSET ?",
            (account_id, keep), fetch="one",
        )
        db.run("DELETE FROM events WHERE account_id = ? AND ts <= ?", (account_id, cutoff["ts"]))


def count_events(account_id):
    return int(db.run("SELECT COUNT(*) AS n FROM events WHERE account_id = ?", (account_id,), fetch="one")["n"])


def events_in(account_id, start, end, sources=None, limit=20_000):
    """Events with start <= ts < end, oldest first, optionally only from these sources."""
    sql = f"SELECT {_EVENT_COLUMNS} FROM events WHERE account_id = ? AND ts >= ? AND ts < ?"
    params = [account_id, start, end]
    if sources is not None:
        sources = list(sources)
        if not sources:
            return []
        sql += " AND src_ip IN (" + ",".join("?" * len(sources)) + ")"
        params += sources
    sql += " ORDER BY ts ASC LIMIT ?"
    return db.run(sql, params + [limit], fetch="all")


def recent_events(account_id, limit=50):
    """The newest events first (for showing that ingestion is working)."""
    return db.run(
        f"SELECT {_EVENT_COLUMNS} FROM events WHERE account_id = ? ORDER BY ts DESC LIMIT ?",
        (account_id, min(max(int(limit), 1), 200)), fetch="all",
    )


def all_events(account_id, limit=MAX_EVENTS_PER_ACCOUNT):
    return db.run(
        f"SELECT {_EVENT_COLUMNS} FROM events WHERE account_id = ? ORDER BY ts ASC LIMIT ?",
        (account_id, limit), fetch="all",
    )


def user_failures_since(account_id, username, since):
    return int(db.run(
        "SELECT COUNT(*) AS n FROM events WHERE account_id = ? AND username = ? AND action = 'failure' AND ts >= ?",
        (account_id, username, since), fetch="one")["n"])


# ---- trained model ---------------------------------------------------------

def save_model(account_id, detector: ThreatDetector):
    now = time.time()
    db.run(
        "INSERT INTO models (account_id, trained_at, n_windows, blob, meta) VALUES (?,?,?,?,?) "
        "ON CONFLICT (account_id) DO UPDATE SET trained_at = excluded.trained_at, "
        "n_windows = excluded.n_windows, blob = excluded.blob, meta = excluded.meta",
        (account_id, now, detector.n_windows, detector.to_bytes(),
         json.dumps({"threshold": detector.threshold, "contamination": detector.contamination})),
    )
    _model_cache[account_id] = (now, detector)


def model_info(account_id):
    row = db.run("SELECT trained_at, n_windows, meta FROM models WHERE account_id = ?", (account_id,), fetch="one")
    if not row:
        return None
    meta = json.loads(row["meta"] or "{}")
    return {"trained_at": row["trained_at"], "n_windows": row["n_windows"],
            "threshold": round(meta.get("threshold", 0), 2), "contamination": meta.get("contamination")}


def load_model(account_id):
    """The account's trained detector, or None. Cached per process."""
    head = db.run("SELECT trained_at FROM models WHERE account_id = ?", (account_id,), fetch="one")
    if not head:
        _model_cache.pop(account_id, None)
        return None
    cached = _model_cache.get(account_id)
    if cached and cached[0] == head["trained_at"]:
        return cached[1]
    row = db.run("SELECT blob FROM models WHERE account_id = ?", (account_id,), fetch="one")
    try:
        detector = ThreatDetector.from_bytes(bytes(row["blob"]))
    except Exception:
        return None  # incompatible or corrupt: the account needs to retrain
    _model_cache[account_id] = (head["trained_at"], detector)
    return detector


# ---- ingest tokens ---------------------------------------------------------

def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(account_id, label):
    count = db.run("SELECT COUNT(*) AS n FROM ingest_tokens WHERE account_id = ?", (account_id,), fetch="one")["n"]
    if count >= MAX_TOKENS_PER_ACCOUNT:
        raise ValueError(f"You can have at most {MAX_TOKENS_PER_ACCOUNT} tokens. Delete one first.")
    token = "lad_" + secrets.token_urlsafe(32)
    row = db.run(
        "INSERT INTO ingest_tokens (account_id, label, prefix, token_hash, created_at) "
        "VALUES (?,?,?,?,?) RETURNING id",
        (account_id, (label or "").strip()[:60] or "token", token[:8], _hash_token(token), time.time()),
        fetch="one",
    )
    return int(row["id"]), token


def list_tokens(account_id):
    return db.run(
        "SELECT id, label, prefix, created_at, last_used FROM ingest_tokens WHERE account_id = ? ORDER BY id",
        (account_id,), fetch="all",
    )


def delete_token(account_id, token_id):
    return db.run("DELETE FROM ingest_tokens WHERE account_id = ? AND id = ?", (account_id, token_id), fetch="count") > 0


def account_for_token(token):
    """The account id a token belongs to, or None."""
    if not token or not token.startswith("lad_") or len(token) > 200:
        return None
    row = db.run("SELECT id, account_id, last_used FROM ingest_tokens WHERE token_hash = ?",
                 (_hash_token(token),), fetch="one")
    if not row:
        return None
    now = time.time()
    if row["last_used"] is None or now - row["last_used"] > 60:
        db.run("UPDATE ingest_tokens SET last_used = ? WHERE id = ?", (now, row["id"]))
    return int(row["account_id"])


# ---- incidents -------------------------------------------------------------

_INCIDENT_LIST_COLUMNS = (
    "id, created_at, updated_at, src_ip, username, host, window_start, window_end, "
    "risk_score, status, severity, verdict, agent_mode"
)


def _loads(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def _incident_summary(row):
    verdict = _loads(row.pop("verdict")) or {}
    row["verdict"] = verdict.get("verdict")
    row["confidence"] = verdict.get("confidence")
    row["title"] = verdict.get("title")
    return row


def find_mergeable_incident(account_id, src_ip, window_start, gap):
    return db.run(
        "SELECT id, risk_score, window_end, status, features FROM incidents WHERE account_id = ? AND src_ip = ? "
        "AND window_end >= ? ORDER BY id DESC LIMIT 1",
        (account_id, src_ip, window_start - gap), fetch="one",
    )


def create_incident(account_id, meta, risk, evidence):
    now = time.time()
    row = db.run(
        "INSERT INTO incidents (account_id, created_at, updated_at, src_ip, username, host, window_start, "
        "window_end, risk_score, status, severity, features, dedupe_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id",
        (account_id, now, now, meta["src_ip"], meta["username"], meta["host"], meta["window_start"],
         meta["window_end"], float(risk), "new", None, json.dumps(evidence),
         f"{meta['src_ip']}:{meta['bucket']}"),
        fetch="one",
    )
    return int(row["id"])


def update_incident_evidence(account_id, incident_id, meta, risk, evidence):
    db.run(
        "UPDATE incidents SET updated_at = ?, risk_score = ?, window_end = ?, features = ? "
        "WHERE account_id = ? AND id = ?",
        (time.time(), float(risk), meta["window_end"], json.dumps(evidence), account_id, incident_id),
    )


def extend_incident(account_id, incident_id, risk, window_end):
    db.run(
        "UPDATE incidents SET updated_at = ?, risk_score = ?, window_end = ? WHERE account_id = ? AND id = ?",
        (time.time(), float(risk), window_end, account_id, incident_id),
    )


def save_investigation(account_id, incident_id, status, severity, verdict, report, trace, mode):
    db.run(
        "UPDATE incidents SET updated_at = ?, status = ?, severity = ?, verdict = ?, report = ?, "
        "trace = ?, agent_mode = ? WHERE account_id = ? AND id = ?",
        (time.time(), status, severity, json.dumps(verdict), json.dumps(report), json.dumps(trace),
         mode, account_id, incident_id),
    )


def set_status(account_id, incident_id, status):
    """Analyst override of an incident's status. Returns False if there is no such incident."""
    return db.run(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE account_id = ? AND id = ?",
        (status, time.time(), account_id, incident_id), fetch="count",
    ) > 0


def list_incidents(account_id, status=None, limit=100):
    sql = f"SELECT {_INCIDENT_LIST_COLUMNS} FROM incidents WHERE account_id = ?"
    params = [account_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY risk_score DESC, id DESC LIMIT ?"
    rows = db.run(sql, params + [min(max(int(limit), 1), 200)], fetch="all")
    return [_incident_summary(r) for r in rows]


def get_incident(account_id, incident_id):
    row = db.run("SELECT * FROM incidents WHERE account_id = ? AND id = ?", (account_id, incident_id), fetch="one")
    if not row:
        return None
    for key in ("features", "verdict", "report", "trace"):
        row[key] = _loads(row.get(key))
    row["evidence"] = row.pop("features")
    row.pop("dedupe_key", None)
    row["actions"] = list_actions(account_id, incident_id)
    return row


def new_incident_ids(account_id, limit=20):
    rows = db.run(
        "SELECT id FROM incidents WHERE account_id = ? AND status = 'new' ORDER BY risk_score DESC LIMIT ?",
        (account_id, limit), fetch="all",
    )
    return [int(r["id"]) for r in rows]


def count_recent_llm_investigations(account_id, since):
    return int(db.run(
        "SELECT COUNT(*) AS n FROM incidents WHERE account_id = ? AND agent_mode = 'llm' AND updated_at >= ?",
        (account_id, since), fetch="one")["n"])


def incident_counts(account_id):
    rows = db.run("SELECT status, COUNT(*) AS n FROM incidents WHERE account_id = ? GROUP BY status",
                  (account_id,), fetch="all")
    return {r["status"]: int(r["n"]) for r in rows}


# ---- response actions ------------------------------------------------------

def create_action(account_id, incident_id, kind, target, status, detail):
    row = db.run(
        "INSERT INTO actions (account_id, incident_id, created_at, kind, target, status, detail) "
        "VALUES (?,?,?,?,?,?,?) RETURNING id",
        (account_id, incident_id, time.time(), kind, target, status, json.dumps(detail)), fetch="one",
    )
    return int(row["id"])


def _action(row):
    row["detail"] = _loads(row.get("detail")) or {}
    return row


def list_actions(account_id, incident_id=None, status=None):
    sql = "SELECT id, incident_id, created_at, kind, target, status, detail FROM actions WHERE account_id = ?"
    params = [account_id]
    if incident_id is not None:
        sql += " AND incident_id = ?"
        params.append(incident_id)
    if status:
        sql += " AND status = ?"
        params.append(status)
    return [_action(r) for r in db.run(sql + " ORDER BY id", params, fetch="all")]


def get_action(account_id, action_id):
    row = db.run(
        "SELECT id, incident_id, created_at, kind, target, status, detail FROM actions WHERE account_id = ? AND id = ?",
        (account_id, action_id), fetch="one")
    return _action(row) if row else None


def update_action(account_id, action_id, status, detail):
    db.run("UPDATE actions SET status = ?, detail = ? WHERE account_id = ? AND id = ?",
           (status, json.dumps(detail), account_id, action_id))


# ---- housekeeping ----------------------------------------------------------

def delete_account_data(account_id):
    """Remove an account's events, incidents, actions and trained model (not its login)."""
    for table in ("events", "incidents", "actions", "models"):
        db.run(f"DELETE FROM {table} WHERE account_id = ?", (account_id,))
    _model_cache.pop(account_id, None)


# ---- dashboard statistics --------------------------------------------------

def dashboard_stats(account_id, now=None, hours=24):
    """Numbers for the overview charts. Time is anchored to the newest event, so a
    quiet system still shows its most recent activity instead of an empty chart."""
    hours = min(max(int(hours), 1), 168)
    newest = db.run("SELECT MAX(ts) AS t FROM events WHERE account_id = ?", (account_id,), fetch="one")["t"]
    end = float(newest) if newest else (now or time.time())
    end_hour = (int(end) // 3600 + 1) * 3600
    start = end_hour - hours * 3600
    buckets = [{"start": start + i * 3600, "events": 0, "failures": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
               for i in range(hours)]

    for e in events_in(account_id, start, end_hour, limit=50_000):
        b = buckets[min(int((e["ts"] - start) // 3600), hours - 1)]
        b["events"] += 1
        if e["action"] == "failure":
            b["failures"] += 1

    rows = db.run(
        "SELECT window_start, risk_score, status, severity, src_ip, host, report FROM incidents "
        "WHERE account_id = ? ORDER BY window_start DESC LIMIT 500", (account_id,), fetch="all")
    severity, sources, mitre, hosts = {}, {}, {}, {}
    for r in rows:
        sev = r["severity"] or "unrated"
        if start <= r["window_start"] < end_hour:
            buckets[min(int((r["window_start"] - start) // 3600), hours - 1)][sev if sev in ("critical", "high", "medium", "low") else "medium"] += 1
        if r["status"] == "dismissed":
            continue                      # false positives shouldn't dominate "top" lists
        severity[sev] = severity.get(sev, 0) + 1
        entry = sources.setdefault(r["src_ip"], {"ip": r["src_ip"], "incidents": 0, "max_risk": 0})
        entry["incidents"] += 1
        entry["max_risk"] = max(entry["max_risk"], round(r["risk_score"]))
        if r["host"]:
            hosts[r["host"]] = hosts.get(r["host"], 0) + 1
        report = _loads(r["report"]) or {}
        for technique in report.get("mitre", []):
            mitre[technique] = mitre.get(technique, 0) + 1

    def top(d, n=6):
        return sorted(d.items(), key=lambda kv: -kv[1])[:n]

    types = db.run(
        "SELECT event_type AS k, COUNT(*) AS n FROM events WHERE account_id = ? AND ts >= ? GROUP BY event_type "
        "ORDER BY n DESC LIMIT 6", (account_id, start), fetch="all")
    return {
        "hours": hours, "from": start, "to": end_hour, "buckets": buckets, "severity": severity,
        "top_sources": sorted(sources.values(), key=lambda x: (-x["max_risk"], -x["incidents"]))[:6],
        "mitre": [{"technique": k, "count": v} for k, v in top(mitre)],
        "hosts": [{"host": k, "count": v} for k, v in top(hosts)],
        "event_types": [{"type": r["k"] or "other", "count": r["n"]} for r in types],
    }
