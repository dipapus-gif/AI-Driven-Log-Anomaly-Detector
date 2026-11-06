"""The detection-and-response loop.

    logs -> ingest -> detect (ML) -> investigate (agent) -> respond (policy)

Each step works on one account's data. Everything that can take a while takes a time
budget, so a request on a serverless host never runs past its limit; whatever isn't
finished stays queued and the next call picks it up.
"""

import os
import time

import agent
import db
import features as F
import intel as intel_module
import netguard
import respond
import simulate
import store
from detector import ThreatDetector

MAX_INGEST_BYTES = 5_000_000
MAX_EVENTS_PER_REQUEST = 20_000
MERGE_GAP = F.WINDOW_SECONDS          # windows from one source within a window of each other form one incident
LLM_MAX_PER_HOUR = int(os.environ.get("AGENT_MAX_PER_HOUR", "20"))


class SocError(Exception):
    """A problem the caller can fix; the message is safe to show."""


class NoModel(SocError):
    pass


# ---- agent and intel (created once per process) ----------------------------

_llm = {"key": None, "client": None}
_intel = {"client": None}


def get_llm():
    key = (os.environ.get("ANTHROPIC_API_KEY"), os.environ.get("AGENT_MODEL"))
    if _llm["key"] != key:
        _llm["key"], _llm["client"] = key, agent.llm_from_env()
    return _llm["client"]


def get_intel():
    if _intel["client"] is None:
        _intel["client"] = intel_module.IntelClient()
    return _intel["client"]


# ---- ingest ----------------------------------------------------------------

def ingest(account_id, body):
    """Parse and store a batch of logs (JSON, NDJSON, key=value or sshd syslog lines)."""
    if len(body) > MAX_INGEST_BYTES:
        raise SocError(f"Request too large (limit {MAX_INGEST_BYTES // 10**6} MB). Send smaller batches.")
    events, rejected = F.parse_payload(body)
    if len(events) > MAX_EVENTS_PER_REQUEST:
        raise SocError(f"Too many events in one request (limit {MAX_EVENTS_PER_REQUEST:,}).")
    if events:
        store.insert_events(account_id, events)
        store.prune_events(account_id)
    return {"accepted": len(events), "rejected": rejected,
            "first_ts": min((e["ts"] for e in events), default=None),
            "last_ts": max((e["ts"] for e in events), default=None)}


# ---- training --------------------------------------------------------------

def _train_on(account_id, events, contamination=0.03):
    if not events:
        raise SocError("There are no events to learn from yet. Send some logs first.")
    baseline = F.Baseline.from_events(events)
    windows = F.build_windows(events, baseline)
    try:
        detector = ThreatDetector(contamination=contamination).fit([f for _, f, _ in windows], baseline)
    except ValueError as exc:
        raise SocError(str(exc)) from exc
    store.save_model(account_id, detector)
    return {"events": len(events), "windows": len(windows), **store.model_info(account_id)}


def train(account_id, before=None, contamination=0.03):
    """Learn this account's normal behavior from its stored events (optionally only those before a time)."""
    if not 0.001 <= contamination <= 0.2:
        raise SocError("Contamination must be between 0.001 and 0.2.")
    events = store.all_events(account_id)
    if before is not None:
        events = [e for e in events if e["ts"] < before]
    return _train_on(account_id, events, contamination)


# ---- detection -------------------------------------------------------------

def detect(account_id, since, until=None):
    """Score every window of events in [since, until) and open or extend incidents for flagged ones."""
    detector = store.load_model(account_id)
    if detector is None:
        raise NoModel("No baseline yet. Train one from your logs (or load the demo) first.")
    since = F.bucket(since) * F.WINDOW_SECONDS
    until = until or time.time() + 3600
    events = store.events_in(account_id, since, until)
    windows = F.build_windows(events, detector.baseline)
    summary = {"windows": len(windows), "flagged": 0, "created": 0, "merged": 0}
    if not windows:
        return summary
    risk, flagged = detector.score([f for _, f, _ in windows])
    for (meta, feats, _), r, is_flagged in zip(windows, risk, flagged):
        if not is_flagged:
            continue
        summary["flagged"] += 1
        evidence = {"meta": meta, "features": {k: round(v, 3) for k, v in feats.items()},
                    "explanation": detector.explain(feats), "threshold": round(detector.threshold, 2)}
        existing = store.find_mergeable_incident(account_id, meta["src_ip"], meta["window_start"], MERGE_GAP)
        if existing:
            top = max(float(r), existing["risk_score"])
            if r > existing["risk_score"]:
                store.update_incident_evidence(account_id, existing["id"], meta, top, evidence)
            else:
                store.extend_incident(account_id, existing["id"], top, max(meta["window_end"], existing["window_end"]))
            summary["merged"] += 1
        else:
            try:
                store.create_incident(account_id, meta, float(r), evidence)
                summary["created"] += 1
            except db.Conflict:
                summary["merged"] += 1
    return summary


# ---- investigation and response -------------------------------------------

def investigate_pending(account_id, budget_seconds=40, max_incidents=20, llm=None, intel=None,
                        sender=netguard.post_json, now=None):
    """Investigate new incidents (highest risk first) until the time budget runs out."""
    started = time.time()
    now = now or started
    llm = llm if llm is not None else get_llm()
    intel = intel or get_intel()
    config = store.get_config(account_id)
    done = []
    for incident_id in store.new_incident_ids(account_id, limit=max_incidents):
        if time.time() - started > budget_seconds:
            break
        incident = store.get_incident(account_id, incident_id)
        use_llm = llm is not None and store.count_recent_llm_investigations(account_id, now - 3600) < LLM_MAX_PER_HOUR
        try:
            case = agent.Case(account_id, incident, config)
            result = agent.investigate(case, intel, llm if use_llm else None)
            report = agent.build_report(case, result)
        except db.StoreUnavailable:
            raise
        except Exception as exc:  # never let one bad incident block the queue
            verdict = {"verdict": "needs_review", "confidence": 0.0, "severity": "medium",
                       "title": f"Investigation failed for {incident['src_ip']}", "summary": "",
                       "root_cause": "", "recommended_actions": []}
            store.save_investigation(account_id, incident_id, "needs_review", "medium", verdict,
                                     None, [{"type": "note", "text": f"Investigation error: {type(exc).__name__}"}], "rules")
            done.append({"id": incident_id, "status": "needs_review"})
            continue
        verdict = result["verdict"]
        store.save_investigation(account_id, incident_id, agent.STATUS_FOR_VERDICT[verdict["verdict"]],
                                 verdict["severity"], verdict, report, result["trace"], result["mode"])
        fresh = store.get_incident(account_id, incident_id)
        respond.respond(account_id, fresh, verdict, config, sender)
        done.append({"id": incident_id, "status": agent.STATUS_FOR_VERDICT[verdict["verdict"]], "mode": result["mode"]})
    return {"investigated": done, "remaining": store.incident_counts(account_id).get("new", 0)}


def process(account_id, since, budget_seconds=40, **kwargs):
    """Detect and investigate in one call."""
    found = detect(account_id, since)
    return {"detection": found, **investigate_pending(account_id, budget_seconds, **kwargs)}


def process_ingested(account_id, ingested, budget_seconds=20, **kwargs):
    """After an ingest: if a baseline exists, run the loop over just the windows the batch touched."""
    if not ingested["accepted"] or store.model_info(account_id) is None:
        return None
    return process(account_id, ingested["first_ts"], budget_seconds, max_incidents=3, **kwargs)


# ---- demo and housekeeping -------------------------------------------------

def load_demo(account_id, now=None):
    """Replace this account's data with simulated traffic and train on the 'normal' part only."""
    sim = simulate.simulate(now=now)
    store.delete_account_data(account_id)
    store.set_config(account_id, sim["config"])
    store.insert_events(account_id, sim["history"] + sim["live"])
    model = _train_on(account_id, sim["history"])
    live_start = min(e["ts"] for e in sim["live"])
    return {"history_events": len(sim["history"]), "live_events": len(sim["live"]),
            "since": F.bucket(live_start) * F.WINDOW_SECONDS, "model": model}


def overview(account_id):
    llm = get_llm()
    counts = store.incident_counts(account_id)
    config = store.get_config(account_id)
    return {
        "events": store.count_events(account_id),
        "model": store.model_info(account_id),
        "incidents": counts,
        "pending_approvals": len([a for a in store.list_actions(account_id) if a["status"] == respond.PENDING]),
        "agent": {"mode": "llm" if llm else "rules", "model": getattr(llm, "model", None),
                  "max_llm_per_hour": LLM_MAX_PER_HOUR},
        "intel": {"mode": get_intel().mode, "providers": get_intel().providers()},
        "alert_webhook_configured": bool(config.get("alert_webhook")),
        "connector": respond.connector_from_env().name,
        "thresholds": config["thresholds"],
    }
