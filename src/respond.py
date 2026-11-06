"""Tier 2: response orchestration.

What happens after the investigator confirms an attack, decided by policy, not by the
model (the model only suggests):

  alert          sent automatically to the account's alert webhook when risk >= thresholds.alert
  isolate_host   proposed, runs only after an analyst approves
  block_ip       proposed, runs only after an analyst approves

Containment goes through a connector. The default connector is a dry run that changes
nothing and says so; set RESPONSE_WEBHOOK_URL (and optionally RESPONSE_WEBHOOK_TOKEN) to
have approved actions POSTed to your own firewall, EDR or SOAR endpoint.

Hosts listed in the account's protected_hosts are never isolated or blocked.
Every step is recorded in the actions table with a history for audit.
"""

import os
import time

import features as F
import netguard
import store

PENDING = "pending_approval"
RECOMMENDED = "recommended"          # below the isolate threshold: shown, approvable, not pushed
APPROVABLE = (PENDING, RECOMMENDED)
CONTAINMENT = ("isolate_host", "block_ip")


# ---- connectors ------------------------------------------------------------

class DryRunConnector:
    name = "dry-run"

    def execute(self, kind, target, incident):
        verb = "isolate host" if kind == "isolate_host" else "block address"
        return {"ok": True, "dry_run": True,
                "message": f"DRY RUN: would {verb} {target}. No change was made. "
                           f"Set RESPONSE_WEBHOOK_URL to connect a real firewall or EDR."}


class WebhookConnector:
    """POSTs approved actions to an operator-configured endpoint (environment, not user input)."""

    name = "webhook"

    def __init__(self, url, token=None, sender=netguard.post_json):
        self.url, self.token, self._send = url, token, sender

    def execute(self, kind, target, incident):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else None
        try:
            status = self._send(self.url, {"action": kind, "target": target, "incident_id": incident["id"],
                                           "risk_score": incident["risk_score"]}, headers=headers)
        except netguard.WebhookError as exc:
            return {"ok": False, "message": str(exc)}
        ok = 200 <= status < 300
        return {"ok": ok, "dry_run": False, "message": f"Response endpoint answered HTTP {status}."}


def connector_from_env(environ=None, sender=netguard.post_json):
    env = os.environ if environ is None else environ
    url = env.get("RESPONSE_WEBHOOK_URL")
    if url and netguard.check_webhook_url(url) is None:
        return WebhookConnector(url, env.get("RESPONSE_WEBHOOK_TOKEN"), sender)
    return DryRunConnector()


# ---- policy ----------------------------------------------------------------

def _step(event, note=""):
    return {"at": round(time.time(), 1), "event": event, "note": note}


def _is_protected(config, target, incident):
    protected = {p.lower() for p in config.get("protected_hosts", [])}
    candidates = {str(target).lower()}
    if incident.get("host") and target == incident["host"]:
        candidates.add(incident["host"].lower())
    return bool(candidates & protected)


def alert_payload(incident, verdict):
    line = (f"[{verdict['severity'].upper()}] {verdict['title']} "
            f"(risk {incident['risk_score']:.0f}, {int(verdict['confidence'] * 100)}% confidence)")
    detail = f"Source {incident['src_ip']}. {verdict['summary']}".strip()
    return {"text": f"{line}\n{detail}", "content": f"{line}\n{detail}",
            "incident": {"id": incident["id"], "title": verdict["title"], "severity": verdict["severity"],
                         "verdict": verdict["verdict"], "risk_score": incident["risk_score"],
                         "source_ip": incident["src_ip"]}}


def respond(account_id, incident, verdict, config, sender=netguard.post_json):
    """Create (and for alerts, send) the actions for a freshly investigated incident."""
    if verdict["verdict"] != "true_positive":
        return []
    thresholds = config["thresholds"]
    risk = float(incident["risk_score"])
    existing = {(a["kind"], a["target"]) for a in store.list_actions(account_id, incident["id"])}
    created = []
    for rec in verdict["recommended_actions"]:
        kind, target = rec["kind"], rec["target"]
        if (kind, target) in existing:
            continue
        detail = {"reason": rec["reason"], "history": []}
        if kind == "alert":
            status = _send_alert(config, incident, verdict, risk, thresholds, detail, sender)
        elif _is_protected(config, target, incident):
            status = "refused"
            detail["history"].append(_step("refused", f"{target} is on the protected hosts list."))
        elif risk >= thresholds["isolate"]:
            status = PENDING
            detail["history"].append(_step("proposed", f"Risk {risk:.0f} is at or above the isolate threshold "
                                                       f"({thresholds['isolate']}). Waiting for an analyst."))
        else:
            status = RECOMMENDED
            detail["history"].append(_step("recommended", f"Risk {risk:.0f} is below the isolate threshold "
                                                          f"({thresholds['isolate']}); an analyst may still approve."))
        created.append(store.create_action(account_id, incident["id"], kind, target, status, detail))
        existing.add((kind, target))
    return created


def _send_alert(config, incident, verdict, risk, thresholds, detail, sender):
    if risk < thresholds["alert"]:
        detail["history"].append(_step("skipped", f"Risk {risk:.0f} is below the alert threshold ({thresholds['alert']})."))
        return "skipped"
    url = config.get("alert_webhook")
    if not url:
        detail["history"].append(_step("skipped", "No alert webhook is configured; the alert is shown in the console only."))
        return "skipped"
    try:
        status = sender(url, alert_payload(incident, verdict))
    except netguard.WebhookError as exc:
        detail["history"].append(_step("failed", str(exc)))
        return "failed"
    if 200 <= status < 300:
        detail["history"].append(_step("sent", f"Alert webhook answered HTTP {status}."))
        return "executed"
    detail["history"].append(_step("failed", f"Alert webhook answered HTTP {status}."))
    return "failed"


# ---- analyst decisions -----------------------------------------------------

class ActionError(Exception):
    """The requested decision isn't allowed (maps to HTTP 409/404)."""


def decide(account_id, action_id, approve, who, config, connector=None):
    """An analyst approves or rejects a proposed action. Returns the updated action."""
    action = store.get_action(account_id, action_id)
    if action is None:
        raise ActionError("No such action.")
    if action["status"] not in APPROVABLE:
        raise ActionError(f"This action is already {action['status'].replace('_', ' ')}.")
    incident = store.get_incident(account_id, action["incident_id"])
    detail = action["detail"]
    detail.setdefault("history", [])

    if not approve:
        detail["history"].append(_step("rejected", f"Rejected by {who}."))
        store.update_action(account_id, action_id, "rejected", detail)
        return store.get_action(account_id, action_id)

    # Re-check at execution time: settings may have changed since it was proposed.
    if _is_protected(config, action["target"], incident):
        detail["history"].append(_step("refused", f"{action['target']} is on the protected hosts list."))
        store.update_action(account_id, action_id, "refused", detail)
        raise ActionError("That target is on the protected hosts list and can't be isolated or blocked.")
    if action["kind"] == "block_ip" and F.is_internal(action["target"]):
        raise ActionError("Internal addresses can't be blocked from here.")

    connector = connector or connector_from_env()
    result = connector.execute(action["kind"], action["target"], incident)
    detail["result"] = result
    detail["connector"] = connector.name
    detail["history"].append(_step("approved", f"Approved by {who}."))
    detail["history"].append(_step("executed" if result["ok"] else "failed", result["message"]))
    store.update_action(account_id, action_id, "executed" if result["ok"] else "failed", detail)
    return store.get_action(account_id, action_id)
