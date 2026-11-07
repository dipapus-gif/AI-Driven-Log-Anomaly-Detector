"""HTTP API for the detection-and-response platform (mounted by api.py).

  POST /api/ingest                      send logs (token auth, for shippers and webhooks)
  /api/platform/...                     everything the dashboard uses (session auth)

All data is scoped to the signed-in account (or, for /api/ingest, the account that owns the token).
"""

import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import agent
import auth
import respond
import soc
import store

ANALYST_STATUSES = ("new", "confirmed", "dismissed", "needs_review", "resolved")
INGEST_LIMIT, INGEST_WINDOW = 120, 60          # requests per minute per account


class StatusBody(BaseModel):
    status: Literal["new", "confirmed", "dismissed", "needs_review", "resolved"]


class TokenBody(BaseModel):
    label: Optional[str] = ""


def _fail(exc):
    status = 409 if isinstance(exc, soc.NoModel) else 400
    return HTTPException(status, str(exc))


def _bearer(request: Request):
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("x-ingest-token", "").strip()


def create_router(require_user):
    router = APIRouter()

    # ---- ingestion (token auth) -------------------------------------------

    @router.post("/api/ingest")
    async def ingest(request: Request, auto: bool = True):
        """Accepts JSON, newline-delimited JSON, key=value or sshd syslog lines."""
        account_id = await run_in_threadpool(store.account_for_token, _bearer(request))
        if account_id is None:
            raise HTTPException(401, "Missing or invalid ingest token.")
        key = f"ingest:{account_id}"
        wait = auth.blocked_for(key, INGEST_LIMIT, INGEST_WINDOW)
        if wait:
            raise HTTPException(429, "Too many requests. Send larger batches less often.",
                                headers={"Retry-After": str(wait)})
        auth.record_hit(key, INGEST_WINDOW)

        body, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > soc.MAX_INGEST_BYTES:
                raise HTTPException(413, f"Request too large (limit {soc.MAX_INGEST_BYTES // 10**6} MB).")
            body.append(chunk)

        def work():
            result = soc.ingest(account_id, b"".join(body))
            if auto:
                result["processing"] = soc.process_ingested(account_id, result)
            return result

        try:
            return await run_in_threadpool(work)
        except soc.SocError as exc:
            raise _fail(exc)

    # ---- dashboard (session auth) -----------------------------------------

    @router.get("/api/platform/overview")
    def overview(user=Depends(require_user)):
        return soc.overview(user.id)

    @router.get("/api/platform/stats")
    def stats(hours: int = 24, user=Depends(require_user)):
        return store.dashboard_stats(user.id, hours=hours)

    @router.post("/api/platform/demo")
    def demo(reset: bool = False, user=Depends(require_user)):
        if store.count_events(user.id) and not reset:
            raise HTTPException(409, "This account already has data. Loading the demo replaces it. Confirm to continue.")
        return soc.load_demo(user.id)

    @router.post("/api/platform/reset")
    def reset(confirm: bool = False, user=Depends(require_user)):
        if not confirm:
            raise HTTPException(400, "Pass confirm=true to delete this account's events, incidents and model.")
        store.delete_account_data(user.id)
        return {"ok": True}

    @router.post("/api/platform/train")
    def train(before: Optional[float] = None, contamination: float = 0.03, user=Depends(require_user)):
        try:
            return soc.train(user.id, before=before, contamination=contamination)
        except soc.SocError as exc:
            raise _fail(exc)

    @router.post("/api/platform/run")
    def run(hours: float = 6, since: Optional[float] = None, user=Depends(require_user)):
        """Detect anomalies in recent events and investigate what it finds, within a time budget."""
        if not 0 < hours <= 24 * 30:
            raise HTTPException(400, "hours must be between 0 and 720.")
        try:
            return soc.process(user.id, since if since is not None else time.time() - hours * 3600)
        except soc.SocError as exc:
            raise _fail(exc)

    @router.get("/api/platform/incidents")
    def incidents(status: Optional[str] = None, user=Depends(require_user)):
        if status is not None and status not in ANALYST_STATUSES:
            raise HTTPException(400, "Unknown status.")
        return {"incidents": store.list_incidents(user.id, status), "counts": store.incident_counts(user.id)}

    @router.get("/api/platform/incidents/{incident_id}")
    def incident(incident_id: int, user=Depends(require_user)):
        row = store.get_incident(user.id, incident_id)
        if row is None:
            raise HTTPException(404, "No such incident.")
        return row

    @router.get("/api/platform/incidents/{incident_id}/report.md")
    def report(incident_id: int, user=Depends(require_user)):
        row = store.get_incident(user.id, incident_id)
        if row is None:
            raise HTTPException(404, "No such incident.")
        return PlainTextResponse(agent.report_markdown(row), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.md"'})

    @router.post("/api/platform/incidents/{incident_id}/status")
    def set_status(incident_id: int, body: StatusBody, user=Depends(require_user)):
        if not store.set_status(user.id, incident_id, body.status):
            raise HTTPException(404, "No such incident.")
        return {"ok": True, "status": body.status}

    @router.post("/api/platform/incidents/{incident_id}/investigate")
    def reinvestigate(incident_id: int, user=Depends(require_user)):
        if not store.set_status(user.id, incident_id, "new"):
            raise HTTPException(404, "No such incident.")
        return soc.investigate_pending(user.id, budget_seconds=40, max_incidents=5)

    def _decide(action_id, approve, user):
        try:
            return respond.decide(user.id, action_id, approve, user.name, store.get_config(user.id))
        except respond.ActionError as exc:
            raise HTTPException(409 if "No such" not in str(exc) else 404, str(exc))

    @router.post("/api/platform/actions/{action_id}/approve")
    def approve(action_id: int, user=Depends(require_user)):
        return _decide(action_id, True, user)

    @router.post("/api/platform/actions/{action_id}/reject")
    def reject(action_id: int, user=Depends(require_user)):
        return _decide(action_id, False, user)

    @router.get("/api/platform/actions")
    def actions(status: Optional[str] = None, user=Depends(require_user)):
        return {"actions": store.list_actions(user.id, status=status)}

    @router.get("/api/platform/config")
    def get_config(user=Depends(require_user)):
        return store.get_config(user.id)

    @router.put("/api/platform/config")
    def put_config(config: dict, user=Depends(require_user)):
        try:
            return store.set_config(user.id, config)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/api/platform/tokens")
    def tokens(user=Depends(require_user)):
        return {"tokens": store.list_tokens(user.id)}

    @router.post("/api/platform/tokens")
    def create_token(body: TokenBody, user=Depends(require_user)):
        try:
            token_id, token = store.create_token(user.id, body.label or "")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"id": token_id, "token": token, "note": "Copy this now. It is shown only once."}

    @router.delete("/api/platform/tokens/{token_id}")
    def delete_token(token_id: int, user=Depends(require_user)):
        if not store.delete_token(user.id, token_id):
            raise HTTPException(404, "No such token.")
        return {"ok": True}

    @router.get("/api/platform/events/recent")
    def recent(limit: int = 30, user=Depends(require_user)):
        return {"events": store.recent_events(user.id, limit), "total": store.count_events(user.id)}

    return router
