"""Prowl's local web server: static UI + JSON API, bound to loopback only.

This is a single-operator, on-the-spot tool, not a shared service: it binds to 127.0.0.1,
and every request is additionally checked to come from loopback. There is no multi-user
auth model — if you can reach this port you are the operator on this machine.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import launch as launch_mod
from . import report
from . import store as store_mod
from .scan import ScanManager
from .scan import net

log = logging.getLogger("prowl.server")

WEB = Path(__file__).resolve().parent / "web"


def _is_loopback(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1") or host.startswith("127.")


def loopback_only(request: Request):
    if not _is_loopback(request):
        raise HTTPException(403, "Prowl only accepts requests from the local machine.")


def create_app(db_path=None) -> FastAPI:
    app = FastAPI(title="Prowl")
    guard = [Depends(loopback_only)]
    audit: deque[dict] = deque(maxlen=1000)  # in-memory action log (never holds secrets)
    authz = {"ok": False}                    # per-session authorization for the default-cred check
    store = store_mod.Store(db_path or store_mod.default_db_path())
    saved_ids: set[str] = set()
    diffs: dict[str, dict] = {}

    def record(action: str, detail: str):
        entry = {"time": time.time(), "action": action, "detail": detail}
        audit.append(entry)
        log.info("audit: %s — %s", action, detail)

    mgr = ScanManager(audit=record)

    def finalize(job):
        """On first sight of a finished real scan, persist it and diff vs the previous baseline."""
        if job.demo or job.status != "done" or not job.result or job.id in saved_ids:
            return diffs.get(job.id)
        saved_ids.add(job.id)
        cur = job.result.as_dict()
        try:
            prev = store.previous(cur["subnet"], cur["started"])
            store.save(cur)
            if prev:
                diffs[job.id] = store_mod.diff(cur, prev)
                record("baseline-diff", f"{cur['subnet']}: +{len(diffs[job.id]['new'])} "
                       f"-{len(diffs[job.id]['gone'])} ~{len(diffs[job.id]['changed'])}")
        except Exception:
            log.exception("failed to persist/diff scan")
        return diffs.get(job.id)

    def known_hosts() -> set[str]:
        ips: set[str] = set()
        for job in mgr.jobs.values():
            if job.result:
                ips.update(h.ip for h in job.result.hosts)
        return ips

    @app.get("/api/local")
    def local(_: None = Depends(loopback_only)):
        return {"networks": [{k: v for k, v in n.items() if k != "network"} for n in net.local_networks()],
                "default": (net.default_subnet() or {}).get("cidr"),
                "gateway": net.default_gateway()}

    @app.get("/api/authorize", dependencies=guard)
    def authorize_status():
        return {"authorized": authz["ok"]}

    @app.post("/api/authorize", dependencies=guard)
    def authorize(body: dict):
        if not body.get("ack"):
            raise HTTPException(400, "acknowledgement required")
        authz["ok"] = True
        record("authorize", "operator acknowledged authorization for default-credential checks")
        return {"authorized": True}

    @app.post("/api/scan", dependencies=guard)
    async def start_scan(body: dict):
        deep_opts = body.get("deep_opts") or {}
        if deep_opts.get("check_default_creds") and not authz["ok"]:
            raise HTTPException(403, "authorization_required")
        try:
            job = mgr.start(mode=body.get("mode", "discovery"), subnet=body.get("subnet"),
                            deep_opts=deep_opts, demo=bool(body.get("demo")))
        except ValueError as e:
            raise HTTPException(400, str(e))
        return job.public()

    @app.get("/api/scan/{job_id}", dependencies=guard)
    def scan_status(job_id: str):
        job = mgr.get(job_id)
        if not job:
            raise HTTPException(404, "no such job")
        d = job.public()
        diff = finalize(job)
        if diff:
            d["diff"] = diff
        return d

    @app.post("/api/scan/{job_id}/cancel", dependencies=guard)
    def scan_cancel(job_id: str):
        job = mgr.get(job_id)
        if not job:
            raise HTTPException(404, "no such job")
        job.cancel()
        return job.public()

    @app.get("/api/latest", dependencies=guard)
    def latest():
        job = mgr.latest()
        if not job:
            return JSONResponse(None)
        d = job.public()
        diff = finalize(job)
        if diff:
            d["diff"] = diff
        return d

    @app.get("/api/history", dependencies=guard)
    def history(subnet: str | None = None, limit: int = 50):
        return {"scans": store.list(subnet, min(limit, 500))}

    @app.get("/api/history/{scan_id}", dependencies=guard)
    def history_get(scan_id: int):
        result = store.get(scan_id)
        if not result:
            raise HTTPException(404, "no such scan")
        return result

    @app.get("/api/report.{fmt}", dependencies=guard)
    def get_report(fmt: str, job: str | None = None):
        j = mgr.get(job) if job else mgr.latest()
        if not j or not j.result:
            raise HTTPException(404, "no completed scan")
        if fmt == "json":
            return PlainTextResponse(report.to_json(j.result), media_type="application/json")
        if fmt == "csv":
            return PlainTextResponse(report.to_csv(j.result), media_type="text/csv",
                                     headers={"Content-Disposition": 'attachment; filename="prowl-report.csv"'})
        if fmt == "html":
            return HTMLResponse(report.to_html(j.result))
        raise HTTPException(400, "format must be json, csv, or html")

    @app.post("/api/launch", dependencies=guard)
    def launch(body: dict):
        proto = (body.get("proto") or "").lower()
        ip = body.get("ip") or ""
        port = body.get("port") or launch_mod.DEFAULT_PORTS.get(proto)
        username = (body.get("username") or "").strip() or None
        password = body.get("password") or None  # used, never stored or logged
        if ip not in known_hosts():
            raise HTTPException(400, "target is not a host from a completed scan")
        try:
            plan = launch_mod.build(proto, ip, int(port), username, password)
        except launch_mod.LaunchError as e:
            raise HTTPException(400, str(e))
        except (TypeError, ValueError):
            raise HTTPException(400, "invalid launch request")
        record("launch", f"{proto} {ip}:{port} user={username or '-'}")
        result = launch_mod.execute(plan)  # result.command never contains the password
        return {"ok": True, **result}

    @app.get("/api/audit", dependencies=guard)
    def get_audit(limit: int = 200):
        items = list(audit)[-min(limit, 500):]
        return {"events": list(reversed(items))}

    @app.get("/api/oui/status", dependencies=guard)
    def oui_status():
        from .scan import oui
        return {**oui.status(), "default_url": oui.DEFAULT_OUI_URL}

    @app.post("/api/oui/update", dependencies=guard)
    def oui_update(body: dict):
        from .scan import oui
        try:
            if body.get("text"):
                n = oui.update_from_text(body["text"], "uploaded file")
                src = "uploaded file"
            else:
                src = body.get("url") or oui.DEFAULT_OUI_URL
                n = oui.update_from_url(body.get("url") or None)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except OSError as e:
            raise HTTPException(502, f"could not fetch the database: {e}")
        record("oui-update", f"loaded {n} prefixes from {src}")
        return {"ok": True, "prefixes": n, "source": src}

    # Static UI last, so /api/* wins.
    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
