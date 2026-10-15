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


def create_app() -> FastAPI:
    app = FastAPI(title="Prowl")
    mgr = ScanManager()
    guard = [Depends(loopback_only)]
    audit: deque[dict] = deque(maxlen=500)  # in-memory action log (never holds secrets)

    def record(action: str, detail: str):
        entry = {"time": time.time(), "action": action, "detail": detail}
        audit.append(entry)
        log.info("audit: %s — %s", action, detail)

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

    @app.post("/api/scan", dependencies=guard)
    async def start_scan(body: dict):
        try:
            job = mgr.start(mode=body.get("mode", "discovery"), subnet=body.get("subnet"),
                            deep_opts=body.get("deep_opts"), demo=bool(body.get("demo")))
        except ValueError as e:
            raise HTTPException(400, str(e))
        return job.public()

    @app.get("/api/scan/{job_id}", dependencies=guard)
    def scan_status(job_id: str):
        job = mgr.get(job_id)
        if not job:
            raise HTTPException(404, "no such job")
        return job.public()

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
        return job.public() if job else JSONResponse(None)

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

    # Static UI last, so /api/* wins.
    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
