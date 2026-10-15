"""Prowl's local web server: static UI + JSON API, bound to loopback only.

This is a single-operator, on-the-spot tool, not a shared service: it binds to 127.0.0.1,
and every request is additionally checked to come from loopback. There is no multi-user
auth model — if you can reach this port you are the operator on this machine.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import report
from .scan import ScanManager
from .scan import net

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

    # Static UI last, so /api/* wins.
    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
