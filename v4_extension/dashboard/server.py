"""
server.py — FastAPI backend for the MCP Security HTML dashboard.

Run:
    python -m uvicorn v4_extension.dashboard.server:app --host 0.0.0.0 --port 8501
    # or just:
    python v4_extension/dashboard/server.py

Endpoints
---------
GET  /                          Serves the standalone HTML dashboard with the
                                bootstrap script injected.
GET  /static/<path>             Static assets (bootstrap.js, widget.css).
GET  /api/health                {"ok": true, "ts": ...}
GET  /api/data                  The assembled MCP_DATA dict.
GET  /api/config                Configured target IPs.
POST /api/config                Body {"baseline_ip": "...", "hardened_ip": "...",
                                       "attacker_ip": "..."}. All optional.
POST /api/run/{scenario}/{arch} Launch a scenario. Returns {"job_id": "..."}.
GET  /api/jobs                  List of jobs (latest first).
GET  /api/jobs/{id}             One job's state (events + raw log tail).
POST /api/jobs/{id}/cancel      SIGTERM the subprocess.
GET  /api/stream/{job_id}       Server-Sent-Events stream of parsed events.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import data_builder, job_runner

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
_STANDALONE_HTML = _REPO_ROOT / "MCP Dashboard _standalone_.html"
_STATIC_DIR = _HERE / "static"

app = FastAPI(title="MCP Security Dashboard", version="1.0.0")

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ──────────────────────────────────────────────────────────────────────────
# HTML — inject our bootstrap into the standalone dashboard
# ──────────────────────────────────────────────────────────────────────────
# The standalone HTML is a self-contained bundle (≈2.6MB). We don't rewrite
# the bundle; instead we append our bootstrap <script> at the end of <body>
# AFTER the bundler script has unpacked everything. The bootstrap polls for
# window.MCP_DATA to appear, then overlays /api/data on top, and adds a
# floating "Live runs" widget.

_INJECT_MARKER = "<!-- MCP_DASHBOARD_BOOTSTRAP_INJECTED -->"


def _read_html_with_bootstrap() -> str:
    if not _STANDALONE_HTML.exists():
        return (
            "<h1>MCP Dashboard HTML missing</h1>"
            f"<p>Expected at: {_STANDALONE_HTML}</p>"
        )
    try:
        # Read in binary then decode — the file is large but bounded.
        html = _STANDALONE_HTML.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"<h1>Failed to read dashboard HTML</h1><pre>{e}</pre>"

    if _INJECT_MARKER in html:
        return html  # already injected

    bootstrap_tag = (
        f"\n{_INJECT_MARKER}\n"
        '<link rel="stylesheet" href="/static/widget.css">\n'
        '<script defer src="/static/bootstrap.js"></script>\n'
    )
    # Insert just before </body>
    if "</body>" in html:
        html = html.replace("</body>", bootstrap_tag + "</body>", 1)
    else:
        html += bootstrap_tag
    return html


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(content=_read_html_with_bootstrap())


@app.get("/dashboard.html", response_class=HTMLResponse)
def dashboard_alias() -> HTMLResponse:
    return HTMLResponse(content=_read_html_with_bootstrap())


# Favicon — return 204 to silence the noisy 404 in dev logs
@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


# ──────────────────────────────────────────────────────────────────────────
# API — health + data + config
# ──────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/data")
def api_data() -> dict:
    target_ips = job_runner.manager.get_target_ips()
    return data_builder.build_data(target_ips=target_ips)


class ConfigPayload(BaseModel):
    baseline_ip: Optional[str] = None
    hardened_ip: Optional[str] = None
    attacker_ip: Optional[str] = None


_IP_RX = re.compile(r"^[0-9a-zA-Z\.\-_:]+$")


def _validate_host(value: str, field: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    if not _IP_RX.match(value) or len(value) > 64:
        raise HTTPException(status_code=400, detail=f"invalid {field}: {value!r}")
    return value


@app.get("/api/config")
def get_config() -> dict:
    return {
        "baseline_ip": job_runner.manager.get_target_ip("baseline"),
        "hardened_ip": job_runner.manager.get_target_ip("hardened"),
        "attacker_ip": job_runner.manager.get_attacker_ip(),
    }


@app.post("/api/config")
def set_config(payload: ConfigPayload) -> dict:
    if payload.baseline_ip is not None:
        job_runner.manager.set_target_ip(
            "baseline", _validate_host(payload.baseline_ip, "baseline_ip"))
    if payload.hardened_ip is not None:
        job_runner.manager.set_target_ip(
            "hardened", _validate_host(payload.hardened_ip, "hardened_ip"))
    if payload.attacker_ip is not None:
        job_runner.manager.set_attacker_ip(
            _validate_host(payload.attacker_ip, "attacker_ip"))
    return get_config()


# ──────────────────────────────────────────────────────────────────────────
# API — jobs
# ──────────────────────────────────────────────────────────────────────────
@app.post("/api/run/{scenario}/{arch}")
def run_scenario(scenario: str, arch: str) -> JSONResponse:
    job, err = job_runner.manager.start(scenario, arch)
    payload = {"job_id": job.id, "scenario": job.scenario, "arch": job.arch}
    if err:
        payload["error"] = err
        return JSONResponse(status_code=400, content=payload)
    return JSONResponse(payload)


@app.get("/api/jobs")
def list_jobs() -> dict:
    jobs = job_runner.manager.list_jobs()
    # Newest first
    jobs.sort(key=lambda j: j.get("started_at") or "", reverse=True)
    return {"jobs": jobs}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    job = job_runner.manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} not found")
    return job.to_dict()


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> dict:
    ok = job_runner.manager.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="cancel failed or no such job")
    return {"cancelled": True}


@app.get("/api/stream/{job_id}")
def stream_events(job_id: str) -> StreamingResponse:
    if job_runner.manager.get(job_id) is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} not found")

    def gen():
        yield from job_runner.stream_job(job_id)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ──────────────────────────────────────────────────────────────────────────
# Allow running with `python v4_extension/dashboard/server.py`
# ──────────────────────────────────────────────────────────────────────────
def main():
    import argparse, uvicorn
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run(
        "v4_extension.dashboard.server:app",
        host=args.host, port=args.port, reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
