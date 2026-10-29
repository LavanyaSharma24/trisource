"""app.py — TriSource ingestion backend (FastAPI).

Replaces Stage 1 (Parse) for real Windows logs; Stages 2-4 (detect, correlate,
reconstruct) stay in the browser, unchanged. The backend only turns a Sysmon
.evtx into the JSON events the front-end already understands — it does no
detection itself, so every alert remains explainable from js/rules.js +
rules.json.

Endpoints
    GET  /api/health       liveness + parser version
    POST /api/parse/evtx   multipart upload (field "file") -> events JSON
    GET  /                 the existing static front-end (same origin, so the
                           page can fetch rules.json and call /api with no CORS)

Run locally:   ./run.sh            (or: uvicorn backend.app:app --port 8000)

Settings (environment variables)
    TRISOURCE_MAX_UPLOAD_MB   reject larger uploads           (default 50)
    TRISOURCE_MAX_EVENTS      cap events returned to browser  (default 20000)
    TRISOURCE_CORS_ORIGINS    comma-separated allowed origins (default "*")
"""
from __future__ import annotations

import os
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .evtx_parser import CorruptEvtxError, NotEvtxError, is_evtx, parse_evtx_file

MAX_UPLOAD_BYTES = int(float(os.getenv("TRISOURCE_MAX_UPLOAD_MB", "50")) * 1024 * 1024)
MAX_EVENTS = int(os.getenv("TRISOURCE_MAX_EVENTS", "20000"))
CORS_ORIGINS = [o.strip() for o in os.getenv("TRISOURCE_CORS_ORIGINS", "*").split(",") if o.strip()]

ROOT = Path(__file__).resolve().parent.parent  # repo root: index.html, css/, js/, ...

try:
    EVTX_VERSION = version("python-evtx")
except PackageNotFoundError:  # pragma: no cover - only when run from a source checkout
    EVTX_VERSION = "unknown"

app = FastAPI(title="TriSource ingestion backend",
              description="Sysmon .evtx -> {ts, image, commandline} events for the TriSource front-end.",
              version="1.0.0")

# CORS matters only for split deployments (static site on one host, API on
# another) or when index.html is opened from disk and calls localhost:8000.
# No cookies or credentials are used, so "*" leaks nothing; narrow it in
# production with TRISOURCE_CORS_ORIGINS=https://your-site.example.
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS,
                   allow_methods=["GET", "POST"], allow_headers=["*"])


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "parser": "python-evtx", "parser_version": EVTX_VERSION,
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024), "max_events": MAX_EVENTS}


# A plain `def` (not async): FastAPI runs it in a worker thread, so the
# CPU-bound parse never blocks the event loop.
@app.post("/api/parse/evtx")
def parse_evtx_upload(file: UploadFile = File(...)) -> dict:
    head = file.file.read(8)
    if not head:
        raise HTTPException(400, "Empty upload.")
    if not is_evtx(head):
        raise HTTPException(400, "Not a Windows event log (.evtx) — the file lacks the 'ElfFile' header. "
                                 "CSV logs are parsed in the browser; upload those directly.")

    # python-evtx memory-maps a real file, so spool the upload to a temp file,
    # enforcing the size cap while copying.
    fd, tmp_path = tempfile.mkstemp(suffix=".evtx")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(head)
            written = len(head)
            while chunk := file.file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
                out.write(chunk)
        try:
            result = parse_evtx_file(tmp_path, max_events=MAX_EVENTS)
        except NotEvtxError as exc:
            raise HTTPException(400, str(exc)) from exc
        except CorruptEvtxError as exc:
            raise HTTPException(422, f"Could not parse this .evtx file: {exc}") from exc
        except Exception as exc:  # corrupt header / chunk tables etc.
            raise HTTPException(422, f"Could not parse this .evtx file: {exc}") from exc
    finally:
        os.remove(tmp_path)

    return {
        "source": "evtx",
        "filename": file.filename,
        "parser": f"python-evtx {EVTX_VERSION}",
        **result.summary(),
        "events": result.events,  # [{ts, image, commandline, record_id}, ...]
    }


# ---- static front-end -------------------------------------------------------
# Serve exactly the files the page needs (not the whole repo, so backend source,
# tests and any local .env are never exposed). Directories are mounted only if
# present: on Vercel the static site is served by the CDN and this function
# bundle only handles /api/*.
for _dir in ("css", "js", "data"):
    if (ROOT / _dir).is_dir():
        app.mount(f"/{_dir}", StaticFiles(directory=ROOT / _dir), name=_dir)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(ROOT / "index.html")


@app.get("/rules.json", include_in_schema=False)
def rules_json() -> FileResponse:
    # no-store: an edited rules.json takes effect on the next page load.
    return FileResponse(ROOT / "rules.json", media_type="application/json",
                        headers={"Cache-Control": "no-store"})
