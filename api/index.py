"""Vercel entry point.

Vercel serves the static front-end (index.html, css/, js/, rules.json) from
its CDN and runs this file as a Python serverless function for /api/* (see the
rewrite in vercel.json). It simply re-exports the FastAPI app.

Note: Vercel limits a function's request body to 4.5 MB, so larger .evtx
uploads need the Render (or any long-running server) deployment instead.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # make `backend` importable

from backend.app import app  # noqa: E402,F401
