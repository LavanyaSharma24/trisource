/* config.js — where the optional Python ingestion backend (backend/app.py) lives.

   The backend is needed ONLY for .evtx uploads. The demo case and CSV uploads
   run entirely in the browser and never touch it.

   ""                      same origin — run.sh / Render serve this page from
                           the backend, and Vercel routes /api/* to it.
   "http://localhost:8000" used automatically when index.html is opened from disk.
   "https://…"             set this for a split deployment (static site on one
                           host, API on another; allow it via TRISOURCE_CORS_ORIGINS). */
const API_BASE = location.protocol === "file:" ? "http://localhost:8000" : "";
