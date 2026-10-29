# TriSource — Multi-Source DFIR Analyzer

A working prototype that automates the multi-source forensic analysis from our DFIR
project. Feed it host evidence and it **detects the attack, maps each step to MITRE
ATT&CK, reconstructs the timeline, and scores how much is recoverable from endpoint
logs vs. disk vs. memory** — live, with visible input and output.

## Run it

**Demo + CSV only — no install, works offline:**

```
open index.html        # macOS
# or just double-click index.html
```

**Everything, including real Sysmon `.evtx` logs — one command** (Python 3.10+):

```
./run.sh               # → http://localhost:8000
```

`run.sh` creates `.venv/`, installs `requirements.txt` the first time (later runs skip it
unless the file changes) and starts the FastAPI backend, which also serves the page. Set
`PORT=…` / `HOST=0.0.0.0` to change where it listens.

Manual equivalent (any OS, including Windows):

```
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
.venv/bin/uvicorn backend.app:app --port 8000
```

The backend is optional: if it is not running, the demo case, CSV upload and PDF export
still work; only `.evtx` upload shows a "backend not reachable" message.

## Live demo (≈3 min)

1. **Load demo case: victim01** — the pipeline animates, then the dashboard fills
   (10 events → 9 alerts → 8 ATT&CK techniques).
2. **Detection alerts** — high-severity rows pulse red. Click any alert for the
   evidence across all sources.
3. **Coverage matrix** — untick **Endpoint logs**: coverage collapses from 8/8 to 3/8
   ("if the attacker wipes the logs, only disk forensics survives").
4. **Upload an event log** → `data/sample_host_log.csv` — the same engine detects
   attacks in a brand-new log, live. Add your own malicious line to prove it.
5. **Upload a real Sysmon `.evtx`** (with `./run.sh` running) — e.g. a file from
   [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). The
   comsvcs `MiniDump` sample fires the T1003 credential-dumping rule as **HIGH**.
6. **⬇ Export report (PDF)** — the alerts, the coverage matrix exactly as shown
   (including any source you untoggled) and the exact patterns of every rule that fired.

## Structure

```
index.html          UI shell + "How it works" section
css/styles.css      near-monochrome theme (colour reserved for red flags)
rules.json          detection rules (14 Sigma-style) — edit here, no code change
js/config.js        where the optional backend lives (same origin by default)
js/data.js          ATT&CK reference + real victim01 case data
js/rules.js         detection rule engine + offline copy of rules.json
js/report.js        dependency-free PDF export
js/app.js           parse → detect → correlate → reconstruct → render
backend/app.py      FastAPI: POST /api/parse/evtx, GET /api/health, serves the page
backend/evtx_parser.py     python-evtx → {ts, image, commandline, record_id}
api/index.py        Vercel serverless entry (re-exports backend.app)
scripts/sync_rules.py      refresh js/rules.js's offline copy from rules.json
tests/              pytest (backend, rules) + node --test (front-end, demo invariants)
data/sample_host_log.csv   second log for the live-upload demo
docs/HOW_IT_WORKS.md       extended algorithm write-up
run.sh · requirements.txt · render.yaml · vercel.json
```

## Detection rules

Rules live in [`rules.json`](rules.json). Each has `id` (ATT&CK), `sev`
(`high|medium|low|informational`), `rule` (name), `pattern` (a JavaScript regex as a
string, matched against the command line), `flags` (`i`, `m`, `s`, `u`), and optional
`caveat` / `note` (amber tags) and `name` / `tactic` (for technique IDs not in
`js/data.js`). **Order matters: the first matching rule wins per event**, so specific /
high-severity rules come first.

| Added rule | ATT&CK | Severity | Catches (examples) |
|---|---|---|---|
| Credential dumping | T1003 | high | mimikatz, `procdump … lsass`, `comsvcs.dll MiniDump`, `reg save HKLM\SAM`, `ntdsutil ifm` |
| Defender disabled | T1562.001 | high | `Set-MpPreference -Disable…`, `Add-MpPreference -Exclusion…`, `DisableAntiSpyware`, `sc stop WinDefend` |
| Process injection | T1055 | high | `Invoke-ReflectivePEInjection`, `mavinject /INJECTRUNNING`, injection API names |
| Account creation | T1136 | medium | `net user … /add`, `New-LocalUser`, `dsadd user` |
| Ingress tool transfer | T1105 | medium | `certutil -urlcache`, `bitsadmin /transfer`, `iwr`, `DownloadFile(`, `curl -o` |

The page shows which rule set is active under the input panel. Served over http it
reads `rules.json` live (an edit takes effect on reload); opened from disk, browsers
block that read, so it uses the identical copy embedded in `js/rules.js`. After editing
`rules.json`, refresh that copy:

```
python3 scripts/sync_rules.py          # --check verifies without writing
```

Invalid rules (bad regex, unknown severity, stateful `g`/`y` flags) are skipped and
listed in the UI; they never fail silently.

## Ingestion backend (`.evtx`)

`POST /api/parse/evtx` (multipart field `file`) → keeps Sysmon **Process Create (Event
ID 1)** records and returns:

```json
{ "source": "evtx", "filename": "cred.evtx", "parser": "python-evtx 0.8.1",
  "total_records": 6, "sysmon_process_events": 2, "skipped_non_sysmon": 0,
  "skipped_other_event_ids": 4, "malformed_records": 0, "truncated": false, "warnings": [],
  "events": [{ "ts": "2019-08-30 12:54:08.331", "image": "C:\\Windows\\System32\\rundll32.exe",
               "commandline": "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump …",
               "record_id": 32154 }, …] }
```

`ts` is Sysmon's `UtcTime` verbatim; `record_id` is the `EventRecordID`, so every alert
traces back to its source record. Skipped records are counted, not hidden. A file with
a bad header is rejected (`422`); a checksum mismatch or "dirty" log (typical of a copy
taken from a live host) is parsed but flagged as an integrity warning. The backend does
**no detection**: Stages 2–4 still run in the browser on the returned events.

| Env var | Default | |
|---|---|---|
| `TRISOURCE_MAX_UPLOAD_MB` | 50 | reject larger uploads (`413`) |
| `TRISOURCE_MAX_EVENTS` | 20000 | cap events returned (response says `truncated`) |
| `TRISOURCE_CORS_ORIGINS` | `*` | comma-separated; only matters for split deployments |

## Deploy

- **Render** (recommended: front-end + API, 50 MB uploads): New → Blueprint → this repo.
  `render.yaml` runs `uvicorn backend.app:app`; health check `/api/health`.
- **Vercel**: import the repo. The static site is served from the CDN and `api/index.py`
  runs the backend as a Python function (`vercel.json` routes `/api/*`). Vercel caps
  request bodies at **4.5 MB**, so use Render for larger logs.
- **Static only** (GitHub Pages, Netlify, …): works as today; `.evtx` upload needs a
  backend. Set `API_BASE` in `js/config.js` to its URL and add the site to
  `TRISOURCE_CORS_ORIGINS`.

## Tests

```
pip install -r requirements-dev.txt && pytest     # backend + rules.json validity/sync
node --test tests/                                 # front-end: demo invariants, new rules, PDF
TRISOURCE_TEST_EVTX=path/to/sysmon.evtx pytest     # + end-to-end on a real log
```

The front-end tests load the real `js/*.js` files and assert the demo still yields
10 events → 9 alerts → 8 techniques → 8/8 coverage, so a rule edit that changes the demo
fails loudly.

## How it works (short)

Parse host events → run a regex rule engine mapping each event to an ATT&CK technique
and severity → correlate each technique across logs/prefetch/registry/memory →
reconstruct the timeline and score multi-source coverage. Full detail in
[`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md).

The `victim01` case data is the real evidence from the project; the upload path runs
the same engine on any event CSV, or on a Sysmon `.evtx` parsed by the Python backend.

## Team

Lavanya Sharma · Ayushi · Mansi Sharma · Alina Noorain — MIT Bengaluru.
