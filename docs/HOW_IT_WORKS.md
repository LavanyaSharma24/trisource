# How TriSource works

TriSource turns the project's multi-source DFIR analysis into an automated tool.
You give it host evidence; it detects the attack, maps it to MITRE ATT&CK,
reconstructs the timeline, and scores how much is recoverable from each source.

## Pipeline

| Stage | File / function | What happens |
|-------|-----------------|--------------|
| 1. Parse | `js/app.js` → `parseCSV` · `backend/evtx_parser.py` | CSV: auto-detects Timestamp / Image / CommandLine columns; quote-aware tokeniser → `{ts, img, cmd}`. EVTX: the Python backend decodes the binary log with python-evtx, keeps Sysmon Event ID 1, returns `{ts, image, commandline, record_id}`; `fromBackend()` maps it to the same shape. |
| 2. Detect | `rules.json` + `js/rules.js` → `detect` | Runs each event against an ordered regex rule set; first match wins; emits an alert with ATT&CK id, severity, rule name, and any caveat. |
| 3. Correlate | `js/data.js` → `CASE_SOURCES` | Joins each detected technique to the disk (prefetch, registry) and memory findings. |
| 4. Reconstruct & score | `js/app.js` → `renderTimeline`, `renderMatrix` | Orders events into a tactic-annotated timeline; scores a technique as *recovered* when ≥2 independent sources contain it. |

## The detection engine

Each rule mirrors a Sigma rule — a field condition that yields a technique and a
level. Example:

```json
{ "id": "T1112", "sev": "medium", "rule": "Registry Modification to Hidden File Extension",
  "pattern": "reg.*add.*(hidefileext|explorer\\\\advanced)", "flags": "i",
  "caveat": "Fired under mis-tag T1137 — a defender triaging by ATT&CK ID would mis-attribute it." }
```

Rules are stored in `rules.json` (regex as a string, since JSON has no regex literal) and
compiled by `compileRules()`, which rejects bad regexes, unknown severities and the
stateful `g`/`y` flags with a visible error instead of failing silently. When the page is
opened from disk, the identical copy embedded in `js/rules.js` is used
(`scripts/sync_rules.py` keeps it in step; a test fails if they drift).

This is the same model Hayabusa and Chainsaw used on the real Sysmon logs. Nine rules
cover the techniques executed in the study (Execution, Persistence, Discovery, Defense
Evasion); five more extend it beyond the demo case — T1003 credential dumping, T1562.001
Defender tampering, T1055 process injection, T1136 account creation and T1105 ingress
tool transfer. These are ordered first so, for example, `powershell Invoke-Mimikatz` is
reported as credential dumping rather than generic PowerShell. None of them match a
victim01 event, so the demo result is unchanged. T1055 carries a caveat: injection is
an API call, and its best evidence (Sysmon Event ID 8/10) is not ingested by Stage 1.
Complexity is `O(events × rules)`.

## Why multi-source correlation works

- **Common key.** Every artifact is mapped to an ATT&CK technique ID, giving a join
  key across sources that otherwise share no fields.
- **Independent failure.** Logs, disk and memory are captured and fail independently,
  so agreement across two is strong corroboration — and *disagreement* is a finding
  (T1112 leaves no registry trace yet appears in prefetch; T1047 appears nowhere
  because wmic was removed in Windows 11 25H2).
- **Coverage scoring** makes the thesis measurable: in the demo case every executed
  technique is recovered by ≥2 sources, and none by memory alone.

## Design: colour = danger

The UI is deliberately near-monochrome. Vivid red is reserved for high-severity
alerts and missing evidence (`N`), and amber for caveats, so the analyst's eye lands
on the red flags rather than on decoration.

## Report export

**⬇ Export report (PDF)** writes the alerts table, the coverage matrix as currently
displayed (source toggles included) and the exact pattern of every rule that fired.
`js/report.js` is a ~200-line PDF 1.4 writer using only built-in fonts (no library, works
from `file://`). Table text is Courier, so column wrapping is exact arithmetic. The same
colour rule applies on paper: red for HIGH and missing evidence, amber for caveats.
`matrixModel()` / `statsModel()` feed both the screen and the PDF, so they cannot disagree.

## Extending

Add a rule to `rules.json` (then `python3 scripts/sync_rules.py`); nothing else changes.
To analyse your own data, upload a CSV with `Timestamp, Image, CommandLine` columns, or a
Sysmon `.evtx` with the backend running (`./run.sh`). Other sources (Security 4688,
Sysmon EID 8/10, prefetch) would be new branches in `backend/evtx_parser.py`; the
browser pipeline does not change.
