/* rules.js — the detection engine.

   Each rule is a signature: a regular expression matched against an event's
   command line, mapped to a MITRE ATT&CK technique and a severity. This mirrors
   how Sigma rules work (field match -> technique + level), which is what Hayabusa
   and Chainsaw applied to the real Sysmon logs in the project. The engine is
   intentionally small and readable so the logic is auditable in a demo.

   Where the rules come from:
     1. rules.json (repo root) is the source of truth — edit rules there, no code
        change needed. loadRules() fetches it when the page is served over http(s).
     2. BUILTIN_RULES below is a verbatim copy used when that fetch is impossible
        (index.html opened from disk: browsers block file:// fetches). Regenerate it
        after editing rules.json with:  python3 scripts/sync_rules.py
        (tests/test_rules.py fails if the two drift apart.)

   Rule fields: id, sev, rule, pattern (+flags) — the regex as a string, since JSON
   has no regex literal — and optional caveat / note / name / tactic. */

const BUILTIN_RULES = /* BEGIN rules.json */
[
  {
    "id": "T1003",
    "sev": "high",
    "rule": "Credential Dumping Tooling or LSASS Memory Access",
    "pattern": "(mimikatz|sekurlsa::|lsadump::|procdump(64)?(\\.exe)?\\s.*lsass|comsvcs(\\.dll)?.*(minidump|#\\+?24\\b)|\\breg(\\.exe)?\\s+save\\s+hklm\\\\(sam|system|security)\\b|ntdsutil.*\\bifm\\b)",
    "flags": "i"
  },
  {
    "id": "T1562.001",
    "sev": "high",
    "rule": "Microsoft Defender Disabled or Tampered",
    "pattern": "(set-mppreference.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|intrusionpreventionsystem)|add-mppreference.*-exclusion(path|process|extension)|disableantispyware|disablerealtimemonitoring|\\bsc(\\.exe)?\\s+(stop|config|delete)\\s+windefend|\\bnet1?(\\.exe)?\\s+stop\\s+windefend)",
    "flags": "i"
  },
  {
    "id": "T1055",
    "sev": "high",
    "rule": "Process Injection API or Tooling on Command Line",
    "pattern": "(invoke-(reflectivepeinjection|shellcode|dllinjection|psinject)|virtualallocex|writeprocessmemory|createremotethread|ntmapviewofsection|queueuserapc|mavinject(\\.exe)?.*\\/injectrunning)",
    "flags": "i",
    "caveat": "Command-line signature only - injection itself is an API call, best evidenced by Sysmon Event ID 8/10, which Stage 1 does not ingest."
  },
  {
    "id": "T1136",
    "sev": "medium",
    "rule": "New Local or Domain Account Created",
    "pattern": "(\\bnet1?(\\.exe)?\\s+user\\s+.*\\/add\\b|new-localuser|\\bdsadd(\\.exe)?\\s+user\\b|new-aduser)",
    "flags": "i"
  },
  {
    "id": "T1105",
    "sev": "medium",
    "rule": "Remote File Download via Built-in Utility",
    "pattern": "(certutil(\\.exe)?.*[-\\/](urlcache|verifyctl)|bitsadmin(\\.exe)?.*\\/(transfer|addfile)|start-bitstransfer|invoke-webrequest|\\biwr\\s.*https?:|downloadfile\\(|downloadstring\\(|\\bwget(\\.exe)?\\s.*https?:|\\bcurl(\\.exe)?\\s.*(\\s-o\\s|\\s--output\\s))",
    "flags": "i"
  },
  {
    "id": "T1059.001",
    "sev": "medium",
    "rule": "Suspicious Execution of PowerShell with Base64",
    "pattern": "powershell.*(-enc|-encodedcommand|frombase64|hidden|-nop|iex)",
    "flags": "i"
  },
  {
    "id": "T1053.005",
    "sev": "high",
    "rule": "Suspicious Command Patterns In Scheduled Task Creation",
    "pattern": "schtasks.*\\/create",
    "flags": "i"
  },
  {
    "id": "T1547.001",
    "sev": "medium",
    "rule": "Potential Persistence Attempt Via Run Keys Using Reg.EXE",
    "pattern": "reg.*add.*(currentversion\\\\run|\\\\run\\b)",
    "flags": "i"
  },
  {
    "id": "T1112",
    "sev": "medium",
    "rule": "Registry Modification to Hidden File Extension",
    "pattern": "reg.*add.*(hidefileext|explorer\\\\advanced)",
    "flags": "i",
    "caveat": "Fired under mis-tag T1137 — a defender triaging by ATT&CK ID would mis-attribute it."
  },
  {
    "id": "T1016",
    "sev": "low",
    "rule": "Suspicious Network Command",
    "pattern": "(ipconfig|netsh|arp\\s|nbtstat|net\\s+config|net1\\s)",
    "flags": "i"
  },
  {
    "id": "T1082",
    "sev": "low",
    "rule": "Suspicious Execution of Systeminfo",
    "pattern": "systeminfo",
    "flags": "i"
  },
  {
    "id": "T1057",
    "sev": "informational",
    "rule": "Suspicious Tasklist Discovery",
    "pattern": "tasklist",
    "flags": "i",
    "caveat": "Missed by default rule sets — caught only by a threat-hunting / custom Sigma rule."
  },
  {
    "id": "T1033",
    "sev": "low",
    "rule": "Local Accounts / Owner Discovery",
    "pattern": "(whoami|quser|qwinsta)",
    "flags": "i"
  },
  {
    "id": "T1047",
    "sev": "low",
    "rule": "WMI Reconnaissance",
    "pattern": "wmic",
    "flags": "i",
    "note": "wmic removed in Windows 11 25H2 — technique fails on this OS."
  }
]
/* END rules.json */;

const SEVERITIES = ["high", "medium", "low", "informational"];

/* compileRules(): validate rule objects and turn `pattern` into a RegExp.
   Invalid rules are skipped (never silently): each problem is returned so the UI
   can show it. Flags g / y are rejected because they make RegExp.test() stateful
   (lastIndex), which would make detection results depend on previous events. */
function compileRules(list) {
  const rules = [], errors = [];
  if (!Array.isArray(list)) return { rules, errors: ["rule list is not an array"] };
  list.forEach((r, i) => {
    const where = `rule #${i} (${(r && r.id) || "?"})`;
    if (!r || typeof r.id !== "string" || typeof r.rule !== "string" || typeof r.pattern !== "string")
      return errors.push(`${where}: needs string id, rule and pattern`);
    if (!SEVERITIES.includes(r.sev))
      return errors.push(`${where}: sev must be one of ${SEVERITIES.join(", ")}`);
    const flags = r.flags || "";
    if (!/^[imsu]*$/.test(flags))
      return errors.push(`${where}: flags may only contain i, m, s, u`);
    let re;
    try { re = new RegExp(r.pattern, flags); }
    catch (e) { return errors.push(`${where}: ${e.message}`); }
    rules.push({ re, id:r.id, sev:r.sev, rule:r.rule, caveat:r.caveat, note:r.note,
                 name:r.name, tactic:r.tactic });
  });
  return { rules, errors };
}

/* The active rule set. Starts as the built-in copy so detection works at once and
   offline; loadRules() swaps in rules.json when it can be fetched. */
let RULES = compileRules(BUILTIN_RULES).rules;
let RULES_INFO = { source: "built-in copy (js/rules.js)", count: RULES.length, errors: [], reason: "" };

/* loadRules(): prefer the external rules.json. On any failure (file://, 404, bad
   JSON, every rule invalid) keep the built-in set and record why. */
async function loadRules(url = "rules.json") {
  if (location.protocol === "file:") {
    RULES_INFO.reason = "page opened from disk — browsers block reading rules.json via file://";
    return RULES_INFO;
  }
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const doc = await res.json();
    const { rules, errors } = compileRules(doc.rules);
    if (!rules.length) throw new Error("no valid rules in file" + (errors.length ? ` (${errors[0]})` : ""));
    RULES = rules;
    RULES_INFO = { source: "rules.json", count: rules.length, errors, reason: "" };
  } catch (e) {
    RULES_INFO.reason = `could not load rules.json (${e.message})`;
  }
  return RULES_INFO;
}

/* detect(): run every event through the rule set.
   First matching rule wins per event (rules are ordered most-specific first). */
function detect(events) {
  const alerts = [];
  for (const e of events) {
    for (const r of RULES) {
      if (r.re.test(e.cmd)) {
        const T = TECHNIQUES[r.id] || { name: r.name || r.id, tactic: r.tactic || "—" };
        alerts.push({ ts:e.ts, id:r.id, name:T.name, tactic:T.tactic,
                      sev:r.sev, rule:r.rule, cmd:e.cmd, caveat:r.caveat, note:r.note,
                      pattern:r.re.source, flags:r.re.flags });
        break;
      }
    }
  }
  return alerts;
}
