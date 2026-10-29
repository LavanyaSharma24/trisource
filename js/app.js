/* app.js — input handling, the analysis pipeline, and all rendering.
   Depends on data.js (case data), rules.js (detection engine), config.js
   (backend location) and report.js (PDF export). */

let MODE = "demo", EVENTS = [], ALERTS = [];
let INPUT_LABEL = "";                   // what was analysed — printed on the PDF report
const $ = (s) => document.querySelector(s);
// HTML-escape for text and attribute values (log content is attacker-controlled).
const esc = (s) => String(s||"").replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));

/* ---------- CSV parsing ---------- */
function splitCsvLine(l){ const out=[]; let cur="",q=false;
  for(const ch of l){ if(ch==='"'){q=!q} else if(ch===','&&!q){out.push(cur);cur=""} else cur+=ch } out.push(cur); return out; }
function parseCSV(text){
  const lines = text.trim().split(/\r?\n/); if(lines.length<2) return [];
  const hdr = lines[0].split(",").map(h=>h.trim().toLowerCase());
  const iT = hdr.findIndex(h=>/time|ts|date/.test(h));
  const iI = hdr.findIndex(h=>/image|process|proc/.test(h));
  const iC = hdr.findIndex(h=>/command|cmd/.test(h));
  return lines.slice(1).map(l=>{ const c=splitCsvLine(l);
    return { ts:(c[iT]||"").trim(), img:(c[iI]||"").trim(), cmd:(c[iC]||c[iI]||"").trim() }; })
    .filter(e=>e.cmd);
}

/* ---------- EVTX parsing (via the Python backend) ----------
   Browsers cannot decode the binary .evtx format, so the file is posted to
   backend/app.py, which returns {ts, image, commandline} events. fromBackend()
   maps them onto the {ts, img, cmd} shape parseCSV produces, so Stages 2-4 run
   exactly as they do for a CSV. */
function fromBackend(e){ return { ts:e.ts||"", img:e.image||"", cmd:(e.commandline||e.image||"").trim() }; }
function inputError(msg){ $("#inStatus").innerHTML = `<span class="err">${esc(msg)}</span>`; }
async function uploadEvtx(f){
  $("#inStatus").innerHTML = 'Parsing <span class="filechip">'+esc(f.name)+'</span> on the ingestion backend…';
  const fd = new FormData(); fd.append("file", f);
  let res, body;
  try { res = await fetch(API_BASE + "/api/parse/evtx", { method:"POST", body:fd }); }
  catch(err){
    return inputError(`Could not reach the ingestion backend at ${API_BASE || location.origin}. `
      + ".evtx files need it — start it with ./run.sh. (The demo case and CSV uploads work without it.)");
  }
  try { body = await res.json(); } catch(_) { body = {}; }
  if(!res.ok) return inputError(typeof body.detail === "string" ? body.detail
      : `Backend returned HTTP ${res.status} — is this page being served by the TriSource backend (./run.sh)?`);
  const ev = body.events.map(fromBackend).filter(e=>e.cmd);
  if(!ev.length) return inputError(`No Sysmon process-creation events (Event ID 1) in ${f.name} — `
      + `${body.total_records} records read, ${body.skipped_non_sysmon} non-Sysmon, ${body.skipped_other_event_ids} other Sysmon event IDs.`);
  INPUT_LABEL = `${f.name} (.evtx, ${ev.length} Sysmon process events of ${body.total_records} records, ${body.parser})`;
  $("#inStatus").innerHTML = 'Uploaded: <span class="filechip">'+esc(f.name)+' — '+ev.length+' Sysmon process events of '
    + body.total_records+' records (parsed by '+esc(body.parser)+')</span>'
    + (body.truncated ? ' <span class="flag-tag" title="Stopped at the backend\'s TRISOURCE_MAX_EVENTS limit">truncated</span>' : '')
    + (body.malformed_records ? ` <span class="flag-tag" title="Records python-evtx could not decode">${body.malformed_records} malformed</span>` : '')
    + (body.warnings||[]).map(w=>` <span class="flag-tag" title="${esc(w)}">integrity warning</span>`).join('');
  runPipeline(ev, "upload");
}

/* ---------- pipeline (animated) ---------- */
function runPipeline(events, mode){
  MODE = mode; EVENTS = events;
  document.querySelectorAll(".step").forEach(s=>s.className="step");
  const seq = ["parse","detect","correlate","timeline"];
  let i = 0;
  $("#results").style.display = "none";
  const iv = setInterval(()=>{
    if(i>0) document.querySelector('.step[data-s="'+seq[i-1]+'"]').className = "step done";
    if(i<seq.length){ document.querySelector('.step[data-s="'+seq[i]+'"]').className = "step active"; i++; }
    else { clearInterval(iv); finish(); }
  }, 420);
}
function finish(){
  ALERTS = detect(EVENTS);               // <-- the actual detection step
  renderStats(); renderAlerts(); renderTimeline(); renderMatrix();
  $("#results").style.display = "block";
  $("#results").scrollIntoView({ behavior:"smooth", block:"start" });
}

/* ---------- coverage scoring ---------- */
function on(src){ return document.querySelector(`#toggles input[data-src="${src}"]`).checked; }
function sourcesForDemo(t){
  const c = CASE_SOURCES[t];
  const det = on("detection") && ALERTS.some(a=>a.id===t);
  const pf  = on("prefetch") && c && c.prefetch==="Y";
  const rg  = on("registry") && c && c.registry==="Y";
  const mem = on("memory")   && c && c.memory==="Y";
  return [det,pf,rg,mem];
}

/* ---------- rendering ---------- */
/* statsModel(): the headline numbers as [label, value, flagRed] — shared by the
   stat tiles and the PDF report. */
function statsModel(){
  const techs = new Set(ALERTS.filter(a=>a.id!=="T1047").map(a=>a.id));
  let cov = "n/a";
  if(MODE==="demo") cov = MX_ORDER.filter(t=>sourcesForDemo(t).filter(Boolean).length>=2).length + " / 8";
  const s = [
    ["Events processed", EVENTS.length, false],
    ["Alerts generated", ALERTS.length, true],     // threats found -> flagged red
    ["ATT&CK techniques", techs.size, false],
    [MODE==="demo" ? "Recovered by ≥2 sources" : "Detected in logs", MODE==="demo" ? cov : techs.size, false]
  ];
  return s;
}
function renderStats(){
  $("#stats").innerHTML = statsModel().map(x=>`<div class="stat ${x[2]?'flag':''}"><div class="n">${x[1]}</div><div class="l">${x[0]}</div></div>`).join("");
}
function renderAlerts(){
  const tb = $("#alertRows");
  if(!ALERTS.length){ tb.innerHTML = `<tr><td colspan="6" class="empty">No detections — the input contained no events matching the rule set.</td></tr>`; return; }
  tb.innerHTML = ALERTS.map((a,idx)=>`<tr class="alert ${a.sev==='high'?'row-high':''}" data-i="${idx}">
    <td class="mono">${a.ts||"—"}</td>
    <td><b>${esc(a.id)}</b><div class="muted">${esc(a.name)}</div></td>
    <td>${esc(a.tactic)}</td>
    <td><span class="chip sev-${a.sev}">${a.sev==='high'?'▲ HIGH':a.sev}</span></td>
    <td>${esc(a.rule)}${a.caveat?' <span class="flag-tag" title="'+esc(a.caveat)+'">caveat</span>':''}${a.note?' <span class="flag-tag" title="'+esc(a.note)+'">note</span>':''}</td>
    <td><span class="mono">${esc(a.cmd.slice(0,52))}${a.cmd.length>52?'…':''}</span></td></tr>`).join("");
  tb.querySelectorAll("tr.alert").forEach(tr=>tr.onclick=()=>openModal(ALERTS[+tr.dataset.i]));
}
function renderTimeline(){
  const mapped = EVENTS.map(e=>({ e, a: ALERTS.find(x=>x.ts===e.ts && x.cmd===e.cmd) }));
  $("#tl").innerHTML = mapped.map(({e,a})=>{
    const cls = a ? (a.note ? "fail" : (a.sev==="high" ? "hi" : "")) : "benign";
    const label = a ? esc(`${a.id} — ${a.name}`) : "Benign / no rule match";
    const tac = a ? esc(a.note ? `${a.tactic} · FAILED (${a.note})` : a.tactic) : "—";
    return `<div class="ev ${cls}"><div class="t">${e.ts||""}</div>
      <div class="d ${a&&a.sev==='high'?'hi':''}">${label}</div>
      <div class="tac">${tac}</div>
      <div class="muted mono" style="margin-top:3px">${esc(e.cmd.slice(0,80))}</div></div>`;
  }).join("");
}
function cell(v){
  if(v==="Y")     return `<span class="cell c-y">Y</span>`;
  if(v==="N")     return `<span class="cell c-n">N</span>`;
  if(v==="amber") return `<span class="cell c-amber">Y</span>`;
  if(v==="off")   return `<span class="cell c-dash">·</span>`;
  return `<span class="cell c-dash">–</span>`;
}
/* matrixModel(): the coverage matrix as plain data — one row per technique with a
   cell state per source (Y / N / - / amber / off) plus the headline. Both the
   on-screen table and the PDF report are drawn from this, so they always agree. */
const MX_SOURCES = ["Endpoint logs", "Prefetch", "Registry", "Memory"];
function matrixModel(){
  if(MODE!=="demo"){
    const ids = [...new Set(ALERTS.map(a=>a.id))];
    return { demo:false, empty:"No techniques detected in uploaded log.",
      rows: ids.map(id=>({ id, name: TECHNIQUES[id] ? TECHNIQUES[id].name : ALERTS.find(a=>a.id===id).name,
        cells: [ALERTS.some(a=>a.id===id && a.caveat) ? "amber" : "Y", "off", "off", "off"] })),
      headline: "Uploaded log analysed for endpoint-log detection only (no disk/memory evidence supplied).", warn:false };
  }
  const rows = MX_ORDER.map(t=>{
    const c = CASE_SOURCES[t];
    const caveat = ALERTS.find(a=>a.id===t && a.caveat);
    return { id:t, name:TECHNIQUES[t].name, cells: [
      !on("detection") ? "off" : (ALERTS.some(a=>a.id===t) ? (caveat?"amber":"Y") : "N"),
      !on("prefetch")  ? "off" : c.prefetch,
      !on("registry")  ? "off" : c.registry,
      !on("memory")    ? "off" : c.memory ] };
  });
  const total = MX_ORDER.length;
  const n = MX_ORDER.filter(t=>sourcesForDemo(t).filter(Boolean).length>=2).length;
  return { demo:true, rows, recovered:n, total, warn: n<total,
    headline: `${n} of ${total} techniques recovered by at least two independent sources`
      + (n<total ? " — coverage has collapsed. Remove a source and evidence disappears." : " — every technique caught by ≥2 sources. Memory alone caught none.") };
}
function renderMatrix(){
  const head = $("#mxHead"), body = $("#mxBody"), m = matrixModel();
  head.innerHTML = `<tr><th>Technique</th>${MX_SOURCES.map(s=>`<th>${s}</th>`).join("")}</tr>`;
  if(!m.demo){
    body.innerHTML = m.rows.map(r=>`<tr><td>${r.id} ${esc(r.name)}</td>${r.cells.map(v=>`<td>${cell(v)}</td>`).join("")}</tr>`).join("")
      || `<tr><td colspan="5" class="empty">${m.empty}</td></tr>`;
  } else {
    body.innerHTML = m.rows.map(r=>`<tr data-t="${r.id}" class="alert"><td>${r.id} <span class="muted">${r.name}</span></td>${r.cells.map(v=>`<td>${cell(v)}</td>`).join("")}</tr>`).join("");
    body.querySelectorAll("tr.alert").forEach(tr=>tr.onclick=()=>{
      const t = tr.dataset.t; const a = ALERTS.find(x=>x.id===t) || { id:t, name:TECHNIQUES[t].name, tactic:TECHNIQUES[t].tactic }; openModal(a);
    });
  }
  const h = $("#mxHeadline");
  h.className = "headline" + (m.warn ? " warn" : "");
  h.textContent = m.headline;
}

/* ---------- drill-down modal ---------- */
function srcBlock(danger,title,body){
  return `<div class="src ${danger?'danger':''}"><div class="sh">${title}</div><div style="margin-top:6px;font-size:13px">${body}</div></div>`;
}
function openModal(a){
  $("#mTitle").textContent = `${a.id} — ${a.name}`;
  $("#mSub").textContent = `Tactic: ${a.tactic}`;
  const logEv = ALERTS.find(x=>x.id===a.id);
  const parts = [];
  parts.push(srcBlock(false, "Endpoint logs (Sysmon + rules)",
    logEv ? `Rule fired: <b>${esc(logEv.rule)}</b> (${logEv.sev})<br><span class="mono">${esc(logEv.cmd)}</span>`
            + (logEv.caveat?`<br><span class="muted">⚠ ${esc(logEv.caveat)}</span>`:"")
            + (logEv.note?`<br><span class="muted">ⓘ ${esc(logEv.note)}</span>`:"")
          : `<span class="muted">No log detection.</span>`));
  if(MODE==="demo" && CASE_SOURCES[a.id]){
    const c = CASE_SOURCES[a.id];
    parts.push(srcBlock(false, "Disk — Prefetch (execution)", esc(c.ev.prefetch)));
    parts.push(srcBlock(c.registry==="N", "Disk — Registry (persistence)", esc(c.ev.registry)));
    parts.push(srcBlock(true, "Physical memory", esc(c.ev.memory)));
  }
  $("#mSrcs").innerHTML = parts.join("");
  $("#modal").classList.add("show");
}

/* ---------- wiring ---------- */
$("#btnDemo").onclick = ()=>{
  $("#inStatus").innerHTML = 'Loaded demo case: <span class="filechip">victim01 — 10 events (2026-10-06, Atomic Red Team)</span>';
  INPUT_LABEL = "Demo case victim01 — 10 events (2026-10-06, Atomic Red Team)";
  runPipeline(DEMO_EVENTS.slice(), "demo");
};
$("#btnUpload").onclick = ()=>$("#file").click();
$("#file").onchange = (e)=>{
  const f = e.target.files[0]; if(!f) return;
  e.target.value = "";                  // allow re-selecting the same file
  if(/\.evtx$/i.test(f.name)) return uploadEvtx(f);   // binary log -> Python backend
  const r = new FileReader();           // CSV -> parsed in the browser (no backend)
  r.onload = ()=>{ const ev = parseCSV(r.result);
    $("#inStatus").innerHTML = 'Uploaded: <span class="filechip">'+esc(f.name)+' — '+ev.length+' events</span>';
    if(!ev.length){ alert("No events parsed. Ensure the CSV has Timestamp, Image and CommandLine columns."); return; }
    INPUT_LABEL = `${f.name} (.csv, ${ev.length} events)`;
    runPipeline(ev, "upload"); };
  r.readAsText(f);
};
$("#btnExport").onclick = ()=>exportReport();

/* Show which rule set is active, so every alert can be traced to its source. */
function renderRulesInfo(){
  const i = RULES_INFO;
  $("#rulesInfo").innerHTML = `Detection rules: <b>${i.count}</b> from <span class="mono">${esc(i.source)}</span>`
    + (i.reason ? ` <span class="muted">— ${esc(i.reason)}</span>` : "")
    + (i.errors.length ? ` <span class="flag-tag" title="${esc(i.errors.join("\n"))}">${i.errors.length} invalid rule${i.errors.length>1?"s":""} skipped</span>` : "");
}
renderRulesInfo();
loadRules().then(renderRulesInfo);
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("sel")); t.classList.add("sel");
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("show"));
  $("#view-"+t.dataset.v).classList.add("show");
});
document.querySelectorAll("#toggles input").forEach(c=>c.onchange=()=>{ renderMatrix(); renderStats(); });
$("#mClose").onclick = ()=>$("#modal").classList.remove("show");
$("#modal").onclick = (e)=>{ if(e.target.id==="modal") $("#modal").classList.remove("show"); };
