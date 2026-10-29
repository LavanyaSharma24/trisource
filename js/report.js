/* report.js — "Export report": the alerts + coverage matrix as a downloadable PDF.

   Why hand-written instead of a PDF library: the tool must keep working offline
   from file://, and a ~200-line writer is something a reviewer can actually audit.
   It emits plain PDF 1.4 using only the built-in Type 1 fonts (Helvetica, Courier),
   so no font embedding is needed and every byte is readable text.

   Layout: A4 landscape. Table text is set in Courier, a monospace font (every
   glyph is 0.6 x the font size), so column wrapping is exact arithmetic with no
   font metrics. Same rule as the UI: the page is near-monochrome and colour marks
   red flags only (red = high severity / missing evidence, amber = caveat).

   buildReportPdf(data) is pure (data in, bytes out) so it can be tested in Node;
   exportReport() collects the current screen state and triggers the download. */

const PDF_W = 842, PDF_H = 595, PDF_M = 36;          // A4 landscape, points
const INK = [0.11, 0.13, 0.16], MUTED = [0.45, 0.49, 0.54], HAIR = [0.82, 0.84, 0.87];
const RED = [0.894, 0.267, 0.227], AMBER = [0.66, 0.45, 0.07], WHITE = [1, 1, 1];

/* Built-in PDF fonts cover Latin-1 only; to keep byte offsets == string offsets
   we go further and emit pure ASCII, transliterating the UI's typographic marks. */
function pdfAscii(s){
  return String(s ?? "").replace(/[\t\r\n]+/g, " ")
    .replace(/[–—]/g, "-").replace(/≥/g, ">=").replace(/→/g, "->")
    .replace(/…/g, "...").replace(/[‘’]/g, "'").replace(/[“”]/g, '"')
    .replace(/[·▲]/g, "-").replace(/[^\x20-\x7e]/g, "?");
}
const pdfStr = (s) => pdfAscii(s).replace(/[\\()]/g, c => "\\" + c);   // PDF string escaping
const rgb = (c) => c.map(v => v.toFixed(3)).join(" ");

/* wrap(): split text into lines of at most n characters, breaking at a space
   when one falls in the second half of the line, otherwise mid-token (long paths
   and base64 have no spaces). Lines beyond maxLines are summarised, not dropped
   silently. */
function wrap(text, n, maxLines = Infinity){
  let s = pdfAscii(text).trim(); const out = [];
  while (s.length > n) {
    let cut = s.lastIndexOf(" ", n); if (cut < n / 2) cut = n;
    out.push(s.slice(0, cut).trimEnd()); s = s.slice(cut).trimStart();
  }
  out.push(s);
  if (out.length > maxLines) {
    const hidden = out.slice(maxLines - 1).join(" ").length;
    out.length = maxLines - 1; out.push(`[... ${hidden} more chars - full text in the UI]`);
  }
  return out;
}

/* A minimal page-description builder: collects drawing operators per page. */
class PdfDoc {
  constructor(){ this.pages = []; this.addPage(); }
  addPage(){ this.ops = []; this.pages.push(this.ops); this.y = PDF_H - PDF_M; }
  text(x, y, s, size = 8, font = "F3", color = INK){
    this.ops.push(`${rgb(color)} rg BT /${font} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td (${pdfStr(s)}) Tj ET`);
  }
  rect(x, y, w, h, color){ this.ops.push(`${rgb(color)} rg ${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`); }
  hline(y, color = HAIR, w = 0.5){
    this.ops.push(`${rgb(color)} RG ${w} w ${PDF_M} ${y.toFixed(2)} m ${PDF_W - PDF_M} ${y.toFixed(2)} l S`);
  }
  /* Start a new page if the next h points will not fit above the footer. */
  ensure(h, onNewPage){ if (this.y - h < PDF_M + 18) { this.addPage(); if (onNewPage) onNewPage(); } }

  /* Serialise to PDF bytes: objects, cross-reference table, trailer. */
  build(title, date){
    const objs = [], add = (body) => objs.push(body);          // returns object number
    const catalog = add(null), pagesRef = add(null);
    const fonts = { F1:"Helvetica", F2:"Helvetica-Bold", F3:"Courier", F4:"Courier-Bold" };
    const fontDict = Object.entries(fonts).map(([k, base]) =>
      `/${k} ${add(`<< /Type /Font /Subtype /Type1 /BaseFont /${base} /Encoding /WinAnsiEncoding >>`)} 0 R`).join(" ");
    const kids = this.pages.map(ops => {
      const stream = ops.join("\n");
      const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
      return add(`<< /Type /Page /Parent ${pagesRef} 0 R /MediaBox [0 0 ${PDF_W} ${PDF_H}] `
               + `/Resources << /Font << ${fontDict} >> >> /Contents ${content} 0 R >>`);
    });
    objs[catalog - 1]  = `<< /Type /Catalog /Pages ${pagesRef} 0 R >>`;
    objs[pagesRef - 1] = `<< /Type /Pages /Kids [${kids.map(k => k + " 0 R").join(" ")}] /Count ${kids.length} >>`;
    const info = add(`<< /Title (${pdfStr(title)}) /Producer (TriSource) /CreationDate (D:${date}Z) >>`);

    let out = "%PDF-1.4\n", offsets = [];
    objs.forEach((body, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${body}\nendobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`
         + offsets.map(o => String(o).padStart(10, "0") + " 00000 n \n").join("")
         + `trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Uint8Array.from(out, c => c.charCodeAt(0));       // all chars are ASCII
  }
}

/* buildReportPdf(): data -> PDF bytes.
   data = { generated: Date, input, rules:{count, source}, stats:[[label,value,flag]],
            alerts:[...], matrix: matrixModel(), sources:[[name, enabled]] } */
function buildReportPdf(d){
  const doc = new PdfDoc(), FS = 8, LH = 10, CW = FS * 0.6;  // font size, line height, char width
  const x0 = PDF_M, chars = Math.floor((PDF_W - 2 * PDF_M) / CW);
  const stamp = d.generated.toISOString().replace("T", " ").slice(0, 19) + " UTC";

  const heading = (s) => {
    doc.ensure(40); doc.y -= 14;
    doc.text(x0, doc.y, s, 12, "F2"); doc.y -= 6; doc.hline(doc.y, INK, 0.8); doc.y -= 4;
  };
  const para = (s, color = INK, size = 9, font = "F1") => {
    for (const line of wrap(s, Math.floor((PDF_W - 2 * PDF_M) / (size * 0.55)))) {   // Helvetica: ~0.55em average glyph, conservative
      doc.ensure(size + 3); doc.y -= size + 3; doc.text(x0, doc.y, line, size, font, color);
    }
  };

  /* ---- title block ---- */
  doc.y -= 6; doc.text(x0, doc.y, "TriSource - Multi-Source DFIR Report", 18, "F2");
  doc.y -= 6; para(`Generated ${stamp} by TriSource (client-side). Input: ${d.input || "-"}`, MUTED);
  para(`Detection rule set: ${d.rules.count} rules from ${d.rules.source}. First matching rule wins per event.`, MUTED);
  doc.y -= 8;
  let sx = x0;                                              // stat tiles as one line of figures
  for (const [label, value, flag] of d.stats) {
    const v = String(value);
    doc.text(sx, doc.y - 16, v, 16, "F2", flag && Number(value) > 0 ? RED : INK);
    doc.text(sx, doc.y - 27, label, 8, "F1", MUTED);
    sx += 175;
  }
  doc.y -= 34;

  /* ---- 1. alerts table ---- */
  heading(`1. Detection alerts (${d.alerts.length})`);
  // column widths in characters; Command takes whatever is left
  const cols = [["Time (UTC)", 23], ["Technique", 10], ["Tactic", 19], ["Sev", 6], ["Rule fired", 34]];
  const cmdW = chars - cols.reduce((n, c) => n + c[1] + 2, 0);
  cols.push(["Matched command", cmdW]);
  const colX = []; cols.reduce((x, c) => (colX.push(x), x + (c[1] + 2) * CW), x0);
  const tableHead = () => {
    doc.y -= LH; cols.forEach(([h], i) => doc.text(colX[i], doc.y, h.toUpperCase(), 7, "F4", MUTED));
    doc.y -= 3; doc.hline(doc.y);
  };
  if (!d.alerts.length) para("No detections - the input contained no events matching the rule set.", MUTED);
  else tableHead();
  for (const a of d.alerts) {
    const high = a.sev === "high";
    const cells = [wrap(a.ts || "-", 23), wrap(a.id, 10), wrap(a.tactic, 19),
                   [high ? "HIGH" : a.sev === "informational" ? "info" : a.sev],
                   wrap(a.rule, 34), wrap(a.cmd, cmdW, 8)];
    const flags = [a.caveat && ["caveat: " + a.caveat, AMBER], a.note && ["note: " + a.note, AMBER]].filter(Boolean);
    const flagLines = flags.map(([t, c]) => [wrap(t, chars - Math.round((colX[4] - x0) / CW)), c]);
    const lines = Math.max(...cells.map(c => c.length)) + flagLines.reduce((n, f) => n + f[0].length, 0);
    doc.ensure(lines * LH + 6, tableHead);
    const top = doc.y;
    cells.forEach((c, i) => c.forEach((line, j) => {
      const color = i === 3 ? (high ? RED : a.sev === "medium" ? AMBER : MUTED) : INK;
      doc.text(colX[i], top - LH * (j + 1), line, FS, i === 3 && high ? "F4" : "F3", color);
    }));
    let y = top - LH * Math.max(...cells.map(c => c.length));
    for (const [ls, color] of flagLines) for (const l of ls) { y -= LH; doc.text(colX[4], y, l, FS - 0.5, "F3", color); }
    doc.y = y - 4;
    if (high) doc.rect(x0 - 7, doc.y + 1, 2.5, top - doc.y - 2, RED);   // red bar, like the UI row
    doc.hline(doc.y);
  }

  /* ---- 2. coverage matrix ---- */
  const m = d.matrix;
  heading("2. Coverage matrix");
  para("Sources included: " + d.sources.map(([n, onOff]) => `${n} ${onOff ? "[on]" : "[OFF]"}`).join("   "), MUTED);
  const mx = [x0, x0 + 300, x0 + 400, x0 + 500, x0 + 600], cellW = 70;
  const centre = (x, t, size = FS) => x + (cellW - t.length * size * 0.6) / 2;   // Courier: exact
  const mHead = () => {
    doc.y -= LH + 2; doc.text(mx[0], doc.y, "TECHNIQUE", 7, "F4", MUTED);
    MX_SOURCES.forEach((h, i) => doc.text(centre(mx[i + 1], h, 7), doc.y, h.toUpperCase(), 7, "F4", MUTED));
    doc.y -= 3; doc.hline(doc.y);
  };
  mHead();
  if (!m.rows.length) para(m.empty || "No techniques.", MUTED);
  for (const r of m.rows) {
    doc.ensure(16, mHead);
    doc.y -= 14;
    doc.text(mx[0], doc.y + 3, `${r.id}  ${r.name}`.slice(0, 60), FS, "F3", INK);
    r.cells.forEach((v, i) => {
      const x = mx[i + 1];
      const [label, font, color] = v === "N" ? ["N", "F4", WHITE] : v === "amber" ? ["Y *", "F4", AMBER]
        : v === "Y" ? ["Y", "F4", INK] : [v === "off" ? "off" : "-", "F3", MUTED];
      if (v === "N") doc.rect(x, doc.y, cellW, 11, RED);           // missing evidence = red flag
      doc.text(centre(x, label), doc.y + 3, label, FS, font, color);
    });
    doc.y -= 3; doc.hline(doc.y);
  }
  doc.y -= 4;
  para(m.headline, m.warn ? RED : INK, 10, "F2");
  para("Y = detected / recovered   - = not applicable (benign default)   N = not present (red flag)   "
     + "Y * = detected with a caveat   off = source excluded by the analyst or not supplied", MUTED, 8);

  /* ---- 3. rules fired (audit trail) ---- */
  const fired = [...new Map(d.alerts.map(a => [a.rule, a])).values()];
  if (fired.length) {
    heading(`3. Rules fired (${fired.length}) - exact patterns, for audit`);
    for (const a of fired) {
      const body = wrap(`/${a.pattern}/${a.flags || ""}`, chars - 4, 6);
      doc.ensure((body.length + 1) * LH + 4);
      doc.y -= LH; doc.text(x0, doc.y, `${a.id}  [${a.sev}]  ${a.rule}`, FS, "F4", a.sev === "high" ? RED : INK);
      for (const l of body) { doc.y -= LH; doc.text(x0 + 4 * CW, doc.y, l, FS, "F3", MUTED); }
      doc.y -= 4;
    }
  }

  /* ---- footer on every page (page count is known only now) ---- */
  doc.pages.forEach((ops, i) => {
    doc.ops = ops;
    doc.text(x0, PDF_M - 14, `TriSource DFIR report - ${stamp}`, 7, "F1", MUTED);
    doc.text(PDF_W - PDF_M - 60, PDF_M - 14, `Page ${i + 1} of ${doc.pages.length}`, 7, "F1", MUTED);
  });

  const pdfDate = d.generated.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return doc.build("TriSource DFIR report", pdfDate);
}

/* exportReport(): snapshot exactly what is on screen (including source toggles)
   and download it. Blob URLs work from file://, so no server is involved. */
function exportReport(){
  if (!EVENTS.length) return;
  const bytes = buildReportPdf({
    generated: new Date(), input: INPUT_LABEL,
    rules: { count: RULES_INFO.count, source: RULES_INFO.source },
    stats: statsModel(), alerts: ALERTS, matrix: matrixModel(),
    sources: MX_SOURCES.map((n, i) => [n, on(["detection", "prefetch", "registry", "memory"][i])]),
  });
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  const a = document.createElement("a");
  a.href = url; a.download = `trisource-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.pdf`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
