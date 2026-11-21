// DOM + formatting helpers (no framework).

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v; // only ever fed built markup
    else if (k.startsWith("on") && typeof v === "function")
      node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child.nodeType ? child : document.createTextNode(child));
  }
  return node;
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

export function pct(x, digits = 1) {
  return (100 * Number(x || 0)).toFixed(digits) + "%";
}
export function num(x) {
  return Number(x || 0).toLocaleString("en-US");
}
export function fixed(x, d = 2) { return Number(x || 0).toFixed(d); }
export function shortTime(iso) {
  if (!iso) return "";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false });
}
export function dateTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  return isNaN(d) ? iso : d.toLocaleString([], { hour12: false });
}

export function statusPill(status) {
  return el("span", { class: `status-pill st-${status}`, text: status || "-" });
}

export function severityChip(sev) {
  const map = { critical: "chip-crit", high: "chip-high", moderate: "chip-mod", low: "chip-ok" };
  return el("span", { class: `chip ${map[sev] || ""}`, text: (sev || "?").toUpperCase() });
}

export function kevChip(kev) {
  return kev
    ? el("span", { class: "chip chip-kev", title: "Listed in the simulated KEV: actively exploited", text: "KEV" })
    : null;
}

export function bar(label, value, maxValue, cls = "", valText = null) {
  const width = maxValue > 0 ? Math.max(0, Math.min(100, (value / maxValue) * 100)) : 0;
  return el("div", { class: "bar-row" },
    el("div", { class: "lbl", text: label }),
    el("div", { class: "bar-track" },
      el("div", { class: `bar-fill ${cls}`, style: `width:${width}%` })),
    el("div", { class: "bar-val", text: valText ?? num(value) }));
}

export function kpiCard(label, value, sub = "", valueClass = "") {
  return el("div", { class: "kpi" },
    el("div", { class: "kpi-label", text: label }),
    el("div", { class: `kpi-value ${valueClass}`, text: String(value) }),
    sub ? el("div", { class: "kpi-sub", text: sub }) : null);
}

export function panel(title, bodyNode, headExtra = null) {
  return el("div", { class: "panel" },
    el("div", { class: "panel-head" },
      el("div", { class: "panel-title", text: title }),
      headExtra),
    bodyNode.classList && bodyNode.classList.contains("panel-body")
      ? bodyNode : el("div", { class: "panel-body" }, bodyNode));
}

export function emptyBox(text) { return el("div", { class: "empty", text }); }
export function errorBox(err) { return el("div", { class: "error-box", text: "ERROR: " + err.message }); }

export function table(headers, rows) {
  return el("table", {},
    el("thead", {}, el("tr", {}, headers.map(h =>
      el("th", { class: h.num ? "num" : "", text: h.label ?? h })))),
    el("tbody", {}, rows));
}

export function rateBar(ringLabel, rate, threshold, extraStats, halted = false, skipped = false) {
  const ratePct = Math.min(100, rate * 100);
  const color = halted ? "var(--bad)" : rate > threshold ? "var(--warn)" : "var(--ok)";
  const thrPos = Math.min(100, threshold * 100);
  return el("div", { class: `funnel-ring${halted ? " halted" : ""}${skipped ? " skipped" : ""}` },
    el("div", { class: "fr-head" },
      el("span", { class: "fr-name", text: ringLabel }),
      el("div", { class: "fr-stats" }, ...(extraStats || []).map(([k, v]) =>
        el("span", { text: `${k}: ${v}` })))),
    skipped ? null : el("div", { class: "ratebar" },
      el("div", { class: "fill", style: `width:${ratePct}%;background:${color}` }),
      el("div", { class: "threshold-mark", style: `left:${thrPos}%`, title: `stop threshold ${pct(threshold, 0)}` })));
}

// Minimal inline SVG line chart for exposure/compliance trends.
export function sparkline(points, color = "var(--accent)") {
  const w = 600, h = 60, pad = 2;
  if (!points.length) return emptyBox("no snapshots yet");
  const vals = points.map(p => p.y);
  const min = Math.min(...vals), max = Math.max(...vals);
  const span = max - min || 1;
  const step = points.length > 1 ? (w - 2 * pad) / (points.length - 1) : 0;
  const path = points.map((p, i) =>
    `${i ? "L" : "M"}${(pad + i * step).toFixed(1)},${(h - pad - ((p.y - min) / span) * (h - 2 * pad)).toFixed(1)}`).join(" ");
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("class", "sparkline");
  svg.setAttribute("preserveAspectRatio", "none");
  const p = document.createElementNS(svgNS, "path");
  p.setAttribute("d", path);
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", color);
  p.setAttribute("stroke-width", "2");
  svg.append(p);
  return svg;
}

export function sortObjEntries(obj) {
  return Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
}
