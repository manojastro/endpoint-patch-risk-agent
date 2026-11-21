// Evaluation & Tools view: ground-truth evaluation runner, tool registry,
// and recent evaluation runs.
import { api } from "../api.js";
import {
  clear, dateTime, el, emptyBox, errorBox, num, panel, table,
} from "../ui.js";

export async function render(root) {
  clear(root);
  root.append(el("div", { class: "grid-2" },
    el("div", { id: "eval-col" }),
    el("div", { id: "tools-col" })));
  await Promise.all([renderEval(), renderTools()]);
}

async function renderEval() {
  const col = document.getElementById("eval-col");
  if (!col) return;
  col.replaceChildren(el("span", { class: "spinner" }));
  try {
    const runs = await api.evaluationRuns().catch(() => []);
    const body = el("div", {},
      el("div", { style: "display:flex;gap:10px;align-items:center;margin-bottom:10px" },
        el("button", {
          class: "btn primary",
          text: "Run labeled evaluation",
          onclick: runNow,
        }),
        el("select", { id: "eval-size" },
          el("option", { value: "200", text: "estate 200 (fast)" }),
          el("option", { value: "400", text: "estate 400" }),
          el("option", { value: "800", text: "estate 800" })),
        el("span", { class: "faint", text: "runs in a throwaway sandbox DB; never touches this world" })),
      el("div", { id: "eval-result" }),
      runs.length ? el("div", { style: "margin-top:12px" },
        el("div", { class: "panel-title", text: "recent runs" }),
        table(["When", { label: "Checks", num: true }, { label: "Passed", num: true }, { label: "Failed", num: true }, "Result"],
          runs.map(r => el("tr", {},
            el("td", { class: "faint mono", text: dateTime(r.created_at) }),
            el("td", { class: "num", text: String(r.total_checks) }),
            el("td", { class: "num v-ok", text: String(r.passed_count) }),
            el("td", { class: r.failed_count ? "num v-bad" : "num faint", text: String(r.failed_count) }),
            el("td", {}, el("span", { class: `status-pill ${r.all_passed ? "st-COMPLETED" : "st-FAILED"}`,
              text: r.all_passed ? "ALL PASS" : "FAILURES" })))))
        : emptyBox("no evaluation runs recorded"));

    async function runNow() {
      const size = Number(document.getElementById("eval-size").value || 200);
      const out = document.getElementById("eval-result");
      out.replaceChildren(el("div", {}, el("span", { class: "spinner" }),
        ` running scenarios at estate=${size} ...`));
      try {
        const result = await api.runEvaluation(size);
        const blocks = result.scenario_results.map(s => el("div", { style: "margin-bottom:10px" },
          el("div", {}, el("span", { class: `status-pill ${s.passed ? "st-COMPLETED" : "st-FAILED"}`, text: s.scenario }),
            " ", el("span", { class: "faint mono", text: `${s.checks.length} checks` })),
          el("ul", { class: "check-list" }, s.checks.map(c =>
            el("li", { class: c.passed ? "" : "fail", text: c.check + (c.detail ? ` (${c.detail})` : "") })))));
        const head = el("div", { style: "margin-bottom:8px" },
          el("span", { class: `status-pill ${result.all_passed ? "st-COMPLETED" : "st-FAILED"}`,
                       text: result.all_passed ? "ALL CHECKS PASS" : "FAILURES PRESENT" }),
          " ",
          el("span", { class: "mono dim",
                       text: `${result.passed_count}/${result.total_checks} passed in ${num(result.duration_ms)} ms` }));
        out.replaceChildren(head, ...blocks);
      } catch (err) {
        out.replaceChildren(errorBox(err));
      }
    }

    col.replaceChildren(panel("Ground-Truth Evaluation", el("div", { class: "panel-body" }, body)));
  } catch (err) {
    col.replaceChildren(errorBox(err));
  }
}

const RISK_CHIP = { read: "chip-ok", write: "chip-info", high: "chip-crit" };

async function renderTools() {
  const col = document.getElementById("tools-col");
  if (!col) return;
  col.replaceChildren(el("span", { class: "spinner" }));
  try {
    const tools = await api.tools();
    const rows = tools.map(t => el("tr", {},
      el("td", { class: "mono", text: t.name }),
      el("td", { class: "dim", text: t.purpose }),
      el("td", {}, el("span", { class: `chip ${RISK_CHIP[t.risk_level] || ""}`, text: t.risk_level })),
      el("td", { class: "faint mono", text: t.permission }),
      el("td", { class: "num faint", text: t.timeout_s + "s" })));
    col.replaceChildren(panel(
      `Registered Agent Tools (${tools.length})`,
      table(["Tool", "Purpose", "Risk", "Permission", "Timeout"], rows),
      el("span", { class: "badge badge-dim", text: "allow-list enforced + every call audited" })));

    // Input schema detail for the gated tools.
    const gated = tools.filter(t => t.risk_level === "high");
    if (gated.length) {
      col.append(panel("Gated tool schemas", el("div", { class: "panel-body" },
        gated.map(t => el("div", { style: "margin-bottom:10px" },
          el("div", { class: "mono v-accent", text: t.name }),
          el("pre", {
            class: "mono dim", style: "white-space:pre-wrap;font-size:11.5px;margin-top:4px",
            text: JSON.stringify(t.input_schema, null, 1),
          }))))));
    }
  } catch (err) {
    col.replaceChildren(errorBox(err));
  }
}
