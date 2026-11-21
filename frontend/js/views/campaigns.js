// Campaigns view: campaign list, creation, lifecycle controls, and the
// detail panel (ring funnel, live feed, failures/RCA, risk mix, rollbacks).
import { api } from "../api.js";
import {
  bar, clear, dateTime, el, emptyBox, errorBox, fixed, num, panel, pct,
  rateBar, severityChip, shortTime, statusPill, table,
} from "../ui.js";

let selectedId = null;
let pollTimer = null;
let listenerBound = false;

export async function render(root) {
  clear(root);
  stopPolling();
  const layout = el("div", { class: "detail-grid" },
    el("div", { id: "camp-list-col" }),
    el("div", { id: "camp-detail-col" }));
  root.append(layout);
  await renderList();
  if (!listenerBound) {
    window.addEventListener("start-campaign", onStartCampaignEvent);
    listenerBound = true;
  }
}

function onStartCampaignEvent(ev) {
  showTab("campaigns");
  createCampaignFlow(ev.detail);
}
function showTab(view) {
  document.querySelector(`.tab[data-view="${view}"]`)?.click();
}

// ------------------------------------------------------------------ list side

async function renderList() {
  const col = document.getElementById("camp-list-col");
  if (!col) return;
  col.replaceChildren(el("div", {}, el("span", { class: "spinner" }), " loading..."));
  try {
    const [campaigns, patches] = await Promise.all([api.campaigns(), api.catalog()]);
    const patchIds = patches.map(p => p.patch_id);

    // ---- new-campaign form -------------------------------------------------
    const select = el("select", {},
      patchIds.map(id => el("option", { value: id, text: id })));
    if (patchIds.includes("KB-SIM-2026-002")) select.value = "KB-SIM-2026-002";
    const policy = el("select", {},
      el("option", { value: "canary_prove", text: "canary_prove (prove risk in canary)" }),
      el("option", { value: "exclude", text: "exclude (hold at-risk cohorts out)" }));
    const nameInput = el("input", { type: "text", placeholder: "optional name", style: "width:100%" });
    const form = panel("New Campaign",
      el("div", { class: "panel-body" },
        el("div", { style: "display:flex;flex-direction:column;gap:10px" },
          el("label", { class: "fld" }, "Patch", select),
          el("label", { class: "fld" }, "At-risk policy", policy),
          el("label", { class: "fld" }, "Name", nameInput),
          el("button", {
            class: "btn primary",
            onclick: () => createCampaignFlow(select.value, policy.value, nameInput.value),
            text: "Investigate & Plan",
          })))));

    // ---- campaign table ----------------------------------------------------
    const rows = campaigns.map(c => el("tr", {
      class: "clickable" + (c.id === selectedId ? "" : ""),
      style: c.id === selectedId ? "background:rgba(56,200,216,0.08)" : "",
      onclick: () => { selectedId = c.id; renderList(); renderDetail(); },
    },
      el("td", { class: "num mono faint", text: "#" + c.id }),
      el("td", {}, el("div", { text: c.name }),
        el("div", { class: "faint mono", text: `${c.patch_id} - eligible ${num(c.eligible_count)}` })),
      el("td", {}, statusPill(c.status)),
      el("td", { class: "faint", text: dateTime(c.created_at) })));

    col.replaceChildren(
      form,
      panel(`Campaigns (${campaigns.length})`,
        campaigns.length
          ? table(["ID", "Campaign", "Status", "Created"], rows)
          : emptyBox("no campaigns yet - create one above")));
  } catch (err) {
    col.replaceChildren(errorBox(err));
  }
}

async function createCampaignFlow(patchId, policy = "canary_prove", name = "") {
  const detailCol = document.getElementById("camp-detail-col");
  try {
    detailCol?.replaceChildren(el("div", {}, el("span", { class: "spinner" }),
      ` investigating ${patchId} ...`));
    const created = await api.createCampaign(patchId, name || null, policy);
    selectedId = created.id;
    await api.plan(selectedId);          // investigate happened at create; plan rings now
    await renderList();
    await renderDetail();
  } catch (err) {
    if (detailCol) detailCol.replaceChildren(panel("New Campaign", errorBox(err)));
    await renderList();
  }
}

// ---------------------------------------------------------------- detail side

async function renderDetail() {
  const col = document.getElementById("camp-detail-col");
  if (!col) return;
  if (selectedId === null) {
    col.replaceChildren(emptyBox("select or create a campaign"));
    return;
  }
  stopPolling();
  col.replaceChildren(el("div", {}, el("span", { class: "spinner" }), " loading campaign..."));
  try {
    const [campaign, executions, events] = await Promise.all([
      api.campaignDetail(selectedId), api.executions(selectedId), api.events(selectedId, 60),
    ]);
    const controls = await buildControls(campaign);
    col.replaceChildren(
      panel(`#${campaign.id} ${campaign.name}`, buildHeaderBody(campaign), controls),
      panel("Ring Funnel", await buildFunnel(executions)),
      await buildFailuresAndRca(),
      panel("Live Feed (events)", buildFeed(events), pollRefreshButton()),
      await buildRiskMix(),
      panel("Audit Trail (tool calls)", await buildToolAudit()),
    );
    schedulePolling(() => refreshLive());
  } catch (err) {
    col.replaceChildren(errorBox(err));
  }
}

function pollRefreshButton() {
  return el("button", { class: "btn", onclick: () => refreshLive(), text: "refresh" });
}

async function buildControls(campaign) {
  const row = el("div", { class: "btn-row" });
  const note = el("span", { class: "faint mono" });
  async function act(fn, okMsg) {
    try {
      const result = await fn();
      note.textContent = "";
      await Promise.all([renderList(), renderDetail()]);
      return result;
    } catch (err) {
      note.textContent = String(err.message).slice(0, 160);
    }
  }

  const st = campaign.status;
  if (st === "DIAGNOSED")
    row.append(el("button", { class: "btn", onclick: () => act(() => api.plan(campaign.id)), text: "Plan rings" }));
  if (st === "PLANNED")
    row.append(el("button", { class: "btn", onclick: () => act(() => api.start(campaign.id)), text: "Request approval" }));
  if (["PLANNED", "AWAITING_APPROVAL"].includes(st))
    row.append(el("button", { class: "btn danger", onclick: () => act(async () =>
      (await api.emergencyOverride(campaign.id)) && null), text: "Emergency override req." }));
  if (st === "AWAITING_APPROVAL") {
    const approvals = await api.approvals().catch(() => []);
    const pending = approvals.find(a => a.campaign_id === campaign.id && a.status === "pending");
    if (pending && pending.approval_type === "deployment")
      row.append(
        el("button", { class: "btn ok", onclick: () => act(() => api.approve(pending.id)), text: "Approve deployment" }),
        el("button", { class: "btn danger", onclick: () => act(() => api.reject(pending.id)), text: "Reject" }));
    else if (pending)
      row.append(
        el("button", { class: "btn ok", onclick: () => act(() => api.approve(pending.id)),
                       text: "Approve " + pending.approval_type }));
  }
  if (["APPROVED", "EXECUTING", "VERIFYING"].includes(st))
    row.append(el("button", { class: "btn primary", onclick: () => act(() => api.advance(campaign.id)), text: "Advance next ring" }));
  if (st === "FAILED")
    row.append(el("button", { class: "btn danger", onclick: () => act(() => api.rollback(campaign.id)), text: "Rollback executed rings" }));
  row.append(note);
  return row;
}

function buildHeaderBody(c) {
  return el("div", { class: "panel-body" },
    el("dl", { class: "kv" },
      el("dt", { text: "Status" }), el("dd", {}, statusPill(c.status)),
      el("dt", { text: "Patch" }), el("dd", { text: c.patch_id }),
      el("dt", { text: "Policy" }), el("dd", { text: c.at_risk_policy }),
      el("dt", { text: "Eligible" }), el("dd", { text: num(c.eligible_count) }),
      el("dt", { text: "Emergency" }),
      el("dd", {}, c.emergency_approved
        ? el("span", { class: "chip chip-crit", text: "OVERRIDE GRANTED" })
        : el("span", { class: "faint", text: "no" })),
      el("dt", { text: "Stop reason" }),
      el("dd", { class: c.stop_reason ? "v-bad" : "faint", text: c.stop_reason || "-" }),
      el("dt", { text: "Blocked reason" }),
      el("dd", { class: c.blocked_reason ? "v-warn" : "faint", text: c.blocked_reason || "-" }),
      el("dt", { text: "Created" }), el("dd", { text: dateTime(c.created_at) }),
      el("dt", { text: "Completed" }), el("dd", { text: dateTime(c.completed_at) })));
}

async function buildFunnel(executions) {
  if (!executions.length) return el("div", { class: "panel-body" }, emptyBox("not started"));
  executions.sort((a, b) => a.position - b.position);
  return el("div", { class: "panel-body" }, el("div", { class: "funnel" },
    executions.map(ex => rateBar(
      ex.ring, ex.failure_rate || 0, ex.threshold || 0.05,
      [["status", ex.status], ["devices", num(ex.device_count)],
       ["success", num(ex.success_count)], ["pending_reboot", num(ex.pending_reboot_count)],
       ["failed", num(ex.failure_count)], ["rate", pct(ex.failure_rate)],
       ["threshold", pct(ex.threshold, 0)]],
      ex.stop_triggered === true,
      ex.status === "skipped"))));
}

const BAD_CLASSES = new Set(["app_crash", "boot_failure", "driver_conflict", "av_conflict"]);

async function buildFailuresAndRca() {
  try {
    const [failures, rcaRecords, results] = await Promise.all([
      api.failures(selectedId), api.rca(selectedId),
      api.results(selectedId, "failed").catch(() => []),
    ]);
    const body = [];
    if (rcaRecords.length) {
      for (const r of rcaRecords) {
        const cf = r.correlated_factor || {};
        body.push(el("div", { style: "border:1px solid var(--border);border-radius:5px;padding:10px;margin-bottom:8px;background:var(--bg-inset)" },
          el("div", {},
            el("span", { class: "chip chip-high", text: r.failure_class }),
            " ",
            el("span", { class: "mono dim", text: `${r.ring} - affected ${r.affected_count} - confidence ${(r.confidence * 100).toFixed(0)}%` })),
          el("div", { style: "margin-top:6px", text: r.root_cause }),
          cf.app_name ? el("div", {
              class: "dim", style: "margin-top:4px",
              text: "differential: " + cf.app_name +
                (cf.dominant_failing_version ? " " + cf.dominant_failing_version : "") +
                (cf.version_below ? " < " + cf.version_below : "") +
                (cf.matches_catalog_known_issue ? " [catalog confirmed]" : ""),
            }) : null,
          r.recommended_action ? el("div", { class: "v-info", style: "margin-top:4px", text: "-> " + r.recommended_action }) : null));
      }
    }
    if (results.length) {
      body.push(table(["Endpoint", "Ring", "Class", "Attempts", "Error detail"],
        results.slice(0, 50).map(r => el("tr", {},
          el("td", { class: "mono dim", text: r.hostname || ("#" + r.endpoint_id) }),
          el("td", { class: "mono dim", text: r.ring }),
          el("td", {}, r.failure_class
            ? el("span", { class: BAD_CLASSES.has(r.failure_class) ? "chip chip-high" : "chip", text: r.failure_class })
            : el("span", { class: "faint", text: "-" })),
          el("td", { class: "num", text: String(r.attempts) }),
          el("td", { class: "dim", text: r.error_detail })))));
    }
    if (!body.length) return el("div", { class: "panel" }); // nothing to show
    return panel("Failures & Root Cause", el("div", { class: "panel-body" }, body));
  } catch {
    return el("div", { class: "panel" });
  }
}

async function buildRiskMix() {
  try {
    const assessments = await api.riskAssessments(selectedId);
    if (!assessments.length) return el("div", { class: "panel" });
    const buckets = { P1: 0, P2: 0, P3: 0, P4: 0 };
    let maxScore = 0, minScore = 100;
    for (const a of assessments) {
      buckets[a.bucket] = (buckets[a.bucket] || 0) + 1;
      maxScore = Math.max(maxScore, a.score);
      minScore = Math.min(minScore, a.score);
    }
    const colors = { P1: "bad", P2: "warn", P3: "info", P4: "ok" };
    return panel(`Risk Distribution (${assessments.length} scored endpoints)`,
      el("div", { class: "panel-body" },
        ["P1", "P2", "P3", "P4"].map(b => bar(b, buckets[b], assessments.length, colors[b])),
        el("div", { class: "legend" },
          el("span", { text: `score range ${fixed(minScore, 1)} - ${fixed(maxScore, 1)} (P1 >= 70, P2 >= 55, P3 >= 40)` }))));
  } catch {
    return el("div", { class: "panel" });
  }
}

function buildFeed(events) {
  if (!events.length) return el("div", { class: "panel-body" }, emptyBox("no events"));
  return el("div", { class: "feed" }, events.map(ev => {
    const cls = /halt|fail|reject|rollback/i.test(ev.type) ? "bad"
      : /complete|success|approve/i.test(ev.type) ? "ok"
      : /emergency|approval/i.test(ev.type) ? "warn" : "";
    return el("div", { class: "feed-item" },
      el("span", { class: "feed-time", text: shortTime(ev.created_at) }),
      el("span", { class: `feed-type ${cls}`, text: ev.type }),
      el("span", { class: "feed-msg", text: ev.message }));
  }));
}

async function buildToolAudit() {
  try {
    const calls = await api.auditTrail(40);
    if (!calls.length) return el("div", { class: "panel-body" }, emptyBox("no tool calls audited yet"));
    return el("div", { class: "panel-body" }, el("div", { class: "feed" }, calls.map(t =>
      el("div", { class: "feed-item" },
        el("span", { class: "feed-time", text: shortTime(t.created_at) }),
        el("span", { class: `feed-type ${t.ok ? "ok" : "bad"}`,
                     text: `${t.tool_name}[${t.risk_level}]` }),
        el("span", { class: "feed-msg",
                     text: `${t.ok ? "ok" : "ERR " + (t.error || "")} - ${t.result_summary || ""}`.slice(0, 140) })))));
  } catch {
    return el("div", { class: "panel-body" }, emptyBox("audit unavailable"));
  }
}

// ------------------------------------------------------------- live polling

function schedulePolling(fn) {
  stopPolling();
  pollTimer = setInterval(fn, 2500);
}
export function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function refreshLive() {
  if (selectedId === null) return;
  try {
    const [campaign, executions, events] = await Promise.all([
      api.campaignDetail(selectedId), api.executions(selectedId), api.events(selectedId, 60),
    ]);
    // Refresh the mutable panels in place.
    const headPanel = document.querySelector("#camp-detail-col .panel");
    if (headPanel) {
      const old = headPanel.querySelector(".panel-body");
      if (old) old.replaceWith(buildHeaderBody(campaign));
      const controls = headPanel.querySelector(".btn-row");
      if (controls) {
        const fresh = await buildControls(campaign);
        controls.replaceWith(fresh);
      }
    }
    const panels = [...document.querySelectorAll("#camp-detail-col .panel")];
    const funnelPanel = panels.find(p => p.querySelector(".funnel") ||
      (p.querySelector(".empty")?.textContent === "not started"));
    if (funnelPanel) {
      const fresh = await buildFunnel(executions);
      funnelPanel.querySelector(".panel-body")?.replaceWith(fresh);
    }
    const feedPanel = panels.find(p => p.querySelector(".feed") &&
      p.querySelector(".panel-title")?.textContent.includes("Live Feed"));
    if (feedPanel) {
      const fresh = buildFeed(events);
      feedPanel.querySelector(".panel-body")?.replaceWith(fresh);
    }
    // Auto-drive: while executing, keep advancing? No - human advances.
  } catch { /* transient */ }
}
