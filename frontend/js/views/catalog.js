// Patch Catalog view: browsable catalog + compatibility matrix per patch.
import { api } from "../api.js";
import {
  clear, el, emptyBox, errorBox, kevChip, num, panel, severityChip, table,
} from "../ui.js";

export async function render(root) {
  clear(root);
  root.append(el("div", {}, el("span", { class: "spinner" }), " loading catalog..."));
  try {
    const patches = await api.catalog();
    clear(root);

    const tbody = patches.map(p => {
      const kevCount = p.cves.filter(c => c.known_exploited).length;
      return el("tr", { class: "clickable", onclick: () => showCompat(root, p) },
        el("td", { class: "mono", text: p.patch_id }),
        el("td", {}, el("div", { text: p.name }),
          el("div", { class: "faint", text: `supersedes: ${p.supersedes.join(", ") || "-"}` })),
        el("td", {}, severityChip(p.severity)),
        el("td", { class: "mono dim", text: p.target_os }),
        el("td", { class: "num dim" },
          p.cves.length ? el("span", { text: String(p.cves.length) }) : el("span", { class: "faint", text: "-" }),
          kevCount ? " " : null, kevCount ? kevChip(true) : null),
        el("td", { class: "faint", text: p.known_issues.length
          ? p.known_issues.map(k => `${k.app_name} < ${k.version_below} (${k.failure_class})`).join("; ")
          : "-" }),
        el("td", {}, el("span", { class: "chip chip-info", text: p.at_risk_policy_default })));
    });

    root.append(panel(`Patch Catalog (${patches.length} patches, simulated feed)`,
      table(["ID", "Name", "Severity", "Target OS", { label: "CVEs", num: true }, "Public Known Issues", "At-Risk Policy"], tbody),
      el("span", { class: "badge badge-dim", text: "click a row for the compatibility matrix" })));

    // Default: show the designed bad patch so the story is visible immediately.
    const bad = patches.find(p => p.patch_id === "KB-SIM-2026-002");
    if (bad) await showCompat(root, bad);
  } catch (err) {
    clear(root);
    root.append(errorBox(err));
  }
}

async function showCompat(root, patch) {
  document.getElementById("compat-panel")?.remove();
  const loading = panel(
    `Compatibility Matrix - ${patch.patch_id}`,
    el("div", {}, el("span", { class: "spinner" }), " computing..."));
  loading.id = "compat-panel";
  root.append(loading);

  try {
    const matrix = await api.compatibility(patch.patch_id);
    const body = [];
    if (matrix.cells.some(c => c.total > 0)) {
      const rows = matrix.cells.filter(c => c.total > 0).map(c => el("tr", {},
        el("td", { class: "mono dim", text: c.department }),
        el("td", { class: "mono dim", text: c.os }),
        el("td", { class: "num", text: num(c.total) }),
        el("td", { class: "num v-ok", text: num(c.applicable) }),
        el("td", { class: c.incompatible ? "num v-bad" : "num faint", text: num(c.incompatible) }),
        el("td", { class: c.at_risk ? "num v-warn" : "num faint", text: num(c.at_risk) }),
        el("td", { class: "num faint", text: num(c.blocked_disk) }),
        el("td", { class: "num faint", text: num(c.missing_prereq) })));
      body.push(table(["Department", "OS", { label: "Total", num: true },
        { label: "Applicable", num: true }, { label: "Incompatible", num: true },
        { label: "At Risk", num: true }, { label: "Disk Blocked", num: true },
        { label: "Prereq Missing", num: true }], rows));
    } else {
      body.push(emptyBox("no endpoints match this patch target OS"));
    }
    if (matrix.cohorts.length) {
      body.push(el("div", { style: "margin-top:10px" },
        el("div", { class: "panel-title",
                    text: "at-risk cohorts (canary_prove seats reps of each in RING_1)" }),
        el("div", { style: "margin-top:6px" },
          matrix.cohorts.map(c => el("span", {
            class: "chip chip-mod",
            title: c.description || "at-risk cohort",
            text: `${c.signature}: ${(c.endpoint_ids || []).length} device(s), ${c.failure_class}` })))));
    }
    const headExtra = el("button", { class: "btn primary", text: "Start campaign",
      onclick: () => window.dispatchEvent(new CustomEvent("start-campaign",
        { detail: patch.patch_id })) });
    loading.replaceWith(panel(
      `Compatibility Matrix - ${patch.patch_id} (${matrix.eligible_total} eligible)`,
      el("div", { class: "panel-body" }, body), headExtra));
  } catch (err) {
    loading.replaceWith(errorBox(err));
  }
}
