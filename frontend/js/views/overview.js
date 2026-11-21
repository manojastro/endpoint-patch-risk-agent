// Overview view: fleet health KPIs, compliance, critical vulnerabilities,
// detections, and metrics trend.
import { api } from "../api.js";
import {
  bar, clear, el, emptyBox, errorBox, fixed, kpiCard, num, panel, pct, severityChip,
  kevChip, sortObjEntries, sparkline, table, shortTime,
} from "../ui.js";

export async function render(root) {
  clear(root);
  root.append(el("div", {}, el("span", { class: "spinner" }), " loading overview..."));
  const grid = el("div", {});
  try {
    const [fleet, metrics, vulns, detections, snapshots] = await Promise.all([
      api.fleetSummary(), api.metricsSummary(), api.vulnerabilities(),
      api.detections().catch(() => null), api.metricSnapshots(80).catch(() => null),
    ]);
    clear(root);

    // ---- fleet health -----------------------------------------------------
    const osBars = el("div", {},
      sortObjEntries(fleet.by_os).map(([os, n]) => bar(os, n, fleet.total_endpoints)));
    const deptBars = el("div", {},
      sortObjEntries(fleet.by_department).map(([d, n]) => bar(d, n, fleet.total_endpoints)));
    grid.append(el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("div", { class: "panel-title", text: "Fleet Health" })),
      el("div", { class: "panel-body" },
        el("div", { class: "kpis" },
          kpiCard("Endpoints", num(fleet.total_endpoints), "simulated estate", "v-accent"),
          kpiCard("Avg Health", fixed(fleet.avg_health, 1), "0-100 score",
            fleet.avg_health >= 70 ? "v-ok" : fleet.avg_health >= 50 ? "v-warn" : "v-bad"),
          kpiCard("EOL Devices", num(fleet.eol_count), "unsupported OS segment",
            fleet.eol_count ? "v-bad" : "v-ok"),
          kpiCard("Pending Reboot >30d", num(fleet.pending_reboot_over_30d), "reboot burden",
            fleet.pending_reboot_over_30d ? "v-warn" : "v-ok"),
          kpiCard("Avg Disk Free", fixed(fleet.avg_disk_free_gb, 1) + " GB", "install headroom")),
        el("div", { class: "grid-2", style: "margin-top:12px" },
          el("div", {}, el("div", { class: "panel-title", text: "OS mix" }), osBars),
          el("div", {}, el("div", { class: "panel-title", text: "Departments" }), deptBars)))));

    // ---- compliance + KPIs ----------------------------------------------
    grid.append(el("div", { class: "grid-2" },
      panel("Patch Compliance by Department",
        el("div", {},
          bar("OVERALL", metrics.compliance_overall_pct, 100,
            metrics.compliance_overall_pct >= 80 ? "ok" : "warn",
            fixed(metrics.compliance_overall_pct, 1) + "%"),
          Object.entries(metrics.compliance_by_department).sort()
            .map(([dept, v]) => bar(dept, v, 100, v >= 80 ? "ok" : v >= 60 ? "warn" : "bad",
              fixed(v, 1) + "%")))),
      panel("Rollout KPIs", el("div", { class: "kpis" },
        kpiCard("Mean Time To Patch", fixed(metrics.mean_time_to_patch_days, 1) + " d", "simulated lag"),
        kpiCard("Canary Detection", fixed(metrics.canary_detection_effectiveness_pct, 0) + "%",
          "halts caught at ring 0/1", "v-accent"),
        kpiCard("Unsafe Preventions", num(metrics.unsafe_deployment_preventions),
          "halts / rejections / rollbacks", "v-ok"),
        kpiCard("KEV Exposure Window", fixed(metrics.exposure_window_critical_kev_before_days, 1) + " d",
          "before -> after: " + fixed(metrics.exposure_window_critical_kev_after_days, 1) + " d",
          "v-warn"))));

    // ---- exposure trend ---------------------------------------------------
    if (snapshots && snapshots.length > 1) {
      const pts = snapshots.map(s => ({ y: s.value_json?.compliance_overall_pct ?? 0 })).reverse();
      grid.append(panel("Compliance Trend (metric snapshots)",
        el("div", {}, sparkline(pts, "var(--accent)"),
          el("div", { class: "legend" },
            el("span", { style: "--dot: var(--accent)", text: `compliance % over last ${pts.length} snapshots` }))),
        el("button", { class: "btn", onclick: () => location.reload(), text: "refresh" })));
    }

    // ---- vulnerabilities --------------------------------------------------
    const vulnRows = vulns.groups.map(g => el("tr", {},
      el("td", {}, el("span", { class: "mono", text: g.cve_id }), " ", kevChip(g.known_exploited)),
      el("td", { class: "mono dim", text: g.patch_id }),
      el("td", { class: "num", text: fixed(g.cvss, 1) }, severityChip(g.cvss >= 9 ? "critical" : g.cvss >= 7 ? "high" : "moderate")),
      el("td", { class: "num", text: num(g.affected_endpoints) }),
      el("td", { class: "dim", text: Object.entries(g.departments).sort((a, b) => b[1] - a[1])
        .map(([d, n]) => `${d} (${n})`).join(", ") || "-" })));
    grid.append(panel(
      `Critical Vulnerabilities (${vulns.summary.kev_cves} KEV of ${vulns.summary.distinct_cves} CVEs)`,
      vulns.groups.length
        ? table(["CVE", "Patch", { label: "CVSS", num: true }, { label: "Affected", num: true }, "Departments"], vulnRows)
        : emptyBox("no open exposures"),
      el("span", { class: "badge badge-dim", text: `exploitable first` })));

    // ---- detections -------------------------------------------------------
    if (detections) {
      const detRows = detections.findings.slice(0, 12).map(f => el("tr", {},
        el("td", {}, severityChip(f.severity)),
        el("td", { class: "mono dim", text: f.type }),
        el("td", { class: "num", text: num(f.count ?? 0) }),
        el("td", { class: "dim", text: f.detail || f.scope?.join(", ") || "" })));
      grid.append(panel(`Detector Findings (${detections.count})`, table(
        ["Severity", "Type", { label: "Count", num: true }, "Detail"], detRows)));
    }
  } catch (err) {
    clear(root);
    grid.append(errorBox(err));
    root.append(grid);
  }
}
