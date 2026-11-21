"""Deterministic detection layer over fleet + catalog.

Each detector returns a list of finding dicts:
  {type, severity, title, detail, scope, count, sample}
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.applicability import build_cohorts, is_applicable, matching_known_issues
from app.engine.common import CRITICALITY_RANK
from app.models import Endpoint, EndpointPatchState, Patch


def _finding(type_, severity, title, detail, scope, count, sample=None):
    return {
        "type": type_, "severity": severity, "title": title,
        "detail": detail, "scope": scope, "count": count,
        "sample": (sample or [])[:5],
    }


def detect_critical_unpatched_with_exploit(endpoints, states_by_ep, patches) -> list[dict]:
    out = []
    for patch in patches:
        cves = getattr(patch, "cves", None) or []
        if not any(c.known_exploited for c in cves):
            continue
        affected = []
        for e in endpoints:
            states = states_by_ep.get(e.id, {})
            res = is_applicable(e, patch, states)
            if res.applicable or (
                states.get(patch.patch_id) in {"downloaded", "failed", "pending_reboot"}
            ):
                affected.append(e)
        if not affected:
            continue
        crit_first = sorted(
            affected,
            key=lambda e: -CRITICALITY_RANK.get(e.criticality, 0),
        )
        depts = defaultdict(int)
        for e in affected:
            depts[e.department] += 1
        out.append(_finding(
            "critical-unpatched-with-known-exploit", "critical",
            f"{patch.patch_id} fixes an actively exploited CVE; "
            f"{len(affected)} endpoint(s) unpatched",
            f"Departments: {dict(sorted(depts.items(), key=lambda kv: -kv[1]))}",
            f"patch={patch.patch_id}", len(affected),
            [e.hostname for e in crit_first],
        ))
    return out


def detect_eol_segments(endpoints) -> list[dict]:
    by_os: dict[str, int] = defaultdict(int)
    by_dept: dict[str, int] = defaultdict(int)
    samples = []
    for e in endpoints:
        if getattr(e, "eol", False):
            by_os[e.os] += 1
            by_dept[e.department] += 1
            samples.append(e.hostname)
    if not by_os:
        return []
    return [_finding(
        "unsupported-eol-os-segment", "high",
        "Windows 10 22H2 approaches end of support; EOL-soon segment present",
        f"by OS: {dict(by_os)}; top departments: "
        f"{dict(sorted(by_dept.items(), key=lambda kv: -kv[1])[:4])}",
        "fleet-wide", sum(by_os.values()), samples,
    )]


def detect_failed_update_clusters(endpoints) -> list[dict]:
    """Same patch failing repeatedly inside one department = systemic signal."""
    per_dept_patch: dict[tuple[str, str], list[str]] = defaultdict(list)
    state_rows_index: dict[int, dict[str, str]] = defaultdict(dict)
    for e in endpoints:
        pass
    # endpoint patch states come pre-grouped from the caller via attribute map;
    # here we rely on endpoint.patch_states relationships being loaded.
    for e in endpoints:
        for st in getattr(e, "patch_states", None) or []:
            state_rows_index[e.id][st.patch_id] = st.state
            if st.state == "failed":
                per_dept_patch[(e.department, st.patch_id)].append(e.hostname)
    out = []
    for (dept, pid), hosts in sorted(per_dept_patch.items()):
        if len(hosts) >= 3:
            out.append(_finding(
                "failed-update-cluster", "medium",
                f"{len(hosts)} devices in '{dept}' historically failed {pid}",
                "Repeat failure inside one department suggests a systemic cause "
                "(image, driver baseline or shared application set).",
                f"department={dept};patch={pid}", len(hosts), hosts,
            ))
    return out


def detect_patch_drift_between_peer_groups(endpoints) -> list[dict]:
    """Peer group = (role, os). Drift = compliance gap vs peer median > 25pp."""
    groups: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"ok": 0, "bad": 0})
    for e in endpoints:
        key = (e.role, e.os)
        total = compliant = 0
        for st in getattr(e, "patch_states", None) or []:
            total += 1
            compliant += 1 if st.state in ("installed", "up_to_date") else 0
        if total == 0:
            continue
        groups[key]["ok"] += compliant
        groups[key]["bad"] += (total - compliant)
    rates = {}
    for key, agg in groups.items():
        tot = agg["ok"] + agg["bad"]
        if tot:
            rates[key] = agg["ok"] / tot
    medians = sorted(rates.values())
    median = medians[len(medians) // 2] if medians else 1.0
    drifted = [
        {"peer_group": f"{role}/{os}", "compliance": round(r, 3)}
        for (role, os), r in sorted(rates.items())
        if median - r > 0.25
    ]
    if not drifted:
        return []
    worst = drifted[0]
    return [_finding(
        "patch-drift-between-peer-groups", "medium",
        f"{len(drifted)} peer group(s) lag fleet median compliance by >25pp",
        f"Worst: {worst['peer_group']} at {worst['compliance']:.0%}.",
        "fleet-wide", len(drifted),
        [d["peer_group"] for d in drifted],
    )]


def detect_missing_prerequisites(db: Session) -> list[dict]:
    patches = db.scalars(select(Patch)).all()
    states_rows = db.scalars(select(EndpointPatchState)).all()
    states_by_ep: dict[int, dict[str, str]] = defaultdict(dict)
    for row in states_rows:
        states_by_ep[row.endpoint_id][row.patch_id] = row.state
    out = []
    for patch in patches:
        prereqs = list(getattr(patch, "prerequisites", None) or [])
        if not prereqs:
            continue
        missing_eps = []
        for e_id, smap in states_by_ep.items():
            if smap.get(patch.patch_id) in ("installed", "up_to_date"):
                continue
            for pre in prereqs:
                if smap.get(pre) not in ("installed", "up_to_date"):
                    missing_eps.append((e_id, pre))
                    break
        if missing_eps:
            out.append(_finding(
                "missing-prerequisite", "medium",
                f"{len(missing_eps)} endpoint(s) target {patch.patch_id} but lack "
                f"prerequisite(s)",
                f"Prereqs: {', '.join(prereqs)}",
                f"patch={patch.patch_id}", len(missing_eps),
                [str(x[0]) for x in missing_eps],
            ))
    return out


def detect_insufficient_disk(db: Session) -> list[dict]:
    patches = db.scalars(select(Patch)).all()
    endpoints = db.scalars(select(Endpoint)).all()
    states_rows = db.scalars(select(EndpointPatchState)).all()
    states_by_ep: dict[int, dict[str, str]] = defaultdict(dict)
    for row in states_rows:
        states_by_ep[row.endpoint_id][row.patch_id] = row.state
    out = []
    for patch in patches:
        blocked = [
            e for e in endpoints
            if is_applicable(e, patch, states_by_ep.get(e.id, {})).applicable
            and float(e.disk_free_gb or 0) * 1024 < (patch.disk_space_required_mb or 0)
        ]
        if blocked:
            out.append(_finding(
                "insufficient-disk-for-required-patch", "medium",
                f"{len(blocked)} endpoint(s) cannot receive {patch.patch_id}: disk too small",
                f"Requires {patch.disk_space_required_mb}MB free.",
                f"patch={patch.patch_id}", len(blocked),
                [e.hostname for e in blocked[:10]],
            ))
    return out


def detect_long_pending_reboots(endpoints) -> list[dict]:
    stale = [e for e in endpoints if (e.pending_reboot_days or 0) > 30]
    if not stale:
        return []
    stale.sort(key=lambda e: -e.pending_reboot_days)
    return [_finding(
        "long-pending-reboot", "medium",
        f"{len(stale)} endpoint(s) pending reboot > 30 days",
        "Long-pending reboots delay patch activation and skew compliance.",
        "fleet-wide", len(stale),
        [f"{e.hostname} ({e.pending_reboot_days}d)" for e in stale],
    )]


def detect_incompatibility_exposures(endpoints, patches) -> list[dict]:
    out = []
    for patch in patches:
        cohorts = build_cohorts(endpoints, patch)
        for sig, cohort in sorted(cohorts.items()):
            out.append(_finding(
                "application-incompatibility-exposure", "high",
                f"{cohort['endpoint_ids'].__len__()} endpoint(s) match known "
                f"incompatibility for {patch.patch_id}",
                f"{cohort['app_name']} < {cohort['version_below']} -> "
                f"{cohort['failure_class']}. {cohort['description']}",
                f"patch={patch.patch_id};cohort={sig}", len(cohort["endpoint_ids"]),
                [str(i) for i in cohort["endpoint_ids"][:5]],
            ))
    return out


def detect_av_conflicts(endpoints, patches) -> list[dict]:
    out = []
    for patch in patches:
        hits = []
        for e in endpoints:
            for m in matching_known_issues(e, patch):
                if m.issue.kind == "av_agent":
                    hits.append(e)
                    break
        if hits:
            out.append(_finding(
                "security-software-conflict", "high",
                f"{len(hits)} endpoint(s): EDR agent version conflicts with "
                f"{patch.patch_id}",
                "Installing would leave endpoints without a running AV/EDR agent.",
                f"patch={patch.patch_id}", len(hits),
                [e.hostname for e in hits],
            ))
    return out


def detect_config_noncompliance(endpoints) -> list[dict]:
    flagged = [e for e in endpoints if getattr(e, "compliance_flags", None)]
    if not flagged:
        return []
    counter: dict[str, int] = defaultdict(int)
    for e in flagged:
        for flag in e.compliance_flags:
            counter[flag] += 1
    return [_finding(
        "config-noncompliance", "low",
        f"{len(flagged)} endpoint(s) carry configuration compliance flags",
        f"Flags: {dict(sorted(counter.items()))}",
        "fleet-wide", len(flagged),
        [e.hostname for e in flagged],
    )]


def run_all_detectors(db: Session) -> list[dict]:
    endpoints = db.scalars(select(Endpoint)).all()
    patches = db.scalars(select(Patch)).all()
    states_rows = db.scalars(select(EndpointPatchState)).all()
    states_by_ep: dict[int, dict[str, str]] = defaultdict(dict)
    for row in states_rows:
        states_by_ep[row.endpoint_id][row.patch_id] = row.state

    findings: list[dict] = []
    findings.extend(detect_critical_unpatched_with_exploit(endpoints, states_by_ep, patches))
    findings.extend(detect_eol_segments(endpoints))
    findings.extend(detect_failed_update_clusters(endpoints))
    findings.extend(detect_patch_drift_between_peer_groups(endpoints))
    findings.extend(detect_missing_prerequisites(db))
    findings.extend(detect_insufficient_disk(db))
    findings.extend(detect_long_pending_reboots(endpoints))
    findings.extend(detect_incompatibility_exposures(endpoints, patches))
    findings.extend(detect_av_conflicts(endpoints, patches))
    findings.extend(detect_config_noncompliance(endpoints))
    return findings


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["type"], -f["count"]),
    )
