"""World seeder: persists the deterministic fleet + catalog into the database."""
from __future__ import annotations

import time
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import (
    Approval, Action, Campaign, DecisionRow, DeviceInstallResult, Endpoint,
    EndpointPatchState, EvaluationRun, Event, Evidence, Finding, Investigation,
    MetricSnapshot, Outcome, Patch, PatchCVE, PatchKnownIssue, RCARecord,
    RingExecution, RingPlan, RiskAssessment, Rollback, StageRun, DepartmentRow,
    Supersedence, ToolCall, Validation,
)
from app.engine.common import stable_ratio
from .generate_catalog import build_catalog
from .generate_fleet import generate_fleet

DEPT_ADOPTION = {
    "it-lab": 0.95, "engineering": 0.45, "executives": 0.30, "finance": 0.25,
    "retail-pos": 0.20, "call-center": 0.15, "warehouse": 0.12,
}

COMPLIANT_STATES = {"installed", "up_to_date"}
BLOCKING_STATES = COMPLIANT_STATES | {"not_applicable"}


def _clear_world(db: Session) -> None:
    """Delete all dynamic rows (order matters for FKs)."""
    for model in (
        ToolCall, EvaluationRun, MetricSnapshot, Outcome, Action, Approval,
        RiskAssessment, DecisionRow, Evidence, StageRun, Investigation, Event,
        Validation, Rollback, RCARecord, DeviceInstallResult, RingExecution,
        RingPlan, Campaign, Finding, EndpointPatchState, Supersedence,
        PatchKnownIssue, PatchCVE, Patch, Endpoint, DepartmentRow,
    ):
        db.execute(delete(model))
        if db.bind is not None and db.bind.dialect.name == "sqlite":
            try:
                db.exec_driver_sql(
                    f"DELETE FROM sqlite_sequence WHERE name='{model.__tablename__}'"
                )
            except Exception:
                pass  # sqlite_sequence row may not exist yet


def seed_world(db: Session, estate_size: int | None = None, seed: int | None = None) -> dict:
    """Reset and repopulate the simulated world. Returns row counts."""
    from app.config import get_settings

    settings = get_settings()
    estate_size = estate_size or settings.ESTATE_SIZE
    seed = seed if seed is not None else settings.SIM_SEED
    started = time.perf_counter()

    _clear_world(db)

    catalog = build_catalog()
    fleet = generate_fleet(estate_size, seed)

    # ---- departments -------------------------------------------------------
    dept_counts: dict[str, int] = {}
    for ep in fleet:
        dept_counts[ep["department"]] = dept_counts.get(ep["department"], 0) + 1
    crit_default = {}
    for ep in fleet:
        crit_default.setdefault(ep["department"], ep["criticality"])
    descriptions = {
        "retail-pos": "Store point-of-sale terminals and store servers",
        "warehouse": "Handheld scanners, kiosks and warehouse servers",
        "call-center": "Agent and supervisor workstations",
        "engineering": "Build agents, dev workstations, infra servers",
        "finance": "Analyst workstations and finance application servers",
        "executives": "Executive laptops and desktops",
        "it-lab": "IT lab machines used as ring-0 canaries",
    }
    for dept, count in sorted(dept_counts.items()):
        db.add(DepartmentRow(
            name=dept, default_criticality=crit_default.get(dept, "medium"),
            description=descriptions.get(dept, ""), endpoint_count=count,
        ))

    # ---- catalog ------------------------------------------------------------
    patch_rows: dict[str, Patch] = {}
    for p in catalog:
        row = Patch(
            patch_id=p["patch_id"], name=p["name"], target_os=p["target_os"],
            severity=p["severity"], reboot_required=p["reboot_required"],
            release_date=p["release_date"],
            typical_install_minutes=p["typical_install_minutes"],
            disk_space_required_mb=p["disk_space_required_mb"],
            supersedes=p["supersedes"], prerequisites=p["prerequisites"],
            superseded_by=p.get("superseded_by"),
            at_risk_policy_default=p["at_risk_policy_default"], notes=p["notes"],
        )
        db.add(row)
        patch_rows[p["patch_id"]] = row
    db.flush()

    for pid, row in patch_rows.items():
        src = next(x for x in catalog if x["patch_id"] == pid)
        for cve in src["cves"]:
            db.add(PatchCVE(patch_row_id=row.id, **cve))
        for issue in src["known_issues"]:
            db.add(PatchKnownIssue(patch_row_id=row.id, **issue))
        for older in src["supersedes"]:
            db.add(Supersedence(newer_patch_id=pid, older_patch_id=older))

    # ---- endpoints ----------------------------------------------------------
    endpoint_rows = [
        Endpoint(**{k: v for k, v in ep.items()}) for ep in fleet
    ]
    db.add_all(endpoint_rows)
    db.flush()

    # ---- initial patch states ----------------------------------------------
    catalog_by_id = {p["patch_id"]: p for p in catalog}
    states: list[EndpointPatchState] = []
    findings: list[Finding] = []
    now = datetime.utcnow()
    for ep_row, ep_src in zip(endpoint_rows, fleet):
        installed_or_uptodate: set[str] = set()
        pending_states: dict[str, str] = {}
        for pid, psrc in catalog_by_id.items():
            if psrc["target_os"] != ep_src["os"]:
                continue
            key = f"{seed}:{ep_src['hostname']}:{pid}:initial"
            r = stable_ratio(key)
            current_gen = psrc["release_date"].year >= 2026
            adoption = DEPT_ADOPTION.get(ep_src["department"], 0.2)
            if current_gen:
                if r < adoption:
                    st = "installed"
                elif r < adoption + 0.05:
                    st = "downloaded"
                elif r < adoption + 0.09:
                    st = "failed"
                elif r < adoption + 0.11:
                    st = "pending_reboot"
                else:
                    st = "applicable"
            else:
                st = "up_to_date" if r < 0.90 else "applicable"
            pending_states[pid] = st

        # Supersedence fix-ups: a superseding install makes the ancestor current.
        for pid, psrc in catalog_by_id.items():
            if psrc["superseded_by"] and pending_states.get(psrc["superseded_by"]) == "installed":
                pending_states[pid] = "up_to_date"
        # Prereq fix-ups: cannot hold a child state without its prerequisite.
        for pid, psrc in catalog_by_id.items():
            if psrc["prerequisites"]:
                if pending_states.get(pid) in {"installed", "failed", "pending_reboot"}:
                    for pre in psrc["prerequisites"]:
                        if pending_states.get(pre) not in {"installed", "up_to_date"}:
                            pending_states[pre] = "up_to_date"

        for pid, st in pending_states.items():
            states.append(EndpointPatchState(
                endpoint_id=ep_row.id, patch_id=pid, state=st,
                last_changed=now, detail="" if st != "failed" else "historical failure",
            ))
            if st in COMPLIANT_STATES:
                installed_or_uptodate.add(pid)

        # Open security findings for anything unpatched with linked CVEs.
        for pid, st in pending_states.items():
            if st in COMPLIANT_STATES:
                continue
            for cve in catalog_by_id[pid]["cves"]:
                findings.append(Finding(
                    endpoint_id=ep_row.id, cve_id=cve["cve_id"], patch_id=pid,
                    severity=catalog_by_id[pid]["severity"], cvss=cve["cvss"],
                    known_exploited=cve.get("known_exploited", False), status="open",
                ))

    # Bulk insert in chunks to keep memory flat at larger estate sizes.
    CHUNK = 2000
    for i in range(0, len(states), CHUNK):
        db.add_all(states[i:i + CHUNK])
    for i in range(0, len(findings), CHUNK):
        db.add_all(findings[i:i + CHUNK])
    db.commit()

    duration_ms = int((time.perf_counter() - started) * 1000)
    return {
        "endpoints": len(fleet),
        "patches": len(catalog),
        "patch_states": len(states),
        "findings": len(findings),
        "departments": len(dept_counts),
        "duration_ms": duration_ms,
    }


def world_is_seeded(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(Endpoint)) > 0
