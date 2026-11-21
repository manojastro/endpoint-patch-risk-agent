"""Ring rollout engine: planning, deterministic install simulation,
ring execution with autonomous stop conditions, and rollback."""
from __future__ import annotations

import time
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.engine import validation as validation_mod
from app.engine.applicability import (
    ApplicabilityResult, at_risk_count, build_cohorts, disk_sufficient,
    is_applicable, matching_known_issues, missing_prerequisites,
)
from app.engine.common import (
    CRITICALITY_RANK, RING_ORDER, evaluate_stop_condition,
    failure_rate, stable_ratio,
)
from app.metrics import CAMPAIGN_HALTS_TOTAL, ROLLBACKS_TOTAL, UNSAFE_PREVENTIONS_TOTAL
from app.models import (
    Action, Campaign, DeviceInstallResult, Endpoint, EndpointPatchState, Event,
    Finding, Outcome, Patch, RingExecution, RingPlan, Rollback, Validation, utcnow,
)

LAB_CAP = 25
COHORT_REPS_PER_COHORT = 2
CANARY_MIN = 5


# --------------------------------------------------------------------- queries

def load_world(db: Session, patch_id: str):
    """Load patch row, endpoints and per-endpoint patch-state maps."""
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == patch_id))
    if patch_row is None:
        raise ValueError(f"unknown patch_id {patch_id}")
    endpoints = db.scalars(select(Endpoint)).all()
    states_rows = db.scalars(select(EndpointPatchState)).all()
    states_by_ep: dict[int, dict[str, str]] = defaultdict(dict)
    for row in states_rows:
        states_by_ep[row.endpoint_id][row.patch_id] = row.state
    return patch_row, endpoints, states_by_ep


def compute_eligibility(db: Session, patch_row, endpoints, states_by_ep, policy: str):
    """Partition endpoints for a patch under the campaign's at-risk policy."""
    eligible: list = []
    excluded_ids: list[int] = []
    exclusion_reasons: dict[str, int] = defaultdict(int)
    reason_map: dict[int, str] = {}

    for e in endpoints:
        states = states_by_ep.get(e.id, {})
        res: ApplicabilityResult = is_applicable(e, patch_row, states)
        if not res.applicable:
            exclusion_reasons[res.reason_code] += 1
            continue
        if missing_prerequisites(patch_row, states):
            exclusion_reasons["missing_prereq"] += 1
            reason_map[e.id] = "missing_prereq"
            continue
        if not disk_sufficient(e, patch_row):
            exclusion_reasons["insufficient_disk"] += 1
            reason_map[e.id] = "insufficient_disk"
            continue
        cohorts_hit = matching_known_issues(e, patch_row)
        if cohorts_hit and policy == "exclude":
            exclusion_reasons["at_risk_policy_exclude"] += 1
            reason_map[e.id] = "at_risk_policy_exclude"
            continue
        eligible.append(e)

    return eligible, excluded_ids, dict(exclusion_reasons), reason_map


# --------------------------------------------------------------------- planner

def _diversity_fill(candidates: list, target: int, chosen: set[int]) -> list:
    """Round-robin across (department, os) segments for representative sampling."""
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for e in candidates:
        if e.id in chosen:
            continue
        groups[(e.department, e.os)].append(e)
    for g in groups.values():
        g.sort(key=lambda x: (CRITICALITY_RANK.get(x.criticality, 1),
                              -x.health_score, x.hostname))
    ordered_groups = sorted(
        groups.values(),
        key=lambda g: (min(CRITICALITY_RANK.get(x.criticality, 1) for x in g), -len(g)),
    )
    picked: list = []
    i = 0
    while len(picked) < target and any(ordered_groups):
        progressed = False
        for g in ordered_groups:
            if i < len(g):
                picked.append(g[i])
                progressed = True
                if len(picked) >= target:
                    break
        if not progressed:
            break
        i += 1
    return picked


def _critical_gate(endpoint, emergency: bool) -> bool:
    """Critical-tier devices are held back until ring 3+ unless overridden."""
    if emergency:
        return False
    return CRITICALITY_RANK.get(endpoint.criticality, 1) >= CRITICALITY_RANK["critical"]


def plan_rings(
    db: Session,
    campaign: Campaign,
    patch_row,
    endpoints,
    states_by_ep: dict[int, dict[str, str]],
    canary_frac: float | None = None,
    pilot_frac: float | None = None,
    dept_frac: float | None = None,
) -> list[RingPlan]:
    settings = get_settings()
    canary_frac = settings.CANARY_FRACTION if canary_frac is None else canary_frac
    pilot_frac = settings.PILOT_FRACTION if pilot_frac is None else pilot_frac
    dept_frac = settings.DEPARTMENT_FRACTION if dept_frac is None else dept_frac

    eligible, _excl, reasons, _rmap = compute_eligibility(
        db, patch_row, endpoints, states_by_ep, campaign.at_risk_policy
    )
    campaign.eligible_count = len(eligible)
    campaign.excluded_endpoint_ids = []
    campaign.exclusion_reasons = {}

    thresholds = settings.ring_thresholds
    emergency = bool(campaign.emergency_approved)
    n = len(eligible)

    chosen: set[int] = set()
    assignments: dict[str, list] = {}
    notes: dict[str, str] = {}

    # RING_0 -- IT lab first (healthy lab boxes make the cleanest smoke test).
    lab = [e for e in eligible if e.department == "it-lab"]
    lab.sort(key=lambda x: (-x.health_score, x.hostname))
    ring0 = [e for e in lab[:LAB_CAP]]
    if not ring0:  # tiny estates without lab coverage
        ring0 = sorted(eligible, key=lambda x: (CRITICALITY_RANK.get(x.criticality, 1), x.hostname))[:CANARY_MIN]
    for e in ring0:
        chosen.add(e.id)
    assignments["RING_0"] = ring0
    notes["RING_0"] = f"IT-lab smoke ring ({len(ring0)} devices, healthiest first)."

    # RING_1 -- canary: deliberate at-risk cohort representatives + diversity fill.
    target1 = max(CANARY_MIN, int(round(canary_frac * n)))
    cohorts = build_cohorts(eligible, patch_row)
    reps: list = []
    if cohorts and campaign.at_risk_policy == "canary_prove":
        for sig in sorted(cohorts.keys()):
            members = sorted(cohorts[sig]["endpoint_ids"])
            by_id = {e.id: e for e in eligible}
            picks = [by_id[m] for m in members[:COHORT_REPS_PER_COHORT] if m in by_id]
            reps.extend(picks)
    reps = [e for e in reps if e.id not in chosen and not _critical_gate(e, emergency)]
    for e in reps:
        chosen.add(e.id)
    pool1 = [e for e in eligible if e.id not in chosen and not _critical_gate(e, emergency)]
    fill1 = _diversity_fill(pool1, max(0, target1 - len(reps)), chosen)
    ring1 = reps + fill1
    for e in ring1:
        chosen.add(e.id)
    assignments["RING_1"] = ring1
    notes["RING_1"] = (
        f"Canary ~{canary_frac:.0%} of eligible"
        + (f" including {len(reps)} at-risk cohort representative(s)" if reps else "")
        + "; critical tier deferred."
    )

    # RING_2 -- pilot (~5%), still critical-free.
    target2 = int(round(pilot_frac * n))
    pool2 = [e for e in eligible if e.id not in chosen and not _critical_gate(e, emergency)]
    ring2 = _diversity_fill(pool2, target2, chosen)
    for e in ring2:
        chosen.add(e.id)
    assignments["RING_2"] = ring2
    notes["RING_2"] = f"Pilot ~{pilot_frac:.0%}; department-stratified sample; critical tier deferred."

    # RING_3 -- broad department wave (~30%); critical tier allowed here.
    target3 = int(round(dept_frac * n))
    pool3 = [e for e in eligible if e.id not in chosen]
    ring3 = _diversity_fill(pool3, target3, chosen)
    for e in ring3:
        chosen.add(e.id)
    assignments["RING_3"] = ring3
    notes["RING_3"] = f"Department wave ~{dept_frac:.0%}; critical tier admitted after clean early rings."

    # RING_4 -- everything else.
    ring4 = [e for e in eligible if e.id not in chosen]
    assignments["RING_4"] = ring4
    notes["RING_4"] = "Broad fleet remainder."

    plans: list[RingPlan] = []
    for position, ring in enumerate(RING_ORDER):
        members = assignments[ring]
        plan = RingPlan(
            campaign_id=campaign.id, ring=ring, position=position,
            endpoint_ids=[e.id for e in members], size=len(members),
            criteria_note=notes[ring],
            threshold=thresholds.get(ring, 0.05),
        )
        plans.append(plan)
    db.add_all(plans)
    db.flush()
    return plans


# ------------------------------------------------------- install simulation

def transient_failure_probability(health: int, hist_failures: int) -> float:
    if health >= 55:
        p = 0.01
    elif health >= 40:
        p = 0.08
    else:
        p = 0.25
    if hist_failures >= 4:
        p += 0.08
    return min(p, 0.35)


def simulate_install(endpoint, patch_row, patch_states: dict[str, str], seed: int) -> dict:
    """Deterministic install outcome derived purely from attributes x catalog."""
    base = {
        "outcome": "failed", "failure_class": None, "attempts": 1,
        "install_seconds": 0, "error_detail": "",
    }
    res = is_applicable(endpoint, patch_row, patch_states)
    if not res.applicable:
        base["outcome"] = "skipped_not_applicable"
        base["error_detail"] = res.reason_code
        return base

    key_prefix = f"{seed}:{endpoint.hostname}:{patch_row.patch_id}"

    if not disk_sufficient(endpoint, patch_row):
        base["failure_class"] = "disk_space"
        base["error_detail"] = (
            f"insufficient disk: {endpoint.disk_free_gb}GB free < "
            f"{patch_row.disk_space_required_mb / 1024:.1f}GB required"
        )
        return base

    missing = missing_prerequisites(patch_row, patch_states)
    if missing:
        base["failure_class"] = "missing_prereq"
        base["error_detail"] = f"missing prerequisite patch(es): {', '.join(missing)}"
        return base

    hits = matching_known_issues(endpoint, patch_row)
    if hits:
        hit = hits[0]
        base["failure_class"] = hit.failure_class
        base["error_detail"] = (
            f"{hit.issue.app_name} {hit.installed_version} < {hit.issue.version_below}: "
            f"{hit.issue.description}"
        )
        return base

    p = transient_failure_probability(endpoint.health_score, endpoint.historical_patch_failures)
    r_transient = stable_ratio(f"{key_prefix}:transient")
    if r_transient < p:
        cls = "network_loss" if stable_ratio(f"{key_prefix}:tclass") < 0.6 else "partial_install"
        # One automatic retry for transient classes (network blips, interrupted staging).
        r_retry = stable_ratio(f"{key_prefix}:retry")
        seconds = patch_row.typical_install_minutes * 60
        if r_retry < 0.80:
            return {
                "outcome": "success", "failure_class": None, "attempts": 2,
                "install_seconds": int(seconds * 1.4),
                "error_detail": f"recovered after transient {cls}",
            }
        return {
            "outcome": "failed", "failure_class": cls, "attempts": 2,
            "install_seconds": int(seconds * 0.7),
            "error_detail": f"transient {cls} persisted across retry",
        }

    seconds = patch_row.typical_install_minutes * 60
    jitter = 0.85 + stable_ratio(f"{key_prefix}:dur") * 0.3
    if patch_row.reboot_required and stable_ratio(f"{key_prefix}:reboot") < 0.35:
        return {
            "outcome": "pending_reboot", "failure_class": None, "attempts": 1,
            "install_seconds": int(seconds * jitter),
            "error_detail": "",
        }
    return {
        "outcome": "success", "failure_class": None, "attempts": 1,
        "install_seconds": int(seconds * jitter), "error_detail": "",
    }


# ------------------------------------------------------------------ execution

def get_plan_for(db: Session, campaign: Campaign, ring: str) -> RingPlan | None:
    return db.scalar(
        select(RingPlan).where(RingPlan.campaign_id == campaign.id, RingPlan.ring == ring)
    )


def next_pending_ring(db: Session, campaign: Campaign) -> RingPlan | None:
    plans = db.scalars(
        select(RingPlan).where(RingPlan.campaign_id == campaign.id).order_by(RingPlan.position)
    ).all()
    done = {
        ex.ring for ex in db.scalars(
            select(RingExecution).where(RingExecution.campaign_id == campaign.id)
        ).all() if ex.status in ("succeeded", "halted", "rolled_back", "skipped")
    }
    for plan in plans:
        if plan.ring not in done:
            return plan
    return None


def _add_event(db: Session, campaign_id: int | None, type_: str, message: str, payload=None):
    db.add(Event(campaign_id=campaign_id, type=type_, message=message, payload=payload or {}))


def execute_ring(db: Session, campaign: Campaign, ring: str, seed: int | None = None) -> dict:
    """Execute one ring end-to-end: install -> reboot step -> validation -> verdict."""
    from app.config import get_settings as _gs
    seed = seed if seed is not None else _gs().SIM_SEED
    started = time.perf_counter()

    patch_row = db.scalar(select(Patch).where(Patch.patch_id == campaign.patch_id))
    plan = get_plan_for(db, campaign, ring)
    if plan is None:
        raise ValueError(f"no ring plan for {ring}")

    prior = db.scalars(
        select(RingExecution).where(
            RingExecution.campaign_id == campaign.id, RingExecution.position < plan.position
        )
    ).all()
    blocked_prior = [
        ex for ex in prior if ex.status in ("halted", "rolled_back", "skipped")
    ]
    if blocked_prior:
        raise PermissionError(f"cannot execute {ring}: earlier ring halted/rolled back")

    existing_exec = db.scalar(
        select(RingExecution).where(
            RingExecution.campaign_id == campaign.id, RingExecution.ring == ring
        )
    )
    if existing_exec is not None:
        raise ValueError(f"ring {ring} already executed")

    execution = RingExecution(
        campaign_id=campaign.id, ring=ring, position=plan.position, status="running",
        threshold=plan.threshold, started_at=utcnow(),
    )
    db.add(execution)
    campaign.status = "EXECUTING"
    _add_event(db, campaign.id, "ring_started", f"{ring} started", {"size": plan.size})
    db.flush()

    ids = plan.endpoint_ids
    endpoints = {e.id: e for e in db.scalars(
        select(Endpoint).where(Endpoint.id.in_(ids))
    ).all()}
    states_rows = db.scalars(
        select(EndpointPatchState).where(EndpointPatchState.endpoint_id.in_(ids))
    ).all()
    states_by_ep: dict[int, dict[str, str]] = defaultdict(dict)
    for row in states_rows:
        states_by_ep[row.endpoint_id][row.patch_id] = row.state

    results: list[DeviceInstallResult] = []
    validations: list[Validation] = []
    outcomes_rows: list[Outcome] = []
    success_n = pr_n = fail_n = 0
    critical_boot_failures = 0
    class_counts: dict[str, int] = defaultdict(int)

    for eid in ids:
        ep = endpoints.get(eid)
        if ep is None:
            continue
        sim = simulate_install(ep, patch_row, states_by_ep.get(eid, {}), seed)
        outcome = sim["outcome"]
        if outcome == "skipped_not_applicable":
            continue

        results.append(DeviceInstallResult(
            campaign_id=campaign.id, ring_execution_id=execution.id,
            endpoint_id=eid, patch_id=campaign.patch_id, ring=ring,
            outcome=outcome, failure_class=sim["failure_class"],
            attempts=sim["attempts"], install_seconds=sim["install_seconds"],
            error_detail=sim["error_detail"],
        ))

        if outcome in ("success", "pending_reboot"):
            if outcome == "pending_reboot":
                pr_n += 1
            else:
                success_n += 1
            if outcome == "pending_reboot":
                # Reboot step: the executor applies the pending reboot right away
                # (simulated clock); validation records reboot_completed=True.
                _set_state(db, eid, campaign.patch_id, "pending_reboot")
                ep.pending_reboot_days = 0
                _set_state(db, eid, campaign.patch_id, "installed",
                           detail="reboot applied during ring execution")
            else:
                _set_state(db, eid, campaign.patch_id, "installed")
            _remediate_findings(db, eid, campaign.patch_id)
            _mark_supersedes_current(db, eid, patch_row)
            val = validation_mod.validate_endpoint_post_patch(
                ep, patch_row, sim, rebooted=True
            )
        else:
            fail_n += 1
            class_counts[sim["failure_class"]] += 1
            if sim["failure_class"] == "boot_failure" and ep.criticality == "critical":
                critical_boot_failures += 1
            _set_state(db, eid, campaign.patch_id, "failed")
            val = validation_mod.validate_endpoint_post_patch(
                ep, patch_row, sim, rebooted=False
            )
        validations.append(Validation(
            campaign_id=campaign.id, endpoint_id=eid, patch_id=campaign.patch_id,
            phase="post_patch", passed=val["passed"], checks=val["checks"],
        ))
        outcomes_rows.append(Outcome(
            campaign_id=campaign.id, endpoint_id=eid, patch_id=campaign.patch_id,
            final_outcome=outcome, detail=sim["failure_class"] or "",
        ))

    total = success_n + pr_n + fail_n
    rate = failure_rate(fail_n, total)
    db.add_all(results)
    db.add_all(validations)
    db.add_all(outcomes_rows)
    db.flush()
    halt, reason = evaluate_stop_condition(
        ring, rate, plan.threshold, critical_boot_failures
    )

    execution.device_count = total
    execution.success_count = success_n
    execution.pending_reboot_count = pr_n
    execution.failure_count = fail_n
    execution.failure_rate = rate
    if halt:
        execution.status = "halted"
        execution.stop_triggered = True
        execution.stop_reason = reason
        campaign.status = "FAILED"
        campaign.stop_reason = reason
        CAMPAIGN_HALTS_TOTAL.labels(ring, _primary_class(class_counts)).inc()
        UNSAFE_PREVENTIONS_TOTAL.labels("halt").inc()
        db.add(Action(
            campaign_id=campaign.id, action_type="rollback_recommended",
            target={"rings": [ring], "failure_rate": rate}, status="recommended",
            reason=reason,
        ))
        _add_event(db, campaign.id, "campaign_halted", reason,
                   {"ring": ring, "failure_rate": rate, "classes": dict(class_counts)})
    else:
        execution.status = "succeeded"
        _add_event(db, campaign.id, "ring_succeeded",
                   f"{ring} succeeded (failure rate {rate:.2%})",
                   {"ring": ring, "failure_rate": rate})
    execution.finished_at = utcnow()
    execution.duration_ms = int((time.perf_counter() - started) * 1000)
    db.flush()

    return {
        "ring": ring, "status": execution.status,
        "device_count": total, "success_count": success_n,
        "pending_reboot_count": pr_n, "failure_count": fail_n,
        "failure_rate": rate, "threshold": plan.threshold,
        "stop_triggered": halt, "stop_reason": reason,
        "failure_classes": dict(class_counts),
        "duration_ms": execution.duration_ms,
    }


def _primary_class(class_counts: dict[str, int]) -> str:
    if not class_counts:
        return "none"
    return max(class_counts.items(), key=lambda kv: kv[1])[0]


def _set_state(db: Session, endpoint_id: int, patch_id: str, state: str, detail: str = ""):
    from datetime import datetime as _dt
    row = db.scalar(select(EndpointPatchState).where(
        EndpointPatchState.endpoint_id == endpoint_id,
        EndpointPatchState.patch_id == patch_id))
    if row is None:
        row = EndpointPatchState(endpoint_id=endpoint_id, patch_id=patch_id)
        db.add(row)
    row.state = state
    row.last_changed = _dt.utcnow()
    if detail:
        row.detail = detail


def _remediate_findings(db: Session, endpoint_id: int, patch_id: str):
    rows = db.scalars(select(Finding).where(
        Finding.endpoint_id == endpoint_id, Finding.patch_id == patch_id,
        Finding.status == "open")).all()
    for f in rows:
        f.status = "remediated"


def _mark_supersedes_current(db: Session, endpoint_id: int, patch_row):
    for older in getattr(patch_row, "supersedes", None) or []:
        _set_state(db, endpoint_id, older, "up_to_date", f"superseded by {patch_row.patch_id}")


# ------------------------------------------------------------------- rollback

def rollback_rings(db: Session, campaign: Campaign, rings: list[str]) -> dict:
    """Controlled simulated rollback: restore pre-campaign patch state for the
    affected rings and re-run validation (must pass post-rollback)."""
    started = time.perf_counter()
    patch_row = db.scalar(select(Patch).where(Patch.patch_id == campaign.patch_id))
    results = db.scalars(select(DeviceInstallResult).where(
        DeviceInstallResult.campaign_id == campaign.id,
        DeviceInstallResult.ring.in_(rings))).all()
    endpoints = {}
    ids = [r.endpoint_id for r in results]
    if ids:
        endpoints = {e.id: e for e in db.scalars(
            select(Endpoint).where(Endpoint.id.in_(ids))).all()}

    restored = 0
    validations_ok = True
    for res in results:
        ep = endpoints.get(res.endpoint_id)
        if ep is None:
            continue
        # Restore prior world state (device was unpatched before the campaign).
        _set_state(db, res.endpoint_id, campaign.patch_id, "applicable",
                   "rolled back")
        for older in getattr(patch_row, "supersedes", None) or []:
            st = db.scalar(select(EndpointPatchState).where(
                EndpointPatchState.endpoint_id == res.endpoint_id,
                EndpointPatchState.patch_id == older))
            if st is not None and st.detail.startswith("superseded"):
                _set_state(db, res.endpoint_id, older, "applicable")
        # Re-open previously remediated findings.
        for cve in getattr(patch_row, "cves", None) or []:
            f = db.scalar(select(Finding).where(
                Finding.endpoint_id == res.endpoint_id,
                Finding.patch_id == campaign.patch_id))
            if f is not None:
                f.status = "open"
        res.outcome = "rolled_back"

        val = validation_mod.validate_endpoint_post_rollback(ep, patch_row)
        db.add(Validation(
            campaign_id=campaign.id, endpoint_id=res.endpoint_id,
            patch_id=campaign.patch_id, phase="post_rollback",
            passed=val["passed"], checks=val["checks"],
        ))
        validations_ok = validations_ok and val["passed"]

        db.add(Outcome(
            campaign_id=campaign.id, endpoint_id=res.endpoint_id,
            patch_id=campaign.patch_id, final_outcome="rolled_back",
            detail=f"rollback of {','.join(rings)}",
        ))
        restored += 1

    rates = [ex.failure_rate for ex in db.scalars(
        select(RingExecution).where(
            RingExecution.campaign_id == campaign.id,
            RingExecution.ring.in_(rings))).all()]
    rate_before = max(rates) if rates else 0.0

    rollback = Rollback(
        campaign_id=campaign.id, rings=rings,
        reason=campaign.stop_reason or "controlled rollback",
        failure_rate_before=rate_before, restored_count=restored,
        validation_passed=bool(validations_ok),
    )
    db.add(rollback)
    for ex in db.scalars(select(RingExecution).where(
            RingExecution.campaign_id == campaign.id,
            RingExecution.ring.in_(rings))).all():
        ex.status = "rolled_back"
    # Remaining unexecuted rings will never run for this campaign.
    for plan in db.scalars(select(RingPlan).where(
            RingPlan.campaign_id == campaign.id)).all():
        executed = db.scalar(select(RingExecution).where(
            RingExecution.campaign_id == campaign.id,
            RingExecution.ring == plan.ring))
        if executed is None:
            skipped = RingExecution(
                campaign_id=campaign.id, ring=plan.ring, position=plan.position,
                status="skipped", device_count=0, threshold=plan.threshold,
                stop_reason="campaign rolled back before this ring",
                finished_at=utcnow(),
            )
            db.add(skipped)

    campaign.status = "ROLLED_BACK"
    ROLLBACKS_TOTAL_LABEL = "success" if validations_ok else "failed"
    from app.metrics import ROLLBACKS_TOTAL
    ROLLBACKS_TOTAL.labels(ROLLBACKS_TOTAL_LABEL).inc()
    _add_event(db, campaign.id, "rollback_completed",
               f"rolled back rings {rings}; restored={restored}; "
               f"post-rollback validation {'passed' if validations_ok else 'FAILED'}",
               {"rings": rings, "restored": restored})
    db.flush()
    duration_ms = int((time.perf_counter() - started) * 1000)
    return {
        "rings": rings, "restored_count": restored,
        "validation_passed": bool(validations_ok),
        "failure_rate_before": rate_before, "duration_ms": duration_ms,
    }


def complete_campaign(db: Session, campaign: Campaign) -> dict:
    """Final verification pass after the last ring succeeds."""
    executions = db.scalars(select(RingExecution).where(
        RingExecution.campaign_id == campaign.id)).all()
    campaign.status = "VERIFYING"
    db.flush()
    bad = [ex for ex in executions if ex.status not in ("succeeded",)]
    if bad:
        campaign.status = "FAILED"
        campaign.stop_reason = campaign.stop_reason or "verification found non-succeeded rings"
        return {"completed": False, "detail": "non-succeeded rings present"}
    from datetime import datetime as _dt
    campaign.completed_at = _dt.utcnow()
    campaign.status = "COMPLETED"
    _add_event(db, campaign.id, "campaign_completed",
               f"all {len(executions)} rings completed cleanly")
    return {"completed": True, "rings": len(executions)}
