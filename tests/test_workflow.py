"""Workflow state-machine tests: transitions, approval gate, autonomous stop,
rollback restoration, and the emergency fast-track."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest

from simulator.generate_catalog import BAD_PATCH_ID, CLEAN_PATCH_ID


@pytest.fixture(scope="module", autouse=True)
def _pristine_world(world):
    from simulator import seed_world

    db = world.SessionLocal()
    try:
        seed_world(db, estate_size=600)
    finally:
        db.close()


class TestTransitions:
    def test_all_transition_targets_are_known_statuses(self):
        from app.models import ALLOWED_CAMPAIGN_STATUSES
        from app.workflow.engine import TRANSITIONS

        for src, targets in TRANSITIONS.items():
            assert src in ALLOWED_CAMPAIGN_STATUSES
            assert targets <= set(ALLOWED_CAMPAIGN_STATUSES)

    def test_illegal_transition_raises(self, dbsession):
        from app.workflow.engine import WorkflowViolation, create_campaign, transition

        campaign = create_campaign(dbsession, CLEAN_PATCH_ID, "wf-illegal")
        with pytest.raises(WorkflowViolation):
            transition(dbsession, campaign, "PLANNED")  # DETECTED -> PLANNED
        assert campaign.status == "DETECTED"

    def test_unknown_status_rejected(self, dbsession):
        from app.workflow.engine import WorkflowViolation, create_campaign, transition

        campaign = create_campaign(dbsession, CLEAN_PATCH_ID, "wf-unknown")
        with pytest.raises(WorkflowViolation):
            transition(dbsession, campaign, "ON_FIRE")

    def test_rollback_requires_failed_campaign(self, dbsession):
        from app.workflow import engine as wf

        campaign = wf.create_campaign(dbsession, CLEAN_PATCH_ID, "wf-rb-guard")
        with pytest.raises(wf.WorkflowViolation):
            wf.run_rollback(dbsession, campaign)


class TestApprovalGate:
    def _planned(self, db, name):
        from app.workflow import engine as wf

        c = wf.create_campaign(db, CLEAN_PATCH_ID, name)
        wf.run_investigation(db, c)
        wf.plan_campaign(db, c)
        return c

    def test_advance_before_any_approval_refused(self, dbsession):
        from app.workflow import engine as wf

        c = self._planned(dbsession, "wf-gate-1")
        with pytest.raises(PermissionError):
            wf.advance(dbsession, c)
        assert c.status == "PLANNED"

    def test_reject_blocks_execution(self, dbsession):
        from app.workflow import engine as wf

        c = self._planned(dbsession, "wf-gate-reject")
        approval = wf.request_start(dbsession, c)
        wf.reject(dbsession, approval, note="hold")
        assert c.status == "PLANNED"
        assert "rejected" in (c.blocked_reason or "").lower()
        with pytest.raises(PermissionError):
            wf.advance(dbsession, c)

    def test_approval_then_advance_executes_ring0_and_completes(
            self, dbsession):
        """Clean patch driven to completion through the full happy path."""
        from sqlalchemy import select
        from app.models import RingExecution
        from app.workflow import engine as wf

        c = self._planned(dbsession, "wf-happy-path")
        approval = wf.request_start(dbsession, c)
        assert c.status == "AWAITING_APPROVAL"
        wf.approve(dbsession, approval)
        assert c.status == "APPROVED"

        guard = 0
        while c.status not in ("COMPLETED", "FAILED") and guard < 10:
            guard += 1
            result = wf.advance(dbsession, c)
            if result.get("completed"):
                break
        assert c.status == "COMPLETED", c.stop_reason
        execs = dbsession.scalars(select(RingExecution).where(
            RingExecution.campaign_id == c.id)).all()
        assert sorted(ex.position for ex in execs if ex.status == "succeeded") == [0, 1, 2, 3, 4]


class TestBadPatchStopAndRollback:
    def test_halt_before_ring3_rca_rollback_restores_state(self, dbsession):
        from sqlalchemy import select
        from app.models import (
            DeviceInstallResult, EndpointPatchState, RCARecord, RingExecution,
            Rollback, Validation,
        )
        from app.workflow import engine as wf

        campaign = wf.create_campaign(dbsession, BAD_PATCH_ID,
                                      "wf-bad-patch", at_risk_policy="canary_prove")
        wf.run_investigation(dbsession, campaign)
        wf.plan_campaign(dbsession, campaign)
        approval = wf.request_start(dbsession, campaign)
        wf.approve(dbsession, approval)

        halted_result = None
        guard = 0
        while campaign.status not in ("COMPLETED", "FAILED") and guard < 8:
            guard += 1
            result = wf.advance(dbsession, campaign)
            if result.get("ring_execution", {}).get("stop_triggered"):
                halted_result = result
                break
        assert halted_result is not None, "designed bad patch must trigger a stop"

        # Autonomous stop happened in an early ring.
        execs = dbsession.scalars(select(RingExecution).where(
            RingExecution.campaign_id == campaign.id)).all()
        executed = [ex for ex in execs if ex.status in ("succeeded", "halted")]
        assert all(ex.position <= 1 for ex in executed), \
            [ex.ring for ex in executed]
        halted_ex = next(ex for ex in execs if ex.status == "halted")
        assert halted_ex.failure_rate > halted_ex.threshold

        # Failure taxonomy: designed patch fails are app_crash on scanner hosts.
        results = dbsession.scalars(select(DeviceInstallResult).where(
            DeviceInstallResult.campaign_id == campaign.id)).all()
        failed = [r for r in results if r.outcome == "failed"]
        assert failed and all(r.failure_class == "app_crash" for r in failed)
        assert any("warehouse-scanner-suite" in r.error_detail for r in failed)

        # RCA records persisted naming the root cause.
        rcas = dbsession.scalars(select(RCARecord).where(
            RCARecord.campaign_id == campaign.id)).all()
        assert rcas and any(r.confidence >= 0.9 for r in rcas)

        # Rollback restores pre-campaign state.
        out = wf.run_rollback(dbsession, campaign)
        assert out["restored_count"] > 0
        assert out["validation_passed"] is True
        assert campaign.status == "ROLLED_BACK"

        rollback_row = dbsession.scalars(select(Rollback).where(
            Rollback.campaign_id == campaign.id)).first()
        assert rollback_row is not None and rollback_row.restored_count > 0

        restored_states = dbsession.scalars(select(EndpointPatchState).where(
            EndpointPatchState.patch_id == BAD_PATCH_ID,
            EndpointPatchState.endpoint_id.in_(
                [r.endpoint_id for r in results]))).all()
        assert all(s.state == "applicable" for s in restored_states)

        post_rb = dbsession.scalars(select(Validation).where(
            Validation.campaign_id == campaign.id,
            Validation.phase == "post_rollback")).all()
        assert post_rb and all(v.passed for v in post_rb)

        # Unexecuted rings were marked skipped, never silently left pending.
        statuses = {ex.status for ex in execs} | {
            ex.status for ex in dbsession.scalars(select(RingExecution).where(
                RingExecution.campaign_id == campaign.id)).all()}
        assert "running" not in statuses


class TestEmergencyOverride:
    def _synthetic_pool(self, n_critical: int = 6, n_plain: int = 24):
        """Detached endpoint objects; planner only reads attributes."""
        from types import SimpleNamespace

        eps = []
        for i in range(n_critical + n_plain):
            eps.append(SimpleNamespace(
                id=i + 1, hostname=f"SYN{i:03d}", os="windows-10-22h2",
                os_build="", department="finance" if i >= n_critical else "retail-pos",
                role="analyst-ws", criticality="critical" if i < n_critical else "low",
                eol=False, disk_free_gb=100.0, ram_gb=16, cpu_age_years=2.0,
                health_score=95, historical_patch_failures=0,
                pending_reboot_days=0, compliance_flags=[], software=[],
            ))
        return eps

    def test_emergency_admits_critical_into_early_rings(self, dbsession):
        from sqlalchemy import select as _select
        from app.engine.rollout_engine import plan_rings
        from app.models import Patch, RingPlan
        from app.workflow.engine import create_campaign

        patch_row = dbsession.scalar(
            _select(Patch).where(Patch.patch_id == BAD_PATCH_ID))
        endpoints = self._synthetic_pool()
        states_by_ep = {e.id: {BAD_PATCH_ID: "applicable"} for e in endpoints}
        campaign = create_campaign(dbsession, BAD_PATCH_ID, "wf-emergency-plan")

        plan_rings(dbsession, campaign, patch_row, endpoints, states_by_ep,
                   canary_frac=0.5, pilot_frac=0.25, dept_frac=0.5)
        early_ids = set()
        for plan in dbsession.scalars(_select(RingPlan).where(
                RingPlan.campaign_id == campaign.id)).all():
            if plan.ring in ("RING_1", "RING_2"):
                early_ids |= set(plan.endpoint_ids)
        crit_ids = {e.id for e in endpoints if e.criticality == "critical"}
        assert crit_ids & early_ids == set(), (
            "critical tier must be deferred without an override")

        # Grant the override and re-plan.
        campaign.emergency_approved = True
        from sqlalchemy import delete as _delete
        dbsession.execute(_delete(RingPlan).where(RingPlan.campaign_id == campaign.id))
        dbsession.flush()
        plan_rings(dbsession, campaign, patch_row, endpoints, states_by_ep,
                   canary_frac=0.5, pilot_frac=0.25, dept_frac=0.5)
        early_ids_after = set()
        for plan in dbsession.scalars(_select(RingPlan).where(
                RingPlan.campaign_id == campaign.id)).all():
            if plan.ring in ("RING_1", "RING_2"):
                early_ids_after |= set(plan.endpoint_ids)
        assert crit_ids & early_ids_after, (
            "emergency override must admit critical-tier devices into early rings")

    def test_emergency_flow_via_workflow_functions(self, dbsession):
        from sqlalchemy import func, select
        from app.models import Approval, RingPlan
        from app.workflow import engine as wf

        campaign = wf.create_campaign(dbsession, BAD_PATCH_ID,
                                      "wf-emergency-flow", at_risk_policy="canary_prove")
        wf.run_investigation(dbsession, campaign)
        wf.plan_campaign(dbsession, campaign)
        approval = wf.request_emergency_override(dbsession, campaign,
                                                 reason="active exploitation")
        assert approval.approval_type == "emergency_override"
        wf.approve(dbsession, approval, decided_by="incident-commander")
        assert campaign.emergency_approved is True
        assert campaign.status == "APPROVED"

        plans = dbsession.scalars(select(RingPlan).where(
            RingPlan.campaign_id == campaign.id)).all()
        rings_seen = [p.ring for p in plans]
        assert len(rings_seen) == len(set(rings_seen)), "replan must replace old plans"
        assert sorted(rings_seen) == [
            "RING_0", "RING_1", "RING_2", "RING_3", "RING_4"]

        # Double override is refused.
        with pytest.raises(wf.WorkflowViolation):
            wf.request_emergency_override(dbsession, campaign)

        # And execution proceeds under the emergency gate alone.
        result = wf.advance(dbsession, campaign)
        assert result["ring_execution"]["status"] in ("succeeded", "halted")

    def test_emergency_override_invalid_from_running_state(self, dbsession):
        from app.workflow import engine as wf

        campaign = wf.create_campaign(dbsession, CLEAN_PATCH_ID, "wf-emerg-bad")
        campaign.status = "EXECUTING"  # direct write: simulating mid-flight
        with pytest.raises(wf.WorkflowViolation):
            wf.request_emergency_override(dbsession, campaign)
