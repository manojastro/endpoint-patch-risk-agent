"""Rollout engine tests: ring sizing, criticality gating, cohort reps,
deterministic install outcomes, execution ordering."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.rollout_engine import (
    compute_eligibility, load_world, plan_rings, simulate_install,
    transient_failure_probability,
)
from simulator.generate_catalog import BAD_PATCH_ID, CLEAN_PATCH_ID


def make_campaign(db, patch_id, policy="canary_prove", emergency=False):
    from app.models import Campaign

    campaign = Campaign(name=f"t-{patch_id}", patch_id=patch_id,
                        status="DIAGNOSED", at_risk_policy=policy,
                        emergency_approved=emergency)
    db.add(campaign)
    db.flush()
    return campaign


class TestRingSizing:
    def test_percentages_and_remainder(self, dbsession):
        patch_row, endpoints, states = load_world(dbsession, CLEAN_PATCH_ID)
        campaign = make_campaign(dbsession, CLEAN_PATCH_ID)
        plans = plan_rings(dbsession, campaign, patch_row, endpoints, states,
                           canary_frac=0.01, pilot_frac=0.05, dept_frac=0.30)
        sizes = {p.ring: p.size for p in plans}
        n = campaign.eligible_count
        assert n >= 12  # meaningful population for percentage math
        # On a small real-world pool the pilot wave may be starved by earlier
        # rings; exact percentage math is asserted on a synthetic fleet below.
        assert sizes["RING_1"] == max(5, int(round(0.01 * n)))
        assert 0 <= sizes["RING_2"] <= int(round(0.05 * n)) + 1
        assert sum(sizes.values()) == n
        assert sizes["RING_4"] >= 0 and sizes["RING_3"] <= int(round(0.30 * n))
        dbsession.rollback()

    def test_percentages_exact_on_large_population(self, dbsession):
        """Formula-level check on a population big enough that no ring starves."""
        from sqlalchemy import select
        from app.models import Patch

        patch_row = dbsession.scalar(
            select(Patch).where(Patch.patch_id == CLEAN_PATCH_ID))
        endpoints = []
        for i in range(400):
            endpoints.append(SimpleNamespace(
                id=i + 1, hostname=f"SZ{i:04d}", os=patch_row.target_os,
                department="call-center", role="agent-ws", criticality="low",
                eol=False, disk_free_gb=100.0, ram_gb=16.0,
                health_score=95, historical_patch_failures=0,
                pending_reboot_days=0, compliance_flags=[], software=[],
            ))
        states = {e.id: {CLEAN_PATCH_ID: "applicable"} for e in endpoints}
        campaign = make_campaign(dbsession, CLEAN_PATCH_ID)
        plans = plan_rings(dbsession, campaign, patch_row, endpoints, states)
        sizes = {p.ring: p.size for p in plans}
        n = campaign.eligible_count
        assert n == 400
        assert sizes["RING_1"] == max(5, int(round(0.01 * n)))
        assert sizes["RING_2"] == int(round(0.05 * n))
        assert sizes["RING_3"] == int(round(0.30 * n))
        assert sum(sizes.values()) == n
        dbsession.rollback()

    def test_no_overlap_between_rings(self, dbsession):
        patch_row, endpoints, states = load_world(dbsession, CLEAN_PATCH_ID)
        campaign = make_campaign(dbsession, CLEAN_PATCH_ID)
        plans = plan_rings(dbsession, campaign, patch_row, endpoints, states)
        seen = []
        for p in plans:
            seen.extend(p.endpoint_ids)
        assert len(seen) == len(set(seen)) == campaign.eligible_count
        dbsession.rollback()

    def test_critical_tier_deferred_past_ring_2(self, dbsession):
        patch_row, endpoints, states = load_world(dbsession, CLEAN_PATCH_ID)
        campaign = make_campaign(dbsession, CLEAN_PATCH_ID)
        plans = plan_rings(dbsession, campaign, patch_row, endpoints, states)
        by_id = {e.id: e for e in endpoints}
        for p in plans[:3]:
            for eid in p.endpoint_ids:
                assert by_id[eid].criticality != "critical", (
                    f"critical device {eid} in early ring {p.ring}")
        dbsession.rollback()

    def test_cohort_reps_in_canary_for_bad_patch(self, dbsession):
        patch_row, endpoints, states = load_world(dbsession, BAD_PATCH_ID)
        campaign = make_campaign(dbsession, BAD_PATCH_ID, "canary_prove")
        plans = plan_rings(dbsession, campaign, patch_row, endpoints, states)
        ring1 = next(p for p in plans if p.ring == "RING_1")
        by_id = {e.id: e for e in endpoints}
        from app.engine.applicability import matching_known_issues
        reps = [eid for eid in ring1.endpoint_ids
                if matching_known_issues(by_id[eid], patch_row)]
        assert len(reps) >= 2, "canary must include at-risk cohort representatives"
        dbsession.rollback()

    def test_exclude_policy_removes_cohort(self, dbsession):
        patch_row, endpoints, states = load_world(dbsession, BAD_PATCH_ID)
        campaign = make_campaign(dbsession, BAD_PATCH_ID, "exclude")
        eligible, _excl, reasons, _rmap = compute_eligibility(
            dbsession, patch_row, endpoints, states, "exclude")
        from app.engine.applicability import matching_known_issues
        assert not any(matching_known_issues(e, patch_row) for e in eligible)
        assert reasons.get("at_risk_policy_exclude", 0) > 0
        dbsession.rollback()

    def test_emergency_override_admits_critical_early(self, dbsession):
        """Synthetic pool guarantees critical-tier candidates exist; the
        default world may simply have none eligible for this patch."""
        from sqlalchemy import select
        from app.models import Patch

        patch_row = dbsession.scalar(
            select(Patch).where(Patch.patch_id == CLEAN_PATCH_ID))
        endpoints = []
        for i in range(30):
            endpoints.append(SimpleNamespace(
                id=i + 1, hostname=f"EM{i:03d}", os=patch_row.target_os,
                department="finance", role="analyst-ws",
                criticality="critical" if i < 6 else "low",
                eol=False, disk_free_gb=100.0, ram_gb=16.0,
                health_score=95, historical_patch_failures=0,
                pending_reboot_days=0, compliance_flags=[], software=[],
            ))
        states = {e.id: {CLEAN_PATCH_ID: "applicable"} for e in endpoints}
        normal = make_campaign(dbsession, CLEAN_PATCH_ID, emergency=False)
        emergency = make_campaign(dbsession, CLEAN_PATCH_ID, emergency=True)
        fracs = dict(canary_frac=0.5, pilot_frac=0.25, dept_frac=0.5)
        plans_n = plan_rings(dbsession, normal, patch_row, endpoints, states, **fracs)
        plans_e = plan_rings(dbsession, emergency, patch_row, endpoints, states, **fracs)
        by_id = {e.id: e for e in endpoints}

        def crit_in(plans, rings):
            return [eid for p in plans if p.ring in rings
                    for eid in p.endpoint_ids
                    if by_id[eid].criticality == "critical"]

        assert not crit_in(plans_n, {"RING_1", "RING_2"})
        assert len(crit_in(plans_e, {"RING_1", "RING_2"})) > 0
        # And the override never leaks into the un-overridden campaign.
        assert normal.emergency_approved is False
        assert emergency.emergency_approved is True
        dbsession.rollback()


class TestInstallOutcomes:
    def test_disk_space_failure(self, dbsession, patch_by_id):
        _, endpoints, states = load_world(dbsession, BAD_PATCH_ID)
        patch_row = patch_by_id[BAD_PATCH_ID]
        victim = SimpleNamespace(**{
            "id": -1, "hostname": "DISK-1", "os": "windows-10-22h2",
            "department": "warehouse", "role": "scanner-handheld",
            "criticality": "low", "health_score": 90,
            "historical_patch_failures": 0, "disk_free_gb": 1.0,
            "pending_reboot_days": 0,
            "software": [{"name": "warehouse-scanner-suite", "version": "7.5.1"}],
        })
        out = simulate_install(victim, patch_row, {}, seed=1337)
        assert out["outcome"] == "failed" and out["failure_class"] == "disk_space"

    def test_missing_prereq_failure(self, dbsession, patch_by_id):
        patch_row = patch_by_id["KB-SIM-2026-004"]  # prereq: KB-SIM-2026-005 SSU
        victim = SimpleNamespace(
            id=-2, hostname="PREREQ-1", os="windows-server-2019",
            department="warehouse", role="warehouse-server", criticality="high",
            health_score=90, historical_patch_failures=0, disk_free_gb=200.0,
            pending_reboot_days=0, software=[],
        )
        out = simulate_install(victim, patch_row, {}, seed=1337)
        assert out["failure_class"] == "missing_prereq"

    def test_app_crash_for_old_scanner_suite(self, dbsession, patch_by_id):
        patch_row = patch_by_id[BAD_PATCH_ID]
        victim = SimpleNamespace(
            id=-3, hostname="SCN-X", os="windows-10-22h2",
            department="warehouse", role="scanner-handheld", criticality="medium",
            health_score=90, historical_patch_failures=0, disk_free_gb=20.0,
            pending_reboot_days=0,
            software=[{"name": "warehouse-scanner-suite", "version": "7.3.1"}],
        )
        out = simulate_install(victim, patch_row, {}, seed=1337)
        assert out["outcome"] == "failed" and out["failure_class"] == "app_crash"

    def test_av_conflict(self, patch_by_id):
        patch_row = patch_by_id["KB-SIM-2026-010"]
        victim = SimpleNamespace(
            id=-4, hostname="AV-X", os="windows-10-22h2",
            department="call-center", role="agent-ws", criticality="medium",
            health_score=95, historical_patch_failures=0, disk_free_gb=80.0,
            pending_reboot_days=0,
            software=[{"name": "av-edr-agent", "version": "4.1.7"}],
        )
        out = simulate_install(victim, patch_row, {}, seed=1337)
        assert out["failure_class"] == "av_conflict"

    def test_driver_conflict(self, patch_by_id):
        patch_row = patch_by_id["KB-SIM-2026-019"]
        victim = SimpleNamespace(
            id=-5, hostname="EXLAP-X", os="windows-11-23h2",
            department="executives", role="exec-laptop", criticality="high",
            health_score=95, historical_patch_failures=0, disk_free_gb=120.0,
            pending_reboot_days=0,
            software=[{"name": "dock-driver", "version": "1.4.x"}],
        )
        out = simulate_install(victim, patch_row, {}, seed=1337)
        assert out["failure_class"] == "driver_conflict"

    def test_healthy_compatible_succeeds_deterministically(self, patch_by_id):
        patch_row = patch_by_id[BAD_PATCH_ID]
        ok = SimpleNamespace(
            id=-6, hostname="OK-1", os="windows-10-22h2",
            department="call-center", role="agent-ws", criticality="medium",
            health_score=95, historical_patch_failures=0, disk_free_gb=100.0,
            pending_reboot_days=0, software=[],
        )
        a = simulate_install(ok, patch_row, {}, seed=1337)
        b = simulate_install(ok, patch_row, {}, seed=1337)
        assert a == b
        assert a["outcome"] in ("success", "pending_reboot")

    def test_pending_reboot_only_when_required(self, patch_by_id):
        patch_row = patch_by_id["KB-SIM-2026-010"]  # reboot_required False
        ok = SimpleNamespace(
            id=-7, hostname="NR-1", os="windows-10-22h2",
            department="call-center", role="agent-ws", criticality="medium",
            health_score=95, historical_patch_failures=0, disk_free_gb=80.0,
            pending_reboot_days=0, software=[{"name": "av-edr-agent", "version": "5.0.0"}],
        )
        out = simulate_install(ok, patch_row, {}, seed=1337)
        assert out["outcome"] == "success"


class TestTransientModel:
    def test_probability_monotonic_in_health(self):
        assert transient_failure_probability(80, 0) < \
            transient_failure_probability(45, 0) < \
            transient_failure_probability(20, 5)

    def test_probability_bounded(self):
        for h in range(0, 101, 10):
            for f in range(0, 8, 2):
                p = transient_failure_probability(h, f)
                assert 0.0 <= p <= 0.35
