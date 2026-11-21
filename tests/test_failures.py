"""Failure-injection tests: deterministic install outcomes for each failure
class, transient retry behaviour (forced via monkeypatched hash), and the
stop-condition wiring through evaluate_stop_condition."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest

from app.engine import rollout_engine
from app.engine.rollout_engine import simulate_install, transient_failure_probability
from simulator.generate_catalog import BAD_PATCH_ID, CLEAN_PATCH_ID


def make_endpoint(**overrides):
    # CLEAN_PATCH_ID targets ubuntu-22.04; default to a matching device.
    base = dict(
        id=1, hostname="FAIL01", os="ubuntu-22.04", os_build="22.04.4",
        department="finance", role="analyst-ws", criticality="medium",
        eol=False, disk_free_gb=100.0, ram_gb=16.0, cpu_age_years=2.0,
        health_score=95, historical_patch_failures=0, pending_reboot_days=0,
        compliance_flags=[], software=[],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture()
def clean_patch(dbsession):
    from sqlalchemy import select
    from app.models import Patch

    row = dbsession.scalar(select(Patch).where(Patch.patch_id == CLEAN_PATCH_ID))
    assert row is not None
    return row


class TestDeterministicClasses:
    def test_disk_space_failure(self, dbsession, clean_patch):
        ep = make_endpoint(disk_free_gb=0.5)
        states = {CLEAN_PATCH_ID: "applicable"}
        out = simulate_install(ep, clean_patch, states, seed=1)
        assert out["outcome"] == "failed"
        assert out["failure_class"] == "disk_space"
        assert "insufficient disk" in out["error_detail"]

    def test_missing_prereq_failure(self, dbsession):
        from sqlalchemy import select
        from app.models import Patch

        row = dbsession.scalars(select(Patch)).all()
        gated = [p for p in row if p.prerequisites]
        if not gated:
            pytest.skip("no catalog patch declares prerequisites")
        patch = gated[0]
        ep = make_endpoint(os=patch.target_os)
        states = {}  # prerequisite patches absent entirely
        out = simulate_install(ep, patch, states, seed=1)
        assert out["failure_class"] == "missing_prereq"

    def test_app_crash_from_public_known_issue(self, dbsession):
        from sqlalchemy import select
        from app.models import Patch

        bad = dbsession.scalar(select(Patch).where(Patch.patch_id == BAD_PATCH_ID))
        ep = make_endpoint(os=bad.target_os, software=[
            {"name": "warehouse-scanner-suite", "version": "7.3.1"}])
        out = simulate_install(ep, bad, {BAD_PATCH_ID: "applicable"}, seed=1)
        assert out["outcome"] == "failed"
        assert out["failure_class"] == "app_crash"
        assert "7.4.2" in out["error_detail"]

    def test_not_applicable_skipped(self, dbsession, clean_patch):
        ep = make_endpoint(os="windows-11-23h2")
        out = simulate_install(ep, clean_patch, {}, seed=1)
        assert out["outcome"] == "skipped_not_applicable"

    def test_success_is_deterministic(self, dbsession, clean_patch):
        ep = make_endpoint()
        states = {p: "up_to_date" for p in clean_patch.prerequisites or []}
        states[CLEAN_PATCH_ID] = "applicable"
        a = simulate_install(ep, clean_patch, states, seed=7)
        b = simulate_install(ep, clean_patch, states, seed=7)
        assert a == b
        assert a["outcome"] in ("success", "pending_reboot")
        if a["outcome"] == "pending_reboot":
            assert clean_patch.reboot_required is True


class TestTransientForcing:
    @pytest.fixture()
    def force_hash(self, monkeypatch):
        """Replace the hash function so every lookup gets the wanted value."""
        def _force(value_by_suffix):
            def fake(key, *args, **kwargs):
                for suffix, value in value_by_suffix.items():
                    if str(key).endswith(suffix):
                        return value
                return 0.99  # everything else: no surprise branches
            return fake
        return lambda mapping: monkeypatch.setattr(
            rollout_engine, "stable_ratio", _force(mapping))

    def test_transient_network_loss_persists_across_retry(self, force_hash,
                                                          clean_patch):
        force_hash({":transient": 0.0, ":tclass": 0.0, ":retry": 0.99})
        ep = make_endpoint()
        states = {p: "up_to_date" for p in clean_patch.prerequisites or []}
        states[CLEAN_PATCH_ID] = "applicable"
        out = simulate_install(ep, clean_patch, states, seed=1)
        assert out["outcome"] == "failed"
        assert out["failure_class"] == "network_loss"
        assert out["attempts"] == 2

    def test_transient_recovers_on_retry(self, force_hash, clean_patch):
        force_hash({":transient": 0.0, ":tclass": 0.9, ":retry": 0.1})
        ep = make_endpoint()
        states = {p: "up_to_date" for p in clean_patch.prerequisites or []}
        states[CLEAN_PATCH_ID] = "applicable"
        out = simulate_install(ep, clean_patch, states, seed=1)
        assert out["outcome"] == "success"
        assert out["attempts"] == 2
        assert out["failure_class"] is None
        assert "partial_install" in out["error_detail"]

    def test_healthy_device_rarely_transient(self):
        assert transient_failure_probability(80, 0) <= 0.02
        assert transient_failure_probability(30, 6) > transient_failure_probability(80, 0)
        assert transient_failure_probability(10, 0) <= 0.35


class TestStopConditionWiring:
    def test_boot_failure_critical_precedes_rate_rule(self):
        from app.engine.common import evaluate_stop_condition

        # Rate under threshold but one critical boot failure -> halt.
        halt, reason = evaluate_stop_condition("RING_2", 0.00, 0.03, 1)
        assert halt and "boot" in reason.lower()

    def test_rate_above_threshold_halts(self):
        from app.engine.common import evaluate_stop_condition

        halt, reason = evaluate_stop_condition("RING_1", 0.06, 0.05, 0)
        assert halt and "rate" in reason.lower()

    def test_clean_ring_continues(self):
        from app.engine.common import evaluate_stop_condition

        halt, reason = evaluate_stop_condition("RING_3", 0.01, 0.02, 0)
        assert halt is False and reason == ""
