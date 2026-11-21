"""Validation engine tests: check sequence, failure mapping, reboot handling."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.validation import (
    CHECK_SEQUENCE, validate_endpoint_post_patch, validate_endpoint_post_rollback,
)

ENDPOINT = SimpleNamespace(
    id=1, hostname="V-1", os="windows-10-22h2", health_score=80, ram_gb=16,
    software=[{"name": "av-edr-agent", "version": "5.0.0"}],
)
PATCH = SimpleNamespace(patch_id="KB-V", reboot_required=True,
                        disk_space_required_mb=1000, severity="high")


def _checks_by_name(result):
    return {c["check"]: c for c in result["checks"]}


class TestCheckSequence:
    def test_sequence_matches_spec(self):
        result = validate_endpoint_post_patch(
            ENDPOINT, PATCH, {"outcome": "success", "failure_class": None}, True)
        names = [c["check"] for c in result["checks"]]
        assert names == CHECK_SEQUENCE
        assert result["passed"] is True

    def test_reboot_required_and_done(self):
        r = validate_endpoint_post_patch(
            ENDPOINT, PATCH, {"outcome": "success", "failure_class": None}, True)
        assert _checks_by_name(r)["reboot_completed"]["passed"]

    def test_pending_reboot_not_yet_done_fails(self):
        r = validate_endpoint_post_patch(
            ENDPOINT, PATCH, {"outcome": "pending_reboot", "failure_class": None},
            rebooted=False)
        assert not _checks_by_name(r)["reboot_completed"]["passed"]
        assert r["passed"] is False

    def test_no_reboot_required_trivially_passes(self):
        patch_nr = SimpleNamespace(**{**PATCH.__dict__, "reboot_required": False})
        r = validate_endpoint_post_patch(
            ENDPOINT, patch_nr, {"outcome": "success", "failure_class": None}, False)
        assert _checks_by_name(r)["reboot_completed"]["passed"]
        assert r["passed"] is True


class TestFailureMapping:
    def run_with(self, failure_class):
        return validate_endpoint_post_patch(
            ENDPOINT, PATCH, {"outcome": "failed", "failure_class": failure_class},
            rebooted=False)

    def test_boot_failure_breaks_boot_check(self):
        r = self.run_with("boot_failure")
        assert not _checks_by_name(r)["boot_ok"]["passed"]
        assert r["passed"] is False

    def test_driver_conflict_counts_as_boot_failure_class(self):
        r = self.run_with("driver_conflict")
        assert not _checks_by_name(r)["boot_ok"]["passed"]

    def test_av_conflict_breaks_services_and_security(self):
        r = self.run_with("av_conflict")
        assert not _checks_by_name(r)["services_running"]["passed"]
        assert not _checks_by_name(r)["security_posture"]["passed"]

    def test_app_crash_breaks_probe_only(self):
        r = self.run_with("app_crash")
        assert not _checks_by_name(r)["app_health_probe"]["passed"]
        assert _checks_by_name(r)["boot_ok"]["passed"]
        assert _checks_by_name(r)["security_posture"]["passed"]

    def test_network_loss_breaks_connectivity(self):
        r = self.run_with("network_loss")
        assert not _checks_by_name(r)["network_connectivity"]["passed"]

    def test_failed_install_always_fails_overall(self):
        for cls in ("disk_space", "missing_prereq", "partial_install"):
            assert self.run_with(cls)["passed"] is False


class TestRollbackValidation:
    def test_post_rollback_passes(self):
        r = validate_endpoint_post_rollback(ENDPOINT, PATCH)
        assert r["passed"] is True
        checks = _checks_by_name(r)
        assert checks["patch_absent"]["passed"]
