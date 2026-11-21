"""Unit tests: applicability, supersedence, prerequisites, disk checks, cohorts."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.applicability import (
    build_cohorts, disk_sufficient, is_applicable, matching_known_issues,
    missing_prerequisites,
)


def ep(**kw):
    base = dict(
        id=1, hostname="H-1", os="windows-10-22h2", department="warehouse",
        role="scanner-handheld", criticality="medium", health_score=70,
        historical_patch_failures=0, disk_free_gb=20.0, pending_reboot_days=0,
        software=[{"name": "warehouse-scanner-suite", "version": "7.5.1"}],
    )
    base.update(kw)
    return SimpleNamespace(**base)


def patch(**kw):
    base = dict(
        patch_id="KB-T-001", target_os="windows-10-22h2", severity="critical",
        reboot_required=True, prerequisites=[], supersedes=[], superseded_by=None,
        disk_space_required_mb=1024,
        known_issues=[],
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestApplicability:
    def test_eligible(self):
        res = is_applicable(ep(), patch(), {})
        assert res.applicable and res.reason_code == "eligible"

    def test_os_mismatch(self):
        res = is_applicable(ep(os="ubuntu-22.04"), patch(), {})
        assert not res.applicable and res.reason_code == "os_mismatch"

    def test_already_installed(self):
        res = is_applicable(ep(), patch(), {"KB-T-001": "installed"})
        assert not res.applicable and res.reason_code == "already_installed"

    def test_up_to_date(self):
        res = is_applicable(ep(), patch(), {"KB-T-001": "up_to_date"})
        assert not res.applicable and res.reason_code == "up_to_date"

    def test_superseded(self):
        p = patch(superseded_by="KB-T-999")
        res = is_applicable(ep(), p, {"KB-T-999": "installed"})
        assert not res.applicable and res.reason_code == "superseded"

    def test_superseding_not_installed_still_eligible(self):
        p = patch(superseded_by="KB-T-999")
        res = is_applicable(ep(), p, {"KB-T-999": "applicable"})
        assert res.applicable


class TestPrereqsAndDisk:
    def test_missing_prereq_detected(self):
        p = patch(prerequisites=["KB-PRE"])
        assert missing_prerequisites(p, {}) == ["KB-PRE"]
        assert missing_prerequisites(p, {"KB-PRE": "applicable"}) == ["KB-PRE"]

    def test_prereq_satisfied(self):
        p = patch(prerequisites=["KB-PRE"])
        assert missing_prerequisites(p, {"KB-PRE": "installed"}) == []

    def test_disk_sufficient(self):
        assert disk_sufficient(ep(disk_free_gb=2.0), patch(disk_space_required_mb=1024))

    def test_disk_insufficient_boundary(self):
        # 2048 MB required vs 2.0 GB free -> exactly equal -> sufficient.
        assert disk_sufficient(ep(disk_free_gb=2.0), patch(disk_space_required_mb=2048))
        assert not disk_sufficient(
            ep(disk_free_gb=1.9), patch(disk_space_required_mb=2048))


class TestKnownIssues:
    ISSUE = SimpleNamespace(
        kind="app_version", app_name="warehouse-scanner-suite",
        version_below="7.4.2", failure_class="app_crash", description="d",
    )

    def test_version_below_matches(self):
        e = ep(software=[{"name": "warehouse-scanner-suite", "version": "7.3.1"}])
        hits = matching_known_issues(e, patch(known_issues=[self.ISSUE]))
        assert len(hits) == 1 and hits[0].failure_class == "app_crash"

    def test_version_at_floor_not_affected(self):
        e = ep(software=[{"name": "warehouse-scanner-suite", "version": "7.4.2"}])
        assert matching_known_issues(e, patch(known_issues=[self.ISSUE])) == []

    def test_app_absent_not_affected(self):
        e = ep(software=[])
        assert matching_known_issues(e, patch(known_issues=[self.ISSUE])) == []


class TestCohorts:
    def test_grouping_by_signature(self):
        e1 = ep(id=1, department="warehouse",
                software=[{"name": "warehouse-scanner-suite", "version": "7.3.1"}])
        e2 = ep(id=2, department="warehouse", os="windows-11-23h2",
                software=[{"name": "warehouse-scanner-suite", "version": "7.3.1"}])
        p = patch(known_issues=[TestKnownIssues.ISSUE])
        cohorts = build_cohorts([e1, e2], p)
        assert len(cohorts) == 2  # different OS -> different cohort signature
        sig1 = next(iter(cohorts))
        assert set(cohorts[sig1]["endpoint_ids"]) >= {1}
