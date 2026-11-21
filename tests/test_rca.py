"""RCA tests: taxonomy classification + root-cause correlation."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.rca import classify_failures, correlate_root_cause

ALL_CLASSES = [
    "disk_space", "app_crash", "boot_failure", "driver_conflict",
    "av_conflict", "network_loss", "partial_install", "missing_prereq",
]


class TestClassifier:
    def test_all_taxonomy_classes_map(self):
        rows = [{"failure_class": c, "error_detail": ""} for c in ALL_CLASSES]
        counts = classify_failures(rows)
        assert set(counts) == set(ALL_CLASSES)
        assert all(v == 1 for v in counts.values())

    def test_inferred_from_detail_when_class_missing(self):
        counts = classify_failures([
            {"failure_class": None, "error_detail": "disk full on C:"},
            {"failure_class": None, "error_detail": "prereq KB missing"},
            {"failure_class": None, "error_detail": "unknown"},
        ])
        assert counts == {"disk_space": 1, "missing_prereq": 1, "partial_install": 1}

    def test_empty(self):
        assert classify_failures([]) == {}


BAD_PATCH = SimpleNamespace(
    patch_id="KB-SIM-2026-002",
    known_issues=[SimpleNamespace(
        kind="app_version", app_name="warehouse-scanner-suite",
        version_below="7.4.2", failure_class="app_crash",
        description="scanner IPC handshake change")],
)


def ep(eid, suite_version):
    software = [{"name": "warehouse-scanner-suite", "version": suite_version}]
    return SimpleNamespace(id=eid, hostname=f"H{eid}", department="warehouse",
                           software=software)


class TestCorrelation:
    def test_catalog_issue_confirmed(self):
        failed = [ep(1, "7.3.1"), ep(2, "7.3.1")]
        ok = [ep(3, "7.5.1"), ep(4, "7.5.2")]
        hyps = correlate_root_cause(failed, ok, BAD_PATCH)
        assert hyps and hyps[0]["matches_catalog_known_issue"] is True
        assert hyps[0]["app_name"] == "warehouse-scanner-suite"
        assert hyps[0]["dominant_failing_version"] == "7.3.1"
        assert hyps[0]["confidence"] >= 0.9
        assert "Exclude" in hyps[0]["recommended_action"]

    def test_unknown_cause_generic_hypothesis(self):
        failed = [SimpleNamespace(id=i, hostname=f"U{i}", software=[
            {"name": "mystery-app", "version": "1.0"}]) for i in (1, 2)]
        ok = [SimpleNamespace(id=9, hostname="OK", software=[])]
        patch_unknown = SimpleNamespace(patch_id="X", known_issues=[])
        hyps = correlate_root_cause(failed, ok, patch_unknown)
        assert hyps and hyps[0]["matches_catalog_known_issue"] is False
        assert hyps[0]["app_name"] == "mystery-app"

    def test_no_failures_no_hypotheses(self):
        assert correlate_root_cause([], [], BAD_PATCH) == []

    def test_non_separating_app_ignored(self):
        # The app is present everywhere -> not a differentiator.
        eps = [ep(i, "7.5.1") for i in range(1, 6)]
        hyps = correlate_root_cause(eps[:2], eps[2:], BAD_PATCH)
        catalog_hits = [h for h in hyps if h["app_name"] == "warehouse-scanner-suite"
                        and h.get("confirmed_by_differential")]
        assert all(h["failed_presence_rate"] < 0.6 or not h["dominant_failing_version"]
                   for h in catalog_hits) or not catalog_hits
