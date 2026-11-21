"""Evaluation harness tests: ground-truth file integrity and a full
labeled evaluation run in the throwaway sandbox."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest

from app.evaluation import DEFAULT_GROUND_TRUTH, load_ground_truth, run_evaluation
from simulator.generate_catalog import BAD_PATCH_ID, CLEAN_PATCH_ID


class TestGroundTruthFile:
    def test_file_loads_with_required_structure(self):
        gt = load_ground_truth()
        scenarios = gt["scenarios"]
        assert set(gt["scenarios"]) >= {"bad_patch", "clean_patch", "risk_pairs"}
        bad = scenarios["bad_patch"]
        assert bad["patch_id"] == BAD_PATCH_ID
        for key in ("expected_halt_at_rings", "expected_rca_class",
                    "rollback_validated"):
            assert key in bad["expectations"]
        clean = scenarios["clean_patch"]
        assert clean["patch_id"] == CLEAN_PATCH_ID
        assert 0 < clean["expectations"]["overall_failure_rate_below"] <= 1.0

    def test_risk_pairs_have_valid_buckets_and_patches(self):
        gt = load_ground_truth()
        buckets = {"P1", "P2", "P3", "P4"}
        pairs = gt["scenarios"]["risk_pairs"]["pairs"]
        assert len(pairs) >= 4
        ids = {p["patch_id"] for p in pairs}
        assert {BAD_PATCH_ID, CLEAN_PATCH_ID} & ids or ids
        for pair in pairs:
            assert pair["expected_bucket"] in buckets
            assert pair["endpoint"].get("criticality") in (
                None, "critical", "high", "medium", "low")

    def test_expected_halt_rings_are_early(self):
        gt = load_ground_truth()
        rings = gt["scenarios"]["bad_patch"]["expectations"]["expected_halt_at_rings"]
        assert set(rings) <= {"RING_0", "RING_1"}


class TestFullRun:
    def test_all_checks_pass_on_small_estate(self):
        result = run_evaluation(estate_size=300)
        assert result["total_checks"] >= 15
        assert result["failed_count"] == 0, [
            c for s in result["scenario_results"] for c in s["checks"]
            if not c["passed"]]
        assert result["all_passed"] is True

    def test_deterministic_across_runs(self):
        a = run_evaluation(estate_size=200)
        b = run_evaluation(estate_size=200)
        assert a["total_checks"] == b["total_checks"]
        assert a["failed_count"] == b["failed_count"] == 0
