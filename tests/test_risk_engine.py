"""Unit tests: risk engine weights, bucket boundaries, factor behaviour,
and the authored ground-truth endpoint/patch pairs."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.risk_engine import (
    WEIGHTS, assess_endpoint_patch, bucket_for_score, compute_factor_values,
    compute_score,
)

GT_PATH = Path(__file__).resolve().parents[1] / "evaluation" / "ground_truth.json"


class TestWeightsAndBuckets:
    def test_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_bucket_boundaries(self):
        assert bucket_for_score(100.0) == "P1"
        assert bucket_for_score(70.0) == "P1"
        assert bucket_for_score(69.999) == "P2"
        assert bucket_for_score(55.0) == "P2"
        assert bucket_for_score(54.999) == "P3"
        assert bucket_for_score(40.0) == "P3"
        assert bucket_for_score(39.999) == "P4"
        assert bucket_for_score(0.0) == "P4"

    def test_score_is_weighted_sum(self):
        factors = {k: 50.0 for k in WEIGHTS}
        assert compute_score(factors) == 50.0
        factors2 = dict.fromkeys(WEIGHTS, 0.0)
        factors2["business_criticality"] = 100.0
        expected = round(100.0 * WEIGHTS["business_criticality"], 4)
        assert compute_score(factors2) == expected


def craft(spec: dict) -> SimpleNamespace:
    return SimpleNamespace(
        id=-1, hostname="crafted", os=spec.get("os", "windows-11-23h2"),
        department=spec.get("department", "it-lab"),
        role=spec.get("role", "lab-box"),
        criticality=spec.get("criticality", "low"),
        health_score=spec.get("health_score", 80),
        historical_patch_failures=spec.get("historical_patch_failures", 0),
        disk_free_gb=spec.get("disk_free_gb", 100),
        ram_gb=16, pending_reboot_days=spec.get("pending_reboot_days", 0),
        software=spec.get("software", []),
    )


class TestGroundTruthPairs:
    """The exact pairs from evaluation/ground_truth.json must score as authored."""

    def test_pairs_from_ground_truth(self, patch_by_id):
        gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
        for pair in gt["scenarios"]["risk_pairs"]["pairs"]:
            patch_row = patch_by_id[pair["patch_id"]]
            crafted = craft(pair["endpoint"])
            result = assess_endpoint_patch(crafted, patch_row,
                                           pair.get("dependents_count", 0))
            assert result["bucket"] == pair["expected_bucket"], (
                f"{pair['id']}: score={result['score']} factors={result['factor_values']}"
            )


class TestFactors:
    def test_kev_dominates_cvss(self, patch_by_id):
        base = dict(os="windows-server-2022", role="store-server",
                    criticality="critical", health_score=90,
                    disk_free_gb=500, software=[])
        e = craft(base)
        kev_patch = SimpleNamespace(
            patch_id="X", severity="critical", reboot_required=False,
            disk_space_required_mb=100, prerequisites=[], known_issues=[],
            cves=[SimpleNamespace(cvss=9.0, known_exploited=True)],
            supersedes=[],
        )
        plain_patch = SimpleNamespace(
            patch_id="Y", severity="critical", reboot_required=False,
            disk_space_required_mb=100, prerequisites=[], known_issues=[],
            cves=[SimpleNamespace(cvss=9.0, known_exploited=False)],
            supersedes=[],
        )
        kev_score = assess_endpoint_patch(e, kev_patch)["score"]
        plain_score = assess_endpoint_patch(e, plain_patch)["score"]
        assert kev_score - plain_score == pytest.approx(100.0 * 0.15 * (1.0 - 0.9))

    def test_insufficient_disk_caps_factor(self):
        e = craft(dict(disk_free_gb=1.0))
        p = SimpleNamespace(patch_id="Z", severity="low", cves=[],
                            disk_space_required_mb=4000, reboot_required=False,
                            prerequisites=[], known_issues=[])
        factors = compute_factor_values(e, p)
        assert factors["disk_headroom"] == 100.0

    def test_compat_hit_flagged(self):
        e = craft(dict(os="windows-10-22h2",
                       software=[{"name": "av-edr-agent", "version": "4.1.7"}]))
        p = SimpleNamespace(
            patch_id="AV", severity="moderate", cves=[],
            disk_space_required_mb=10, reboot_required=False,
            prerequisites=[],
            known_issues=[SimpleNamespace(
                kind="av_agent", app_name="av-edr-agent", version_below="4.2.0",
                failure_class="av_conflict", description="d")],
        )
        result = assess_endpoint_patch(e, p)
        assert result["factor_values"]["compat_hit"] == 100.0

    def test_assessment_persists_weights(self):
        e = craft({})
        p = SimpleNamespace(patch_id="W", severity="low", cves=[],
                            disk_space_required_mb=10, reboot_required=False,
                            prerequisites=[], known_issues=[])
        result = assess_endpoint_patch(e, p)
        assert result["weights"] == WEIGHTS
