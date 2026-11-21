"""Simulator tests: fleet determinism, catalog integrity, planted cohorts."""
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from simulator.generate_catalog import (
    BAD_PATCH_ID, CLEAN_PATCH_ID, SCANNER_COMPAT_FLOOR, build_catalog,
)
from simulator.generate_fleet import (
    generate_fleet, fleet_checksum, old_scanner_suite_rate,
)


class TestFleetDeterminism:
    def test_same_seed_same_world(self):
        a = generate_fleet(500, 1337)
        b = generate_fleet(500, 1337)
        assert fleet_checksum(a) == fleet_checksum(b)
        assert [e["hostname"] for e in a] == [e["hostname"] for e in b]

    def test_different_seed_differs(self):
        a = generate_fleet(500, 1337)
        b = generate_fleet(500, 99)
        assert fleet_checksum(a) != fleet_checksum(b)

    def test_unique_hostnames(self):
        fleet = generate_fleet(800, 1337)
        hostnames = [e["hostname"] for e in fleet]
        assert len(hostnames) == len(set(hostnames)) == 800


class TestCatalogIntegrity:
    def test_at_least_20_patches(self):
        catalog = build_catalog()
        assert len(catalog) >= 20

    def test_unique_patch_ids(self):
        ids = [p["patch_id"] for p in build_catalog()]
        assert len(ids) == len(set(ids))

    def test_designed_bad_patch_present(self):
        catalog = build_catalog()
        bad = next(p for p in catalog if p["patch_id"] == BAD_PATCH_ID)
        issues = bad["known_issues"]
        assert any(
            i["app_name"] == "warehouse-scanner-suite"
            and i["version_below"] == SCANNER_COMPAT_FLOOR
            and i["failure_class"] == "app_crash"
            for i in issues
        )
        # It must be a critical patch with an exploited CVE to justify rollout.
        assert bad["severity"] == "critical"
        assert any(c["known_exploited"] for c in bad["cves"])

    def test_clean_patch_has_no_known_issues(self):
        catalog = build_catalog()
        clean = next(p for p in catalog if p["patch_id"] == CLEAN_PATCH_ID)
        assert clean["known_issues"] == []

    def test_supersedence_references_resolve(self):
        catalog = build_catalog()
        ids = {p["patch_id"] for p in catalog}
        for p in catalog:
            for older in p["supersedes"]:
                assert older in ids
            if p["superseded_by"]:
                assert p["superseded_by"] in ids

    def test_prerequisites_reference_existing_patches(self):
        catalog = build_catalog()
        ids = {p["patch_id"] for p in catalog}
        for p in catalog:
            for pre in p["prerequisites"]:
                assert pre in ids

    def test_severities_valid(self):
        allowed = {"critical", "high", "moderate", "low"}
        for p in build_catalog():
            assert p["severity"] in allowed


class TestPlantedCohorts:
    def test_old_scanner_rate_near_8_percent(self):
        fleet = generate_fleet(2500, 1337)
        rate = old_scanner_suite_rate(fleet)
        assert 0.05 <= rate <= 0.11, f"warehouse cohort rate {rate:.3f}"

    def test_cohort_on_windows_10_handhelds(self):
        fleet = generate_fleet(2500, 1337)
        for e in fleet:
            for item in e["software"]:
                if item["name"] == "warehouse-scanner-suite" and item["version"] == "7.3.1":
                    assert e["department"] == "warehouse"
                    assert e["os"] == "windows-10-22h2"

    def test_eol_flag_consistent(self):
        fleet = generate_fleet(600, 1337)
        for e in fleet:
            assert e["eol"] == (e["os"] == "windows-10-22h2")
            if e["eol"]:
                assert "eol-os" in e["compliance_flags"]

    def test_department_distribution(self):
        fleet = generate_fleet(2500, 1337)
        counts = Counter(e["department"] for e in fleet)
        expected_depts = {"retail-pos", "warehouse", "call-center", "engineering",
                          "finance", "executives", "it-lab"}
        assert set(counts) == expected_depts
        assert counts["it-lab"] >= 20  # ring-0 needs lab coverage

    def test_critical_tier_exists(self):
        fleet = generate_fleet(600, 1337)
        crits = Counter(e["criticality"] for e in fleet)
        assert crits["critical"] > 10 and crits["low"] > 10


class TestSeededWorld:
    def test_world_persisted(self, dbsession):
        from sqlalchemy import func, select
        from app.models import Endpoint, EndpointPatchState, Finding, Patch

        n_ep = dbsession.scalar(select(func.count()).select_from(Endpoint))
        n_patches = dbsession.scalar(select(func.count()).select_from(Patch))
        n_states = dbsession.scalar(select(func.count()).select_from(EndpointPatchState))
        n_findings = dbsession.scalar(select(func.count()).select_from(Finding))
        assert n_ep == 600
        assert n_patches >= 20
        assert n_states > n_ep
        assert n_findings > 0

    def test_bad_patch_state_rows_exist(self, dbsession):
        from sqlalchemy import select
        from app.models import EndpointPatchState

        rows = dbsession.scalars(select(EndpointPatchState).where(
            EndpointPatchState.patch_id == BAD_PATCH_ID)).all()
        assert rows, "expected patch-state rows for the designed bad patch"
        states = {r.state for r in rows}
        assert "installed" in states or "applicable" in states
