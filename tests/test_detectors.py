"""Detector tests over the seeded world + dependency graph behaviour."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.engine.detectors import run_all_detectors, sort_findings
from simulator.generate_catalog import BAD_PATCH_ID


class TestDetectors:
    def test_critical_exploit_detector_fires(self, dbsession):
        findings = run_all_detectors(dbsession)
        types = {f["type"] for f in findings}
        assert "critical-unpatched-with-known-exploit" in types

    def test_eol_segment_detected(self, dbsession):
        findings = run_all_detectors(dbsession)
        eol = [f for f in findings if f["type"] == "unsupported-eol-os-segment"]
        assert eol and eol[0]["count"] > 20

    def test_incompatibility_exposure_for_bad_patch(self, dbsession):
        findings = run_all_detectors(dbsession)
        exposures = [f for f in findings
                     if f["type"] == "application-incompatibility-exposure"
                     and BAD_PATCH_ID in f["scope"]]
        assert exposures and exposures[0]["count"] >= 1

    def test_config_noncompliance_detected(self, dbsession):
        findings = run_all_detectors(dbsession)
        assert any(f["type"] == "config-noncompliance" for f in findings)

    def test_sorting_is_severity_first(self, dbsession):
        ordered = sort_findings(run_all_detectors(dbsession))
        ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        seq = [ranks[f["severity"]] for f in ordered]
        assert seq == sorted(seq)


class TestDependencyGraph:
    def test_store_server_has_dependents(self, dbsession):
        from sqlalchemy import select
        from app.engine.dependencies import (
            blast_radius, build_dependency_graph, dependents_count,
        )
        from app.models import Endpoint

        endpoints = dbsession.scalars(select(Endpoint)).all()
        g = build_dependency_graph(endpoints)
        servers = [e for e in endpoints if e.role == "store-server"]
        assert servers and any(dependents_count(g, s.id) > 3 for s in servers)

    def test_blast_radius_reaches_consumers(self, dbsession):
        from sqlalchemy import select
        from app.engine.dependencies import blast_radius, build_dependency_graph
        from app.models import Endpoint

        endpoints = dbsession.scalars(select(Endpoint)).all()
        g = build_dependency_graph(endpoints)
        server = next(e for e in endpoints if e.role == "store-server")
        br = blast_radius(g, [server.id])
        assert br["seed_count"] == 1
        assert br["downstream_impacted"] > 0
        assert "pos-terminal" in br["by_role"]
