"""API tests: meta/health, fleet queries + validation, campaign lifecycle,
approve/reject paths, metrics, tools listing. Runs against a pristine world
(reseeded at module start because some tests reseed via the API itself)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest


@pytest.fixture(scope="module", autouse=True)
def _pristine_world(world):
    from simulator import seed_world

    db = world.SessionLocal()
    try:
        seed_world(db, estate_size=600)
    finally:
        db.close()


class TestMeta:
    def test_meta_mock_mode(self, client):
        resp = client.get("/api/v1/meta")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mock_mode"] is True
        assert body["llm_mode"] == "mock"

    def test_health(self, client):
        assert client.get("/health").status_code == 200

    def test_readiness_ready_after_seed(self, client):
        body = client.get("/readiness").json()
        assert body["ready"] is True and body["endpoints_seeded"] > 0


class TestFleetQueries:
    def test_pagination(self, client):
        body = client.get("/api/v1/fleet/endpoints?limit=5&offset=0").json()
        assert len(body) == 5
        ids = [e["id"] for e in body]
        assert ids == sorted(ids)

    def test_filters(self, client):
        body = client.get(
            "/api/v1/fleet/endpoints?department=warehouse&limit=500").json()
        assert body and all(e["department"] == "warehouse" for e in body)

    def test_summary(self, client):
        body = client.get("/api/v1/fleet/summary").json()
        assert body["total_endpoints"] > 0
        assert sum(body["by_os"].values()) == body["total_endpoints"]

    def test_endpoint_detail_404(self, client):
        assert client.get("/api/v1/fleet/endpoints/999999").status_code == 404

    def test_invalid_criticality_is_422(self, client):
        r = client.get("/api/v1/fleet/endpoints?criticality=bogus")
        assert r.status_code == 422

    def test_invalid_limit_is_422(self, client):
        r = client.get("/api/v1/fleet/endpoints?limit=0")
        assert r.status_code == 422


class TestVulnerabilitiesAndCompat:
    def test_vulnerabilities_kev_first(self, client):
        body = client.get("/api/v1/vulnerabilities").json()
        assert body["summary"]["kev_cves"] >= 1
        groups = body["groups"]
        kev_flags = [g["known_exploited"] for g in groups]
        assert kev_flags == sorted(kev_flags, reverse=True)

    def test_compat_matrix_bad_patch_shows_risk(self, client):
        body = client.get("/api/v1/compatibility/KB-SIM-2026-002").json()
        assert body["eligible_total"] > 0
        assert any(c["at_risk"] > 0 for c in body["cells"])
        assert len(body["cohorts"]) >= 1

    def test_compat_unknown_patch_404(self, client):
        assert client.get("/api/v1/compatibility/KB-NOPE").status_code == 404


class TestCampaignLifecycle:
    def test_full_lifecycle_with_approval(self, client):
        # create (runs investigation automatically) -> DIAGNOSED
        r = client.post("/api/v1/campaigns", json={
            "patch_id": "KB-SIM-2026-006", "name": "api-lifecycle"})
        assert r.status_code == 201, r.text
        campaign_id = r.json()["id"]
        assert r.json()["status"] in ("DIAGNOSED",)

        # plan -> PLANNED
        r = client.post(f"/api/v1/campaigns/{campaign_id}/plan")
        assert r.status_code == 200 and r.json()["plans"]

        rings = client.get(f"/api/v1/campaigns/{campaign_id}/rings").json()
        assert [p["ring"] for p in rings] == [
            "RING_0", "RING_1", "RING_2", "RING_3", "RING_4"]

        # start -> AWAITING_APPROVAL with pending approval record
        r = client.post(f"/api/v1/campaigns/{campaign_id}/start")
        assert r.status_code == 200
        approval_id = r.json()["approval"]["id"]
        assert r.json()["campaign_status"] == "AWAITING_APPROVAL"

        # advance before approval -> 403
        r = client.post(f"/api/v1/campaigns/{campaign_id}/advance")
        assert r.status_code == 403

        # approve -> APPROVED, then advance executes ring 0
        r = client.post(f"/api/v1/approvals/{approval_id}/approve",
                        params={"decided_by": "tester"})
        assert r.status_code == 200
        r = client.post(f"/api/v1/campaigns/{campaign_id}/advance")
        assert r.status_code == 200
        assert r.json()["ring_execution"]["ring"] == "RING_0"

        execs = client.get(f"/api/v1/campaigns/{campaign_id}/executions").json()
        assert execs[0]["status"] == "succeeded"

    def test_reject_blocks_execution(self, client):
        r = client.post("/api/v1/campaigns", json={
            "patch_id": "KB-SIM-2026-006", "name": "api-reject"})
        campaign_id = r.json()["id"]
        client.post(f"/api/v1/campaigns/{campaign_id}/plan")
        r = client.post(f"/api/v1/campaigns/{campaign_id}/start")
        approval_id = r.json()["approval"]["id"]
        r = client.post(f"/api/v1/approvals/{approval_id}/reject",
                        params={"note": "not today"})
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        body = client.get(f"/api/v1/campaigns/{campaign_id}").json()
        assert body["status"] == "PLANNED"
        assert "rejected" in body["blocked_reason"].lower()
        r = client.post(f"/api/v1/campaigns/{campaign_id}/advance")
        assert r.status_code == 403

    def test_unknown_patch_404(self, client):
        r = client.post("/api/v1/campaigns", json={"patch_id": "KB-MISSING"})
        assert r.status_code == 404

    def test_create_body_validation_422(self, client):
        r = client.post("/api/v1/campaigns", json={})
        assert r.status_code == 422
        r = client.post("/api/v1/campaigns",
                        json={"patch_id": "KB-SIM-2026-006",
                              "at_risk_policy": "bogus"})
        assert r.status_code == 422


class TestOps:
    def test_metrics_summary_shape(self, client):
        body = client.get("/api/v1/metrics/summary").json()
        for key in ("compliance_overall_pct", "compliance_by_department",
                    "mean_time_to_patch_days", "failed_patch_rate_by_ring",
                    "canary_detection_effectiveness_pct",
                    "exposure_window_critical_kev_before_days"):
            assert key in body

    def test_tools_listing(self, client):
        body = client.get("/api/v1/tools").json()
        assert len(body) == 12
        names = {t["name"] for t in body}
        assert "rollback_ring" in names

    def test_prometheus_endpoint(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert b"patch_tool_calls_total" in r.content or b"# HELP" in r.content

    def test_evaluation_run_all_pass(self, client):
        r = client.post("/api/v1/evaluation/run", params={"estate_size": 300})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["all_passed"] is True, body["scenario_results"]
        assert body["failed_count"] == 0

    def test_static_spa_served(self, client):
        r = client.get("/")
        if r.status_code == 404:
            pytest.skip("frontend not present")
        assert "text/html" in r.headers["content-type"]
