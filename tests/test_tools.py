"""Tool registry tests: allow-list, schema validation, gating, audit rows."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest

from app.tools.base import REGISTRY, ToolError, ToolPermissionError, register_all
from simulator.generate_catalog import CLEAN_PATCH_ID

EXPECTED_TOOLS = {
    "query_fleet", "get_endpoint_detail", "query_patch_catalog",
    "compute_patch_risk", "plan_rollout", "start_campaign", "advance_ring",
    "check_ring_health", "classify_failures", "rollback_ring",
    "validate_endpoint_post_patch", "exclude_endpoints",
}


@pytest.fixture(scope="module", autouse=True)
def _registered():
    register_all()


class TestRegistry:
    def test_all_twelve_tools_registered(self):
        assert set(REGISTRY.names()) == EXPECTED_TOOLS

    def test_no_shell_tools(self):
        for name in REGISTRY.names():
            assert "shell" not in name and "exec" not in name and "subprocess" not in name

    def test_high_risk_tools_are_gated(self):
        for name in ("start_campaign", "advance_ring", "rollback_ring"):
            spec = REGISTRY.get(name)
            assert spec.risk_level == "high"
            assert spec.permission == "human-approval"

    def test_specs_expose_schema_and_timeout(self):
        spec = REGISTRY.get("query_fleet")
        assert spec.input_schema["type"] == "object"
        assert spec.timeout_s > 0
        assert spec.purpose


class TestValidationAndAudit:
    def test_unknown_tool_rejected_and_audited(self, dbsession):
        before = audit_count(dbsession)
        with pytest.raises(ToolError):
            REGISTRY.execute(dbsession, "delete_everything", {})
        assert audit_count(dbsession) == before + 1
        row = last_audit_row(dbsession)
        assert row.ok is False and row.tool_name == "delete_everything"

    def test_bad_arguments_rejected(self, dbsession):
        with pytest.raises(ToolError):
            REGISTRY.execute(dbsession, "query_fleet", {"limit": "many"})
        with pytest.raises(ToolError):
            REGISTRY.execute(dbsession, "compute_patch_risk", {})

    def test_successful_call_writes_audit_row(self, dbsession):
        before = audit_count(dbsession)
        result = REGISTRY.execute(
            dbsession, "query_fleet", {"department": "warehouse", "limit": 5})
        assert result["count"] <= 5
        assert audit_count(dbsession) == before + 1
        row = last_audit_row(dbsession)
        assert row.ok is True and row.risk_level == "read"


def audit_count(db):
    from sqlalchemy import func, select
    from app.models import ToolCall

    return db.scalar(select(func.count()).select_from(ToolCall))


def last_audit_row(db):
    from sqlalchemy import select
    from app.models import ToolCall

    return db.scalars(select(ToolCall).order_by(ToolCall.id.desc())).first()


class TestGatedTools:
    def _make_planned_campaign(self, db):
        from app.workflow import engine as wf

        campaign = wf.create_campaign(db, CLEAN_PATCH_ID, "tools-test")
        wf.run_investigation(db, campaign)
        wf.plan_campaign(db, campaign)
        return campaign

    def test_start_requires_planned_status(self, dbsession):
        from app.workflow import engine as wf

        campaign = wf.create_campaign(dbsession, CLEAN_PATCH_ID, "tools-test-raw")
        with pytest.raises(ToolError, match="PLANNED"):
            REGISTRY.execute(dbsession, "start_campaign",
                             {"campaign_id": campaign.id})

    def test_advance_refused_without_approval(self, dbsession):
        from app.workflow import engine as wf

        campaign = self._make_planned_campaign(dbsession)
        wf.request_start(dbsession, campaign)  # AWAITING_APPROVAL, no approval yet
        dbsession.commit()
        with pytest.raises(ToolPermissionError):
            REGISTRY.execute(dbsession, "advance_ring", {"campaign_id": campaign.id})

    def test_advance_allowed_after_approval(self, dbsession):
        from app.workflow import engine as wf

        campaign = self._make_planned_campaign(dbsession)
        approval = wf.request_start(dbsession, campaign)
        wf.approve(dbsession, approval)
        dbsession.commit()
        result = REGISTRY.execute(dbsession, "advance_ring", {"campaign_id": campaign.id})
        ring_result = result["ring_execution"]
        assert ring_result["status"] in ("succeeded", "halted")
