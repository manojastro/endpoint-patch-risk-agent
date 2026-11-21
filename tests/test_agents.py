"""Agent tests: mock LLM determinism, facts-only rationales, evidence rows."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.agents.base import Fact, make_investigation
from app.agents.inventory_agent import InventoryAgent, fleet_stats
from app.llm.provider import MockLLMProvider


class TestMockProvider:
    def test_deterministic(self):
        p = MockLLMProvider()
        facts = ["Fleet size is 600 endpoints.", "OS mix: {windows: 600}."]
        a = p.rationale("task", facts)
        b = p.rationale("task", facts)
        assert a == b

    def test_cites_only_supplied_facts(self):
        p = MockLLMProvider()
        fact_text = "The quick brown fox cohort has 42 devices."
        out = p.rationale("summarize", [fact_text])
        assert fact_text in out
        assert "No information beyond the supplied facts was used." in out

    def test_empty_facts_escalates(self):
        p = MockLLMProvider()
        out = p.rationale("decide", [])
        assert "No facts were supplied" in out

    def test_mode_is_mock(self):
        assert MockLLMProvider().mode == "mock"


class TestInventoryAgent:
    def test_stats_consistent(self, dbsession):
        from sqlalchemy import select
        from app.models import Endpoint

        endpoints = dbsession.scalars(select(Endpoint)).all()
        stats = fleet_stats(endpoints)
        assert stats["total_endpoints"] == len(endpoints)
        assert sum(stats["by_os"].values()) == len(endpoints)
        assert sum(stats["by_department"].values()) == len(endpoints)
        assert 0.0 <= stats["avg_health"] <= 100.0

    def test_run_persists_stage_and_evidence(self, dbsession):
        inv = make_investigation(dbsession, topic="agent-test")
        agent = InventoryAgent(MockLLMProvider())
        stats = agent.run(dbsession, inv, sequence=1)
        assert stats["total_endpoints"] > 0
        runs = list(inv.stage_runs)
        assert len(runs) == 1
        run = runs[0]
        assert run.agent == "inventory"
        assert run.llm_mode == "mock"
        assert run.output["total_endpoints"] == stats["total_endpoints"]
        assert len(run.llm_rationale) > 20
        # Evidence rows created for each supplied fact (agent decides the count).
        assert len(inv.evidence) >= 3
        assert all(ev.fact and ev.source for ev in inv.evidence)

    def test_fact_dataclass_fields(self):
        f = Fact(source="s", fact="f", reliability="medium", raw_reference="r")
        assert f.reliability == "medium" and f.raw_reference == "r"
