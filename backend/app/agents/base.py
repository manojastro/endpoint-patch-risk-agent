"""Agent infrastructure: facts, evidence persistence, LLM-grounded rationales."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.llm.provider import get_llm_provider
from app.metrics import STAGE_DURATION
from app.models import DecisionRow, Evidence, Investigation, StageRun


@dataclass
class Fact:
    source: str
    fact: str
    reliability: str = "high"
    raw_reference: str = ""


class BaseAgent:
    """Runs a deterministic computation, persists Evidence + a StageRun whose
    rationale comes from the configured LLM provider restricted to the facts."""

    name: str = "base"

    def __init__(self, provider=None):
        self.provider = provider or get_llm_provider()

    def record_stage(
        self,
        db: Session,
        investigation: Investigation,
        sequence: int,
        facts: list[Fact],
        output: dict,
        question: str,
    ) -> StageRun:
        started = time.perf_counter()
        evidence_ids: list[int] = []
        for f in facts:
            row = Evidence(
                investigation_id=investigation.id, source=f.source,
                fact=f.fact, reliability=f.reliability,
                raw_reference=f.raw_reference[:160],
            )
            db.add(row)
            db.flush()
            evidence_ids.append(row.id)

        rationale = self.provider.rationale(
            question, [f.fact for f in facts], {k: v for k, v in output.items()
                                                if isinstance(v, (int, float, str, bool))}
        )
        duration_ms = int((time.perf_counter() - started) * 1000)
        STAGE_DURATION.labels(self.name).observe(duration_ms / 1000.0)
        stage = StageRun(
            investigation_id=investigation.id, agent=self.name, sequence=sequence,
            status="done", output=output, llm_mode=self.provider.mode,
            llm_rationale=rationale, duration_ms=duration_ms,
        )
        db.add(stage)
        db.flush()
        return stage

    def record_decision(
        self, db: Session, investigation: Investigation, decision: str,
        confidence: float, evidence_ids: list[int], alternatives: list[str],
        risk_level: str = "low", requires_approval: bool = False,
    ) -> DecisionRow:
        row = DecisionRow(
            investigation_id=investigation.id, decision=decision,
            confidence=confidence, evidence_ids=evidence_ids,
            alternatives=alternatives, risk_level=risk_level,
            requires_approval=requires_approval,
        )
        db.add(row)
        db.flush()
        return row


def make_investigation(db: Session, topic: str, campaign_id: int | None = None) -> Investigation:
    inv = Investigation(topic=topic, stage="open", campaign_id=campaign_id, status="open")
    db.add(inv)
    db.flush()
    return inv
