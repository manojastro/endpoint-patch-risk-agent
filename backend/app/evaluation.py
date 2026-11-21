"""Ground-truth evaluation harness.

Runs each authored scenario inside a THROWAWAY SQLite sandbox so the main
world is never mutated, then scores assertions honestly against observed
behavior. Deterministic world -> identical results every run.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Base, make_engine
from app.engine.risk_engine import assess_endpoint_patch
from app.models import (
    Approval, Campaign, Endpoint, Patch, RingExecution,
)
from simulator import seed_world
from app.workflow import engine as wf

DEFAULT_GROUND_TRUTH = Path(__file__).resolve().parents[2] / "evaluation" / "ground_truth.json"


def load_ground_truth(path: Path | None = None) -> dict:
    path = path or DEFAULT_GROUND_TRUTH
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Sandbox:
    """Isolated DB world for one evaluation run."""

    def __init__(self, estate_size: int = 800):
        self.dir = tempfile.mkdtemp(prefix="patch-eval-")
        self.url = f"sqlite:///{Path(self.dir).joinpath('eval.db').as_posix()}"
        self.estate_size = estate_size

    def __enter__(self):
        self.engine = make_engine(self.url)
        Base.metadata.create_all(self.engine)
        from sqlalchemy.orm import sessionmaker
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        db = self.Session()
        seed_world(db, estate_size=self.estate_size)
        return self, db

    def __exit__(self, *exc):
        # Dispose only this sandbox's engine; the app-level engine/session
        # factory must stay untouched for whoever ran the evaluation.
        self.engine.dispose()
        try:
            for f in Path(self.dir).glob("*"):
                f.unlink(missing_ok=True)
            os.rmdir(self.dir)
        except OSError:
            pass
        return False


def _check(checks: list, name: str, passed: bool, detail: str = "") -> bool:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})
    return bool(passed)


def run_bad_patch_scenario(db: Session, patch_id: str, expectations: dict) -> dict:
    checks: list[dict] = []
    campaign = wf.create_campaign(db, patch_id, name="eval-bad-patch",
                                  at_risk_policy="canary_prove")
    wf.run_investigation(db, campaign)
    wf.plan_campaign(db, campaign)
    approval = wf.request_start(db, campaign)
    # Gate check first: unapproved advance must be refused.
    try:
        wf.advance(db, campaign)
        _check(checks, "approval gate enforced", False,
               "advance succeeded without an approved deployment")
    except PermissionError:
        _check(checks, "approval gate enforced", True)
    wf.approve(db, approval)

    # Drive rings until terminal state.
    ring_log: list[dict] = []
    rca_classes: set[str] = set()
    halt_seen = False
    guard = 0
    while campaign.status not in ("COMPLETED", "FAILED") and guard < 8:
        guard += 1
        try:
            result = wf.advance(db, campaign)
            re_ = result.get("ring_execution", {})
            ring_log.append(re_)
            if re_.get("stop_triggered"):
                halt_seen = True
                rca_classes |= set((re_.get("failure_classes") or {}).keys())
                rca_out = result.get("rca") or {}
                rca_classes |= set((rca_out.get("failure_classes") or {}).keys())
            if result.get("completed"):
                break
        except Exception as exc:  # noqa: BLE001 - record and stop driving
            checks.append({"check": "advance_error", "passed": False,
                           "detail": str(exc)})
            break

    executed_positions = [
        ex.position for ex in db.scalars(select(RingExecution).where(
            RingExecution.campaign_id == campaign.id)).all()
        if ex.status in ("succeeded", "halted")
    ]
    max_executed_position = max(executed_positions) if executed_positions else -1
    expected_stop_rings = {
        "RING_0": 0, "RING_1": 1, "RING_2": 2, "RING_3": 3, "RING_4": 4,
    }
    allowed_stop = {expected_stop_rings[r] for r in expectations["expected_halt_at_rings"]}

    _check(checks, "campaign halted autonomously", halt_seen or campaign.status == "FAILED",
           f"status={campaign.status}")
    _check(checks, f"stop at ring <= {max(allowed_stop)}",
           max_executed_position <= max(allowed_stop),
           f"max executed position={max_executed_position}")
    _check(checks, "no RING_3+ execution after stop",
           all(p < 3 for p in executed_positions),
           f"positions={executed_positions}")
    expected_class = expectations["expected_rca_class"]
    _check(checks, f"RCA class includes {expected_class}",
           expected_class in rca_classes, f"observed={sorted(rca_classes)}")

    # Rollback + recommendation present.
    rollback_done = False
    if campaign.status == "FAILED":
        try:
            wf.run_rollback(db, campaign)
            rollback_done = True
        except Exception as exc:  # noqa: BLE001
            checks.append({"check": "rollback_error", "passed": False, "detail": str(exc)})
    _check(checks, "rollback executed after halt", rollback_done,
           f"campaign={campaign.status}")
    from app.models import Rollback, Validation, Action
    rollbacks = db.scalars(select(Rollback)).all()
    _check(checks, "post-rollback validation passed",
           any(r.validation_passed for r in rollbacks),
           f"rollbacks={len(rollbacks)}")

    # Exclusion / remediation recommended by RCA.
    actions = db.scalars(select(Action).where(Action.campaign_id == campaign.id)).all()
    rec_types = {a.action_type for a in actions}
    _check(checks, "exclusion-or-remediation recommended",
           any(t in rec_types for t in ("exclude_cohort_recommended",
                                        "rollback_recommended")),
           f"actions={sorted(rec_types)}")
    return {"checks": checks, "ring_log": ring_log}


def run_clean_scenario(db: Session, patch_id: str, expectations: dict) -> dict:
    checks: list[dict] = []
    campaign = wf.create_campaign(db, patch_id, name="eval-clean",
                                  at_risk_policy=expectations.get("at_risk_policy", "canary_prove"))
    wf.run_investigation(db, campaign)
    wf.plan_campaign(db, campaign)
    wf.request_start(db, campaign)
    approvals = db.scalars(select(Approval).where(
        Approval.campaign_id == campaign.id)).all()
    dep = [a for a in approvals if a.approval_type == "deployment"][-1]
    wf.approve(db, dep)

    guard = 0
    while campaign.status not in ("COMPLETED", "FAILED") and guard < 10:
        guard += 1
        wf.advance(db, campaign)

    execs = db.scalars(select(RingExecution).where(
        RingExecution.campaign_id == campaign.id)).all()
    succeeded = sorted([ex.position for ex in execs if ex.status == "succeeded"])
    overall_fail = 0.0
    total_devices = sum(ex.device_count for ex in execs)
    total_fails = sum(ex.failure_count for ex in execs)
    overall_fail = total_fails / total_devices if total_devices else 0.0

    _check(checks, "all five rings executed cleanly",
           succeeded == [0, 1, 2, 3, 4], f"succeeded positions={succeeded}")
    _check(checks, f"overall failure rate below {expectations['overall_failure_rate_below']}",
           overall_fail < expectations["overall_failure_rate_below"],
           f"rate={overall_fail:.4f}")
    _check(checks, "campaign COMPLETED", campaign.status == "COMPLETED",
           f"status={campaign.status}")
    return {"checks": checks}


def score_risk_pairs(db: Session, pairs: list[dict]) -> dict:
    """Crafted endpoint+patch pairs scored against the live catalog rows."""
    from types import SimpleNamespace

    checks: list[dict] = []
    patches = {p.patch_id: p for p in db.scalars(select(Patch)).all()}
    for pair in pairs:
        patch = patches.get(pair["patch_id"])
        spec = pair["endpoint"]
        if patch is None:
            _check(checks, f"patch {pair['patch_id']} exists", False)
            continue
        crafted = SimpleNamespace(
            id=-1,
            hostname=f"crafted:{pair['id']}",
            os=spec.get("os", "windows-11-23h2"),
            department=spec.get("department", "it-lab"),
            role=spec.get("role", "lab-box"),
            criticality=spec.get("criticality", "low"),
            health_score=spec.get("health_score", 80),
            historical_patch_failures=spec.get("historical_patch_failures", 0),
            disk_free_gb=spec.get("disk_free_gb", 100),
            ram_gb=spec.get("ram_gb", 16),
            pending_reboot_days=spec.get("pending_reboot_days", 0),
            software=spec.get("software", []),
        )
        result = assess_endpoint_patch(crafted, patch,
                                       dependents_count=pair.get("dependents_count", 0))
        _check(checks,
               f"{pair['id']} ({pair['patch_id']}) -> {pair['expected_bucket']}",
               result["bucket"] == pair["expected_bucket"],
               f"score={result['score']:.2f} bucket={result['bucket']}")
    return {"checks": checks}


def run_evaluation(ground_truth_path: Path | None = None,
                   estate_size: int = 800) -> dict:
    started = time.perf_counter()
    gt = load_ground_truth(ground_truth_path)
    scenario_results: list[dict] = []

    with Sandbox(estate_size=estate_size) as (_sandbox, db):
        bad = gt["scenarios"]["bad_patch"]
        res = run_bad_patch_scenario(db, bad["patch_id"], bad["expectations"])
        scenario_results.append({
            "scenario": "bad_patch_warehouse_scanner",
            "passed": all(c["passed"] for c in res["checks"]),
            "checks": res["checks"],
        })
        db.rollback()

        clean = gt["scenarios"]["clean_patch"]
        res = run_clean_scenario(db, clean["patch_id"], clean["expectations"])
        scenario_results.append({
            "scenario": "clean_patch_progression",
            "passed": all(c["passed"] for c in res["checks"]),
            "checks": res["checks"],
        })
        db.rollback()

        risk = score_risk_pairs(db, gt["scenarios"]["risk_pairs"]["pairs"])
        scenario_results.append({
            "scenario": "risk_engine_truths",
            "passed": all(c["passed"] for c in risk["checks"]),
            "checks": risk["checks"],
        })

    total_checks = sum(len(s["checks"]) for s in scenario_results)
    passed_count = sum(len([c for c in s["checks"] if c["passed"]])
                       for s in scenario_results)
    failed_count = total_checks - passed_count
    duration_ms = int((time.perf_counter() - started) * 1000)
    return {
        "scenario_results": scenario_results,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "total_checks": total_checks,
        "all_passed": failed_count == 0,
        "duration_ms": duration_ms,
    }
