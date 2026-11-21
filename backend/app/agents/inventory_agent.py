"""Endpoint Inventory Agent: fleet statistics + segmentation."""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.models import Endpoint


def fleet_stats(endpoints: list) -> dict:
    by_os: defaultdict[str, int] = defaultdict(int)
    by_dept: defaultdict[str, int] = defaultdict(int)
    by_crit: defaultdict[str, int] = defaultdict(int)
    eol = reboot_stale = 0
    health_sum = disk_sum = 0
    for e in endpoints:
        by_os[e.os] += 1
        by_dept[e.department] += 1
        by_crit[e.criticality] += 1
        eol += 1 if getattr(e, "eol", False) else 0
        reboot_stale += 1 if (e.pending_reboot_days or 0) > 30 else 0
        health_sum += e.health_score or 0
        disk_sum += float(e.disk_free_gb or 0)
    n = len(endpoints) or 1
    return {
        "total_endpoints": len(endpoints),
        "by_os": dict(sorted(by_os.items(), key=lambda kv: -kv[1])),
        "by_department": dict(sorted(by_dept.items(), key=lambda kv: -kv[1])),
        "by_criticality": dict(sorted(by_crit.items())),
        "eol_count": eol,
        "pending_reboot_over_30d": reboot_stale,
        "avg_health": round(health_sum / n, 1),
        "avg_disk_free_gb": round(disk_sum / n, 1),
    }


class InventoryAgent(BaseAgent):
    name = "inventory"

    def run(self, db: Session, investigation, sequence: int = 1) -> dict:
        total = db.scalar(select(func.count()).select_from(Endpoint))
        endpoints = db.scalars(select(Endpoint)).all()
        stats = fleet_stats(endpoints)
        facts = [
            Fact("simulator.inventory",
                 f"Fleet size is {stats['total_endpoints']} endpoints.", "high"),
            Fact("simulator.inventory",
                 f"OS mix: {stats['by_os']}.", "high"),
            Fact("simulator.inventory",
                 f"Department mix: {stats['by_department']}.", "high"),
            Fact("simulator.inventory",
                 f"{stats['eol_count']} endpoints run EOL-soon Windows 10 22H2.", "high"),
            Fact("simulator.inventory",
                 f"Average health score {stats['avg_health']}; "
                 f"{stats['pending_reboot_over_30d']} devices pending reboot >30 days.",
                 "medium"),
        ]
        self.record_stage(db, investigation, sequence, facts, stats,
                          "Summarize the endpoint estate from inventory facts.")
        return stats
