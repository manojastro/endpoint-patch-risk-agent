"""Application Dependency Agent: blast radius per failing device class."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.base import BaseAgent, Fact
from app.engine.dependencies import blast_radius, build_dependency_graph


class DependencyAgent(BaseAgent):
    name = "dependency"

    def run(self, db: Session, investigation, endpoints, sequence: int = 4) -> dict:
        graph = build_dependency_graph(endpoints)
        by_role: dict[str, list] = {}
        for e in endpoints:
            by_role.setdefault(e.role, []).append(e)

        per_class = []
        for role, members in sorted(by_role.items()):
            br = blast_radius(graph, [m.id for m in members])
            per_class.append({
                "role": role,
                "device_count": len(members),
                "critical_devices": sum(1 for m in members if m.criticality == "critical"),
                **br,
            })
        per_class.sort(key=lambda r: -r["downstream_impacted"])

        top_dependents = sorted(
            ((e, graph.in_degree(f"ep:{e.id}")) for e in endpoints),
            key=lambda kv: -kv[1],
        )[:5]
        facts = [
            Fact("dependency.graph",
                 f"Dependency graph built with {graph.number_of_nodes()} nodes and "
                 f"{graph.number_of_edges()} dependency edges.", "high"),
            Fact("dependency.graph",
                 f"Highest fan-in device(s): "
                 f"{[(e.hostname, d) for e, d in top_dependents[:2]]}.", "high"),
        ]
        if per_class:
            worst = per_class[0]
            facts.append(Fact(
                "dependency.graph",
                f"Largest blast-radius class '{worst['role']}': {worst['device_count']} "
                f"devices; failure would impact {worst['impacted_total']} endpoint(s) "
                f"including {worst['downstream_impacted']} downstream consumers.",
                "high",
            ))
        output = {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "blast_radius_by_role": per_class,
            "top_dependents": [
                {"endpoint_id": e.id, "hostname": e.hostname, "role": e.role,
                 "dependents": d} for e, d in top_dependents
            ],
        }
        self.record_stage(db, investigation, sequence, facts, output,
                          "Assess blast radius of device-class failures.")
        return output
