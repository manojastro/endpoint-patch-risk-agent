"""Application dependency graph (blast-radius analysis) built with networkx.

Dependency edges are derived deterministically from endpoint roles:
  consumer role -> provider role within the same department.
"""
from __future__ import annotations

from collections import defaultdict

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Endpoint

# (consumer_role, provider_role): the provider's outage takes the consumer down.
DEPENDENCY_EDGES: list[tuple[str, str]] = [
    ("pos-terminal", "store-server"),
    ("back-office", "store-server"),
    ("scanner-handheld", "warehouse-server"),
    ("dock-kiosk", "warehouse-server"),
    ("agent-ws", "supervisor-ws"),
    ("analyst-ws", "finance-app-server"),
    ("dev-ws", "infra-server"),
    ("build-agent", "infra-server"),
    ("lab-box", "lab-server"),
]


def build_dependency_graph(endpoints: list) -> nx.DiGraph:
    """Nodes: 'ep:<id>'. Edge consumer -> provider."""
    g = nx.DiGraph()
    providers_by_dept: dict[tuple[str, str], list] = defaultdict(list)
    for e in endpoints:
        g.add_node(f"ep:{e.id}", hostname=e.hostname, role=e.role,
                   department=e.department, criticality=e.criticality)
        providers_by_dept[(e.department, e.role)].append(e)
    for e in endpoints:
        for consumer_role, provider_role in DEPENDENCY_EDGES:
            if e.role == consumer_role:
                for p in providers_by_dept.get((e.department, provider_role), []):
                    g.add_edge(f"ep:{e.id}", f"ep:{p.id}",
                               relation=f"{consumer_role}->{provider_role}")
    return g


def dependents_count(g: nx.DiGraph, endpoint_id: int) -> int:
    """Number of endpoints that directly depend on this one."""
    node = f"ep:{endpoint_id}"
    if node not in g:
        return 0
    return g.in_degree(node)


def blast_radius(g: nx.DiGraph, endpoint_ids: list[int]) -> dict:
    """If these endpoints fail, what falls over? (direct + transitive)."""
    seeds = {f"ep:{i}" for i in endpoint_ids if f"ep:{i}" in g}
    impacted = set(seeds)
    frontier = set(seeds)
    # Consumers depend on providers; a provider failure walks REVERSE edges to consumers.
    while frontier:
        nxt: set[str] = set()
        for node in frontier:
            preds = set(g.predecessors(node))
            nxt |= preds - impacted
        impacted |= nxt
        frontier = nxt
    by_role: defaultdict[str, int] = defaultdict(int)
    by_dept: defaultdict[str, int] = defaultdict(int)
    hostnames = []
    for node in impacted:
        data = g.nodes[node]
        by_role[data["role"]] += 1
        by_dept[data["department"]] += 1
        hostnames.append(data["hostname"])
    return {
        "seed_count": len(seeds),
        "impacted_total": len(impacted),
        "downstream_impacted": len(impacted) - len(seeds),
        "by_role": dict(sorted(by_role.items(), key=lambda kv: -kv[1])),
        "by_department": dict(sorted(by_dept.items(), key=lambda kv: -kv[1])),
        "sample_hostnames": sorted(hostnames)[:10],
    }


def load_graph_from_db(db: Session) -> tuple[nx.DiGraph, list]:
    endpoints = db.scalars(select(Endpoint)).all()
    return build_dependency_graph(endpoints), endpoints
