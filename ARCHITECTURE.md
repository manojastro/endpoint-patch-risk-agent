# Architecture

## Layers

```
frontend/ (vanilla JS SPA, dark SecOps theme)
    |  fetch /api/v1/*
backend/app/
    api/        FastAPI routers (meta, fleet, campaigns, ops) - thin HTTP shells
    tools/      12 agent tools: allow-list + JSON-schema validation + audit rows
    workflow/   server-enforced state machine + agent orchestration
    agents/     9 agents (inventory, vulnerability, compatibility, dependency,
                risk, planning, rca, rollback, validation) over a shared
                Fact/Decision/StageRun evidence protocol
    engine/     pure decision logic: applicability, risk, rollout, RCA,
                validation, detectors, dependency graph
    llm/        provider seam: MockLLMProvider (default) / OpenAICompatibleProvider
simulator/      deterministic fleet + catalog generation, world seeding
evaluation/     ground_truth.json + sandbox harness (throwaway SQLite per run)
```

Direction of dependencies is strictly inward: API -> workflow -> agents/engine ->
models/db. The engine modules are importable and testable without FastAPI.

## Data model (26 tables, SQLAlchemy 2.x)

Core: `Endpoint`, `Patch` (+ `PatchCVE`, `PatchKnownIssue`, `Supersedence`),
`EndpointPatchState` (per endpoint x patch state machine), `Finding`.

Campaigns: `Campaign` (status, at_risk_policy, emergency_approved, blocked_reason,
stop_reason), `RingPlan` (endpoint_ids JSON, threshold per ring),
`RingExecution` (rates, stop_triggered), `DeviceInstallResult` (outcome,
failure_class, attempts), `Validation` (post_patch/post_rollback check lists),
`Outcome`, `Rollback`.

Governance/evidence: `Approval` (deployment | emergency_override | rollback),
`Investigation` -> `StageRun` / `Evidence` / `DecisionRow`, `RCARecord`,
`Action` (recommendations), `Event` (audit feed), `ToolCall` (tool audit),
`MetricSnapshot`, `EvaluationRun`, `DepartmentRow`.

SQLite in WAL mode with `synchronous=OFF` for simulator-grade throughput; the URL
swaps to PostgreSQL without code changes (psycopg driver installed).

## Workflow states (server-enforced)

```
DETECTED -> INVESTIGATING -> DIAGNOSED -> PLANNED -> AWAITING_APPROVAL
     -> APPROVED -> EXECUTING <-> VERIFYING -> COMPLETED
                    |                 |
                    +-> FAILED -> ROLLED_BACK -> (PLANNED | COMPLETED)
```

- `TRANSITIONS` dict is the single authority; illegal moves raise
  `WorkflowViolation` (HTTP 409).
- Execution requires an APPROVED deployment approval record. Unapproved advance
  raises `PermissionError` (HTTP 403). A rejected approval sets
  `blocked_reason`, which blocks all further execution.
- Emergency fast-track is a SEPARATE approval type (`emergency_override`);
  approving it re-plans rings so critical-tier devices may enter early rings.
  It never bypasses the deployment gate itself - the campaign still transitions
  through APPROVED before any device is touched.

LangGraph mapping note: each function corresponds to a graph node; the persisted
`campaigns.status` column is the serialized graph state; AWAITING_APPROVAL is the
human-in-the-loop interrupt point.

## Ring planner

| Ring | Population | Notes |
|---|---|---|
| RING_0 lab | healthiest it-lab boxes, cap 25 | cleanest smoke signal |
| RING_1 canary | max(5, ~1%) + 2 reps per at-risk cohort (`canary_prove`) | cohort reps make detection deterministic, not lucky |
| RING_2 pilot | ~5%, department-stratified diversity fill | critical tier still deferred |
| RING_3 dept wave | ~30% | critical tier admitted |
| RING_4 broad | remainder | |

Critical-tier devices (rank-gated) cannot appear before RING_3 unless
`emergency_approved`. Diversity fill round-robins across (department, os)
segments ordered by criticality.

## Install outcome model (deterministic)

`simulate_install` evaluates rules in a fixed order against endpoint attributes x
catalog facts, using `stable_ratio(key)` = sha256-derived float in [0,1):

1. not applicable (OS mismatch / already current / superseded) -> skipped
2. insufficient disk -> `disk_space`
3. missing prerequisite -> `missing_prereq`
4. public known-issue match (version-aware, e.g. suite 7.3.1 < 7.4.2)
   -> catalog failure class (`app_crash` / `driver_conflict` / `av_conflict`)
5. transient probability by health/history (1%-35%), one automatic retry at 80%
   success -> `network_loss` / `partial_install`
6. success, or `pending_reboot` when reboot required (executor applies the
   reboot during the ring)

No runtime randomness anywhere: identical seed => identical outcomes, which is
what makes the labeled evaluation meaningful.

## Stop conditions

Per-ring thresholds (strictly greater than): RING_0 10%, RING_1 **5%**,
RING_2 3%, RING_3 2%, RING_4 2%. Any boot failure on a critical-tier device halts
immediately regardless of rate. On halt the workflow runs RCA + validation
agents, marks the campaign FAILED, recommends rollback, and every unexecuted
ring is recorded as `skipped`.

## Root-cause analysis

Version-aware differential analysis: failed vs succeeded peers in the same ring;
when a failing app matches a catalog known_issue below its version floor with
fail-rate >= 0.6 and ok-rate <= 0.3, the hypothesis is marked catalog-confirmed
(confidence 0.95). Undocumented causes fall back to generic app-presence
correlation (confidence 0.85) with a recommendation to add a catalog entry.

## Frontend

Static files under `frontend/`, mounted LAST so `/api/v1/*` wins. Vanilla ES
modules, no build step, no CDN. Views: Overview (fleet KPIs, compliance bars,
KEV-first vulnerability table, detector findings, trend sparkline), Patch
Catalog (with compatibility matrix + cohort chips), Campaigns (list, lifecycle
controls, ring funnel with threshold markers, failures/RCA, live event feed,
risk distribution, tool audit trail), Evaluation & Tools (ground-truth runner +
12-tool registry). Amber MOCK MODE badge comes from `/api/v1/meta`.
