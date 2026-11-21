# Resume bullets (implemented capabilities only; local POC measurements)

## Project: Autonomous Endpoint Patch Risk & Safe Rollout Agent
*Python 3.11, FastAPI, SQLAlchemy 2.x, Pydantic v2, pytest, Prometheus, vanilla JS SPA*

- Built a working staged-rollout decision engine for endpoint patching - weighted
  risk scoring of every endpoint x patch pair (10 factors, P1-P4 buckets),
  five-ring rollout planner with criticality gating and at-risk cohort canary
  representatives, and an autonomous stop engine that halted a designed bad-patch
  scenario at the 1% canary ring (50% observed failure vs 5% threshold) before any
  broad ring executed, on a deterministic 2,500-endpoint simulated estate.

- Implemented a server-enforced campaign state machine (12 states) with persisted
  human approval gates for deployment and emergency override; illegal transitions,
  unapproved execution, and rejected deployments are refused at the API layer
  (403/409) - verified by REST-level tests.

- Designed a version-aware root-cause analysis that differentiates failed vs
  succeeded install cohorts and confirms catalog-documented incompatibilities with
  confidence scoring (0.95 catalog-confirmed), driving automatic exclusion and
  rollback recommendations with per-device post-rollback validation.

- Enforced agentic safety by contract: exactly 12 allow-listed, schema-validated
  tools with zero shell/code-execution surface, high-risk tools gated on recorded
  human approval, and full audit persistence of arguments, results, evidence,
  decisions, and rationales for every agent action.

- Authored a labeled ground-truth evaluation harness (15 assertions across bad-
  patch detection, clean-patch progression, and pinned risk-bucket truths) that
  runs in isolated throwaway databases; all checks pass deterministically across
  seeds/runs, backed by a 157-test pytest suite at zero failures.

- Shipped the full stack as a self-contained product: FastAPI backend with
  structured 4xx/5xx errors and request IDs, Prometheus metrics + KPI snapshots,
  Docker image verified via container health check, and a zero-dependency dark
  SecOps dashboard (fleet health, KEV-first exposure table, compatibility matrix,
  live campaign funnel with threshold markers, RCA cards, tool audit trail).

Notes for tailoring:
- All numbers above are from this repo's runs (157 tests / 15 evaluation checks /
  2,500-endpoint default estate); re-measure if you change the code.
- Avoid claiming production deployments, real MDM integrations, or multi-node
  operation - see LIMITATIONS.md.
