# Limitations (honest list)

## Simulation scope

- **No real MDM/Intune/WSUS/SCCM adapters.** The fleet, catalog, install
  outcomes, and reboots are simulated deterministically from endpoint attributes
  x catalog facts (`stable_ratio` sha256 hashing, seed 1337). Real-world patch
  telemetry would replace `simulator/` and the install-outcome model; every other
  layer (risk engine, planner, workflow, gates, RCA, evaluation) is agnostic.
- Install failure probabilities are plausible but authored (transient rates by
  health/history buckets; one automatic retry at 80% success). They are
  documented rules, not fitted from production telemetry.
- The catalog (22 patches, CVE-SIM-* identifiers, KEV flags) mirrors real
  structures but is synthetic by design.
- "Reboot during ring execution" collapses reboot windows to zero simulated time.

## Architecture tradeoffs

- **SQLite in WAL mode with `synchronous=OFF`**: chosen after measuring Windows
  Defender real-time scanning as the dominant I/O cost on this laptop. Durability
  on power loss is traded for throughput; PostgreSQL is a config swap
  (`DATABASE_URL`, psycopg installed), not a code change.
- **Schema management is `Base.metadata.create_all()`, not Alembic** - fine for a
  POC world that can be regenerated; migrations would be added before evolving
  schemas with live data.
- Single-process, single-node. No background scheduler: ring advancement is an
  explicit API/UI action (human-paced demo) rather than a cron-driven loop.
- Static-file SPA mounted at `/` (API routes take precedence). No auth layer:
  this assumes one local operator; production needs SSO/RBAC on top.

## LLM

- `LLM_MODE=mock` only in this build. The provider seam exists for an
  OpenAI-compatible backend, but no external LLM call is exercised here;
  rationales are deterministic templates over recorded facts (which also keeps
  the evaluation honest - agent text cannot drift between runs).

## Trims / scope cuts made deliberately

- Evaluation sandbox seeds small estates (200-800) for speed; full-scale behavior
  was verified separately at the default 2,500-endpoint estate (~6 s seed).
- Frontend is functional-first: no unit tests for JS, polling instead of
  WebSockets, sparkline-level charts instead of a charting library.
- Rollback restores patch states and re-opens findings but does not simulate
  partial uninstalls or reboot-after-rollback.
- Mean-time-to-patch KPI uses a deterministic simulated lag model, not real
  install timestamps.

## Known rough edges

- Test modules share one world DB (session fixture) for runtime; module-level
  reseeds handle isolation but mean test order within a file matters in two
  places (documented in EVALUATION.md).
- Emergency replan replaces RingPlan rows wholesale (valid because override is
  only available pre-execution); if overrides were ever allowed mid-flight this
  would need execution-aware merging.
