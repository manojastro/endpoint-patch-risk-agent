# Security posture

This is a local POC against a SIMULATED estate - it touches no real endpoints -
but the control plane is built the way a production one should be:

## Tool gating

- Exactly **12 registered tools**, resolved through an allow-list registry.
  Unknown tool names raise `ToolError` AND are written to the audit trail with
  `ok=false`.
- Every call is JSON-schema validated before execution; malformed arguments are
  rejected, never "best-effort" coerced.
- Risk levels: read tools `read`, state-changing tools `write`,
  `start_campaign` / `advance_ring` / `rollback_ring` are **high risk** and
  require `human-approval` permission. The advance tool independently re-checks
  the campaign gate and raises `ToolPermissionError` without an approved
  deployment - defense in depth on top of the workflow check.
- **No shell/subprocess/file-exec tools exist.** The agent cannot execute
  arbitrary code; its entire action surface is the 12 typed tools.

## Approval gates

- Deployments require an explicit `deployment` approval record (type, requester,
  decider, timestamps persisted). Rejection sets `blocked_reason` which blocks
  execution even if a later approval attempt occurs.
- Emergency fast-track is a distinct `emergency_override` approval type; it
  widens ring placement policy but still routes through APPROVED status. Double
  overrides raise WorkflowViolation.
- Unsafe-prevention counters increment on every halt and rejection
  (`unsafe_deployment_preventions` KPI).

## Workflow integrity

- State transitions are enforced server-side from a single TRANSITIONS map;
  clients cannot skip the approval gate by crafting requests (verified: HTTP 403
  on unapproved advance, HTTP 409 on illegal transitions).
- On halt: RCA + validation agents run automatically, unexecuted rings are
  recorded `skipped`, and rollback restores prior patch states with post-rollback
  validation per device.

## API hardening

- Generic 500 handler returns `{detail, request_id}` only - no stack traces to
  clients (logged server-side with the same request_id).
- Request validation errors return structured 422s.
- CORS restricted to configured origins (`CORS_ORIGINS`), credentials disabled.
- All list endpoints have bounded limits (ge/le constraints) to prevent
  unbounded queries.

## Auditability

Every consequential act is persisted: `Event` rows (state transitions, halts,
approvals, rollbacks), `Action` rows (recommendations with reasons),
`DecisionRow`s (agent decisions with confidence + rejected alternatives),
`Evidence` rows (facts agents reasoned over), `StageRun` rows (per-agent output +
rationale + LLM mode), and `ToolCall` rows (arguments, results, duration,
risk level). The SPA surfaces the event feed and tool audit trail directly.

## Known gaps (also in LIMITATIONS.md)

No authentication/authorization layer yet (single-operator POC); secrets would
live in env/config, never committed; SQLite durability tradeoff documented;
LLM provider is mock-only so prompt-injection surface is not exercised here.
