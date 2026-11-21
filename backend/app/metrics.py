"""Prometheus metrics registry (process-wide singletons)."""
from prometheus_client import Counter, Gauge, Histogram

TOOL_CALLS_TOTAL = Counter(
    "patch_tool_calls_total", "Tool invocations", ["tool", "status"]
)
TOOL_ERRORS_TOTAL = Counter(
    "patch_tool_errors_total", "Tool errors", ["tool"]
)
TOOL_DURATION = Histogram(
    "patch_tool_duration_seconds", "Tool duration", ["tool"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
STAGE_DURATION = Histogram(
    "patch_stage_duration_seconds", "Workflow stage duration", ["agent"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
LLM_LATENCY = Histogram(
    "patch_llm_latency_seconds", "LLM provider latency", ["mode"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
CAMPAIGN_HALTS_TOTAL = Counter(
    "patch_campaign_halts_total", "Autonomous campaign halts", ["ring", "reason_class"]
)
ROLLBACKS_TOTAL = Counter(
    "patch_rollbacks_total", "Rollbacks performed", ["outcome"]  # outcome: success|failed
)
UNSAFE_PREVENTIONS_TOTAL = Counter(
    "patch_unsafe_deployments_prevented_total",
    "Unsafe deployments prevented (halt/reject/exclusion gate)",
    ["kind"],
)
COMPLIANCE_RATIO = Gauge(
    "patch_compliance_ratio", "Current patch compliance ratio (0..1)"
)
ENDPOINTS_TOTAL = Gauge("patch_endpoints_total", "Endpoints in the estate")
CRITICAL_KEV_EXPOSURES = Gauge(
    "patch_critical_kev_exposures", "Endpoints exposed to known-exploited critical CVEs"
)
