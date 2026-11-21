// Thin fetch wrapper. All endpoints are same-origin under /api/v1.
const BASE = "/api/v1";

async function request(path, options = {}) {
  let resp;
  try {
    resp = await fetch(BASE + path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch (err) {
    throw new Error("network error: " + err.message);
  }
  let body = null;
  const text = await resp.text();
  if (text) {
    try { body = JSON.parse(text); } catch { body = { detail: text }; }
  }
  if (!resp.ok) {
    const detail = body && body.detail ? JSON.stringify(body.detail).slice(0, 200) : resp.status;
    const err = new Error(`${resp.status} ${detail}`);
    err.status = resp.status;
    err.body = body;
    throw err;
  }
  return body;
}

export const api = {
  meta: () => request("/meta"),
  readiness: () => request("/readiness").catch(() => null),
  fleetSummary: () => request("/fleet/summary"),
  endpoints: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request("/fleet/endpoints" + (q ? "?" + q : ""));
  },
  catalog: () => request("/catalog"),
  compatibility: (patchId, policy = "canary_prove") =>
    request(`/compatibility/${encodeURIComponent(patchId)}?at_risk_policy=${policy}`),
  vulnerabilities: () => request("/vulnerabilities"),
  detections: () => request("/detections"),
  metricsSummary: () => request("/metrics/summary"),
  metricSnapshots: (limit = 60) => request(`/metrics/snapshots?limit=${limit}`),
  campaigns: () => request("/campaigns?limit=100"),
  campaignDetail: (id) => request(`/campaigns/${id}`),
  createCampaign: (patchId, name, policy) =>
    request("/campaigns", { method: "POST", body: JSON.stringify({ patch_id: patchId, name, at_risk_policy: policy }) }),
  deleteCampaign: (id) => request(`/campaigns/${id}`, { method: "DELETE" }),
  plan: (id) => request(`/campaigns/${id}/plan`, { method: "POST", body: "{}" }),
  start: (id) => request(`/campaigns/${id}/start`, { method: "POST", body: "{}" }),
  emergencyOverride: (id) => request(`/campaigns/${id}/emergency-override`, { method: "POST", body: "{}" }),
  advance: (id) => request(`/campaigns/${id}/advance`, { method: "POST", body: "{}" }),
  rollback: (id) => request(`/campaigns/${id}/rollback`, { method: "POST", body: "null", headers: { "Content-Type": "application/json" } }),
  rings: (id) => request(`/campaigns/${id}/rings`),
  executions: (id) => request(`/campaigns/${id}/executions`),
  results: (id, outcome = "") =>
    request(`/campaigns/${id}/results?limit=200${outcome ? "&outcome=" + outcome : ""}`),
  failures: (id) => request(`/campaigns/${id}/failures`),
  rca: (id) => request(`/campaigns/${id}/rca`),
  validations: (id, phase = "") =>
    request(`/campaigns/${id}/validations${phase ? "?phase=" + phase : ""}`),
  events: (id = null, limit = 120) =>
    request(id ? `/campaigns/${id}/events?limit=${limit}` : `/events?limit=${limit}`),
  actions: (id) => request(`/campaigns/${id}/actions`),
  riskAssessments: (id) => request(`/risk-assessments?campaign_id=${id}&limit=500`),
  approvals: () => request("/approvals"),
  approve: (approvalId) => request(`/approvals/${approvalId}/approve`, { method: "POST", body: "{}" }),
  reject: (approvalId) => request(`/approvals/${approvalId}/reject`, { method: "POST", body: "{}" }),
  rollbacks: (id = null) => request(`/rollbacks${id ? "?campaign_id=" + id : ""}`),
  runEvaluation: (estateSize = 400) =>
    request(`/evaluation/run?estate_size=${estateSize}`, { method: "POST", body: "{}" }),
  evaluationRuns: () => request("/evaluation/runs?limit=5"),
  tools: () => request("/tools"),
  auditTrail: (limit = 60) => request(`/audit/tool-calls?limit=${limit}`),
};
