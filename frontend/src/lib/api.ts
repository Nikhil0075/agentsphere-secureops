/**
 * API client and types.
 *
 * Types mirror the Pydantic models in app/api/models.py, which themselves reuse the frozen agent
 * contracts. A change to an agent contract shows up as a TypeScript error here, which is the
 * point of having frozen them.
 */

export type TriageLabel = "TruePositive" | "BenignPositive" | "FalsePositive";
export type RiskLevel = "low" | "medium" | "high";
export type Verdict = "accept" | "reject" | "escalate";

export interface DatasetInfo {
  source: string;
  incidents: number;
  evidence_rows: number;
  labels: Record<string, number>;
  splits: Record<string, number>;
  sentinels_masked: string[];
  index_available: boolean;
  llm_backend: string;
  witfoo: Record<string, any>;
  chain: {
    available: boolean;
    reason?: string;
    network?: string;
    chain_id?: number;
    decision_proof_address?: string;
    registry_address?: string;
    agents?: Record<string, string>;
  };
}

export interface IncidentSummary {
  incident_id: string;
  label: TriageLabel | "";
  split: string;
  risk_score: number;
  alert_count: number;
  evidence_count: number;
  top_category: string;
  top_detector: string;
  top_alert_title: string;
  max_suspicion_level: string;
  mitre_techniques: string;
  first_seen: string;
  is_showcase: boolean;
  baseline_label: string;
  baseline_confidence: number;
}

export interface IncidentDetail extends IncidentSummary {
  summary: string;
  entity_counts: Record<string, number>;
  threat_families: string;
  duration_minutes: number;
}

export interface EvidenceRow {
  evidence_id: string;
  alert_id: string;
  timestamp: string;
  entity_type: string;
  evidence_role: string;
  suspicion_level: string;
  last_verdict: string;
  fields: Record<string, string>;
}

export interface SimilarIncident {
  incident_id: string;
  score: number;
  why: string;
  summary: string;
}

export interface GraphInfo {
  blast_radius: {
    seeds: string[];
    impacted_by_type: Record<string, string[]>;
    total_nodes: number;
    hubs_blocked: string[];
    truncated: boolean;
  };
  attack_path: {
    path: string[];
    hops: number;
    probability: number;
    edge_confidences: number[];
    weakest_link: number;
  } | null;
  node_count: number;
  edge_count: number;
}

export interface PolicyCheck {
  policy_id: string;
  passed: boolean;
  detail: string;
}

export interface AgentRun {
  agent: string;
  sequence: number;
  status: string;
  attempts: number;
  latency_ms: number;
  backend: string;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  validation_error: string;
  output_hash: string;
}

export interface WorkflowResponse {
  workflow_id: string;
  incident_id: string;
  decision_id: string;
  label: TriageLabel | "";
  confidence: number;
  requires_approval: boolean;
  baseline: { label: TriageLabel; confidence: number; model_name: string } | null;
  detection: {
    severity_score: number;
    suspicious_entities: { entity_type: string; value: string; reason: string }[];
    initial_reason: string;
  } | null;
  correlation: {
    evidence_bundle: string[];
    relationships: { source: string; target: string; relation: string }[];
    timeline: { timestamp: string; description: string; evidence_id: string }[];
    missing_information: string[];
  } | null;
  investigation: {
    similar_cases: { incident_id: string; similarity: number; why_similar: string }[];
    mitre_mapping: {
      technique_id: string;
      technique_name: string;
      supporting_evidence_ids: string[];
    }[];
    investigation_summary: string;
  } | null;
  triage: {
    label: TriageLabel;
    confidence: number;
    rationale: string;
    supporting_evidence_ids: string[];
  } | null;
  remediation: {
    recommended_action: string;
    action_risk: RiskLevel;
    rollback_plan: string;
    justification: string;
  } | null;
  verifier: {
    verdict: Verdict;
    contradictions: string[];
    policy_checks: PolicyCheck[];
    escalation_required: boolean;
    reasoning: string;
  } | null;
  gate: {
    requires_approval: boolean;
    auto_approved: boolean;
    action_risk: string;
    reasons: string[];
    checks: PolicyCheck[];
  } | null;
  correlation_info: {
    alert_count: number;
    cluster_count: number;
    reduction: number;
    largest_cluster: number;
    clusters: {
      cluster_id: string;
      size: number;
      evidence_count: number;
      linking_entities: string[];
    }[];
  } | null;
  runs: AgentRun[];
  errors: string[];
  evidence_hash: string;
  output_hash: string;
  total_latency_ms: number;
  degraded_agents: string[];
}

export interface ProofInfo {
  decision_id: string;
  found: boolean;
  anchored: boolean;
  evidence_hash: string;
  output_hash: string;
  tx_hash: string;
  block_number: number | null;
  chain_id: number | null;
  contract_address: string;
  onchain_decision_id: number | null;
  onchain_state: string;
  explorer_url: string;
  valid: boolean | null;
  chain_available: boolean;
  reason: string;
}

/**
 * The result of recomputing both digests from stored data.
 *
 * `anchored_*` is what the chain recorded. `recomputed_*` is what the stored agent outputs and
 * evidence rows hash to right now. They diverge exactly when the off-chain record was altered
 * after anchoring.
 */
export interface IntegrityInfo {
  decision_id: string;
  found: boolean;
  workflow_id: string;
  incident_id: string;
  anchored_evidence_hash: string;
  anchored_output_hash: string;
  recomputed_evidence_hash: string;
  recomputed_output_hash: string;
  evidence_valid: boolean | null;
  output_valid: boolean | null;
  onchain_valid: boolean | null;
  valid: boolean | null;
  tampered: string[];
  tamper_active: boolean;
  chain_available: boolean;
  tx_hash: string;
  onchain_decision_id: number | null;
  detail: string;
}

export interface TamperResult {
  decision_id: string;
  agent: string;
  field: string;
  before: string;
  after: string;
  integrity: IntegrityInfo;
}

/**
 * A WitFoo incident. `threat_labels` counts benign/suspicious/malicious edges — threat
 * assessments, not the analyst triage verdicts GUIDE carries.
 */
export interface WitFooIncident {
  incident_id: string;
  mo_name: string;
  disposition: string;
  disposition_category: string;
  status_name: string;
  lifecycle_stage: string;
  suspicion_score: number;
  attack_techniques: string[];
  attack_tactics: string[];
  matched_rules: string[];
  products_observed: string[];
  edge_count: number;
  node_count: number;
  threat_labels: Record<string, number>;
  first_observed_at: number | null;
  last_observed_at: number | null;
  report_text: string;
}

export interface ProvenanceEdge {
  source: string;
  target: string;
  type: string;
  threat_label: string;
  confidence: number;
  scored: boolean;
  attack_techniques: string[];
}

export interface ProvenanceGraph {
  incident: WitFooIncident;
  nodes: string[];
  edges: ProvenanceEdge[];
  blast_radius: GraphInfo["blast_radius"] | null;
  attack_path: NonNullable<GraphInfo["attack_path"]> | null;
  confidence_sources: Record<string, number>;
  node_count: number;
  /** Distinct connections. Lower than incident.edge_count, which counts raw observations. */
  edge_count: number;
  edge_records: number;
}

export interface MetricsResponse {
  witfoo: Record<string, any>;
  proofs: Record<string, any>;
  baseline: Record<string, any>;
  evaluation: Record<string, any>;
  graph: Record<string, any>;
  index: Record<string, any>;
}

class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep the status text */
    }
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

const qs = (params: Record<string, string | number | boolean | undefined>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
};

export const api = {
  dataset: () => request<DatasetInfo>("/api/dataset"),

  incidents: (params: {
    limit?: number;
    offset?: number;
    showcase_only?: boolean;
    label?: string;
    search?: string;
  }) => request<IncidentSummary[]>(`/api/incidents${qs(params)}`),

  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${id}`),

  evidence: (id: string, limit = 100) =>
    request<EvidenceRow[]>(`/api/incidents/${id}/evidence${qs({ limit })}`),

  similar: (id: string, k = 5) =>
    request<SimilarIncident[]>(`/api/incidents/${id}/similar${qs({ k })}`),

  graph: (id: string, maxHops = 2) =>
    request<GraphInfo>(`/api/incidents/${id}/graph${qs({ max_hops: maxHops })}`),

  runWorkflow: (incident_id: string, backend?: string) =>
    request<WorkflowResponse>("/api/workflows", {
      method: "POST",
      body: JSON.stringify({ incident_id, backend, persist: true }),
    }),

  approve: (decisionId: string, approved: boolean, analyst: string, comment: string) =>
    request<ProofInfo>(`/api/decisions/${decisionId}/approve`, {
      method: "POST",
      body: JSON.stringify({ approved, analyst, comment }),
    }),

  anchor: (decisionId: string) =>
    request<ProofInfo>(`/api/decisions/${decisionId}/anchor`, { method: "POST" }),

  verify: (decisionId: string) =>
    request<IntegrityInfo>(`/api/decisions/${decisionId}/verify`),

  tamper: (decisionId: string, agent = "triage") =>
    request<TamperResult>(`/api/decisions/${decisionId}/tamper`, {
      method: "POST",
      body: JSON.stringify({ agent }),
    }),

  restore: (decisionId: string) =>
    request<TamperResult>(`/api/decisions/${decisionId}/restore`, { method: "POST" }),

  witfooIncidents: (params: { limit?: number; offset?: number; search?: string } = {}) =>
    request<WitFooIncident[]>(`/api/witfoo/incidents${qs(params)}`),

  witfooGraph: (incidentId: string) =>
    request<ProvenanceGraph>(`/api/witfoo/incidents/${incidentId}/graph`),

  metrics: () => request<MetricsResponse>("/api/metrics"),
};

export { ApiError };
