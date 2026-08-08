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
export type ExecutionMode = "replay" | "live" | "deterministic";
export type QueueSort =
  | "risk"
  | "first_seen"
  | "alerts"
  | "evidence"
  | "baseline_confidence"
  | "incident"
  | "demo_rank";

/** State of the six-case presentation arc. Presentation only — never a metric denominator. */
export interface DemoArcInfo {
  size: number;
  expected: number;
  complete: boolean;
  roles: string[];
}

export interface DatasetInfo {
  source: string;
  incidents: number;
  evidence_rows: number;
  labels: Record<string, number>;
  splits: Record<string, number>;
  showcase_incidents: number;
  demo_arc: DemoArcInfo;
  sentinels_masked: string[];
  index_available: boolean;
  llm_backend: string;
  execution_mode: ExecutionMode;
  model_profile: Record<string, string>;
  replay_entries: number;
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
  /** Position in the six-case narration order, or null for every other incident. */
  demo_rank: number | null;
  demo_role: string;
  baseline_label: string;
  baseline_confidence: number;
}

export interface IncidentDetail extends IncidentSummary {
  summary: string;
  entity_counts: Record<string, number>;
  threat_families: string;
  duration_minutes: number;
}

export interface IncidentPage {
  items: IncidentSummary[];
  total: number;
  limit: number;
  offset: number;
  sort_by: QueueSort;
  sort_dir: "asc" | "desc";
  facets: { categories: string[]; suspicions: string[] };
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

/**
 * What an agent was actually asked, and what it was allowed to see.
 *
 * `label_free` covers the rendered user prompt only. Triage's role names the three labels because
 * it is choosing between them; that static text is identical for every incident and cannot carry
 * an answer.
 */
export interface AgentTrace {
  run_index: number;
  agent: string;
  sequence: number;
  status: string;
  system_prompt: string;
  user_prompt: string;
  context_json: string;
  context_keys: string[];
  truncated: boolean;
  pre_decision: boolean;
  label_free: boolean;
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
  cached: boolean;
  trace_id: string;
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
  /** One entry per agent run, in run order. Joined to `runs` on `run_index`. */
  traces: AgentTrace[];
  degraded_agents: string[];
  /** Succeeded only on a retry — an identical prompt re-sent, so on a live model, a resample. */
  resampled_agents: string[];
  /** The live-only triage correction pass ran: nine agent runs, and a hash its replay cannot match. */
  revision_fired: boolean;
  execution_mode: ExecutionMode;
  model_profile: Record<string, string>;
  cache_status: "hit" | "miss_filled" | "bypassed" | "degraded";
  trace_id: string;
  token_usage: { input: number; output: number; total: number };
  retry_count: number;
}

/**
 * The `DecisionProof.Decision` struct, field for field.
 *
 * Named to match the Solidity so the UI can present it as "this is literally what is on chain".
 * Note what is absent: no evidence rows, no prompts, no rationale.
 */
export interface OnchainDecision {
  incident_id: string;
  evidence_hash: string;
  output_hash: string;
  label: string;
  risk: string;
  state: string;
  agent: string;
  approver: string;
  comment_hash: string;
  submitted_at: number;
  decided_at: number;
  finalized_at: number;
}

/** One row of `blockchain_proofs`. Plural because a retry records another attempt. */
export interface AnchorAttempt {
  proof_id: string;
  tx_hash: string;
  block_number: number | null;
  gas_used: number | null;
  agent_address: string;
  onchain_state: string;
  anchored_at: string;
}

/**
 * The human decision as recorded in SQLite, before anything reaches the chain.
 *
 * Distinct from `OnchainDecision.approver`: this is what the analyst did, that is what the contract
 * witnessed, and until an anchor succeeds only the first one exists.
 */
export interface LocalApproval {
  approver: string;
  approved: boolean;
  comment_hash: string;
  recorded_at: string;
}

export interface ProofInfo {
  decision_id: string;
  found: boolean;
  anchored: boolean;
  evidence_hash: string;
  output_hash: string;
  tx_hash: string;
  block_number: number | null;
  gas_used: number | null;
  chain_id: number | null;
  contract_address: string;
  registry_address: string;
  network: string;
  agent_address: string;
  registered_agents: Record<string, string>;
  onchain_decision_id: number | null;
  onchain_state: string;
  explorer_url: string;
  valid: boolean | null;
  chain_available: boolean;
  /** False when the response was assembled without an RPC — "we did not ask", not "it said no". */
  chain_checked: boolean;
  onchain: OnchainDecision | null;
  attempts: AnchorAttempt[];
  /** The locally recorded human decision, if one has been made yet. */
  approval: LocalApproval | null;
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

export interface ProofMetrics {
  decisions: number;
  anchored: number;
  valid: number;
  tampered: number;
  validity_rate: number | null;
  verification_scope: "local";
}

export interface MetricsResponse {
  witfoo: Record<string, any>;
  proofs: ProofMetrics;
  baseline: Record<string, any>;
  evaluation: Record<string, any>;
  graph: Record<string, any>;
  index: Record<string, any>;
  /** Measured live run-to-run variance. `{}` until scripts/measure_variance.py has run. */
  variance: Record<string, any>;
  /** The end-to-end rehearsal sweep. `{}` until scripts/rehearse.py has run. */
  rehearsal: Record<string, any>;
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
    demo_only?: boolean;
    label?: string;
    search?: string;
  }) => request<IncidentSummary[]>(`/api/incidents${qs(params)}`),

  queryIncidents: (params: {
    limit?: number;
    offset?: number;
    showcase_only?: boolean;
    demo_only?: boolean;
    label?: string;
    category?: string;
    suspicion?: string;
    min_risk?: number;
    baseline_status?: string;
    search?: string;
    sort_by?: QueueSort;
    sort_dir?: "asc" | "desc";
  }) => request<IncidentPage>(`/api/incidents/query${qs(params)}`),

  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${id}`),

  evidence: (id: string, limit = 100) =>
    request<EvidenceRow[]>(`/api/incidents/${id}/evidence${qs({ limit })}`),

  similar: (id: string, k = 5) =>
    request<SimilarIncident[]>(`/api/incidents/${id}/similar${qs({ k })}`),

  graph: (id: string, maxHops = 2) =>
    request<GraphInfo>(`/api/incidents/${id}/graph${qs({ max_hops: maxHops })}`),

  runWorkflow: (incident_id: string, mode?: ExecutionMode) =>
    request<WorkflowResponse>("/api/workflows", {
      method: "POST",
      body: JSON.stringify({ incident_id, mode, persist: true }),
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

  /**
   * Everything known about the anchor. Zero-RPC unless `check_chain` is set — the Proof screen
   * opens with this and only reaches the contract when the analyst explicitly asks.
   */
  proof: (decisionId: string, params: { check_chain?: boolean } = {}) =>
    request<ProofInfo>(`/api/decisions/${decisionId}/proof${qs(params)}`),

  tamper: (decisionId: string, agent = "triage") =>
    request<TamperResult>(`/api/decisions/${decisionId}/tamper`, {
      method: "POST",
      body: JSON.stringify({ agent }),
    }),

  restore: (decisionId: string) =>
    request<TamperResult>(`/api/decisions/${decisionId}/restore`, { method: "POST" }),

  witfooIncidents: (
    params: {
      limit?: number;
      offset?: number;
      search?: string;
      mo_name?: string;
      status?: string;
      /** No threat-label option: every shipped incident is labelled malicious. */
      sort?: "suspicion" | "suspicion_asc" | "nodes" | "recent";
    } = {},
  ) => request<WitFooIncident[]>(`/api/witfoo/incidents${qs(params)}`),

  witfooGraph: (
    incidentId: string,
    params: { max_hops?: number; hub_degree?: number } = {},
  ) =>
    request<ProvenanceGraph>(
      `/api/witfoo/incidents/${incidentId}/graph${qs(params)}`,
    ),

  metrics: () => request<MetricsResponse>("/api/metrics"),
};

export { ApiError };
