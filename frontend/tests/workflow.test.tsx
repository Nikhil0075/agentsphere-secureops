import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({ runWorkflow: vi.fn(), approve: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: apiMock }));

import { Workflow } from "../src/pages/Workflow";

const AGENTS = ["detection", "correlation", "investigation", "triage", "remediation", "verifier"];

const run = (agent: string, sequence: number) => ({
  agent,
  sequence,
  status: "ok",
  attempts: 1,
  latency_ms: 120,
  backend: "replay",
  model: "gpt-5.6-terra",
  prompt_tokens: 900,
  completion_tokens: 300,
  cached: true,
  trace_id: "",
  validation_error: "",
  output_hash: `0xhash${sequence}`,
});

const trace = (agent: string, index: number) => ({
  run_index: index,
  agent,
  sequence: index + 1,
  status: "ok",
  system_prompt: "You are a specialised agent inside a Security Operations Centre triage system.",
  user_prompt: `Incident INC-DEMO rendered for ${agent}`,
  context_json: '{\n  "incident_id": "INC-DEMO"\n}',
  context_keys: ["evidence_ids", "incident_id"],
  truncated: false,
  pre_decision: index < 3,
  label_free: index < 3,
});

const result = {
  workflow_id: "WF-abc",
  incident_id: "INC-DEMO",
  decision_id: "DEC-abc",
  label: "TruePositive",
  confidence: 0.82,
  requires_approval: true,
  baseline: { label: "TruePositive", confidence: 0.86, model_name: "lightgbm" },
  detection: {
    severity_score: 0.72,
    suspicious_entities: [
      { entity_type: "account", value: "acct-90210", reason: "authenticated from a new country" },
    ],
    initial_reason: "Detector and entity evidence warrant investigation.",
  },
  correlation: {
    evidence_bundle: ["EVD-1", "EVD-2"],
    relationships: [{ source: "acct-90210", target: "dev-7", relation: "signed-in-to" }],
    timeline: [
      { timestamp: "2024-06-03T01:58Z", description: "First mailbox rule created", evidence_id: "EVD-1" },
    ],
    missing_information: ["no endpoint telemetry"],
  },
  investigation: {
    similar_cases: [{ incident_id: "INC-SIMILAR", similarity: 0.71, why_similar: "shares an account" }],
    mitre_mapping: [
      { technique_id: "T1566.002", technique_name: "Phishing", supporting_evidence_ids: ["EVD-1"] },
    ],
    investigation_summary: "Consistent with credential phishing followed by mailbox rule abuse.",
  },
  triage: {
    label: "TruePositive",
    confidence: 0.82,
    rationale: "Cited rationale.",
    supporting_evidence_ids: ["EVD-1"],
  },
  remediation: {
    recommended_action: "monitor_and_watchlist",
    action_risk: "low",
    rollback_plan: "Remove from watchlist.",
    justification: "Bounded and reversible.",
  },
  verifier: {
    verdict: "escalate",
    contradictions: ["confidence exceeds the evidence"],
    policy_checks: [{ policy_id: "VER-001", passed: true, detail: "all citations in bundle" }],
    escalation_required: true,
    reasoning: "Gaps reported by correlation are unresolved.",
  },
  gate: {
    requires_approval: true,
    auto_approved: false,
    action_risk: "low",
    reasons: ["verifier verdict is escalate"],
    checks: [{ policy_id: "POL-005", passed: false, detail: "verifier did not accept" }],
  },
  correlation_info: {
    alert_count: 26,
    cluster_count: 12,
    reduction: 0.54,
    largest_cluster: 5,
    clusters: [{ cluster_id: "CLU-1", size: 5, evidence_count: 5, linking_entities: ["acct-90210"] }],
  },
  runs: AGENTS.map((agent, index) => run(agent, index + 1)),
  traces: AGENTS.map((agent, index) => trace(agent, index)),
  errors: [],
  evidence_hash: "0xevidence",
  output_hash: "0xoutput",
  total_latency_ms: 720,
  degraded_agents: [],
  resampled_agents: [],
  revision_fired: false,
  execution_mode: "replay",
  model_profile: { support: "gpt-5.6-terra", judge: "gpt-5.6-sol" },
  cache_status: "hit",
  trace_id: "",
  token_usage: { input: 5400, output: 1800, total: 7200 },
  retry_count: 0,
};

async function runWorkflow() {
  const user = userEvent.setup();
  render(<Workflow incidentId="INC-DEMO" backend="replay" onDecision={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Run workflow" }));
  await screen.findByText("Agent chain");
  return user;
}

describe("workflow stages", () => {
  beforeEach(() => {
    apiMock.runWorkflow.mockReset().mockResolvedValue(result);
    apiMock.approve.mockReset();
  });

  it("renders one card per agent run", async () => {
    await runWorkflow();
    for (const agent of AGENTS) {
      expect(screen.getAllByText(agent).length).toBeGreaterThan(0);
    }
  });

  it("renders the three agents that used to show nothing", async () => {
    await runWorkflow();
    // detection. The entity value also appears as a correlation relationship endpoint, which is
    // the point of rendering both stages, so match all rather than one.
    expect(screen.getAllByText("acct-90210").length).toBeGreaterThan(0);
    expect(
      screen.getByText("authenticated from a new country"),
    ).toBeInTheDocument();
    // correlation
    expect(screen.getByText("First mailbox rule created")).toBeInTheDocument();
    // investigation
    expect(screen.getByText("T1566.002")).toBeInTheDocument();
    expect(screen.getByText("INC-SIMILAR")).toBeInTheDocument();
  });

  it("shows the prompt each agent was given", async () => {
    await runWorkflow();
    expect(
      screen.getByText(/Incident INC-DEMO rendered for detection/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/You are a specialised agent inside a Security Operations Centre/).length,
    ).toBeGreaterThan(0);
  });

  it("states that pre-decision prompts carry no label", async () => {
    await runWorkflow();
    expect(screen.getAllByText(/none present/).length).toBe(3);
    // Triage onward gets the honest caveat instead of a clean bill of health.
    expect(screen.getAllByText(/baseline's/).length).toBeGreaterThan(0);
  });

  it("surfaces per-run trace facts that were previously dropped", async () => {
    await runWorkflow();
    expect(screen.getAllByText("gpt-5.6-terra").length).toBeGreaterThan(0);
    expect(screen.getAllByText("cached").length).toBeGreaterThan(0);
    expect(screen.getByText(/5,400 in · 1,800 out/)).toBeInTheDocument();
  });

  it("shows verifier fields the old page dropped", async () => {
    await runWorkflow();
    expect(screen.getByText("escalation required")).toBeInTheDocument();
    expect(
      screen.getByText("Gaps reported by correlation are unresolved."),
    ).toBeInTheDocument();
  });

  it("focuses a stage from the navigator", async () => {
    const user = await runWorkflow();
    const navButtons = screen.getAllByRole("button", { pressed: false });
    await user.click(navButtons[0]);
    expect(screen.getAllByRole("button", { pressed: true }).length).toBe(1);
  });

  it("reports the completed run to the session feed", async () => {
    const onRunComplete = vi.fn();
    const user = userEvent.setup();
    render(
      <Workflow
        incidentId="INC-DEMO"
        backend="replay"
        onDecision={vi.fn()}
        onRunComplete={onRunComplete}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Run workflow" }));
    await screen.findByText("Agent chain");

    expect(onRunComplete).toHaveBeenCalledWith(
      expect.objectContaining({
        incident_id: "INC-DEMO",
        label: "TruePositive",
        cache_status: "hit",
        degraded: 0,
      }),
    );
  });
});
