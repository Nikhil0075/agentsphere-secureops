import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  dataset: vi.fn(),
  metrics: vi.fn(),
  queryIncidents: vi.fn(),
}));

vi.mock("../src/lib/api", () => ({ api: apiMock }));
vi.mock("../src/pages/Incident", () => ({
  Incident: ({ incidentId }: { incidentId: string }) => <h1>Selected incident {incidentId}</h1>,
}));

import App from "../src/App";

const dataset = {
  source: "guide",
  incidents: 5000,
  evidence_rows: 591340,
  labels: {},
  splits: {},
  showcase_incidents: 30,
  demo_arc: {
    size: 6,
    expected: 6,
    complete: true,
    roles: ["high_risk_true_positive", "correlation_collapse", "baseline_disagreement",
            "benign_positive", "low_risk_false_positive", "lowest_risk_exfil"],
  },
  sentinels_masked: ["a", "b", "c", "d", "e", "f", "g"],
  index_available: true,
  llm_backend: "replay",
  execution_mode: "replay",
  model_profile: { support: "gpt-5.6-terra", judge: "gpt-5.6-sol", reasoning: "medium" },
  replay_entries: 60,
  witfoo: { available: true, declared_edges: 634190 },
  chain: { available: false, network: "sepolia", chain_id: 11155111 },
};

const demo = {
  incident_id: "INC-DEMO",
  label: "TruePositive",
  split: "val",
  risk_score: 0.91,
  alert_count: 5,
  evidence_count: 8,
  top_category: "InitialAccess",
  top_detector: "1",
  top_alert_title: "Demo",
  max_suspicion_level: "Suspicious",
  mitre_techniques: "T1078",
  first_seen: "2026-08-06T00:00:00Z",
  is_showcase: true,
  demo_rank: 1,
  demo_role: "high_risk_true_positive",
  baseline_label: "TruePositive",
  baseline_confidence: 0.88,
};

describe("application home", () => {
  beforeEach(() => {
    apiMock.dataset.mockResolvedValue(dataset);
    apiMock.metrics.mockResolvedValue({
      witfoo: {}, proofs: {}, baseline: {}, graph: {}, index: {},
      evaluation: { agents: { macro_f1: 0.8 } },
      variance: {}, rehearsal: {},
    });
    apiMock.queryIncidents.mockResolvedValue({
      items: [demo], total: 1, limit: 25, offset: 0,
      sort_by: "risk", sort_dir: "desc", facets: { categories: [], suspicions: [] },
    });
  });

  it("opens on Home and keeps the global KPIs there only", async () => {
    const user = userEvent.setup();
    render(<App />);

    expect(screen.getByRole("heading", { name: /Turn evidence overload/i })).toBeInTheDocument();
    expect(await screen.findByText("5,000")).toBeInTheDocument();
    expect(screen.getByText("591,340")).toBeInTheDocument();
    expect(screen.getByText("634,190")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Queue" }));
    expect(await screen.findByRole("heading", { name: /Start with the incidents/i })).toBeInTheDocument();
    expect(screen.queryByText("591,340")).not.toBeInTheDocument();
  });

  it("Run demo opens case 1 of the curated arc", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Run demo" }));

    await waitFor(() => expect(apiMock.queryIncidents).toHaveBeenCalledWith({
      limit: 1,
      demo_only: true,
      sort_by: "demo_rank",
      sort_dir: "asc",
    }));
    expect(await screen.findByRole("heading", { name: "Selected incident INC-DEMO" })).toBeInTheDocument();
  });
});
