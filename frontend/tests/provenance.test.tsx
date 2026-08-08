import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  witfooIncidents: vi.fn(),
  witfooGraph: vi.fn(),
  graph: vi.fn(),
}));
vi.mock("../src/lib/api", () => ({ api: apiMock }));

import { Provenance } from "../src/pages/Provenance";

const incident = {
  incident_id: "wf-0001",
  mo_name: "Credential harvesting",
  disposition: "Disrupted",
  disposition_category: "contained",
  status_name: "Disrupted",
  lifecycle_stage: "complete-mission",
  suspicion_score: 0.82,
  attack_techniques: ["T1566"],
  attack_tactics: ["initial-access"],
  matched_rules: ["rule-a"],
  products_observed: ["firewall"],
  edge_count: 4,
  node_count: 4,
  threat_labels: { benign: 10, suspicious: 4, malicious: 6 },
  // Epoch seconds. 1681754887 is 2023-04-17; read as milliseconds it would be January 1970.
  first_observed_at: 1681754887,
  last_observed_at: 1681755043,
  report_text: "Analyst report.",
};

const graph = {
  incident,
  nodes: ["account:alice", "device:laptop", "ip:10.0.0.4"],
  edges: [
    {
      source: "account:alice",
      target: "device:laptop",
      type: "AUDIT_EVENT",
      threat_label: "malicious",
      confidence: 0.9,
      scored: true,
      attack_techniques: ["T1566"],
    },
    {
      source: "device:laptop",
      target: "ip:10.0.0.4",
      type: "NETWORK_FLOW",
      threat_label: "benign",
      confidence: 0.3,
      scored: false,
      attack_techniques: [],
    },
  ],
  blast_radius: {
    seeds: ["account:alice"],
    impacted_by_type: { account: ["account:alice"], device: ["device:laptop"] },
    total_nodes: 3,
    hubs_blocked: ["ip:100.64.70.227"],
    truncated: false,
  },
  attack_path: {
    path: ["account:alice", "device:laptop", "ip:10.0.0.4"],
    hops: 2,
    probability: 0.27,
    edge_confidences: [0.9, 0.3],
    weakest_link: 0.3,
  },
  confidence_sources: { grounded_lookups: 1, fallback_lookups: 1, grounded_fraction: 0.5 },
  node_count: 3,
  edge_count: 2,
  edge_records: 2,
};

describe("provenance lab", () => {
  beforeEach(() => {
    apiMock.witfooIncidents.mockReset().mockResolvedValue([incident]);
    apiMock.witfooGraph.mockReset().mockResolvedValue(graph);
    apiMock.graph
      .mockReset()
      .mockResolvedValue({ blast_radius: {}, attack_path: null, node_count: 12, edge_count: 30 });
  });

  const mount = () =>
    render(<Provenance summary={{ available: true }} onBack={vi.fn()} backLabel="Back" />);

  it("explains the attack path at a glance", async () => {
    mount();
    expect(await screen.findByText("Most probable attack path")).toBeInTheDocument();
    expect(screen.getByText("Confidence per hop")).toBeInTheDocument();
    // Invariant 7 stated where the chart is, not in a distant doc.
    expect(screen.getByText(/−log\(confidence\)/)).toBeInTheDocument();
  });

  it("shows blast radius and the hub cap", async () => {
    mount();
    expect(await screen.findByText("Blast radius")).toBeInTheDocument();
    expect(screen.getByText("Reachable entities by type")).toBeInTheDocument();
    expect(screen.getByText(/never expands through a hub/)).toBeInTheDocument();
  });

  it("keeps the WitFoo-versus-GUIDE label warning beside the labels themselves", async () => {
    mount();
    expect(await screen.findByText("Threat labels on this incident")).toBeInTheDocument();
    expect(screen.getByText(/threat assessments/)).toBeInTheDocument();
    expect(screen.getByText(/excluded from every accuracy number/)).toBeInTheDocument();
  });

  it("describes the graph encoding in its accessible label and legend", async () => {
    mount();
    const svg = await screen.findByRole("img", { name: /Provenance graph with 3 entities/ });
    expect(svg).toHaveAccessibleName(/thickness is confidence/);
    expect(svg).toHaveAccessibleName(/node size is degree/);
    expect(screen.getByText("Legend")).toBeInTheDocument();
    expect(screen.getByText("Thicker line = higher confidence")).toBeInTheDocument();
    expect(screen.getByText("Dashed = fallback prior, not scored")).toBeInTheDocument();
  });

  it("renders incident metadata with timestamps read as seconds", async () => {
    mount();
    expect(await screen.findByText("Incident record")).toBeInTheDocument();
    expect(screen.getByText("complete-mission")).toBeInTheDocument();
    // 1681754887 seconds -> 2023-04-17. A millisecond reading would render 1970.
    expect(screen.getByText(/2023-04-17/)).toBeInTheDocument();
  });
  it("separates measured confidence from the fallback prior", async () => {
    mount();
    // Two edges, one scored — the strip must say so rather than leaving the reader to infer it
    // from stroke width, which encodes both identically.
    expect(await screen.findByText("Where these confidences come from")).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 scored/)).toBeInTheDocument();
    expect(screen.getByText(/looks exactly as confident as a measured one/)).toBeInTheDocument();
  });

  it("compares the GUIDE graph only when an incident was carried in", async () => {
    mount();
    await screen.findByText("Dataset provenance");
    expect(screen.queryByText(/two sources of confidence/)).not.toBeInTheDocument();

    render(
      <Provenance
        summary={{ available: true, declared_nodes: 35133 }}
        compareIncidentId="INC-1"
        onBack={vi.fn()}
        backLabel="Back"
      />,
    );
    // "Compare shipped graph" used to navigate here with nothing to compare against.
    expect(await screen.findAllByText(/two sources of confidence/)).not.toHaveLength(0);
    expect(apiMock.graph).toHaveBeenCalledWith("INC-1");
  });
});
