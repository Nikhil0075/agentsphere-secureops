import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({ metrics: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: apiMock }));

import { Metrics } from "../src/pages/Metrics";

/**
 * jsdom gives ResponsiveContainer zero size, so no chart geometry ever renders here. Every
 * assertion is on caption or heading text, which is deliberate — the numbers and the disclosures
 * are what must not regress, not the SVG.
 */
const metrics = {
  baseline: {
    implementation: "lightgbm-4.7.0",
    accuracy: 0.7072,
    macro_f1: 0.6774,
    true_positive_recall: 0.6092,
    per_class: {
      TruePositive: { precision: 0.625, recall: 0.609, f1: 0.617, support: 238 },
      BenignPositive: { precision: 0.759, recall: 0.788, f1: 0.773, support: 533 },
      FalsePositive: { precision: 0.662, recall: 0.622, f1: 0.642, support: 233 },
    },
    confusion_matrix: {
      labels: ["TruePositive", "BenignPositive", "FalsePositive"],
      matrix: [
        [145, 65, 28],
        [67, 420, 46],
        [20, 68, 145],
      ],
      rows_are_actual: true,
    },
    feature_importance: { hour_of_day: 0.2756, duration_minutes: 0.1583, alert_count: 0.0729 },
    dataset: {
      train_incidents: 3529,
      val_incidents: 1004,
      train_label_distribution: { TruePositive: 800, BenignPositive: 1800, FalsePositive: 929 },
      val_label_distribution: { TruePositive: 238, BenignPositive: 533, FalsePositive: 233 },
    },
  },
  evaluation: {
    incidents: 200,
    split: "val",
    backend: "deterministic",
    agents: { macro_f1: 0.4084 },
    baseline: { macro_f1: 0.4669 },
    verifier: { rejection_rate: 0.0, escalation_rate: 0.05, verdicts: { accept: 190, escalate: 10 } },
    gate: { auto_approval_rate: 0.14 },
    reliability: { degraded_rate: 0 },
    latency_ms: { detection: { mean: 0, max: 1 }, triage: { mean: 0, max: 1 } },
  },
  graph: {
    nodes: 96351,
    edges: 26194,
    max_degree: 1025,
    by_type: { account: 33176, ip: 23214 },
    hubs: [{ node: "process:6", degree: 1025 }],
  },
  index: { incidents: 5000, dimensions: 384, build_seconds: 10.9, embedding_backend: "tfidf-svd" },
  // Deliberately empty: this is the shape a fresh clone serves, and it used to crash the page.
  proofs: {},
  witfoo: {},
  variance: {
    decision_stability: 0.5,
    runs_per_incident: 3,
    total_live_calls: 36,
    wall_seconds: 682.9,
    model_profile: { support: "gpt-5.6-terra" },
    incidents: {
      "INC-020335f5c65e": {
        decision_stable: true,
        output_hash: { n_distinct: 3 },
        triage: {
          label: { counts: { TruePositive: 3 }, n_distinct: 1 },
          confidence: { min: 0.42, max: 0.51 },
        },
        verifier: { verdict: { counts: { escalate: 3 } } },
        correlation: { deterministic: true },
      },
      "INC-0874da0f54ed": {
        decision_stable: false,
        output_hash: { n_distinct: 3 },
        triage: {
          label: {
            counts: { TruePositive: 1, FalsePositive: 1, BenignPositive: 1 },
            n_distinct: 3,
          },
          confidence: { min: 0.36, max: 0.38 },
        },
        verifier: { verdict: { counts: { escalate: 3 } } },
        correlation: { deterministic: true },
      },
    },
  },
  rehearsal: {
    backend: "replay",
    passed: 17,
    total: 17,
    mean_latency_ms: 6521.3,
    cases: Array.from({ length: 17 }, (_, index) => ({
      name: `case ${index + 1}`,
      passed: true,
      detail: "ok",
    })),
  },
};

describe("metrics screen", () => {
  beforeEach(() => {
    apiMock.metrics.mockReset().mockResolvedValue(metrics);
  });

  it("does not crash when proofs is empty", async () => {
    render(<Metrics />);
    expect(await screen.findByText("Proof integrity")).toBeInTheDocument();
    expect(screen.getByText("local")).toBeInTheDocument();
  });

  it("leads with measured decision stability", async () => {
    render(<Metrics />);
    expect(await screen.findByText("Live variance, measured")).toBeInTheDocument();
    expect(screen.getByText("0.50")).toBeInTheDocument();
    expect(screen.getByText("decision flipped")).toBeInTheDocument();
  });

  it("says that even the stable incident was byte-unstable", async () => {
    render(<Metrics />);
    expect(await screen.findByText(/Both/)).toBeInTheDocument();
    expect(
      screen.getByText(/stability of the decision is not\s+reproducibility of the run/),
    ).toBeInTheDocument();
  });

  it("reports the rehearsal sweep", async () => {
    render(<Metrics />);
    expect(await screen.findByText("17 / 17 passed")).toBeInTheDocument();
  });

  it("discloses the hour_of_day artefact next to the feature chart", async () => {
    render(<Metrics />);
    expect(await screen.findByText(/temporal\s+artefact/)).toBeInTheDocument();
  });

  it("reads the held-out count from the dataset rather than a missing key", async () => {
    render(<Metrics />);
    // 238 + 533 + 233 = 1,004. Previously rendered "?" because baseline.test_incidents never exists.
    expect(await screen.findByText(/1,004 held-out incidents/)).toBeInTheDocument();
  });

  it("keeps the honest below-baseline callout", async () => {
    render(<Metrics />);
    expect(await screen.findByText(/scores/)).toBeInTheDocument();
    expect(screen.getByText(/below/)).toBeInTheDocument();
  });

  it("shows an empty session feed until a workflow runs", async () => {
    render(<Metrics />);
    expect(await screen.findByText("Run a workflow to start the tally.")).toBeInTheDocument();
  });

  it("tallies session runs without a network call", async () => {
    render(
      <Metrics
        runs={[
          {
            at: 1,
            incident_id: "INC-DEMO",
            label: "TruePositive",
            confidence: 0.8,
            total_latency_ms: 300,
            cache_status: "hit",
            execution_mode: "replay",
            degraded: 0,
            resampled: 0,
            revision_fired: false,
          },
        ]}
      />,
    );
    expect(await screen.findByText("This session")).toBeInTheDocument();
    expect(screen.getByText("INC-DEMO")).toBeInTheDocument();
    // One fetch for the aggregates; the feed adds none.
    expect(apiMock.metrics).toHaveBeenCalledTimes(1);
  });
});
