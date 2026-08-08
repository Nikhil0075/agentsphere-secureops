import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  verify: vi.fn(),
  proof: vi.fn(),
  anchor: vi.fn(),
  tamper: vi.fn(),
  restore: vi.fn(),
}));
vi.mock("../src/lib/api", () => ({ api: apiMock }));

import { Proof } from "../src/pages/Proof";

const DECISION = "DEC-abc123";

const integrity = {
  decision_id: DECISION,
  found: true,
  workflow_id: "WF-000111222",
  incident_id: "INC-020335f5c65e",
  anchored_evidence_hash: "0xaaa111",
  anchored_output_hash: "0xbbb222",
  recomputed_evidence_hash: "0xaaa111",
  recomputed_output_hash: "0xbbb222",
  evidence_valid: true,
  output_valid: true,
  onchain_valid: null,
  valid: true,
  tampered: [],
  tamper_active: false,
  chain_available: false,
  tx_hash: "0xfeed",
  onchain_decision_id: 7,
  detail: "",
};

const proof = {
  decision_id: DECISION,
  found: true,
  anchored: true,
  evidence_hash: "0xaaa111",
  output_hash: "0xbbb222",
  tx_hash: "0xfeedfacecafe",
  block_number: 6543210,
  gas_used: 218455,
  chain_id: 11155111,
  contract_address: "0xC0nTrAcT0000000000000000000000000000abcd",
  registry_address: "0xReG1sTrY000000000000000000000000000012ef",
  network: "sepolia",
  agent_address: "0xAgEnT00000000000000000000000000000000111",
  registered_agents: { triage: "0xAgEnT00000000000000000000000000000000111", verifier: "0xVeR1f13r0000000000000000000000000000222" },
  onchain_decision_id: 7,
  onchain_state: "Proposed",
  // Deliberately not a sepolia.etherscan.io URL: the page must use what the API returned rather
  // than rebuilding it from a hardcoded host.
  explorer_url: "https://explorer.example/tx/0xfeedfacecafe",
  valid: null,
  chain_available: false,
  chain_checked: false,
  onchain: null,
  attempts: [
    {
      proof_id: "PRF-1",
      tx_hash: "0xfeedfacecafe",
      block_number: 6543210,
      gas_used: 218455,
      agent_address: "0xAgEnT00000000000000000000000000000000111",
      onchain_state: "submitted",
      anchored_at: "2026-08-08T00:00:00Z",
    },
  ],
  reason: "",
};

describe("proof screen", () => {
  beforeEach(() => {
    apiMock.verify.mockReset().mockResolvedValue(integrity);
    apiMock.proof.mockReset().mockResolvedValue(proof);
    apiMock.anchor.mockReset().mockResolvedValue(proof);
    apiMock.tamper.mockReset();
    apiMock.restore.mockReset().mockResolvedValue({});
  });

  it("opens without contacting the chain", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("VALID")).toBeInTheDocument();

    // Exactly the two zero-RPC reads, and the proof call carries no check_chain flag.
    expect(apiMock.proof).toHaveBeenCalledWith(DECISION);
    expect(apiMock.proof).toHaveBeenCalledTimes(1);
    expect(screen.getByText("local only")).toBeInTheDocument();
  });

  it("never reports a contract verdict it did not ask for", async () => {
    // /verify computes onchain_valid from the *locally recorded* proof row, so it reads true on a
    // decision that was never anchored. Rendering that as "match" would claim an independent
    // confirmation the system never obtained.
    apiMock.verify.mockResolvedValue({ ...integrity, onchain_valid: true });
    apiMock.proof.mockResolvedValue({ ...proof, chain_checked: false });

    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("not asked")).toBeInTheDocument();
    expect(screen.queryByText("match")).not.toBeInTheDocument();
  });

  it("reports the contract verdict once the contract has been read", async () => {
    apiMock.verify.mockResolvedValue({ ...integrity, onchain_valid: true });
    apiMock.proof.mockResolvedValue({ ...proof, chain_checked: true });

    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("match")).toBeInTheDocument();
  });

  it("links the transaction using the URL the API returned", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    const link = await screen.findByRole("link", { name: /0xfeedfacecafe/ });
    expect(link).toHaveAttribute("href", proof.explorer_url);
    expect(link.getAttribute("href")).not.toContain("sepolia.etherscan.io");
  });

  it("shows block and gas, which were previously never populated", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("6,543,210")).toBeInTheDocument();
    expect(screen.getByText("218,455")).toBeInTheDocument();
  });

  it("lists every registered agent and marks the signer", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("triage")).toBeInTheDocument();
    expect(screen.getByText("verifier")).toBeInTheDocument();
    expect(screen.getByText("signed this decision")).toBeInTheDocument();
  });

  it("reaches the contract only when explicitly asked", async () => {
    const user = userEvent.setup();
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    await user.click(screen.getByRole("button", { name: /Confirm against the contract/ }));
    await waitFor(() =>
      expect(apiMock.proof).toHaveBeenCalledWith(DECISION, { check_chain: true }),
    );
  });

  it("shows the before/after diff when the record is tampered", async () => {
    const user = userEvent.setup();
    apiMock.tamper.mockResolvedValue({
      decision_id: DECISION,
      agent: "triage",
      field: "label",
      before: "TruePositive",
      after: "FalsePositive",
      integrity,
    });
    apiMock.verify.mockResolvedValueOnce(integrity).mockResolvedValue({
      ...integrity,
      output_valid: false,
      valid: false,
      tampered: ["triage output"],
      tamper_active: true,
      recomputed_output_hash: "0xdiverged",
    });

    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    await user.click(screen.getByRole("button", { name: /Edit the stored triage label/ }));

    expect(await screen.findByText("TAMPERED")).toBeInTheDocument();
    expect(screen.getByText("Stored record edited")).toBeInTheDocument();
    expect(screen.getByText("TruePositive")).toBeInTheDocument();
    expect(screen.getByText("FalsePositive")).toBeInTheDocument();
  });

  it("names the three controls the chain provides", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(
      await screen.findByText(/Reject an unauthorised writer at the storage layer/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Block finalisation of a high-risk action without a human/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Detect tampering by the party operating the storage/),
    ).toBeInTheDocument();
  });

  it("prompts for a workflow when there is no decision", () => {
    render(<Proof decisionId={null} onGoToWorkflow={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Go to the workflow" })).toBeInTheDocument();
    expect(apiMock.proof).not.toHaveBeenCalled();
  });
});
