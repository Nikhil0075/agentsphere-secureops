import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  explorer_base: "https://explorer.example",
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

  it("links the contracts and the signer, not only the transaction", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("On the explorer");
    // Built from the explorer origin the API served for the chain id it actually used.
    const contract = screen.getByRole("link", { name: proof.contract_address });
    expect(contract).toHaveAttribute(
      "href",
      `${proof.explorer_base}/address/${proof.contract_address}`,
    );
    expect(screen.getByRole("link", { name: proof.registry_address })).toBeInTheDocument();
    expect(screen.getByText("holds decision #7")).toBeInTheDocument();
  });

  it("still links the anchored record when the anchor was resolved by fingerprint", async () => {
    // The duplicate-protected path: anchored, verifiable, and no transaction of ours to show.
    // The links block used to render nothing at all here, which reads as "nothing is on chain".
    apiMock.proof.mockResolvedValue({ ...proof, tx_hash: "", explorer_url: "", block_number: null, gas_used: null });
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("On the explorer");

    expect(screen.getByText(/already on chain, so no new transaction was sent/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: proof.contract_address })).toBeInTheDocument();
    // And the missing block/gas are named rather than left as bare dashes.
    expect(screen.getAllByText("no transaction").length).toBeGreaterThan(0);
  });

  it("offers nothing to click before an anchor has been attempted", async () => {
    apiMock.proof.mockResolvedValue({ ...proof, anchored: false, tx_hash: "", attempts: [] });
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("On the explorer");
    expect(screen.getByText(/Anchor proof on chain/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: proof.contract_address })).not.toBeInTheDocument();
  });

  it("shows block and gas, which were previously never populated", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("6,543,210")).toBeInTheDocument();
    expect(screen.getByText("218,455")).toBeInTheDocument();
  });

  it("shows a recovered content-addressed anchor as submitted, not refused", async () => {
    apiMock.proof.mockResolvedValue({
      ...proof,
      tx_hash: "",
      block_number: null,
      gas_used: null,
      explorer_url: "",
      onchain_decision_id: 21,
      onchain_state: "finalized",
      attempts: [
        {
          ...proof.attempts[0],
          tx_hash: "",
          block_number: null,
          gas_used: null,
          onchain_state: "submitted",
        },
      ],
    });

    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);

    expect(await screen.findByText("existing decision #21")).toBeInTheDocument();
    expect(screen.getByText("state committed on chain")).toBeInTheDocument();
    expect(screen.queryByText("refused by the chain")).not.toBeInTheDocument();
    expect(screen.queryByText("Anchor failed")).not.toBeInTheDocument();
  });

  it("lists every registered agent and marks the signer", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    expect(await screen.findByText("triage")).toBeInTheDocument();
    expect(screen.getByText("verifier")).toBeInTheDocument();
    expect(screen.getByText("signed this decision")).toBeInTheDocument();
  });

  it("reaches the contract only when explicitly asked", async () => {
    const user = userEvent.setup();
    apiMock.proof
      .mockResolvedValueOnce(proof)
      .mockResolvedValueOnce({ ...proof, chain_checked: true, valid: true });
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    await user.click(screen.getByRole("button", { name: /Confirm against the contract/ }));
    await waitFor(() =>
      expect(apiMock.proof).toHaveBeenCalledWith(DECISION, { check_chain: true }),
    );
    expect(await screen.findByText("match")).toBeInTheDocument();
    expect(apiMock.proof).toHaveBeenCalledTimes(2);
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

  // --- the anchoring journey -------------------------------------------------------------------

  it("lays out the whole path from stored record to contract storage", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    const labels = [
      "Stored record",
      "Canonicalised",
      "keccak256",
      "Transaction",
      "Block",
      "Decision slot",
    ];
    labels.forEach((label, index) => {
      // By accessible name, because several of these words also appear as field labels elsewhere
      // on the page -- "Transaction" and "Block" both do.
      expect(
        screen.getByRole("button", { name: `Stage ${index + 1}: ${label}` }),
      ).toBeInTheDocument();
    });
    // The boundary is the claim the panel exists to make: only digests cross it.
    expect(screen.getByText("boundary")).toBeInTheDocument();
    expect(screen.getByText("stage 1 of 6")).toBeInTheDocument();
  });

  it("marks the diverging bytes when the record no longer hashes to the anchor", async () => {
    const anchored = `0x${"11".repeat(32)}`;
    // Same digest with three bytes moved -- the visible difference is the point.
    const recomputed = `0x${"11".repeat(29)}${"ff".repeat(3)}`;
    apiMock.verify.mockResolvedValue({
      ...integrity,
      anchored_output_hash: anchored,
      recomputed_output_hash: recomputed,
      output_valid: false,
      valid: false,
      tampered: ["agent output"],
      tamper_active: true,
    });

    const user = userEvent.setup();
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("TAMPERED");

    // Visible on the rail without touching anything.
    expect(screen.getByText("3 of 32 bytes differ")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stage 3: keccak256" }));
    const grid = await screen.findByLabelText(/32 bytes, 3 differing from the anchored digest/);
    expect(grid.querySelectorAll('[data-changed="true"]')).toHaveLength(3);
  });

  it("marks nothing when the digests still agree", async () => {
    const digest = `0x${"ab".repeat(32)}`;
    apiMock.verify.mockResolvedValue({
      ...integrity,
      anchored_output_hash: digest,
      recomputed_output_hash: digest,
    });

    const user = userEvent.setup();
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");
    expect(screen.getByText("32 bytes, matching")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stage 3: keccak256" }));
    const grid = await screen.findByLabelText(/32 bytes, 0 differing from the anchored digest/);
    expect(grid.querySelectorAll('[data-changed="true"]')).toHaveLength(0);
  });

  it("walks the stages on play and stops the moment a stage is clicked", async () => {
    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    vi.useFakeTimers();
    try {
      fireEvent.click(screen.getByLabelText("Play the walkthrough"));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(2300);
      });
      expect(screen.getByText("stage 2 of 6")).toBeInTheDocument();

      await act(async () => {
        await vi.advanceTimersByTimeAsync(2300);
      });
      expect(screen.getByText("stage 3 of 6")).toBeInTheDocument();

      // A timer that keeps moving while someone is mid-sentence is a liability on stage.
      fireEvent.click(screen.getByRole("button", { name: "Stage 5: Block" }));
      expect(screen.getByText("stage 5 of 6")).toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000);
      });
      expect(screen.getByText("stage 5 of 6")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows where a decision stopped without needing a click", async () => {
    apiMock.proof.mockResolvedValue({
      ...proof,
      onchain_state: "",
      approval: { approver: "anaya.rao", approved: false, recorded_at: "2026-08-09", comment: "" },
    });

    render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
    await screen.findByText("VALID");

    // A rejection recorded locally is not the same as an un-reviewed decision, and the contract
    // will never finalise it -- both facts readable from the rail.
    expect(screen.getByText("a rejected decision is never finalised")).toBeInTheDocument();
    expect(screen.getByText(/Rejected by anaya.rao/)).toBeInTheDocument();
  });

  it("does not auto-advance when the system asks for reduced motion", async () => {
    // A timed walkthrough is exactly the kind of motion the setting exists to suppress, and the
    // CSS reduced-motion block cannot reach a JavaScript timer.
    const original = window.matchMedia;
    window.matchMedia = ((query: string) => ({
      matches: query.includes("prefers-reduced-motion"),
      media: query,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    })) as typeof window.matchMedia;

    try {
      render(<Proof decisionId={DECISION} onGoToWorkflow={vi.fn()} />);
      await screen.findByText("VALID");
      // The stages stay clickable; only the timer is withheld.
      expect(screen.getByLabelText("Play the walkthrough")).toBeDisabled();
      expect(screen.getByRole("button", { name: "Stage 4: Transaction" })).toBeEnabled();
    } finally {
      window.matchMedia = original;
    }
  });

  it("prompts for a workflow when there is no decision", () => {
    render(<Proof decisionId={null} onGoToWorkflow={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Go to the workflow" })).toBeInTheDocument();
    expect(apiMock.proof).not.toHaveBeenCalled();
  });
});
