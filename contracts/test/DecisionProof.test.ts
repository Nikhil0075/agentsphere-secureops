import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

/**
 * The two controls that justify a chain over an append-only database (§12.3):
 *
 *   1. an unauthorised writer is rejected by the contract, not by application code the
 *      operator controls;
 *   2. a high-risk action cannot finalise without a recorded human approval.
 *
 * Both are tested here as reverts. `finalizeDecision` reverting on an unapproved high-risk
 * decision is the Day 5 exit criterion.
 */

const Risk = { Low: 0, Medium: 1, High: 2 } as const;
const State = { Proposed: 0, Approved: 1, Rejected: 2, Finalized: 3 } as const;

const EVIDENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("evidence-bundle"));
const OUTPUT_HASH = ethers.keccak256(ethers.toUtf8Bytes("agent-outputs"));
const COMMENT_HASH = ethers.keccak256(ethers.toUtf8Bytes("looks right to me"));
const INCIDENT = "INC-002cdb785d37";

async function deployed() {
  const [owner, triageAgent, verifierAgent, analyst, rogue] = await ethers.getSigners();

  const registry = await (await ethers.getContractFactory("AgentRegistry")).deploy();
  const proof = await (
    await ethers.getContractFactory("DecisionProof")
  ).deploy(await registry.getAddress());

  await registry.registerAgent(
    triageAgent.address,
    "triage",
    ethers.keccak256(ethers.toUtf8Bytes("triage-card"))
  );
  await registry.registerAgent(
    verifierAgent.address,
    "verifier",
    ethers.keccak256(ethers.toUtf8Bytes("verifier-card"))
  );

  return { registry, proof, owner, triageAgent, verifierAgent, analyst, rogue };
}

async function submit(
  proof: any,
  agent: any,
  risk: number = Risk.High,
  incident: string = INCIDENT,
  outputHash: string = OUTPUT_HASH
) {
  await proof
    .connect(agent)
    .submitDecision(incident, EVIDENCE_HASH, outputHash, "TruePositive", risk);
  return proof.decisionCount();
}

describe("AgentRegistry", () => {
  it("registers an agent with a role and marks it active", async () => {
    const { registry, triageAgent } = await loadFixture(deployed);
    const [role, , active] = await registry.getAgent(triageAgent.address);
    expect(role).to.equal("triage");
    expect(active).to.equal(true);
  });

  it("treats an unregistered address as inactive", async () => {
    const { registry, rogue } = await loadFixture(deployed);
    expect(await registry.isActive(rogue.address)).to.equal(false);
    expect(await registry.isRegistered(rogue.address)).to.equal(false);
  });

  it("only the owner may register agents", async () => {
    const { registry, rogue } = await loadFixture(deployed);
    await expect(
      registry.connect(rogue).registerAgent(rogue.address, "triage", ethers.ZeroHash)
    ).to.be.revertedWithCustomError(registry, "NotOwner");
  });

  it("rejects re-registration rather than silently resetting history", async () => {
    const { registry, triageAgent } = await loadFixture(deployed);
    await expect(
      registry.registerAgent(triageAgent.address, "triage", ethers.ZeroHash)
    ).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
  });

  it("rejects the zero address and an empty role", async () => {
    const { registry, analyst } = await loadFixture(deployed);
    await expect(
      registry.registerAgent(ethers.ZeroAddress, "triage", ethers.ZeroHash)
    ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    await expect(
      registry.registerAgent(analyst.address, "", ethers.ZeroHash)
    ).to.be.revertedWithCustomError(registry, "EmptyRole");
  });

  it("can deactivate a compromised agent", async () => {
    const { registry, triageAgent } = await loadFixture(deployed);
    await registry.setAgentStatus(triageAgent.address, false);
    expect(await registry.isActive(triageAgent.address)).to.equal(false);
  });

  it("cannot change the status of an unknown agent", async () => {
    const { registry, rogue } = await loadFixture(deployed);
    await expect(
      registry.setAgentStatus(rogue.address, true)
    ).to.be.revertedWithCustomError(registry, "UnknownAgent");
  });
});

describe("DecisionProof — authorisation", () => {
  it("REJECTS a submission from an unregistered address", async () => {
    // The control a database cannot provide: the operator does not administer this check.
    const { proof, rogue } = await loadFixture(deployed);
    await expect(
      proof
        .connect(rogue)
        .submitDecision(INCIDENT, EVIDENCE_HASH, OUTPUT_HASH, "TruePositive", Risk.Low)
    ).to.be.revertedWithCustomError(proof, "UnauthorisedAgent");
  });

  it("REJECTS a submission from a deactivated agent", async () => {
    const { registry, proof, triageAgent } = await loadFixture(deployed);
    await registry.setAgentStatus(triageAgent.address, false);
    await expect(
      proof
        .connect(triageAgent)
        .submitDecision(INCIDENT, EVIDENCE_HASH, OUTPUT_HASH, "TruePositive", Risk.Low)
    ).to.be.revertedWithCustomError(proof, "UnauthorisedAgent");
  });

  it("accepts a submission from a registered active agent", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    await expect(
      proof
        .connect(triageAgent)
        .submitDecision(INCIDENT, EVIDENCE_HASH, OUTPUT_HASH, "TruePositive", Risk.High)
    ).to.emit(proof, "DecisionSubmitted");
  });

  it("records the submitting agent as the author", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    expect((await proof.getDecision(id)).agent).to.equal(triageAgent.address);
  });

  it("a deactivated agent cannot finalise either", async () => {
    const { registry, proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.Low);
    await registry.setAgentStatus(triageAgent.address, false);
    await expect(
      proof.connect(triageAgent).finalizeDecision(id)
    ).to.be.revertedWithCustomError(proof, "UnauthorisedAgent");
  });
});

describe("DecisionProof — integrity", () => {
  it("rejects a duplicate incident+hash pair", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    await submit(proof, triageAgent);
    await expect(submit(proof, triageAgent)).to.be.revertedWithCustomError(
      proof,
      "DuplicateDecision"
    );
  });

  it("allows a genuinely different decision on the same incident", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    await submit(proof, triageAgent);
    const other = ethers.keccak256(ethers.toUtf8Bytes("different-outputs"));
    await expect(submit(proof, triageAgent, Risk.High, INCIDENT, other)).not.to.be.reverted;
  });

  it("rejects a zero hash, which would make verification vacuous", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    await expect(
      proof
        .connect(triageAgent)
        .submitDecision(INCIDENT, ethers.ZeroHash, OUTPUT_HASH, "TruePositive", Risk.Low)
    ).to.be.revertedWithCustomError(proof, "ZeroHash");
  });

  it("rejects an empty incident id", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    await expect(
      proof
        .connect(triageAgent)
        .submitDecision("", EVIDENCE_HASH, OUTPUT_HASH, "TruePositive", Risk.Low)
    ).to.be.revertedWithCustomError(proof, "EmptyIncidentId");
  });

  it("reverts on an unknown decision id", async () => {
    const { proof } = await loadFixture(deployed);
    await expect(proof.getDecision(999)).to.be.revertedWithCustomError(
      proof,
      "UnknownDecision"
    );
  });

  it("verify() returns true for the anchored hashes", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    expect(await proof.verify(id, EVIDENCE_HASH, OUTPUT_HASH)).to.equal(true);
  });

  it("verify() returns FALSE when the off-chain record has changed", async () => {
    // The tamper-detection moment: same decision id, recomputed hash no longer matches.
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    const tampered = ethers.keccak256(ethers.toUtf8Bytes("agent-outputs-EDITED"));
    expect(await proof.verify(id, EVIDENCE_HASH, tampered)).to.equal(false);
  });

  it("stores no evidence content, only digests", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const decision = await proof.getDecision(await submit(proof, triageAgent));
    expect(decision.evidenceHash).to.equal(EVIDENCE_HASH);
    expect(decision.evidenceHash).to.have.lengthOf(66); // 0x + 32 bytes
  });
});

describe("DecisionProof — the human approval gate", () => {
  it("a HIGH-risk decision CANNOT be finalised without approval", async () => {
    // ***** The Day 5 exit criterion. *****
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.High);
    await expect(
      proof.connect(triageAgent).finalizeDecision(id)
    ).to.be.revertedWithCustomError(proof, "ApprovalRequired");
  });

  it("a MEDIUM-risk decision also requires approval", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.Medium);
    await expect(
      proof.connect(triageAgent).finalizeDecision(id)
    ).to.be.revertedWithCustomError(proof, "ApprovalRequired");
  });

  it("a LOW-risk decision may finalise autonomously", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.Low);
    await expect(proof.connect(triageAgent).finalizeDecision(id)).to.emit(
      proof,
      "DecisionFinalized"
    );
  });

  it("finalises a high-risk decision once a human has approved", async () => {
    const { proof, triageAgent, analyst } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.High);
    await proof.connect(analyst).approveDecision(id, true, COMMENT_HASH);
    await proof.connect(triageAgent).finalizeDecision(id);
    expect((await proof.getDecision(id)).state).to.equal(State.Finalized);
  });

  it("records the approver from the transaction sender, not a payload claim", async () => {
    const { proof, triageAgent, analyst } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    await proof.connect(analyst).approveDecision(id, true, COMMENT_HASH);
    const decision = await proof.getDecision(id);
    expect(decision.approver).to.equal(analyst.address);
    expect(decision.commentHash).to.equal(COMMENT_HASH);
  });

  it("a rejected decision can never be finalised", async () => {
    const { proof, triageAgent, analyst } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    await proof.connect(analyst).approveDecision(id, false, COMMENT_HASH);
    await expect(
      proof.connect(triageAgent).finalizeDecision(id)
    ).to.be.revertedWithCustomError(proof, "DecisionWasRejected");
  });

  it("cannot be approved twice", async () => {
    const { proof, triageAgent, analyst, verifierAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    await proof.connect(analyst).approveDecision(id, true, COMMENT_HASH);
    await expect(
      proof.connect(verifierAgent).approveDecision(id, false, COMMENT_HASH)
    ).to.be.revertedWithCustomError(proof, "AlreadyDecided");
  });

  it("cannot be finalised twice", async () => {
    const { proof, triageAgent } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent, Risk.Low);
    await proof.connect(triageAgent).finalizeDecision(id);
    await expect(
      proof.connect(triageAgent).finalizeDecision(id)
    ).to.be.revertedWithCustomError(proof, "AlreadyFinalized");
  });

  it("keeps the full audit trail: submitted, decided and finalised timestamps", async () => {
    const { proof, triageAgent, analyst } = await loadFixture(deployed);
    const id = await submit(proof, triageAgent);
    await proof.connect(analyst).approveDecision(id, true, COMMENT_HASH);
    await proof.connect(triageAgent).finalizeDecision(id);

    const d = await proof.getDecision(id);
    expect(d.submittedAt).to.be.greaterThan(0n);
    expect(d.decidedAt).to.be.greaterThanOrEqual(d.submittedAt);
    expect(d.finalizedAt).to.be.greaterThanOrEqual(d.decidedAt);
  });
});
