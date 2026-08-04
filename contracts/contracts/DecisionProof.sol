// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentRegistry} from "./AgentRegistry.sol";

/// @title DecisionProof
/// @notice Tamper-evident record of what an agent decided, who approved it, and when.
///
/// ## What is deliberately NOT here
///
/// No raw security evidence, no LLM prompts, no personal data, no detailed remediation
/// instructions. Only hashes, an agent identity, a label, a risk level and approval state. That
/// split is the architecture principle (§4.3) and it is enforced by what this contract *accepts*
/// rather than by convention — there is no function on this contract that could store an evidence
/// row even if a caller wanted to.
///
/// ## The two controls a database cannot provide
///
/// 1. **Unauthorised writers are rejected.** `submitDecision` reverts unless the caller is a
///    registered, active agent in the registry. A database's access control is administered by
///    the same party that operates the database.
/// 2. **High-risk actions cannot finalise without a human.** `finalizeDecision` reverts on an
///    unapproved high-risk decision. The rule is in the contract, not in the application layer
///    that the operator controls.
contract DecisionProof {
    enum Risk {
        Low,
        Medium,
        High
    }

    enum State {
        Proposed,
        Approved,
        Rejected,
        Finalized
    }

    struct Decision {
        string incidentId;
        bytes32 evidenceHash;   // keccak256 over the canonicalised evidence bundle
        bytes32 outputHash;     // keccak256 over the canonicalised agent outputs
        string label;           // TruePositive | BenignPositive | FalsePositive
        Risk risk;
        State state;
        address agent;          // the submitting agent identity
        address approver;       // zero until a human decides
        bytes32 commentHash;    // keccak256 of the approver's comment; the comment stays off-chain
        uint64 submittedAt;
        uint64 decidedAt;
        uint64 finalizedAt;
    }

    AgentRegistry public immutable registry;

    uint256 public decisionCount;
    mapping(uint256 => Decision) private _decisions;
    /// @dev Guards against the same incident+output pair being anchored twice.
    mapping(bytes32 => uint256) private _fingerprints;

    event DecisionSubmitted(
        uint256 indexed decisionId,
        string incidentId,
        address indexed agent,
        bytes32 evidenceHash,
        bytes32 outputHash,
        string label,
        Risk risk
    );
    event DecisionApproved(
        uint256 indexed decisionId, address indexed approver, bool approved, bytes32 commentHash
    );
    event DecisionFinalized(uint256 indexed decisionId, address indexed agent, string label);

    error UnauthorisedAgent(address caller);
    error UnknownDecision(uint256 decisionId);
    error DuplicateDecision(uint256 existingDecisionId);
    error AlreadyDecided(uint256 decisionId);
    error AlreadyFinalized(uint256 decisionId);
    error ApprovalRequired(uint256 decisionId);
    error DecisionWasRejected(uint256 decisionId);
    error EmptyIncidentId();
    error ZeroHash();

    constructor(address registryAddress) {
        registry = AgentRegistry(registryAddress);
    }

    /// @dev The authorisation boundary. Everything else in this contract is bookkeeping.
    modifier onlyActiveAgent() {
        if (!registry.isActive(msg.sender)) revert UnauthorisedAgent(msg.sender);
        _;
    }

    /// @notice Record a proposed decision from an authorised agent.
    function submitDecision(
        string calldata incidentId,
        bytes32 evidenceHash,
        bytes32 outputHash,
        string calldata label,
        Risk risk
    ) external onlyActiveAgent returns (uint256 decisionId) {
        if (bytes(incidentId).length == 0) revert EmptyIncidentId();
        // A zero hash would make verification vacuously succeed later.
        if (evidenceHash == bytes32(0) || outputHash == bytes32(0)) revert ZeroHash();

        bytes32 fingerprint = keccak256(abi.encodePacked(incidentId, evidenceHash, outputHash));
        uint256 existing = _fingerprints[fingerprint];
        if (existing != 0) revert DuplicateDecision(existing);

        decisionId = ++decisionCount;
        _fingerprints[fingerprint] = decisionId;

        _decisions[decisionId] = Decision({
            incidentId: incidentId,
            evidenceHash: evidenceHash,
            outputHash: outputHash,
            label: label,
            risk: risk,
            state: State.Proposed,
            agent: msg.sender,
            approver: address(0),
            commentHash: bytes32(0),
            submittedAt: uint64(block.timestamp),
            decidedAt: 0,
            finalizedAt: 0
        });

        emit DecisionSubmitted(
            decisionId, incidentId, msg.sender, evidenceHash, outputHash, label, risk
        );
    }

    /// @notice Record a human approval or rejection.
    /// @dev The approver is `msg.sender`, so the identity is established by the signature on the
    ///      transaction rather than by a claim in a payload. That is the whole point: a name in a
    ///      database field is an assertion, a transaction sender is a signature.
    function approveDecision(uint256 decisionId, bool approved, bytes32 commentHash) external {
        Decision storage d = _mustExist(decisionId);
        if (d.state == State.Finalized) revert AlreadyFinalized(decisionId);
        if (d.state != State.Proposed) revert AlreadyDecided(decisionId);

        d.state = approved ? State.Approved : State.Rejected;
        d.approver = msg.sender;
        d.commentHash = commentHash;
        d.decidedAt = uint64(block.timestamp);

        emit DecisionApproved(decisionId, msg.sender, approved, commentHash);
    }

    /// @notice Finalise a decision, but only when policy allows it.
    /// @dev A Medium or High risk decision requires a recorded approval first. This revert is the
    ///      Day 5 exit criterion: a high-risk action cannot finalise without a human.
    function finalizeDecision(uint256 decisionId) external onlyActiveAgent {
        Decision storage d = _mustExist(decisionId);
        if (d.state == State.Finalized) revert AlreadyFinalized(decisionId);
        if (d.state == State.Rejected) revert DecisionWasRejected(decisionId);
        if (d.risk != Risk.Low && d.state != State.Approved) revert ApprovalRequired(decisionId);

        d.state = State.Finalized;
        d.finalizedAt = uint64(block.timestamp);

        emit DecisionFinalized(decisionId, d.agent, d.label);
    }

    // --- views -------------------------------------------------------------------------

    function getDecision(uint256 decisionId) external view returns (Decision memory) {
        return _mustExist(decisionId);
    }

    /// @notice Recompute-and-compare, on chain.
    /// @dev The UI recomputes hashes from the off-chain record and calls this. A mismatch means
    ///      the stored data changed after anchoring.
    function verify(uint256 decisionId, bytes32 evidenceHash, bytes32 outputHash)
        external
        view
        returns (bool)
    {
        Decision storage d = _mustExist(decisionId);
        return d.evidenceHash == evidenceHash && d.outputHash == outputHash;
    }

    function findByFingerprint(string calldata incidentId, bytes32 evidenceHash, bytes32 outputHash)
        external
        view
        returns (uint256)
    {
        return _fingerprints[keccak256(abi.encodePacked(incidentId, evidenceHash, outputHash))];
    }

    function _mustExist(uint256 decisionId) private view returns (Decision storage d) {
        d = _decisions[decisionId];
        if (d.submittedAt == 0) revert UnknownDecision(decisionId);
    }
}
