// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentRegistry
/// @notice Permissioned identities for the agent workforce.
///
/// This contract exists to answer one question that an application database cannot answer
/// credibly: *was this decision produced by an agent that was authorised to produce it, at the
/// time it was produced?* The party operating a database also controls its rows, so an audit log
/// asserting "agent X was active" is only as trustworthy as the operator. Here, deactivating an
/// agent is a transaction with a block number attached, and nobody — including the owner — can
/// retroactively claim an agent was active when it was not.
///
/// Kept separate from DecisionProof deliberately. The authorisation boundary is the thing being
/// demonstrated, and it reads far more clearly when a distinct contract is doing the rejecting.
contract AgentRegistry {
    struct Agent {
        string role;          // detection | correlation | investigation | triage | remediation | verifier
        bytes32 metadataHash; // keccak256 of the off-chain agent card; never the card itself
        bool active;
        uint64 registeredAt;
    }

    address public owner;

    mapping(address => Agent) private _agents;
    address[] private _agentList;

    event AgentRegistered(address indexed agent, string role, bytes32 metadataHash);
    event AgentStatusChanged(address indexed agent, bool active);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error AlreadyRegistered(address agent);
    error UnknownAgent(address agent);
    error ZeroAddress();
    error EmptyRole();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Create a permissioned identity for an agent.
    /// @dev Re-registration is rejected rather than silently overwriting: an agent's registration
    ///      timestamp is part of the audit trail, and quietly resetting it would erase history.
    function registerAgent(address agent, string calldata role, bytes32 metadataHash)
        external
        onlyOwner
    {
        if (agent == address(0)) revert ZeroAddress();
        if (bytes(role).length == 0) revert EmptyRole();
        if (_agents[agent].registeredAt != 0) revert AlreadyRegistered(agent);

        _agents[agent] = Agent({
            role: role,
            metadataHash: metadataHash,
            active: true,
            registeredAt: uint64(block.timestamp)
        });
        _agentList.push(agent);

        emit AgentRegistered(agent, role, metadataHash);
    }

    /// @notice Activate or deactivate an agent.
    /// @dev The containment control: a compromised agent is stopped from submitting further
    ///      proofs without touching anything it has already signed.
    function setAgentStatus(address agent, bool active) external onlyOwner {
        if (_agents[agent].registeredAt == 0) revert UnknownAgent(agent);
        _agents[agent].active = active;
        emit AgentStatusChanged(agent, active);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // --- views -------------------------------------------------------------------------

    function isActive(address agent) external view returns (bool) {
        return _agents[agent].active;
    }

    function isRegistered(address agent) external view returns (bool) {
        return _agents[agent].registeredAt != 0;
    }

    function getAgent(address agent)
        external
        view
        returns (string memory role, bytes32 metadataHash, bool active, uint64 registeredAt)
    {
        Agent storage a = _agents[agent];
        if (a.registeredAt == 0) revert UnknownAgent(agent);
        return (a.role, a.metadataHash, a.active, a.registeredAt);
    }

    function agentCount() external view returns (uint256) {
        return _agentList.length;
    }

    function agentAt(uint256 index) external view returns (address) {
        return _agentList[index];
    }
}
