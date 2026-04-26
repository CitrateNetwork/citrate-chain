// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/Governable.sol";

/// @title AgentDecisionRegistry
/// @notice On-chain audit trail for AI agent tool executions.
/// Every high-risk agent action (deploy, transfer, execute) is recorded
/// with its parameters hash, block number, and outcome. Disputes can be
/// filed against any decision.
///
/// Sprint HARDEN — WP-H.13
contract AgentDecisionRegistry is Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum DecisionStatus { Recorded, Disputed, Resolved }

    struct Decision {
        bytes32 agentId;        // Identifier for the agent instance
        string toolName;        // Tool that was called (e.g., "deploy_contract")
        bytes32 paramsHash;     // keccak256(abi.encode(params))
        uint256 blockNumber;    // Block when decision was executed
        uint256 timestamp;      // Block timestamp
        address executor;       // Address that submitted the record
        DecisionStatus status;  // Current status
        string disputeEvidence; // Evidence if disputed (empty otherwise)
    }

    // ── State ───────────────────────────────────────────────────────

    /// All decisions indexed by ID
    mapping(uint256 => Decision) public decisions;

    /// Decision count (also serves as next ID)
    uint256 public decisionCount;

    /// Decisions per agent (agentId → decision IDs)
    mapping(bytes32 => uint256[]) private agentDecisions;

    /// Dispute count per agent (for trust scoring)
    mapping(bytes32 => uint256) public disputeCount;

    /// Governance-approved addresses allowed to write decision records.
    mapping(address => bool) public authorizedRecorders;

    /// Governance-approved addresses allowed to open disputes.
    mapping(address => bool) public authorizedDisputers;

    // ── Events ──────────────────────────────────────────────────────

    event DecisionRecorded(
        uint256 indexed decisionId,
        bytes32 indexed agentId,
        string toolName,
        bytes32 paramsHash,
        uint256 blockNumber
    );

    event DecisionDisputed(
        uint256 indexed decisionId,
        bytes32 indexed agentId,
        address disputer,
        string evidence
    );

    event DisputeResolved(
        uint256 indexed decisionId,
        bytes32 indexed agentId,
        DecisionStatus resolution
    );

    event AuthorizedRecorderSet(address indexed recorder, bool allowed);
    event AuthorizedDisputerSet(address indexed disputer, bool allowed);

    error NotAuthorizedRecorder(address caller);
    error NotAuthorizedDisputer(address caller);
    error ZeroAddress();

    modifier onlyAuthorizedRecorder() {
        if (!authorizedRecorders[msg.sender]) revert NotAuthorizedRecorder(msg.sender);
        _;
    }

    modifier onlyAuthorizedDisputer() {
        if (!authorizedDisputers[msg.sender]) revert NotAuthorizedDisputer(msg.sender);
        _;
    }

    constructor(address initialGovernance) Governable(initialGovernance) {
        authorizedRecorders[initialGovernance] = true;
        authorizedDisputers[initialGovernance] = true;
        emit AuthorizedRecorderSet(initialGovernance, true);
        emit AuthorizedDisputerSet(initialGovernance, true);
    }

    // ── Authorization ────────────────────────────────────────────────

    /// @notice Allow or remove an address that may record agent decisions.
    function setAuthorizedRecorder(address recorder, bool allowed) external onlyGovernance {
        if (recorder == address(0)) revert ZeroAddress();
        authorizedRecorders[recorder] = allowed;
        emit AuthorizedRecorderSet(recorder, allowed);
    }

    /// @notice Allow or remove an address that may open disputes.
    function setAuthorizedDisputer(address disputer, bool allowed) external onlyGovernance {
        if (disputer == address(0)) revert ZeroAddress();
        authorizedDisputers[disputer] = allowed;
        emit AuthorizedDisputerSet(disputer, allowed);
    }

    // ── Core Functions ──────────────────────────────────────────────

    /// @notice Record an agent decision on-chain
    /// @param agentId Unique identifier for the agent
    /// @param toolName Name of the tool that was called
    /// @param paramsHash keccak256 hash of the tool parameters
    function registerDecision(
        bytes32 agentId,
        string calldata toolName,
        bytes32 paramsHash
    ) external onlyAuthorizedRecorder returns (uint256 decisionId) {
        decisionId = decisionCount++;

        decisions[decisionId] = Decision({
            agentId: agentId,
            toolName: toolName,
            paramsHash: paramsHash,
            blockNumber: block.number,
            timestamp: block.timestamp,
            executor: msg.sender,
            status: DecisionStatus.Recorded,
            disputeEvidence: ""
        });

        agentDecisions[agentId].push(decisionId);

        emit DecisionRecorded(decisionId, agentId, toolName, paramsHash, block.number);
    }

    /// @notice Dispute a recorded decision
    /// @param decisionId ID of the decision to dispute
    /// @param evidence Description of why the decision was wrong
    function disputeDecision(
        uint256 decisionId,
        string calldata evidence
    ) external onlyAuthorizedDisputer {
        require(decisionId < decisionCount, "Decision does not exist");
        Decision storage d = decisions[decisionId];
        require(d.status == DecisionStatus.Recorded, "Decision already disputed or resolved");

        d.status = DecisionStatus.Disputed;
        d.disputeEvidence = evidence;
        disputeCount[d.agentId]++;

        emit DecisionDisputed(decisionId, d.agentId, msg.sender, evidence);
    }

    /// @notice Resolve a dispute (governance or owner action)
    /// @param decisionId ID of the disputed decision
    /// @param upheld True if the dispute is upheld (decision was wrong)
    function resolveDispute(
        uint256 decisionId,
        bool upheld
    ) external onlyGovernance {
        require(decisionId < decisionCount, "Decision does not exist");
        Decision storage d = decisions[decisionId];
        require(d.status == DecisionStatus.Disputed, "Decision not disputed");

        d.status = DecisionStatus.Resolved;

        if (!upheld) {
            // Dispute was invalid — decrement dispute count
            if (disputeCount[d.agentId] > 0) {
                disputeCount[d.agentId]--;
            }
        }

        emit DisputeResolved(decisionId, d.agentId, d.status);
    }

    // ── View Functions ──────────────────────────────────────────────

    /// @notice Get all decision IDs for an agent
    function getDecisionHistory(bytes32 agentId) external view returns (uint256[] memory) {
        return agentDecisions[agentId];
    }

    /// @notice Get the number of decisions for an agent
    function getDecisionCount(bytes32 agentId) external view returns (uint256) {
        return agentDecisions[agentId].length;
    }

    /// @notice Get dispute status for a decision
    function getDisputeStatus(uint256 decisionId) external view returns (DecisionStatus) {
        require(decisionId < decisionCount, "Decision does not exist");
        return decisions[decisionId].status;
    }

    /// @notice Calculate trust score for an agent (decisions - disputes * 2)
    function getTrustScore(bytes32 agentId) external view returns (int256) {
        uint256 total = agentDecisions[agentId].length;
        uint256 disputes = disputeCount[agentId];
        return int256(total) - int256(disputes * 2);
    }

    // ── Trust Tiers (WP-H.16) ─────────────────────────────────────────

    /// Trust tier boundaries (inclusive lower bound).
    /// Untrusted: score < 100
    /// Standard:  100 <= score < 500
    /// Trusted:   score >= 500
    uint256 public constant TIER_STANDARD_THRESHOLD = 100;
    uint256 public constant TIER_TRUSTED_THRESHOLD = 500;

    event TrustTierChanged(
        bytes32 indexed agentId,
        string oldTier,
        string newTier,
        int256 newScore
    );

    /// @notice Return the trust tier name for an agent.
    /// @return tier "Untrusted", "Standard", or "Trusted"
    function getTrustTier(bytes32 agentId) external view returns (string memory tier) {
        int256 score = this.getTrustScore(agentId);
        return _tierName(score);
    }

    /// @notice Record a decision AND emit a tier-change event if the tier transitions.
    function registerDecisionWithTierCheck(
        bytes32 agentId,
        string calldata toolName,
        bytes32 paramsHash
    ) external onlyAuthorizedRecorder returns (uint256 decisionId) {
        string memory oldTier = _tierName(this.getTrustScore(agentId));

        decisionId = decisionCount++;
        decisions[decisionId] = Decision({
            agentId: agentId,
            toolName: toolName,
            paramsHash: paramsHash,
            blockNumber: block.number,
            timestamp: block.timestamp,
            executor: msg.sender,
            status: DecisionStatus.Recorded,
            disputeEvidence: ""
        });
        agentDecisions[agentId].push(decisionId);

        emit DecisionRecorded(decisionId, agentId, toolName, paramsHash, block.number);

        string memory newTier = _tierName(this.getTrustScore(agentId));
        if (keccak256(bytes(oldTier)) != keccak256(bytes(newTier))) {
            emit TrustTierChanged(agentId, oldTier, newTier, this.getTrustScore(agentId));
        }
    }

    /// @notice Dispute a decision AND emit a tier-change event if the tier transitions.
    function disputeDecisionWithTierCheck(
        uint256 decisionId,
        string calldata evidence
    ) external onlyAuthorizedDisputer {
        require(decisionId < decisionCount, "Decision does not exist");
        Decision storage d = decisions[decisionId];
        require(d.status == DecisionStatus.Recorded, "Decision already disputed or resolved");

        bytes32 agentId = d.agentId;
        string memory oldTier = _tierName(this.getTrustScore(agentId));

        d.status = DecisionStatus.Disputed;
        d.disputeEvidence = evidence;
        disputeCount[agentId]++;

        emit DecisionDisputed(decisionId, agentId, msg.sender, evidence);

        string memory newTier = _tierName(this.getTrustScore(agentId));
        if (keccak256(bytes(oldTier)) != keccak256(bytes(newTier))) {
            emit TrustTierChanged(agentId, oldTier, newTier, this.getTrustScore(agentId));
        }
    }

    /// @dev Map a trust score to a tier name.
    function _tierName(int256 score) internal pure returns (string memory) {
        if (score < int256(TIER_STANDARD_THRESHOLD)) {
            return "Untrusted";
        } else if (score < int256(TIER_TRUSTED_THRESHOLD)) {
            return "Standard";
        } else {
            return "Trusted";
        }
    }
}
