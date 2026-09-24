// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./LiquidStakingPool.sol";
import "./StablecoinTreasury.sol";

/// @dev Minimal interface for calling `acceptGovernance` on a
/// Governable target. Avoids importing the full mixin.
interface IGovernableTarget {
    function acceptGovernance() external;
}

/// @title TreasuryGovernor — On-Chain DAO Governor for Treasury Spending
/// @notice Full on-chain governance for Citrate treasury operations.
///         Voting power = SALT balance + stSALT shares * sharePrice (from LiquidStakingPool).
///
/// @dev Governance parameters (matching core/economics/src/governance.rs):
///   - Proposal threshold: 10,000 SALT
///   - Voting period: 50,400 blocks (~7 days)
///   - Execution delay (timelock): 7,200 blocks (~1 day)
///   - Quorum: 10% of total supply
///   - Approval: 60%
///   - Grace period: 50,400 blocks (~7 days)
///
/// Proposal types:
///   - TreasurySpend: calls StablecoinTreasury.distribute()
///   - ParameterChange: updates governance parameters
///   - OracleUpdate: updates oracle addresses on dependent contracts
///   - Emergency: expedited governance action (higher threshold required)
///
/// Lifecycle: propose -> vote -> queue (timelock) -> execute
///
/// Sprint ECON-3 — WP-E3.2
contract TreasuryGovernor is ReentrancyGuard {
    // ============================================================
    // Constants — Governance Parameters
    // ============================================================

    /// @notice Minimum SALT required to create a proposal (10,000 SALT)
    uint256 public constant PROPOSAL_THRESHOLD = 10_000 ether;

    /// @notice Voting period in blocks (~7 days at ~12s block time)
    uint256 public constant VOTING_PERIOD = 50_400;

    /// @notice Execution delay after proposal passes (~1 day)
    uint256 public constant EXECUTION_DELAY = 7_200;

    /// @notice Quorum as basis points of total supply (10% = 1000 bps)
    uint256 public constant QUORUM_BPS = 1_000;

    /// @notice Approval threshold as basis points (60% = 6000 bps)
    uint256 public constant APPROVAL_BPS = 6_000;

    /// @notice Grace period for execution in blocks (~7 days)
    uint256 public constant GRACE_PERIOD = 50_400;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10_000;

    /// @notice Emergency proposal threshold multiplier (3x normal = 30,000 SALT)
    uint256 public constant EMERGENCY_THRESHOLD_MULTIPLIER = 3;

    // ============================================================
    // Types
    // ============================================================

    enum ProposalType {
        TreasurySpend,
        ParameterChange,
        OracleUpdate,
        Emergency,
        /// CHAIN-B-C030: generic (target, value, calldata) execution. Without
        /// it, `execute` could only call `treasury.distribute`, so once a
        /// Governable target's governance was handed to this governor, every
        /// OTHER governance function on that target (e.g. `addStablecoin`,
        /// `addOracle`/`removeOracle`, `emergencyWithdraw`) became permanently
        /// unreachable — a documented-deployment-flow governance capture.
        Call
    }

    enum ProposalState {
        Pending,
        Active,
        Succeeded,
        Queued,
        Executed,
        Failed,
        Canceled,
        Expired
    }

    enum VoteType {
        For,
        Against,
        Abstain
    }

    struct Proposal {
        uint256 id;
        address proposer;
        ProposalType proposalType;
        string title;
        string description;
        uint256 createdAt;
        uint256 votingStarts;
        uint256 votingEnds;
        uint256 executionEta;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        bool executed;
        bool canceled;
        // For TreasurySpend proposals
        address spendStablecoin;
        address[] spendRecipients;
        uint256[] spendAmounts;
        // For ParameterChange proposals
        bytes32 parameterKey;
        uint256 parameterValue;
        // For OracleUpdate proposals
        address oracleTarget;
        address newOracleAddress;
        // CHAIN-B-C030: for Call proposals — an arbitrary governed-target call.
        address callTarget;
        uint256 callValue;
        bytes callData;
    }

    struct Vote {
        VoteType support;
        uint256 weight;
        uint256 blockHeight;
    }

    // ============================================================
    // State — Dependencies
    // ============================================================

    /// @notice LiquidStakingPool for stSALT voting power calculation
    LiquidStakingPool public stakingPool;

    /// @notice StablecoinTreasury for TreasurySpend execution
    StablecoinTreasury public treasury;

    /// @notice Guardian address for emergency cancellation
    address public guardian;

    /// @notice Total supply of SALT for quorum calculation (1B SALT)
    uint256 public totalSaltSupply;

    // ============================================================
    // State — Proposals
    // ============================================================

    /// @notice Auto-incrementing proposal ID
    uint256 public nextProposalId;

    /// @notice All proposals by ID
    mapping(uint256 => Proposal) internal _proposals;

    /// @notice Votes per proposal: proposalId => voter => Vote
    mapping(uint256 => mapping(address => Vote)) public votes;

    /// @notice Whether a voter has voted on a proposal
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    // ============================================================
    // Events
    // ============================================================

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        ProposalType proposalType,
        string title,
        uint256 votingStarts,
        uint256 votingEnds
    );
    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        VoteType support,
        uint256 weight
    );
    event ProposalQueued(uint256 indexed proposalId, uint256 executionEta);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCanceled(uint256 indexed proposalId);
    event GuardianTransferred(address indexed oldGuardian, address indexed newGuardian);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyGuardian() {
        require(msg.sender == guardian, "TreasuryGovernor: not guardian");
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    /// @notice Deploy the governor
    /// @param _stakingPool LiquidStakingPool for voting power
    /// @param _treasury StablecoinTreasury for spend execution
    /// @param _guardian Emergency guardian address
    /// @param _totalSaltSupply Total SALT supply for quorum calculation
    constructor(
        address _stakingPool,
        address _treasury,
        address _guardian,
        uint256 _totalSaltSupply
    ) {
        require(_stakingPool != address(0), "TreasuryGovernor: zero staking pool");
        require(_treasury != address(0), "TreasuryGovernor: zero treasury");
        require(_guardian != address(0), "TreasuryGovernor: zero guardian");
        require(_totalSaltSupply > 0, "TreasuryGovernor: zero supply");

        stakingPool = LiquidStakingPool(payable(_stakingPool));
        treasury = StablecoinTreasury(_treasury);
        guardian = _guardian;
        totalSaltSupply = _totalSaltSupply;
        nextProposalId = 1;
    }

    // ============================================================
    // Proposal Creation
    // ============================================================

    /// @notice Create a TreasurySpend proposal
    /// @param title Proposal title
    /// @param description Proposal description
    /// @param stablecoin Stablecoin to distribute
    /// @param recipients Array of recipient addresses
    /// @param amounts Array of amounts to distribute
    /// @return proposalId The new proposal ID
    function proposeTreasurySpend(
        string calldata title,
        string calldata description,
        address stablecoin,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external payable returns (uint256 proposalId) {
        require(recipients.length > 0, "TreasuryGovernor: empty recipients");
        require(recipients.length == amounts.length, "TreasuryGovernor: length mismatch");
        require(stablecoin != address(0), "TreasuryGovernor: zero stablecoin");

        proposalId = _createProposal(msg.sender, ProposalType.TreasurySpend, title, description);

        Proposal storage p = _proposals[proposalId];
        p.spendStablecoin = stablecoin;
        p.spendRecipients = recipients;
        p.spendAmounts = amounts;
    }

    /// @notice Create a ParameterChange proposal
    /// @param title Proposal title
    /// @param description Proposal description
    /// @param parameterKey keccak256 hash of parameter name
    /// @param parameterValue New parameter value
    /// @return proposalId The new proposal ID
    function proposeParameterChange(
        string calldata title,
        string calldata description,
        bytes32 parameterKey,
        uint256 parameterValue
    ) external payable returns (uint256 proposalId) {
        proposalId = _createProposal(msg.sender, ProposalType.ParameterChange, title, description);

        Proposal storage p = _proposals[proposalId];
        p.parameterKey = parameterKey;
        p.parameterValue = parameterValue;
    }

    /// @notice Create an OracleUpdate proposal
    /// @param title Proposal title
    /// @param description Proposal description
    /// @param target Contract that holds the oracle reference
    /// @param newOracle New oracle address
    /// @return proposalId The new proposal ID
    function proposeOracleUpdate(
        string calldata title,
        string calldata description,
        address target,
        address newOracle
    ) external payable returns (uint256 proposalId) {
        require(target != address(0), "TreasuryGovernor: zero target");
        require(newOracle != address(0), "TreasuryGovernor: zero oracle");

        proposalId = _createProposal(msg.sender, ProposalType.OracleUpdate, title, description);

        Proposal storage p = _proposals[proposalId];
        p.oracleTarget = target;
        p.newOracleAddress = newOracle;
    }

    /// @notice Create a generic Call proposal — CHAIN-B-C030.
    /// @dev Executes `target.call{value}(data)` on success, after vote +
    ///      timelock. This is what keeps every governance function on a
    ///      Governable target reachable once its governance is transferred to
    ///      this governor.
    /// @param title Proposal title
    /// @param description Proposal description
    /// @param target Contract to call
    /// @param value Native value to forward
    /// @param data Calldata to invoke on `target`
    /// @return proposalId The new proposal ID
    function proposeCall(
        string calldata title,
        string calldata description,
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (uint256 proposalId) {
        require(target != address(0), "TreasuryGovernor: zero target");
        require(data.length >= 4, "TreasuryGovernor: empty calldata");

        proposalId = _createProposal(msg.sender, ProposalType.Call, title, description);

        Proposal storage p = _proposals[proposalId];
        p.callTarget = target;
        p.callValue = value;
        p.callData = data;
    }

    /// @notice Create an Emergency proposal (requires 3x threshold)
    /// @param title Proposal title
    /// @param description Proposal description
    /// @return proposalId The new proposal ID
    function proposeEmergency(
        string calldata title,
        string calldata description
    ) external payable returns (uint256 proposalId) {
        uint256 votingPower = getVotingPower(msg.sender);
        require(
            votingPower >= PROPOSAL_THRESHOLD * EMERGENCY_THRESHOLD_MULTIPLIER,
            "TreasuryGovernor: below emergency threshold"
        );

        proposalId = _createProposal(msg.sender, ProposalType.Emergency, title, description);
    }

    // ============================================================
    // Voting
    // ============================================================

    /// @notice Cast a vote on an active proposal
    /// @param proposalId The proposal to vote on
    /// @param support Vote type: For (0), Against (1), Abstain (2)
    function castVote(uint256 proposalId, VoteType support) external {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");

        Proposal storage p = _proposals[proposalId];
        require(!p.canceled, "TreasuryGovernor: proposal canceled");
        require(!p.executed, "TreasuryGovernor: proposal executed");
        require(block.number >= p.votingStarts, "TreasuryGovernor: voting not started");
        require(block.number <= p.votingEnds, "TreasuryGovernor: voting ended");
        require(!hasVoted[proposalId][msg.sender], "TreasuryGovernor: already voted");

        uint256 weight = getVotingPower(msg.sender);
        require(weight > 0, "TreasuryGovernor: no voting power");

        // Native SALT is not an ERC20Votes token and cannot be checkpointed
        // by this contract. Bound aggregate counted voting power to the
        // declared supply so the same balance cannot be recycled through
        // fresh addresses to manufacture quorum.
        require(
            p.forVotes + p.againstVotes + p.abstainVotes + weight <= totalSaltSupply,
            "TreasuryGovernor: voting power exceeds supply"
        );

        hasVoted[proposalId][msg.sender] = true;
        votes[proposalId][msg.sender] = Vote({
            support: support,
            weight: weight,
            blockHeight: block.number
        });

        if (support == VoteType.For) {
            p.forVotes += weight;
        } else if (support == VoteType.Against) {
            p.againstVotes += weight;
        } else {
            p.abstainVotes += weight;
        }

        emit VoteCast(proposalId, msg.sender, support, weight);
    }

    // ============================================================
    // Queue & Execute
    // ============================================================

    /// @notice Queue a succeeded proposal for execution after timelock
    /// @param proposalId The proposal to queue
    function queue(uint256 proposalId) external {
        require(state(proposalId) == ProposalState.Succeeded, "TreasuryGovernor: not succeeded");

        Proposal storage p = _proposals[proposalId];
        p.executionEta = block.number + EXECUTION_DELAY;

        emit ProposalQueued(proposalId, p.executionEta);
    }

    /// @notice Execute a queued proposal after the timelock has elapsed
    /// @param proposalId The proposal to execute
    function execute(uint256 proposalId) external nonReentrant {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");

        Proposal storage p = _proposals[proposalId];
        require(!p.executed, "TreasuryGovernor: already executed");
        require(!p.canceled, "TreasuryGovernor: proposal canceled");
        require(p.executionEta > 0, "TreasuryGovernor: not queued");
        require(block.number >= p.executionEta, "TreasuryGovernor: timelock not elapsed");
        require(
            block.number <= p.executionEta + GRACE_PERIOD,
            "TreasuryGovernor: execution expired"
        );

        // Verify the proposal actually passed (check votes)
        uint256 totalVotes = p.forVotes + p.againstVotes + p.abstainVotes;
        uint256 quorumRequired = (totalSaltSupply * QUORUM_BPS) / BPS;
        uint256 approvalRequired = (totalVotes * APPROVAL_BPS) / BPS;
        require(totalVotes >= quorumRequired, "TreasuryGovernor: quorum not met");
        require(p.forVotes >= approvalRequired, "TreasuryGovernor: approval not met");

        p.executed = true;

        if (p.proposalType == ProposalType.TreasurySpend) {
            _executeTreasurySpend(p);
        } else if (p.proposalType == ProposalType.Call) {
            // CHAIN-B-C030: generic on-chain execution of a governed-target
            // call, so vote + timelock can reach any function on a target this
            // governor governs.
            _executeCall(p);
        }
        // ParameterChange, OracleUpdate, and Emergency proposals emit events
        // and are executed off-chain by the guardian/multisig reading the event

        emit ProposalExecuted(proposalId);
    }

    // ============================================================
    // Cancellation
    // ============================================================

    /// @notice Cancel a proposal (only proposer or guardian)
    /// @param proposalId The proposal to cancel
    function cancel(uint256 proposalId) external {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");

        Proposal storage p = _proposals[proposalId];
        require(!p.executed, "TreasuryGovernor: already executed");
        require(!p.canceled, "TreasuryGovernor: already canceled");
        require(
            msg.sender == p.proposer || msg.sender == guardian,
            "TreasuryGovernor: not authorized"
        );

        p.canceled = true;

        emit ProposalCanceled(proposalId);
    }

    // ============================================================
    // Governable handover plumbing (audit SOL-21 follow-on)
    // ============================================================

    /// @notice Accept pending governance for an external Governable
    /// contract. The standard handover flow is:
    ///   1. Current governor calls `target.transferGovernance(governor)`.
    ///   2. Anyone calls `governor.acceptGovernanceOf(target)` to
    ///      complete the two-step transfer.
    ///
    /// Permissionless because the Governable mixin already requires
    /// that the calling address be `pendingGovernance` — only the
    /// governor itself can satisfy that, and this method just lets
    /// anyone trigger it on behalf of the governor contract.
    function acceptGovernanceOf(address target) external {
        IGovernableTarget(target).acceptGovernance();
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get the current state of a proposal
    /// @param proposalId The proposal ID
    /// @return The current ProposalState
    function state(uint256 proposalId) public view returns (ProposalState) {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");

        Proposal storage p = _proposals[proposalId];

        if (p.canceled) return ProposalState.Canceled;
        if (p.executed) return ProposalState.Executed;

        if (block.number < p.votingStarts) return ProposalState.Pending;
        if (block.number <= p.votingEnds) return ProposalState.Active;

        // Voting has ended — check results
        uint256 totalVotes = p.forVotes + p.againstVotes + p.abstainVotes;
        uint256 quorumRequired = (totalSaltSupply * QUORUM_BPS) / BPS;
        uint256 approvalRequired = (totalVotes * APPROVAL_BPS) / BPS;

        bool quorumMet = totalVotes >= quorumRequired;
        bool approvalMet = p.forVotes >= approvalRequired;

        if (!quorumMet || !approvalMet) return ProposalState.Failed;

        // Proposal succeeded
        if (p.executionEta == 0) return ProposalState.Succeeded;

        // Check if in timelock period
        if (block.number < p.executionEta) return ProposalState.Queued;

        // Check if within grace period
        if (block.number <= p.executionEta + GRACE_PERIOD) return ProposalState.Queued;

        // Past grace period without execution
        return ProposalState.Expired;
    }

    /// @notice Get voting power for an address
    /// @dev Voting power = SALT balance + stSALT shares * sharePrice / 1e18
    /// @param voter The address to check
    /// @return power Total voting power in wei
    function getVotingPower(address voter) public view returns (uint256 power) {
        // Native SALT balance
        power = voter.balance;

        // stSALT voting power: shares * sharePrice / 1e18
        uint256 stakedShares = stakingPool.shares(voter);
        if (stakedShares > 0) {
            uint256 sharePrice = stakingPool.getSharePrice();
            power += (stakedShares * sharePrice) / 1e18;
        }
    }

    /// @notice Get proposal details
    /// @param proposalId The proposal ID
    function getProposal(uint256 proposalId) external view returns (
        uint256 id,
        address proposer,
        ProposalType proposalType,
        string memory title,
        string memory description,
        uint256 createdAt,
        uint256 votingStarts,
        uint256 votingEnds,
        uint256 executionEta,
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes,
        bool executed,
        bool canceled
    ) {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");
        Proposal storage p = _proposals[proposalId];
        return (
            p.id,
            p.proposer,
            p.proposalType,
            p.title,
            p.description,
            p.createdAt,
            p.votingStarts,
            p.votingEnds,
            p.executionEta,
            p.forVotes,
            p.againstVotes,
            p.abstainVotes,
            p.executed,
            p.canceled
        );
    }

    /// @notice Get the quorum requirement in absolute SALT terms
    function quorumThreshold() external view returns (uint256) {
        return (totalSaltSupply * QUORUM_BPS) / BPS;
    }

    /// @notice Get TreasurySpend proposal details
    /// @param proposalId The proposal ID
    function getSpendDetails(uint256 proposalId) external view returns (
        address stablecoin,
        address[] memory recipients,
        uint256[] memory amounts
    ) {
        require(proposalId > 0 && proposalId < nextProposalId, "TreasuryGovernor: invalid proposal");
        Proposal storage p = _proposals[proposalId];
        return (p.spendStablecoin, p.spendRecipients, p.spendAmounts);
    }

    // ============================================================
    // Guardian Management
    // ============================================================

    /// @notice Transfer guardian role
    /// @param newGuardian New guardian address
    function transferGuardian(address newGuardian) external onlyGuardian {
        require(newGuardian != address(0), "TreasuryGovernor: zero guardian");
        address old = guardian;
        guardian = newGuardian;
        emit GuardianTransferred(old, newGuardian);
    }

    // ============================================================
    // Internal Helpers
    // ============================================================

    /// @dev Create a base proposal and validate proposer's voting power
    function _createProposal(
        address proposer,
        ProposalType proposalType,
        string calldata title,
        string calldata description
    ) internal returns (uint256 proposalId) {
        uint256 votingPower = getVotingPower(proposer);

        // Emergency proposals have a higher threshold, checked in proposeEmergency
        if (proposalType != ProposalType.Emergency) {
            require(
                votingPower >= PROPOSAL_THRESHOLD,
                "TreasuryGovernor: below proposal threshold"
            );
        }

        require(bytes(title).length > 0, "TreasuryGovernor: empty title");

        proposalId = nextProposalId++;

        uint256 votingStarts = block.number + 1;
        uint256 votingEnds = votingStarts + VOTING_PERIOD;

        Proposal storage p = _proposals[proposalId];
        p.id = proposalId;
        p.proposer = proposer;
        p.proposalType = proposalType;
        p.title = title;
        p.description = description;
        p.createdAt = block.number;
        p.votingStarts = votingStarts;
        p.votingEnds = votingEnds;

        emit ProposalCreated(
            proposalId,
            proposer,
            proposalType,
            title,
            votingStarts,
            votingEnds
        );
    }

    /// @dev Execute a TreasurySpend proposal by calling treasury.distribute()
    function _executeTreasurySpend(Proposal storage p) internal {
        require(p.spendRecipients.length > 0, "TreasuryGovernor: no spend data");

        treasury.distribute(p.spendStablecoin, p.spendRecipients, p.spendAmounts);
    }

    /// @dev CHAIN-B-C030: execute a generic Call proposal.
    function _executeCall(Proposal storage p) internal {
        (bool ok, bytes memory ret) = p.callTarget.call{value: p.callValue}(p.callData);
        if (!ok) {
            // Bubble up the revert reason if any.
            if (ret.length > 0) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            revert("TreasuryGovernor: call failed");
        }
    }

    // ============================================================
    // Receive
    // ============================================================

    /// @notice Accept SALT transfers (for voting power deposits)
    receive() external payable {}
}
