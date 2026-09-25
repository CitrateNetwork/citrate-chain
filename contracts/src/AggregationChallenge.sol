// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";
import "./interfaces/INematocystSlashing.sol";

/// @title AggregationChallenge — optimistic verification for gradient-aggregation roots
/// @notice The on-chain half of WS-1 (verifiable gradient aggregation). A coordinator
///         commits a round's aggregate digest; it is **default-accepted** after a
///         challenge window unless a staked challenger disputes it. A challenge names a
///         coordinate; the coordinator must reveal the aggregate (bound to its commit);
///         a referee resolves using the **deterministic recompute** — `nat-aggregate`
///         produces a bit-reproducible aggregate, so the recompute is unambiguous (no
///         tolerance window). A proven-wrong coordinator is slashed (Byzantine tier).
///
///         This generalizes `DisputeResolution.sol`'s bisection game from compute-job
///         step ranges to aggregation-vector coordinates. It does NOT re-implement
///         slashing or the aggregate math: slashing is `NematocystSlashing`, the
///         aggregate + its digest are `nat-aggregate` (off-chain, bit-reproducible).
///
///         Economic sizing (ECON-S1 soundness report): the sim found p* ≈ 0.05 — a
///         cheat is −EV once caught with ≳5% probability, because a Byzantine slash
///         bans it and forfeits its 50M-CRP stream. So a modest bond + the Byzantine
///         tier suffice; no mandatory attestation floor is required.
///
/// @dev WP-4 of sprint AGG-S1 (FEDERATED_METALEARNING_METAPLAN.md, WS-1).
contract AggregationChallenge is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum Status { None, Committed, Challenged, Defended, Accepted, Slashed }

    struct Round {
        address coordinator;     // committed the aggregate (the defender)
        bytes32 aggregateDigest; // keccak256 of the committed aggregate bytes
        uint256 dim;             // number of coordinates in the aggregate
        uint256 deadline;        // challenge-window / response deadline (block number)
        Status status;
        address challenger;
        uint256 coordIndex;      // the disputed coordinate (for the selective recompute)
        uint256 challengerBond;
        bool slashed;
    }

    /// @notice The Byzantine slash tier (NematocystSlashing: 100% + permanent ban).
    uint8 public constant TIER_BYZANTINE = 2;

    /// @notice Default challenge window in blocks (~5 min at 2s blocks).
    uint256 public constant DEFAULT_WINDOW = 150;

    // ── State ───────────────────────────────────────────────────────

    /// @notice Bond a challenger stakes to dispute a round (SALT). Sized to p* (ECON-S1).
    uint256 public challengeBond;

    /// @notice Challenge window / response deadline, in blocks.
    uint256 public challengeWindow;

    /// @notice rounds[roundId].
    mapping(bytes32 => Round) public rounds;

    /// @notice The slashing contract (set by governance).
    INematocystSlashing public slashingContract;

    // ── Events ──────────────────────────────────────────────────────

    event AggregateCommitted(bytes32 indexed roundId, address indexed coordinator, bytes32 aggregateDigest, uint256 dim, uint256 deadline);
    event AggregateChallenged(bytes32 indexed roundId, address indexed challenger, uint256 coordIndex, uint256 bond);
    event AggregateDefended(bytes32 indexed roundId, bytes32 revealedDigest);
    event ChallengeResolved(bytes32 indexed roundId, bool challengerWon);
    event AggregateAccepted(bytes32 indexed roundId);
    event CoordinatorSlashed(bytes32 indexed roundId, address indexed coordinator);
    /// PBA-L2-041: the slash hook reverted; resolution still completed.
    event SlashHookFailed(bytes32 indexed roundId, address indexed coordinator);
    event ChallengeBondUpdated(uint256 oldBond, uint256 newBond);
    event ChallengeWindowUpdated(uint256 oldWindow, uint256 newWindow);
    event SlashingContractUpdated(address oldContract, address newContract);

    // ── Constructor ─────────────────────────────────────────────────

    constructor(uint256 _challengeBond, uint256 _challengeWindow, address initialGovernance)
        Governable(initialGovernance)
    {
        require(_challengeBond >= 1, "Bond must be >= 1");
        require(_challengeWindow >= 1, "Window must be >= 1");
        challengeBond = _challengeBond;
        challengeWindow = _challengeWindow;
    }

    // ── Commit (default-accept after the window) ─────────────────────

    /// @notice A coordinator commits a round's aggregate digest. Default-accepted after
    ///         the challenge window unless disputed. `aggregateDigest` is keccak256 of
    ///         the aggregate bytes the coordinator will reveal if challenged.
    function commitAggregate(bytes32 roundId, bytes32 aggregateDigest, uint256 dim) external {
        require(rounds[roundId].status == Status.None, "Round exists");
        require(aggregateDigest != bytes32(0), "Empty digest");
        require(dim >= 1, "dim must be >= 1");

        Round storage r = rounds[roundId];
        r.coordinator = msg.sender;
        r.aggregateDigest = aggregateDigest;
        r.dim = dim;
        r.deadline = block.number + challengeWindow;
        r.status = Status.Committed;

        emit AggregateCommitted(roundId, msg.sender, aggregateDigest, dim, r.deadline);
    }

    // ── Challenge ────────────────────────────────────────────────────

    /// @notice A staked challenger disputes a coordinate of a committed aggregate,
    ///         within the window. The challenge resets the deadline for the defender's
    ///         reveal.
    function challenge(bytes32 roundId, uint256 coordIndex) external payable nonReentrant {
        Round storage r = rounds[roundId];
        require(r.status == Status.Committed, "Not challengeable");
        require(block.number <= r.deadline, "Window closed");
        require(msg.value >= challengeBond, "Insufficient bond");
        require(coordIndex < r.dim, "coord out of range");
        require(msg.sender != r.coordinator, "Cannot challenge self");

        r.status = Status.Challenged;
        r.challenger = msg.sender;
        r.coordIndex = coordIndex;
        r.challengerBond = msg.value;
        r.deadline = block.number + challengeWindow;

        emit AggregateChallenged(roundId, msg.sender, coordIndex, msg.value);
    }

    /// @notice The coordinator reveals the aggregate bytes, bound to the commit
    ///         (`keccak256(aggregate) == aggregateDigest`). The referee then compares
    ///         the disputed coordinate against the deterministic recompute off-chain.
    function defend(bytes32 roundId, bytes calldata aggregate) external {
        Round storage r = rounds[roundId];
        require(r.status == Status.Challenged, "Not challenged");
        require(msg.sender == r.coordinator, "Not the coordinator");
        require(block.number <= r.deadline, "Deadline expired");
        require(keccak256(aggregate) == r.aggregateDigest, "Reveal != commit");
        require(aggregate.length == r.dim * 32, "Bad aggregate length");

        r.status = Status.Defended;
        emit AggregateDefended(roundId, keccak256(aggregate));
    }

    // ── Resolution ───────────────────────────────────────────────────

    /// @notice The referee resolves a challenge using the deterministic recompute. If
    ///         the challenger wins (the committed aggregate was wrong), the coordinator
    ///         is slashed (Byzantine) and the challenger recovers its bond; otherwise
    ///         the aggregate is accepted and the challenger forfeits its bond to the
    ///         coordinator (a frivolous-challenge cost — grief-unprofitable).
    function resolve(bytes32 roundId, bool challengerWins) external onlyGovernance nonReentrant {
        Round storage r = rounds[roundId];
        require(r.status == Status.Challenged || r.status == Status.Defended, "Not resolvable");

        uint256 bond = r.challengerBond;
        r.challengerBond = 0;

        if (challengerWins) {
            r.status = Status.Slashed;
            emit ChallengeResolved(roundId, true);
            _slashCoordinator(roundId);
            _pay(r.challenger, bond); // challenger recovers its stake
        } else {
            r.status = Status.Accepted;
            emit ChallengeResolved(roundId, false);
            emit AggregateAccepted(roundId);
            _pay(r.coordinator, bond); // frivolous challenge funds the coordinator
        }
    }

    /// @notice A defender whose challenge was never resolved in time loses by timeout —
    ///         a coordinator that fails to reveal/respond is treated as wrong (slashed).
    function timeoutChallenge(bytes32 roundId) external nonReentrant {
        Round storage r = rounds[roundId];
        require(r.status == Status.Challenged, "Not awaiting defense");
        require(block.number > r.deadline, "Deadline not expired");

        uint256 bond = r.challengerBond;
        r.challengerBond = 0;
        r.status = Status.Slashed;
        emit ChallengeResolved(roundId, true);
        _slashCoordinator(roundId);
        _pay(r.challenger, bond);
    }

    /// @notice After the window with no challenge, the aggregate is **default-accepted**.
    function finalize(bytes32 roundId) external {
        Round storage r = rounds[roundId];
        require(r.status == Status.Committed, "Not pending");
        require(block.number > r.deadline, "Window open");
        r.status = Status.Accepted;
        emit AggregateAccepted(roundId);
    }

    // ── Views ────────────────────────────────────────────────────────

    function isAccepted(bytes32 roundId) external view returns (bool) {
        return rounds[roundId].status == Status.Accepted;
    }

    function statusOf(bytes32 roundId) external view returns (Status) {
        return rounds[roundId].status;
    }

    // ── Governance ───────────────────────────────────────────────────

    function setChallengeBond(uint256 newBond) external onlyGovernance {
        require(newBond >= 1, "Bond must be >= 1");
        emit ChallengeBondUpdated(challengeBond, newBond);
        challengeBond = newBond;
    }

    function setChallengeWindow(uint256 newWindow) external onlyGovernance {
        require(newWindow >= 1, "Window must be >= 1");
        emit ChallengeWindowUpdated(challengeWindow, newWindow);
        challengeWindow = newWindow;
    }

    function setSlashingContract(address _slashing) external onlyGovernance {
        emit SlashingContractUpdated(address(slashingContract), _slashing);
        slashingContract = INematocystSlashing(_slashing);
    }

    // ── Internal ─────────────────────────────────────────────────────

    function _slashCoordinator(bytes32 roundId) internal {
        Round storage r = rounds[roundId];
        require(!r.slashed, "Already slashed");
        r.slashed = true;
        emit CoordinatorSlashed(roundId, r.coordinator);
        if (address(slashingContract) != address(0)) {
            // PBA-L2-041: a reverting slash hook (e.g. NematocystSlashing's
            // "Not staked" for an unstaked coordinator, or a missing slasher
            // authorization) must not brick challenge resolution forever.
            // The failure is surfaced as an event instead of reverting.
            try slashingContract.slash(r.coordinator, TIER_BYZANTINE, abi.encode(roundId, r.coordIndex)) {}
            catch {
                emit SlashHookFailed(roundId, r.coordinator);
            }
        }
    }

    function _pay(address to, uint256 amount) internal {
        if (amount > 0) {
            (bool ok, ) = payable(to).call{value: amount}("");
            require(ok, "Payout failed");
        }
    }
}
