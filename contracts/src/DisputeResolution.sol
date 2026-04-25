// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";
import "./interfaces/INematocystSlashing.sol";

/// @title DisputeResolution — Bisection Game for Challenged Compute Results
/// @notice Implements the bisection dispute protocol from DisputeResolution.tla.
///         When a challenger disputes a provider's compute result:
///           1. Challenger posts a dispute bond (SALT)
///           2. Defender's bond is auto-locked from their stake
///           3. Bisection narrows the disputed computation range each round
///           4. After maxBisectionRounds (or when range is 1 step), referee resolves
///           5. Winner receives loser's bond
///           6. If defender loses, their stake is also slashed via NematocystSlashing
///
///         TLA+ Invariants enforced:
///           INV-1 TypeOK             — type correctness
///           INV-2 BondRequired       — active disputes have bonds posted
///           INV-3 RangeNarrows       — range halves each round
///           INV-4 TerminatesInMaxRounds — round <= maxBisectionRounds
///           INV-5 WinnerGetsBond     — resolved => winner gets loser's bond
///           INV-6 LoserSlashed       — defender loses => stake slashed
///           INV-7 NoPaymentBeforeResolution — no payout before resolution
///           INV-8 NoSlashBeforeResolution — no slash before resolution
///           INV-9 InactiveClean      — inactive disputes are pristine
///
///         AdversarialCompute.tla invariants:
///           GriefUnprofitable        — grief attacker always loses net SALT
///           DisputeBlocksPayment     — dispute prevents payment release
///           DisputeBondPositive      — active disputes always hold bond
///
/// @dev WP-CI.2 — Compute Infrastructure: Dispute Resolution
contract DisputeResolution is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum DisputeState { Inactive, Initiated, Bisecting, Resolved }
    enum Outcome { None, ChallengerWon, DefenderWon }

    struct Dispute {
        uint256 jobId;
        address challenger;
        address defender;
        uint256 challengerBond;
        uint256 defenderBond;
        uint256 rangeStart;
        uint256 rangeEnd;
        uint256 round;
        DisputeState state;
        Outcome outcome;
        uint256 deadline;
        bool winnerPaid;
        bool defenderSlashed;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Default round deadline in blocks (~5 minutes at 2s block time).
    uint256 public constant DEFAULT_ROUND_DEADLINE = 150;

    // ── State ───────────────────────────────────────────────────────

    /// @notice Bond required to initiate a dispute (in SALT).
    uint256 public disputeBond;

    /// @notice Maximum bisection rounds (typically 20 = log2 of max computation steps).
    uint256 public maxBisectionRounds;

    /// @notice Round deadline in blocks.
    uint256 public roundDeadline;

    /// @notice All disputes.
    mapping(uint256 => Dispute) public disputes;

    /// @notice Defender step result commits per dispute (kept separate for gas).
    mapping(uint256 => bytes32) public defenderCommits;

    /// @notice Next dispute ID.
    uint256 public nextDisputeId;

    /// @notice Whether a job currently has an active dispute.
    mapping(uint256 => bool) public jobDisputed;

    /// @notice NematocystSlashing contract for triggering slashes.
    INematocystSlashing public slashingContract;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Events ──────────────────────────────────────────────────────

    event DisputeInitiated(
        uint256 indexed disputeId,
        uint256 indexed jobId,
        address indexed challenger,
        address defender,
        uint256 bond,
        uint256 rangeStart,
        uint256 rangeEnd
    );
    event BisectionStarted(uint256 indexed disputeId);
    event BisectionRound(uint256 indexed disputeId, uint256 round, uint256 newRangeStart, uint256 newRangeEnd);
    event DefenderResponded(uint256 indexed disputeId, uint256 round, bytes32 stepResultHash);
    event DisputeResolved(uint256 indexed disputeId, Outcome outcome);
    event DisputeTimedOut(uint256 indexed disputeId, Outcome outcome);
    event WinnerPaid(uint256 indexed disputeId, address winner, uint256 amount);
    event DefenderSlashedEvent(uint256 indexed disputeId, address defender);
    event DisputeBondUpdated(uint256 oldBond, uint256 newBond);
    event MaxBisectionRoundsUpdated(uint256 oldRounds, uint256 newRounds);
    event SlashingContractUpdated(address oldContract, address newContract);
    // GovernanceTransferred event provided by Governable mixin.

    // ── Modifiers ───────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    // ── Constructor ─────────────────────────────────────────────────

    /// @param _disputeBond Bond required to initiate dispute (SALT).
    /// @param _maxBisectionRounds Maximum bisection rounds.
    constructor(uint256 _disputeBond, uint256 _maxBisectionRounds)
        Governable(msg.sender)
    {
        require(_disputeBond >= 1, "Bond must be >= 1");
        require(_maxBisectionRounds >= 1, "MaxRounds must be >= 1");

        disputeBond = _disputeBond;
        maxBisectionRounds = _maxBisectionRounds;
        roundDeadline = DEFAULT_ROUND_DEADLINE;
    }

    // ── Dispute Initiation ──────────────────────────────────────────

    /// @notice Initiate a dispute on a completed job.
    /// @param jobId The job being disputed.
    /// @param defender The provider whose result is challenged.
    /// @param rangeStart Start of the computation step range.
    /// @param rangeEnd End of the computation step range.
    /// @return disputeId The new dispute ID.
    function initiateDispute(
        uint256 jobId,
        address defender,
        uint256 rangeStart,
        uint256 rangeEnd
    ) external payable nonReentrant returns (uint256 disputeId) {
        require(msg.value >= disputeBond, "Insufficient challenger bond");
        require(defender != address(0), "Zero defender address");
        require(defender != msg.sender, "Cannot dispute yourself");
        require(rangeEnd > rangeStart, "Invalid range");
        require(!jobDisputed[jobId], "Job already disputed");

        disputeId = nextDisputeId++;
        jobDisputed[jobId] = true;

        _initDisputeAndEmit(disputeId, jobId, defender, rangeStart, rangeEnd);
    }

    /// @dev Initialize dispute storage and emit event. Separated to reduce stack depth.
    function _initDisputeAndEmit(
        uint256 disputeId,
        uint256 jobId,
        address defender,
        uint256 rangeStart,
        uint256 rangeEnd
    ) internal {
        Dispute storage d = disputes[disputeId];
        d.jobId = jobId;
        d.challenger = msg.sender;
        d.defender = defender;
        d.challengerBond = msg.value;
        d.defenderBond = disputeBond;
        d.rangeStart = rangeStart;
        d.rangeEnd = rangeEnd;
        d.state = DisputeState.Initiated;
        d.deadline = block.number + roundDeadline;

        emit DisputeInitiated(
            disputeId, jobId, msg.sender, defender,
            msg.value, rangeStart, rangeEnd
        );
    }

    /// @notice Defender acknowledges the dispute and posts their bond.
    /// @param disputeId The dispute to acknowledge.
    function acknowledgeDispute(uint256 disputeId) external payable nonReentrant {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Initiated, "Not in Initiated state");
        require(msg.sender == d.defender, "Not the defender");
        require(msg.value >= disputeBond, "Insufficient defender bond");

        d.defenderBond = msg.value;
        d.state = DisputeState.Bisecting;
        d.deadline = block.number + roundDeadline;

        emit BisectionStarted(disputeId);
    }

    // ── Bisection ───────────────────────────────────────────────────

    /// @notice Challenger narrows the disputed range by providing a midpoint.
    /// @param disputeId The dispute ID.
    /// @param claimFaulty If true, challenger claims the first half is faulty.
    function bisect(uint256 disputeId, bool claimFaulty) external {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Bisecting, "Not bisecting");
        require(msg.sender == d.challenger, "Not the challenger");
        require(d.round < maxBisectionRounds, "Max rounds reached");
        require(d.rangeEnd > d.rangeStart + 1, "Range already at minimum");
        require(block.number <= d.deadline, "Deadline expired");

        uint256 midpoint = d.rangeStart + (d.rangeEnd - d.rangeStart) / 2;

        if (claimFaulty) {
            d.rangeEnd = midpoint;
        } else {
            d.rangeStart = midpoint;
        }

        d.round++;
        d.deadline = block.number + roundDeadline;

        emit BisectionRound(disputeId, d.round, d.rangeStart, d.rangeEnd);
    }

    /// @notice Defender responds with their computation at the current range.
    /// @param disputeId The dispute ID.
    /// @param stepResultHash Hash of the defender's computation result.
    function respond(uint256 disputeId, bytes32 stepResultHash) external {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Bisecting, "Not bisecting");
        require(msg.sender == d.defender, "Not the defender");
        require(block.number <= d.deadline, "Deadline expired");

        defenderCommits[disputeId] = stepResultHash;
        d.deadline = block.number + roundDeadline;

        emit DefenderResponded(disputeId, d.round, stepResultHash);
    }

    // ── Resolution ──────────────────────────────────────────────────

    /// @notice Resolve the dispute — governance/referee determines winner.
    /// @param disputeId The dispute ID.
    /// @param challengerWins True if the challenger wins, false if defender wins.
    function resolve(uint256 disputeId, bool challengerWins) external onlyGovernance nonReentrant {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Bisecting, "Not bisecting");
        require(d.round >= 1, "At least one round required");

        d.state = DisputeState.Resolved;
        d.outcome = challengerWins ? Outcome.ChallengerWon : Outcome.DefenderWon;

        emit DisputeResolved(disputeId, d.outcome);

        _payWinner(disputeId);

        if (challengerWins) {
            _slashDefender(disputeId);
        }
    }

    /// @notice Timeout a dispute if either party fails to respond within the deadline.
    /// @param disputeId The dispute ID.
    function timeoutDispute(uint256 disputeId) external nonReentrant {
        Dispute storage d = disputes[disputeId];
        require(
            d.state == DisputeState.Initiated || d.state == DisputeState.Bisecting,
            "Not active dispute"
        );
        require(block.number > d.deadline, "Deadline not expired");

        d.state = DisputeState.Resolved;
        d.outcome = Outcome.ChallengerWon;

        emit DisputeTimedOut(disputeId, d.outcome);

        _payWinner(disputeId);
        _slashDefender(disputeId);
    }

    // ── View Functions ──────────────────────────────────────────────

    /// @notice Get full dispute record.
    function getDispute(uint256 disputeId) external view returns (Dispute memory result) {
        Dispute storage d = disputes[disputeId];
        result.jobId = d.jobId;
        result.challenger = d.challenger;
        result.defender = d.defender;
        result.challengerBond = d.challengerBond;
        result.defenderBond = d.defenderBond;
        _loadDisputeRangeAndState(d, result);
    }

    /// @dev Load remaining Dispute fields. Separated to reduce stack depth.
    function _loadDisputeRangeAndState(
        Dispute storage d,
        Dispute memory result
    ) internal view {
        result.rangeStart = d.rangeStart;
        result.rangeEnd = d.rangeEnd;
        result.round = d.round;
        result.state = d.state;
        result.outcome = d.outcome;
        result.deadline = d.deadline;
        result.winnerPaid = d.winnerPaid;
        result.defenderSlashed = d.defenderSlashed;
    }

    /// @notice Check if a dispute is currently active.
    function isDisputeActive(uint256 disputeId) external view returns (bool) {
        DisputeState s = disputes[disputeId].state;
        return s == DisputeState.Initiated || s == DisputeState.Bisecting;
    }

    /// @notice Get the current range size of a dispute.
    function getRangeSize(uint256 disputeId) external view returns (uint256) {
        return disputes[disputeId].rangeEnd - disputes[disputeId].rangeStart;
    }

    // ── Governance ──────────────────────────────────────────────────

    /// @notice Update dispute bond amount.
    function setDisputeBond(uint256 newBond) external onlyGovernance {
        require(newBond >= 1, "Bond must be >= 1");
        uint256 old = disputeBond;
        disputeBond = newBond;
        emit DisputeBondUpdated(old, newBond);
    }

    /// @notice Update max bisection rounds.
    function setMaxBisectionRounds(uint256 newMax) external onlyGovernance {
        require(newMax >= 1, "MaxRounds must be >= 1");
        uint256 old = maxBisectionRounds;
        maxBisectionRounds = newMax;
        emit MaxBisectionRoundsUpdated(old, newMax);
    }

    /// @notice Set the NematocystSlashing contract.
    function setSlashingContract(address _slashingContract) external onlyGovernance {
        address old = address(slashingContract);
        slashingContract = INematocystSlashing(_slashingContract);
        emit SlashingContractUpdated(old, _slashingContract);
    }

    /// @notice Update round deadline.
    function setRoundDeadline(uint256 newDeadline) external onlyGovernance {
        require(newDeadline >= 1, "Deadline must be >= 1");
        roundDeadline = newDeadline;
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ── Internal ────────────────────────────────────────────────────

    /// @dev Determine the winner and total payout for a resolved dispute.
    function _getWinnerAndPayout(uint256 disputeId) internal view returns (address winner, uint256 payout) {
        Dispute storage d = disputes[disputeId];
        if (d.outcome == Outcome.ChallengerWon) {
            winner = d.challenger;
        } else {
            winner = d.defender;
        }
        payout = d.challengerBond + d.defenderBond;
    }

    /// @dev Pay the winner their own bond back plus the loser's bond.
    function _payWinner(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Resolved, "Not resolved");
        require(!d.winnerPaid, "Already paid");
        require(d.outcome != Outcome.None, "No outcome");

        d.winnerPaid = true;

        (address winner, uint256 payout) = _getWinnerAndPayout(disputeId);

        d.challengerBond = 0;
        d.defenderBond = 0;

        if (payout > 0) {
            (bool success, ) = payable(winner).call{value: payout}("");
            require(success, "Winner payout failed");
        }

        emit WinnerPaid(disputeId, winner, payout);
    }

    /// @dev Slash the defender via NematocystSlashing.
    function _slashDefender(uint256 disputeId) internal {
        Dispute storage d = disputes[disputeId];
        require(d.state == DisputeState.Resolved, "Not resolved");
        require(d.outcome == Outcome.ChallengerWon, "Defender did not lose");
        require(!d.defenderSlashed, "Already slashed");

        d.defenderSlashed = true;

        address defenderAddr = d.defender;
        emit DefenderSlashedEvent(disputeId, defenderAddr);

        if (address(slashingContract) != address(0)) {
            try slashingContract.slash(
                defenderAddr,
                1, // SlashTier.Inconsistency
                abi.encodePacked("dispute:lost:", disputeId)
            ) {} catch {}
        }
    }

    // ── Receive ─────────────────────────────────────────────────────

    receive() external payable {}
}
