// ── VENDORED: DO NOT EDIT. Change upstream, then re-vendor with a new header. ─────
// Source:    CitrateNetwork/citrate-coop contracts/src/PatronageLedger.sol
// Upstream:  github.com/CitrateNetwork/citrate-coop @ b8a884f01d84a4605e5752e052ef092e1922ba0b
//            (branch fix/explicit-initial-admin; re-vendor from main after it merges), vendored 2026-10-18.
// Includes:  PBA R2 remediation (citrate-coop #3), Apache-2.0 relicense, explicit initial admin/registrar, role-holder validation.
// Integrity: every line after this 10-line header is byte-identical to upstream:
//            `tail -n +11 <this file> | sha256sum` == b7a3efd84e3ff73d7ce3a70df059dd986a1fa763bdf9eed7c9065582d549d263
// Why:       C2 D9 / C4: deployed dormant at betanet genesis by the citrate-chain
//            ceremony (script/DeployDormantLedgers.s.sol).
// ───────────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/Auth.sol";
import "./MembershipSBT.sol"; // IKYCRegistry

interface IMembership {
    function isMember(address a) external view returns (bool);
}

/// @title PatronageLedger — the economics rail (RFC-CIT-COOP-0001)
/// @notice Non-transferable patronage units = compute x data-quality (relative to the
///         pool), plus the patronage-dividend accumulator. Units mutate and the dividend
///         settles together (MasterChef pattern) — that co-location is what makes the
///         conservation + no-retroactive invariants hold. Carries NO votes (ADR-0001).
/// @dev Formal: specs/tla/coop/PatronageDividend.tla, CoopLifecycle.tla.
///      Feature: features/coop_patronage.feature, coop_revenue_dividend.feature.
contract PatronageLedger is Auth {
    bytes32 public constant SETTLER_ROLE = keccak256("SETTLER_ROLE"); // federation coordinator
    bytes32 public constant COOP_ROLE = keccak256("COOP_ROLE");       // ModelCooperative
    // SETL-H1/M3 fix: advanceYear is gated by a DEDICATED role held ONLY by the ContributionRewardPool
    // (the sole year-keeper), not the broad COOP_ROLE. This removes the second, bookkeeping-skipping
    // path to advance the cohort year and keeps the pool least-privileged (it needs nothing else).
    bytes32 public constant YEAR_KEEPER_ROLE = keccak256("LEDGER_YEAR_KEEPER_ROLE");

    uint256 private constant ACC = 1e18;
    /// PBA-L2-040 bounds. B-010: data quality is a basis-point fraction (<= 100%). B-018: weights are
    /// basis-point multipliers in (0, 100%]. B-019: one record's metered compute is capped so
    /// `units * accDividendPerUnit` cannot overflow and brick a member's dividend accounting.
    uint16 public constant MAX_BPS = 10_000;
    uint256 public constant MAX_COMPUTE_PER_RECORD = 1e30;

    IKYCRegistry public immutable kyc;
    IMembership public immutable membership;

    // governance-tunable balance between compute and data emphasis (bps)
    uint16 public wCompute = 10_000;
    uint16 public wData = 10_000;

    // --- patronage units ---
    mapping(address => uint256) public units;     // lifetime patronage
    uint256 public totalUnits;
    uint256 public currentYear;                   // CRP cohort year
    mapping(uint256 => mapping(address => uint256)) public yearUnits;
    mapping(uint256 => uint256) public yearTotalUnits;

    // --- provenance binding + idempotency ---
    mapping(bytes32 => bytes32) public roundMergedHash;
    mapping(bytes32 => mapping(address => bool)) public recorded;

    // --- contribution window ---
    bool public contributionsOpen = true;

    // --- dividend accumulator ---
    uint256 public accDividendPerUnit;            // scaled by ACC
    mapping(address => uint256) public dividendDebt;
    mapping(address => uint256) public pendingDividend;
    // SETL-M1 fix: there is no `unallocatedRevenue`. Revenue can only be credited once units exist
    // (creditRevenue reverts on totalUnits==0) — the standard "no rewards before shares" rule. The
    // prior pre-units-revenue path folded the whole pool into the FIRST member recorded, a
    // settler-ordering windfall. Revenue arriving before the first round is credited (pro-rata to the
    // round's members) only after that round's units are minted.
    uint256 public totalRevenueCredited;
    uint256 public totalDividendClaimed;

    event RoundCommitted(bytes32 indexed roundId, bytes32 mergedHash);
    event PatronageRecorded(bytes32 indexed roundId, address indexed member, uint256 year, uint256 units);
    event RevenueCredited(uint256 amount, uint256 toHolders);
    event YearAdvanced(uint256 newYear);
    event ContributionsClosed();
    event WeightsSet(uint16 wCompute, uint16 wData);

    error RoundNotCommitted();
    error RoundAlreadyCommitted();
    error EmptyHash();
    error DoubleCount();
    error WindowClosed();
    error NotKyc();
    error NotMember();
    error NoUnits(); // SETL-M1: cannot credit revenue before any patronage units exist
    error BadQuality();       // PBA-L2-040 B-010
    error ComputeTooLarge();  // PBA-L2-040 B-019
    error BadWeights();       // PBA-L2-040 B-018

    /// @param initialAdmin sole initial DEFAULT_ADMIN_ROLE holder (explicit; see Auth)
    constructor(address kycRegistry, address membership_, address initialAdmin) Auth(initialAdmin) {
        kyc = IKYCRegistry(kycRegistry);
        membership = IMembership(membership_);
    }

    // --- patronage minting (SETTLER_ROLE) ---

    function commitRound(bytes32 roundId, bytes32 mergedHash) external onlyRole(SETTLER_ROLE) {
        if (mergedHash == bytes32(0)) revert EmptyHash();
        if (roundMergedHash[roundId] != bytes32(0)) revert RoundAlreadyCommitted();
        roundMergedHash[roundId] = mergedHash;
        emit RoundCommitted(roundId, mergedHash);
    }

    /// @notice Mint patronage = compute x data-quality (weighted). Provenance-bound,
    ///         idempotent, KYC + membership gated, window-gated.
    function recordContribution(bytes32 roundId, address member, uint256 computeMetered, uint16 dataQualityBps)
        external
        onlyRole(SETTLER_ROLE)
    {
        if (roundMergedHash[roundId] == bytes32(0)) revert RoundNotCommitted();
        if (recorded[roundId][member]) revert DoubleCount();
        if (!contributionsOpen) revert WindowClosed();
        if (!kyc.isVerified(member)) revert NotKyc();
        if (!membership.isMember(member)) revert NotMember();
        if (dataQualityBps > MAX_BPS) revert BadQuality();
        if (computeMetered > MAX_COMPUTE_PER_RECORD) revert ComputeTooLarge();

        recorded[roundId][member] = true;

        uint256 weightedCompute = (computeMetered * wCompute) / 10_000;
        uint256 weightedQualityBps = (uint256(dataQualityBps) * wData) / 10_000;
        uint256 p = (weightedCompute * weightedQualityBps) / 10_000;

        _settle(member);
        units[member] += p;
        totalUnits += p;
        yearUnits[currentYear][member] += p;
        yearTotalUnits[currentYear] += p;
        _resetDebt(member);

        emit PatronageRecorded(roundId, member, currentYear, p);
    }

    // --- dividend accumulator (COOP_ROLE) ---

    function creditRevenue(uint256 amount) external onlyRole(COOP_ROLE) {
        // SETL-M1: no crediting before there are units to distribute to (else the fold would land
        // entirely on the first-recorded member). The caller (deposit/sync) reverts; credit once a
        // round's units exist.
        if (totalUnits == 0) revert NoUnits();
        totalRevenueCredited += amount;
        accDividendPerUnit += (amount * ACC) / totalUnits;
        emit RevenueCredited(amount, amount);
    }

    /// @notice Settle + zero a member's pending dividend, returning the owed amount.
    ///         The cooperative performs the SALT transfer and the KYC re-check.
    function recordClaim(address member) external onlyRole(COOP_ROLE) returns (uint256 owed) {
        _settle(member);
        owed = pendingDividend[member];
        pendingDividend[member] = 0;
        _resetDebt(member);
        totalDividendClaimed += owed;
    }

    function advanceYear() external onlyRole(YEAR_KEEPER_ROLE) {
        currentYear += 1;
        emit YearAdvanced(currentYear);
    }

    function closeContributionWindow() external onlyRole(COOP_ROLE) {
        contributionsOpen = false;
        emit ContributionsClosed();
    }

    function setWeights(uint16 wCompute_, uint16 wData_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (wCompute_ == 0 || wData_ == 0 || wCompute_ > MAX_BPS || wData_ > MAX_BPS) revert BadWeights();
        wCompute = wCompute_;
        wData = wData_;
        emit WeightsSet(wCompute_, wData_);
    }

    // --- views ---

    function pendingDividendOf(address m) external view returns (uint256) {
        return pendingDividend[m] + _accrued(m);
    }

    // --- internals ---

    // `dividendDebt` is stored PRE-division (units * accDividendPerUnit), so accrued is the
    // exact floor of the incremental share: floor(units * (acc_now - acc_reset) / ACC).
    // Storing debt post-division would let floor(a)-floor(b) exceed floor(a-b) by up to 1 wei
    // per reset, over-accruing the pool into marginal insolvency (caught by invariant_solvent).
    function _accrued(address m) internal view returns (uint256) {
        return (units[m] * accDividendPerUnit - dividendDebt[m]) / ACC;
    }

    function _settle(address m) internal {
        if (units[m] > 0) {
            pendingDividend[m] += _accrued(m);
        }
    }

    function _resetDebt(address m) internal {
        dividendDebt[m] = units[m] * accDividendPerUnit;
    }
}
