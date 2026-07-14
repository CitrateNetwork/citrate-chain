// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";

import "../lib/ReentrancyGuard.sol";
import "../LiquidStakingPool.sol";

/// @title MembershipStakeVault — CORE-S5.4 (citrate-core planset 02 §3b, D-11)
///
/// Custodies the 32,000-SALT membership grant so it NEVER becomes liquid
/// member balance pre-mainnet. The grant orchestrator (contract owner —
/// the operator-gated treasury signer, Rule 8) deposits SALT here; the
/// vault immediately stakes it in LiquidStakingPool and holds the stSALT
/// shares itself. The member receives *attribution* (validator-eligibility
/// stake coverage), never custody.
///
/// State machine per grant (Foundry-tested, 05 WP 5.4):
///
///   grant ──▶ Attributed ⇄ Lapsed
///                 │           │
///                 └── release ┘  (requires the one-way mainnet-release
///                       │         flag + per-grant owner unlock)
///                       ▼
///                   Released ──▶ Claimed (pool lockup elapsed; SALT
///                                 forwarded to the member wallet)
///
/// Custody invariants (verified by negative tests, not require-strings):
///   - The ONLY code path that moves SALT out of this contract is
///     `claimReleased`, which requires GrantState.Released — reachable
///     only via owner-driven `releaseGrant` under the enabled
///     mainnet-release flag — and pays the member wallet exclusively.
///   - There is no owner-withdrawal, no sweep, no arbitrary call, no
///     selfdestruct. Even the treasury cannot pull principal back out
///     (see Q3 below — this is deliberate for the securities posture:
///     the vault is stake coverage, not a treasury pocket).
///   - `receive()` accepts SALT only from the staking pool (withdrawal
///     claims); donations/dust cannot be injected.
///
/// Slashing (D-11 "surfaced to the member honestly"):
///   LiquidStakingPool socializes slashes through the stSALT share
///   price, so a slash economically hits vaulted principal the moment
///   the oracle report finalizes. `pokeSlash` makes that pass-through
///   explicit on-chain: anyone may call it to emit `SlashPassedThrough`
///   with the observed value drop for a grant. Known limitation
///   (documented, not hidden): if rewards accrue in the same oracle
///   report as a slash, the net share-price move can mask the slash;
///   the authoritative per-event record is the pool's `RewardsReported`
///   event stream, which the app surfaces alongside this vault's view.
///
/// Mainnet-release governance assumption (Q4, natspec'd per CORE-S5.4):
///   Release is modeled as (a) a ONE-WAY contract-wide flag
///   (`enableMainnetRelease`, owner-set) representing the network-level
///   "mainnet release policy" decision, plus (b) a per-grant owner
///   unlock (`releaseGrant`) so the orchestrator can sequence releases
///   (e.g. only members whose 1-year term has completed — the planset's
///   "whichever is later" rule is enforced by the orchestrator, which
///   holds the term source of truth; see Q5). The governance assumption
///   is that "owner" is the operator-gated treasury signer under Rule 8
///   dual control TODAY, and is expected to migrate to the timelocked
///   multisig controller (the cit_agent 6b pattern) BEFORE mainnet
///   release is enabled. Whether the flag should instead be set by an
///   on-chain governance vote (TreasuryGovernor) is an open question
///   for the counsel gate — flipping it is irreversible by design.
///
/// Open design questions (for governance/counsel before deployment;
/// deployment is Rule-8 operator work — security sign-off + counsel
/// gate required, per 05 CORE-S5 ext):
///   Q3. Revocation/clawback: 06 §1 T6 (refund-after-grant) implies the
///       network may want to recover a grant from a revoked member.
///       This contract deliberately ships WITHOUT a clawback path —
///       adding one creates a treasury-directed value-out path that
///       weakens the "no code path" custody story and has securities
///       implications; counsel + security must decide.
///   Q4. Mainnet-release trigger: owner flag (current) vs on-chain
///       governance vote vs timelocked multisig — see above.
///   Q5. Term enforcement locus: the vault does not read term
///       timestamps (the SBT holds them); lapse/renew/release
///       sequencing is orchestrator-driven. Should the vault
///       additionally hard-enforce `block.timestamp >= grantedAt + 365
///       days` on release as defense in depth?
///   Q6. Release amount: on release the member receives the CURRENT
///       share value of the grant (principal − socialized slashes +
///       pool-level share appreciation). D-11 routes the member's
///       validator rewards through the enhanced-rewards pools, not this
///       vault, but stSALT share price also rises with oracle-reported
///       pool rewards — so released value can exceed nominal principal.
///       Whether that excess belongs to the member or the treasury is a
///       counsel-gate question; current code gives it to the member
///       (simplest honest accounting: the shares were attributed to
///       them the whole time).
contract MembershipStakeVault is Ownable, ReentrancyGuard {
    // ============================================================
    // Types
    // ============================================================

    enum GrantState {
        None, // no such grant
        Attributed, // staked; validator eligibility attributed to member
        Lapsed, // membership lapsed; still staked, attribution detached
        Released, // mainnet release: pool withdrawal requested
        Claimed // pool lockup elapsed; principal forwarded to member
    }

    struct Grant {
        /// Member smart-wallet address. The ONLY address that can ever
        /// receive this grant's principal.
        address member;
        /// SALT deposited at grant time (nominal principal).
        uint256 principal;
        /// stSALT shares minted to the vault for this grant (fixed at
        /// grant time; current SALT value = pool.previewWithdraw(shares)).
        uint256 shares;
        /// Last share value observed by pokeSlash (starts at principal).
        uint256 lastKnownValue;
        /// Pool withdrawal request id once Released.
        uint256 poolWithdrawalId;
        /// SALT amount locked in by the pool at release time.
        uint256 releaseAmount;
        /// Grant creation timestamp.
        uint64 grantedAt;
        GrantState state;
    }

    // ============================================================
    // State
    // ============================================================

    /// The staking pool the vault stakes grants into (LiquidStakingPool,
    /// stSALT shares model, 7-day withdrawal lockup).
    LiquidStakingPool public immutable pool;

    uint256 public nextGrantId;
    mapping(uint256 => Grant) private _grants;

    /// member → grant ids (all states).
    mapping(address => uint256[]) private _grantsByMember;

    /// member → stSALT shares currently ATTRIBUTED (Attributed state
    /// only; lapse detaches, renew re-attaches). Validator-eligibility
    /// readers convert via `attributedStake`.
    mapping(address => uint256) public attributedShares;

    /// One-way mainnet-release flag (Q4). Until true, no grant can
    /// leave the vault by any code path.
    bool public mainnetReleaseEnabled;

    /// Validator stake requirement on chain 40204 (planset 02 §4).
    uint256 public constant VALIDATOR_STAKE_REQUIREMENT = 32_000 ether;

    /// @dev Guards receive(): SALT is accepted only inside claimReleased.
    bool private _expectingPoolPayout;

    // ============================================================
    // Errors / Events
    // ============================================================

    error ZeroAddress();
    error ZeroAmount();
    error ValueMismatch();
    error UnknownGrant();
    error WrongState(GrantState actual);
    error ReleaseNotEnabled();
    error ReleaseAlreadyEnabled();
    error UnsolicitedTransfer();
    error PayoutFailed();

    event Granted(
        uint256 indexed grantId,
        address indexed member,
        uint256 principal,
        uint256 shares
    );
    event GrantLapsed(uint256 indexed grantId, address indexed member);
    event GrantRenewed(uint256 indexed grantId, address indexed member);
    event MainnetReleaseEnabled();
    event GrantReleased(
        uint256 indexed grantId,
        address indexed member,
        uint256 poolWithdrawalId,
        uint256 releaseAmount
    );
    event GrantClaimed(uint256 indexed grantId, address indexed member, uint256 amount);
    event SlashPassedThrough(
        uint256 indexed grantId,
        address indexed member,
        uint256 valueLost,
        uint256 currentValue
    );

    // ============================================================
    // Constructor
    // ============================================================

    constructor(address initialOwner, LiquidStakingPool _pool) Ownable(initialOwner) {
        if (address(_pool) == address(0)) revert ZeroAddress();
        pool = _pool;
    }

    // ============================================================
    // Grant lifecycle (all owner = grant orchestrator, Rule 8)
    // ============================================================

    /// Grant `amount` SALT to `member`: deposit into the vault, stake
    /// via LiquidStakingPool, attribute validator eligibility to the
    /// member. `msg.value` must equal `amount` (SALT is the native
    /// asset on 40204). Data source: LiquidStakingPool.deposit() —
    /// shares are whatever the pool actually mints at the current
    /// share price, never a locally recomputed number.
    function grant(address member, uint256 amount)
        external
        payable
        onlyOwner
        nonReentrant
        returns (uint256 grantId)
    {
        if (member == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (msg.value != amount) revert ValueMismatch();

        uint256 sharesOut = pool.deposit{value: amount}();

        grantId = nextGrantId++;
        _grants[grantId] = Grant({
            member: member,
            principal: amount,
            shares: sharesOut,
            lastKnownValue: amount,
            poolWithdrawalId: 0,
            releaseAmount: 0,
            grantedAt: uint64(block.timestamp),
            state: GrantState.Attributed
        });
        _grantsByMember[member].push(grantId);
        attributedShares[member] += sharesOut;

        emit Granted(grantId, member, amount, sharesOut);
    }

    /// Membership lapse: detach attribution (validator eligibility
    /// drops); principal remains vaulted and staked. Orchestrator-
    /// driven — the membership service holds the term source of truth.
    function lapse(uint256 grantId) external onlyOwner {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Attributed) revert WrongState(g.state);
        g.state = GrantState.Lapsed;
        attributedShares[g.member] -= g.shares;
        emit GrantLapsed(grantId, g.member);
    }

    /// Membership renewal: re-attach attribution.
    function renew(uint256 grantId) external onlyOwner {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Lapsed) revert WrongState(g.state);
        g.state = GrantState.Attributed;
        attributedShares[g.member] += g.shares;
        emit GrantRenewed(grantId, g.member);
    }

    /// One-way mainnet-release flag (governance assumption Q4: owner is
    /// the Rule-8 dual-control treasury signer, expected to be a
    /// timelocked multisig before this is ever called). Irreversible.
    function enableMainnetRelease() external onlyOwner {
        if (mainnetReleaseEnabled) revert ReleaseAlreadyEnabled();
        mainnetReleaseEnabled = true;
        emit MainnetReleaseEnabled();
    }

    /// Per-grant unlock under the enabled release flag: unstakes the
    /// grant's shares (pool 7-day lockup starts now). Allowed from
    /// Attributed or Lapsed. Release amount is whatever the pool locks
    /// in at request time (principal − socialized slashes + share
    /// appreciation — see Q6).
    function releaseGrant(uint256 grantId) external onlyOwner nonReentrant {
        if (!mainnetReleaseEnabled) revert ReleaseNotEnabled();
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Attributed && g.state != GrantState.Lapsed) {
            revert WrongState(g.state);
        }
        if (g.state == GrantState.Attributed) {
            attributedShares[g.member] -= g.shares;
        }
        g.state = GrantState.Released;

        uint256 withdrawalId = pool.requestWithdrawal(g.shares);
        g.poolWithdrawalId = withdrawalId;
        // Data source: LiquidStakingPool.withdrawals(id).saltAmount —
        // the amount the pool locked in for this request.
        (, , uint256 saltAmount, , ) = pool.withdrawals(withdrawalId);
        g.releaseAmount = saltAmount;

        emit GrantReleased(grantId, g.member, withdrawalId, saltAmount);
    }

    /// Claim a released grant after the pool's withdrawal lockup and
    /// forward the SALT to the member wallet. Callable by anyone: the
    /// destination is fixed to `grant.member`, so third-party calls can
    /// only ever deliver the member their own funds. This is the ONLY
    /// value-out path in the contract.
    function claimReleased(uint256 grantId) external nonReentrant {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Released) revert WrongState(g.state);
        g.state = GrantState.Claimed;

        _expectingPoolPayout = true;
        pool.claimWithdrawal(g.poolWithdrawalId); // reverts "Too early" inside lockup
        _expectingPoolPayout = false;

        (bool ok, ) = payable(g.member).call{value: g.releaseAmount}("");
        if (!ok) revert PayoutFailed();

        emit GrantClaimed(grantId, g.member, g.releaseAmount);
    }

    // ============================================================
    // Slash pass-through
    // ============================================================

    /// Surface a socialized pool slash for a specific grant. Anyone may
    /// call (it only reads pool state and emits). Emits
    /// `SlashPassedThrough` when the grant's current share value has
    /// dropped below the last observed value. See the contract-level
    /// natspec for the reward-masking limitation.
    function pokeSlash(uint256 grantId) external {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Attributed && g.state != GrantState.Lapsed) {
            revert WrongState(g.state);
        }
        // Data source: LiquidStakingPool.previewWithdraw(shares) —
        // current SALT value of the grant's shares at pool share price.
        uint256 current = pool.previewWithdraw(g.shares);
        uint256 last = g.lastKnownValue;
        if (current < last) {
            g.lastKnownValue = current;
            emit SlashPassedThrough(grantId, g.member, last - current, current);
        } else if (current > last) {
            // Rewards appreciation — track silently, no slash event.
            g.lastKnownValue = current;
        }
    }

    // ============================================================
    // Views
    // ============================================================

    function getGrant(uint256 grantId) external view returns (Grant memory) {
        Grant memory g = _grants[grantId];
        if (g.member == address(0)) revert UnknownGrant();
        return g;
    }

    function grantsOf(address member) external view returns (uint256[] memory) {
        return _grantsByMember[member];
    }

    /// Current SALT value of a member's ATTRIBUTED shares (validator
    /// stake coverage). Data source: pool.previewWithdraw — reflects
    /// socialized slashes and reward appreciation live.
    function attributedStake(address member) public view returns (uint256) {
        return pool.previewWithdraw(attributedShares[member]);
    }

    /// Convenience: does the member's attributed coverage meet the
    /// 40204 validator stake requirement?
    function isValidatorEligible(address member) external view returns (bool) {
        return attributedStake(member) >= VALIDATOR_STAKE_REQUIREMENT;
    }

    // ============================================================
    // Internal
    // ============================================================

    function _requireGrant(uint256 grantId) internal view returns (Grant storage g) {
        g = _grants[grantId];
        if (g.member == address(0)) revert UnknownGrant();
    }

    // ============================================================
    // Receive — pool payouts only
    // ============================================================

    /// Accept SALT only from the staking pool, and only during a
    /// claimReleased call (SOL-16 discipline: no donation/dust path
    /// into vault accounting).
    receive() external payable {
        if (msg.sender != address(pool) || !_expectingPoolPayout) {
            revert UnsolicitedTransfer();
        }
    }
}
