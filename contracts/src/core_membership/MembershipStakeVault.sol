// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {ReentrancyGuard} from "../lib/ReentrancyGuard.sol";
import {ValidatorRegistry} from "../ValidatorRegistry.sol";
import {CitrateMemberSBT} from "./CitrateMemberSBT.sol";
import {MemberBond} from "./MemberBond.sol";

/// @title MembershipStakeVault — the 32,000-SALT membership grant, as a validator bond
///
/// Custodies the membership grant so it NEVER becomes liquid member balance.
/// The grant orchestrator (contract owner — the operator-gated treasury signer,
/// Rule 8) funds a grant; the vault places it in a per-member `MemberBond`
/// escrow which bonds it into `ValidatorRegistry`. The member receives
/// *attribution* (validator eligibility) and, once their node is synced,
/// control of the proposer key — never custody of the principal.
///
/// ## M-2.0 — what changed, and why it had to
///
/// This contract used to deposit grants into `LiquidStakingPool` and hold the
/// stSALT shares. That is incompatible with owner decision A.1, "the locked 32k
/// IS the validator bond": the same 32k cannot be simultaneously pool-staked as
/// stSALT and bonded as native `msg.value` in the registry (citrate-chain #139,
/// M-2 blocking correction).
///
/// So `attributedShares` / `attributedStake` / `isValidatorEligible` have
/// changed MEANING, not just implementation. They were stSALT previews that
/// floated with an oracle-reported share price; they are now the bonded
/// principal. The numbers coincide today, at a 1:1 share price. Their semantics
/// do not.
///
/// A consequence worth stating plainly: pool slashes were socialized across all
/// stakers, so a slash of any validator debited every member's attribution.
/// Bonded principal is slashable only for the member's OWN equivocation. That
/// is the deterrent VALIDATOR-S1 intended, and `pokeSlash` — which existed to
/// surface socialized pool slashes — has no referent under bonding and is gone.
///
/// ## Custody invariants (negative tests, not require-string trust)
///
///   - The vault holds no principal. Grants pass through it into the member's
///     bond escrow in the same transaction.
///   - The vault cannot pull principal back out of a bond. There is no sweep,
///     no clawback, no arbitrary call, no selfdestruct. Even the treasury
///     cannot reach it (Q3 — deliberate, for the securities posture: the vault
///     is stake coverage, not a treasury pocket).
///   - Every value-out path in `MemberBond` pays the member and nobody else.
///
/// ## Open questions carried forward
///
///   Q3. Clawback from a revoked member — still deliberately absent. Under
///       bonding the question sharpens: the principal is slashable by the
///       registry for equivocation, so a clawback path would be a SECOND
///       seizure mechanism with different authority. Counsel + security.
///   Q6. Value above nominal principal — largely dissolves under bonding.
///       Rewards are a separate registry-held bucket and are the member's
///       (owner-confirmed); the principal is exactly the principal.
contract MembershipStakeVault is Initializable, UUPSUpgradeable, ReentrancyGuard {
    // ============================================================
    // Ownership
    // ============================================================
    //
    // Inlined rather than inherited. OZ 5.1's `Ownable` sets `_owner` in a
    // CONSTRUCTOR, which never runs behind a proxy — the owner would be zero
    // and every `onlyOwner` path permanently unreachable. The fix is normally
    // `OwnableUpgradeable`, which lives in `openzeppelin-contracts-upgradeable`;
    // that package is NOT vendored here, and pulling a new submodule into a T1
    // money repo for ~20 lines is a worse trade than writing them.
    //
    // ABI-compatible with what this contract exposed before: `owner()` is still
    // a view returning the owner address.

    address public owner;

    error NotOwner();
    error OwnerIsZero();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// Single-step, matching the previous `Ownable` behaviour. The zero-address
    /// guard is the one hardening added: this contract's owner is the only
    /// address that can place grants or authorize an upgrade, so orphaning it
    /// would freeze the money path permanently.
    ///
    /// AUDIT NOTE (M-3): single-step transfer of a T1 money contract's owner is
    /// a live footgun — a typo'd address is unrecoverable. Two-step
    /// (`Ownable2Step`) is the safer shape; retained single-step here only for
    /// behavioural parity with the deployed contract. Flagged for the rule-8
    /// security review.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert OwnerIsZero();
        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }

    // ============================================================
    // Types
    // ============================================================

    enum GrantState {
        None, // no such grant
        Attributed, // bonded; validator eligibility attributed to member
        Lapsed, // membership lapsed; still bonded, attribution detached
        Released // member has begun exiting; attribution detached
    }

    struct Grant {
        /// Member smart-wallet address.
        address member;
        /// The member's bond escrow (CREATE2, salt = member).
        address bond;
        /// SALT placed in the bond at grant time (nominal principal).
        uint256 principal;
        /// The member's SBT token id — the subject of the KYC attestation.
        uint256 memberTokenId;
        /// Grant creation block (height leg of the lock is derived from this).
        uint64 grantedAtBlock;
        /// Grant creation timestamp (wall-clock leg).
        uint64 grantedAt;
        GrantState state;
    }

    // ============================================================
    // State — layout frozen here (M-2.0 before M-2.1, deliberately)
    // ============================================================

    ValidatorRegistry public registry;
    CitrateMemberSBT public sbt;
    /// The `MemberBond` master copy every bond clones.
    address public bondImplementation;

    uint256 public nextGrantId;
    mapping(uint256 => Grant) private _grants;

    /// member → grant ids (all states).
    mapping(address => uint256[]) private _grantsByMember;

    /// member → principal currently ATTRIBUTED (Attributed state only; lapse
    /// detaches, renew re-attaches).
    mapping(address => uint256) public attributedPrincipal;

    /// Validator stake requirement on chain 40204 (planset 02 §4).
    uint256 public constant VALIDATOR_STAKE_REQUIREMENT = 32_000 ether;

    /// @dev Storage gap so future upgrades can add state without colliding
    /// with anything a child contract or a later version introduces.
    uint256[44] private __gap;

    // ============================================================
    // Errors / Events
    // ============================================================

    error ZeroAddress();
    error ZeroAmount();
    error ValueMismatch();
    error UnknownGrant();
    error WrongState(GrantState actual);
    error BondExists();
    error NotTheMembersToken();

    event Granted(
        uint256 indexed grantId,
        address indexed member,
        address indexed bond,
        uint256 principal,
        uint64 unlockBlock,
        uint64 unlockTimestamp
    );
    event GrantLapsed(uint256 indexed grantId, address indexed member);
    event GrantRenewed(uint256 indexed grantId, address indexed member);
    event GrantReleased(uint256 indexed grantId, address indexed member);

    // ============================================================
    // Initialization (UUPS — M-2.1)
    // ============================================================

    /// @dev Locks the implementation so it can never be initialized and driven
    /// directly behind the proxy's back.
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        ValidatorRegistry registry_,
        CitrateMemberSBT sbt_,
        address bondImplementation_
    ) external initializer {
        if (
            initialOwner == address(0) ||
            address(registry_) == address(0) ||
            address(sbt_) == address(0) ||
            bondImplementation_ == address(0)
        ) revert ZeroAddress();

        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);

        registry = registry_;
        sbt = sbt_;
        bondImplementation = bondImplementation_;
    }

    /// Upgrade authority is the vault owner — the Rule-8 dual-control treasury
    /// signer today, expected to migrate to the timelocked multisig controller
    /// before mainnet. Upgradeability is owner decision A.3.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ============================================================
    // Grant lifecycle (owner = grant orchestrator, Rule 8)
    // ============================================================

    /// Grant `amount` SALT to `member`: deploy their bond escrow and fund it.
    ///
    /// `msg.value` must equal `amount` (SALT is the native asset on 40204).
    /// The grant does NOT bond into the registry — that is `MemberBond.activate`,
    /// which only the member can call once their node is synced and their
    /// proposer key exists. Grant and bond are necessarily two transactions.
    ///
    /// `memberTokenId` binds the grant to a specific membership token, which is
    /// the subject of the KYC attestation the bond reads. It is passed
    /// explicitly rather than looked up, because `CitrateMemberSBT` enforces
    /// uniqueness per `subHash`, NOT per address — an address→token lookup
    /// would need a uniqueness rule the SBT does not have.
    function grant(address member, uint256 amount, uint256 memberTokenId)
        external
        payable
        onlyOwner
        nonReentrant
        returns (uint256 grantId)
    {
        if (member == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (msg.value != amount) revert ValueMismatch();
        if (sbt.ownerOf(memberTokenId) != member) revert NotTheMembersToken();

        address predicted = bondOf(member);
        if (predicted.code.length != 0) revert BondExists();

        uint64 unlockBlock = uint64(block.number + MemberBond(payable(bondImplementation)).LOCK_BLOCKS());
        uint64 unlockTimestamp = uint64(block.timestamp + MemberBond(payable(bondImplementation)).LOCK_SECONDS());

        address bond = Clones.cloneDeterministic(bondImplementation, _saltFor(member));
        MemberBond(payable(bond)).initialize{value: amount}(
            member, memberTokenId, registry, sbt, unlockBlock, unlockTimestamp
        );

        grantId = nextGrantId++;
        _grants[grantId] = Grant({
            member: member,
            bond: bond,
            principal: amount,
            memberTokenId: memberTokenId,
            grantedAtBlock: uint64(block.number),
            grantedAt: uint64(block.timestamp),
            state: GrantState.Attributed
        });
        _grantsByMember[member].push(grantId);
        attributedPrincipal[member] += amount;

        emit Granted(grantId, member, bond, amount, unlockBlock, unlockTimestamp);
    }

    /// Membership lapse: detach attribution (validator eligibility drops).
    /// The principal remains bonded — lapsing a membership does not seize a
    /// validator bond. Orchestrator-driven; the membership service holds the
    /// term source of truth.
    function lapse(uint256 grantId) external onlyOwner {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Attributed) revert WrongState(g.state);
        g.state = GrantState.Lapsed;
        attributedPrincipal[g.member] -= g.principal;
        emit GrantLapsed(grantId, g.member);
    }

    /// Membership renewal: re-attach attribution.
    function renew(uint256 grantId) external onlyOwner {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Lapsed) revert WrongState(g.state);
        g.state = GrantState.Attributed;
        attributedPrincipal[g.member] += g.principal;
        emit GrantRenewed(grantId, g.member);
    }

    /// Record that a member has begun exiting, so attribution stops.
    ///
    /// Permissionless and non-custodial: it only mirrors a decision the member
    /// already made in their own bond, and reverts unless they actually did.
    /// The vault cannot start an exit — that is the member's alone (A.5).
    function recordRelease(uint256 grantId) external {
        Grant storage g = _requireGrant(grantId);
        if (g.state != GrantState.Attributed && g.state != GrantState.Lapsed) {
            revert WrongState(g.state);
        }
        // Data source: MemberBond.releaseRequested — set only by the member's
        // own `requestRelease`, under the KYC + lock gates.
        require(MemberBond(payable(g.bond)).releaseRequested(), "release not requested");

        if (g.state == GrantState.Attributed) {
            attributedPrincipal[g.member] -= g.principal;
        }
        g.state = GrantState.Released;
        emit GrantReleased(grantId, g.member);
    }

    // ============================================================
    // Views
    // ============================================================

    /// The member's bond escrow address — CREATE2-deterministic, and computable
    /// BEFORE the bond exists. The app's SignatureCeremony needs exactly that:
    /// the registry's ed25519 digest binds the staker address, and it has to be
    /// signed before the grant is placed.
    function bondOf(address member) public view returns (address) {
        return Clones.predictDeterministicAddress(bondImplementation, _saltFor(member), address(this));
    }

    function getGrant(uint256 grantId) external view returns (Grant memory) {
        Grant memory g = _grants[grantId];
        if (g.member == address(0)) revert UnknownGrant();
        return g;
    }

    function grantsOf(address member) external view returns (uint256[] memory) {
        return _grantsByMember[member];
    }

    /// The member's attributed validator stake coverage.
    ///
    /// Data source: this contract's own `attributedPrincipal` — the bonded
    /// principal. NOT a pool share preview: under bonding there is no share
    /// price and no socialized slash, so there is nothing to preview.
    function attributedStake(address member) public view returns (uint256) {
        return attributedPrincipal[member];
    }

    /// Does the member's attributed coverage meet the 40204 requirement?
    function isValidatorEligible(address member) external view returns (bool) {
        return attributedStake(member) >= VALIDATOR_STAKE_REQUIREMENT;
    }

    // ============================================================
    // Internal
    // ============================================================

    /// Salt is the member address alone — one bond per member, so the address
    /// is derivable from the member address by itself (see `bondOf`). A second
    /// grant to the same member is rejected rather than silently colliding;
    /// renewal extends the existing grant via `renew`.
    function _saltFor(address member) internal pure returns (bytes32) {
        return keccak256(abi.encode(member));
    }

    function _requireGrant(uint256 grantId) internal view returns (Grant storage g) {
        g = _grants[grantId];
        if (g.member == address(0)) revert UnknownGrant();
    }
}
