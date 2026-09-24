// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {ValidatorRegistry} from "../ValidatorRegistry.sol";
import {CitrateMemberSBT} from "./CitrateMemberSBT.sol";

/// @title MemberBond — M-2.0, the per-member validator bond escrow
///
/// One minimal-proxy clone per member, deployed CREATE2 by
/// `MembershipStakeVault`. The clone — not the vault — is the `staker` in
/// `ValidatorRegistry`.
///
/// ## Why a clone at all
///
/// `ValidatorRegistry.registerValidator` reverts `StakerHasValidator()` once
/// `pubkeyOfStaker[msg.sender]` is set (`ValidatorRegistry.sol:243`, written at
/// `:279`). A single vault contract could therefore bond **exactly one member,
/// ever**. Giving each member their own staker address sidesteps that without
/// touching a live consensus-critical contract — citrate-chain #139 design (c),
/// chosen over adding a `custodians` allowlist to the registry itself.
///
/// ## Who controls what
///
/// - **Principal is the vault's concern**: it funds the bond and the bond alone
///   decides when it may leave, under the lock + KYC gates below. Neither the
///   vault nor the owner can pull it out; there is no sweep, no arbitrary call,
///   no selfdestruct, and every value-out path pays `member` and nobody else.
/// - **The proposer key is the member's**: only they can prove control of it, so
///   only they can `activate`. The vault deliberately cannot.
/// - **Rewards are the member's** (owner-confirmed, #139 §"What I need from the
///   owner" item 3). Only principal is locked. `claimRewards` forwards straight
///   to the member wallet; if that ever regressed, membership would silently
///   confiscate earnings.
///
/// ## Gate ordering
///
/// KYC is checked **FIRST**, before the lock, on every value-out path — owner
/// decision A.6, "KYC supersedes every withdrawal check, even after the lock
/// elapses". A paid-but-unverified member keeps their membership and their
/// validator slot (decision A.7); only the money out is gated.
///
/// The registry's own `EXIT_LOCK_EPOCHS` stacks on top of this contract's lock.
/// That is defence in depth, not a conflict: this lock governs when the member
/// may *start* exiting, the registry's governs when the principal is payable.
contract MemberBond is Initializable {
    // ============================================================
    // Lock constants (M-2.2)
    // ============================================================

    /// Wall-clock leg of the lock: one year MINUS one day.
    ///
    /// Owner decision A.4 — "slightly early beats slightly late". A member whose
    /// year is up should not be held an extra week by an accounting artefact.
    uint256 public constant LOCK_SECONDS = 364 days;

    /// Height leg of the lock: `LOCK_SECONDS` at the **measured** 40204 block
    /// time of 2.000 s (43,200 blocks/day, sampled over 2,000 blocks at tip
    /// ~84,240 on 2026-07-29). Measured, not guessed — #139 refused to guess it
    /// and so does this.
    uint256 public constant LOCK_BLOCKS = LOCK_SECONDS / 2;

    // ============================================================
    // State
    // ============================================================

    /// The vault that deployed and funded this bond (its custodian).
    address public vault;
    /// The member. The ONLY address any value in this contract can reach.
    address public member;
    /// The member's SBT token id — the subject of the KYC attestation.
    uint256 public memberTokenId;

    ValidatorRegistry public registry;
    CitrateMemberSBT public sbt;

    /// Nominal principal placed in this bond at grant time.
    uint256 public principal;

    /// Height leg: `grantBlock + LOCK_BLOCKS`.
    uint64 public unlockBlock;
    /// Wall-clock leg: `grantedAt + LOCK_SECONDS`.
    uint64 public unlockTimestamp;

    /// The member's proposer key, set on `activate`. Zero until then.
    bytes32 public pubkey;
    /// True once the principal has been bonded into the registry.
    bool public activated;
    /// True once `requestRelease` has started the unbond.
    bool public releaseRequested;

    // ============================================================
    // Errors / Events
    // ============================================================

    error NotMember();
    error NotVault();
    error ZeroAddress();
    error AlreadyActivated();
    error NotActivated();
    error KycRequired();
    error StillLocked();
    error AlreadyReleasing();
    error PayoutFailed();
    error UnsolicitedTransfer();

    event BondInitialized(
        address indexed member,
        uint256 indexed memberTokenId,
        uint256 principal,
        uint64 unlockBlock,
        uint64 unlockTimestamp
    );
    event BondActivated(address indexed member, bytes32 indexed pubkey, uint256 principal);
    event RewardsForwarded(address indexed member, uint256 amount);
    event ReleaseRequested(address indexed member, bytes32 indexed pubkey, uint256 amount);
    event PrincipalWithdrawn(address indexed member, uint256 amount);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyMember() {
        if (msg.sender != member) revert NotMember();
        _;
    }

    /// KYC FIRST, then the lock — owner decision A.6. The order is observable
    /// only through which error surfaces, which is exactly why it is pinned by
    /// a test: an unverified member inside the lock must be told the KYC
    /// reason, not the lock reason.
    modifier withdrawable() {
        if (!isKycVerified()) revert KycRequired();
        if (!isUnlocked()) revert StillLocked();
        _;
    }

    // ============================================================
    // Initialization (clone — no constructor)
    // ============================================================

    /// @dev Locks the implementation so the master copy can never be
    /// initialized and driven directly.
    constructor() {
        _disableInitializers();
    }

    /// Called by the vault immediately after `cloneDeterministic`, carrying the
    /// principal as `msg.value`. `initializer` makes this once-only: a second
    /// call could repoint `member` at an attacker and hand them the principal.
    function initialize(
        address member_,
        uint256 memberTokenId_,
        ValidatorRegistry registry_,
        CitrateMemberSBT sbt_,
        uint64 unlockBlock_,
        uint64 unlockTimestamp_
    ) external payable initializer {
        if (member_ == address(0)) revert ZeroAddress();
        if (address(registry_) == address(0) || address(sbt_) == address(0)) revert ZeroAddress();

        vault = msg.sender;
        member = member_;
        memberTokenId = memberTokenId_;
        registry = registry_;
        sbt = sbt_;
        principal = msg.value;
        unlockBlock = unlockBlock_;
        unlockTimestamp = unlockTimestamp_;

        emit BondInitialized(member_, memberTokenId_, msg.value, unlockBlock_, unlockTimestamp_);
    }

    // ============================================================
    // Activation
    // ============================================================

    /// Bond the principal into `ValidatorRegistry` under the member's proposer
    /// key. Member-callable only, through the app's SignatureCeremony, once the
    /// node is synced.
    ///
    /// Grant and bond are necessarily two transactions: at grant time — the
    /// moment of payment — the member has no node and no proposer key. The
    /// registry's digest binds the staker address, which is THIS contract, and
    /// is CREATE2-deterministic, so the app can sign it before this clone even
    /// exists.
    function activate(bytes32 pubkey_, bytes calldata ed25519Sig) external onlyMember {
        if (activated) revert AlreadyActivated();
        activated = true;
        pubkey = pubkey_;

        uint256 amount = principal;
        registry.registerValidator{value: amount}(pubkey_, ed25519Sig);

        emit BondActivated(member, pubkey_, amount);
    }

    // ============================================================
    // Rewards — the member's, not the membership's
    // ============================================================

    /// Claim matured validator rewards and forward them to the member.
    ///
    /// Deliberately NOT gated on the lock: only principal is locked. It IS
    /// gated on KYC, because this is money leaving to a person.
    function claimRewards() external onlyMember {
        if (!activated) revert NotActivated();
        if (!isKycVerified()) revert KycRequired();

        uint256 before = address(this).balance;
        registry.claimRewards(pubkey);
        uint256 amount = address(this).balance - before;

        if (amount > 0) _payMember(amount);
        emit RewardsForwarded(member, amount);
    }

    // ============================================================
    // Exit — eligible, never automatic
    // ============================================================

    /// Begin the unbond. Owner decision A.5: reaching the unlock makes exit
    /// ELIGIBLE; nothing moves until the member acts, and this is that act.
    function requestRelease() external onlyMember withdrawable {
        if (!activated) revert NotActivated();
        if (releaseRequested) revert AlreadyReleasing();
        releaseRequested = true;

        uint256 amount = registry.stakeOf(pubkey);
        registry.initiateUnbond(pubkey, amount);

        emit ReleaseRequested(member, pubkey, amount);
    }

    /// Draw the matured escrow out of the registry and forward it to the
    /// member. Re-checks KYC: verification can be revoked between requesting
    /// the release and the registry's exit lock maturing, and A.6 says KYC
    /// supersedes every withdrawal check.
    function withdrawToMember() external onlyMember withdrawable {
        if (!activated) revert NotActivated();

        uint256 before = address(this).balance;
        registry.withdraw(pubkey);
        uint256 amount = address(this).balance - before;

        if (amount > 0) _payMember(amount);
        emit PrincipalWithdrawn(member, amount);
    }

    // ============================================================
    // Views
    // ============================================================

    /// Either leg unlocks. The height leg is primary; the wall-clock leg exists
    /// because a pure height lock can only OVERSHOOT real time when the chain
    /// stalls — and 40204 demonstrably stalls (~3 h on 2026-07-29). Under a
    /// stall, blocks stop arriving and a height-only lock would hold the
    /// member's principal well past their year.
    function isUnlocked() public view returns (bool) {
        return block.number >= unlockBlock || block.timestamp >= unlockTimestamp;
    }

    /// Data source: `CitrateMemberSBT.isKycVerified(tokenId)` — the on-chain
    /// attestation set by the membership orchestrator.
    function isKycVerified() public view returns (bool) {
        return sbt.isKycVerified(memberTokenId);
    }

    // ============================================================
    // Internal
    // ============================================================

    function _payMember(uint256 amount) internal {
        (bool ok, ) = payable(member).call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    // ============================================================
    // Receive — registry payouts only
    // ============================================================

    /// Accept SALT only from the registry (reward claims, escrow withdrawals).
    /// Donations and dust cannot be injected into this contract's accounting.
    receive() external payable {
        if (msg.sender != address(registry)) revert UnsolicitedTransfer();
    }
}
