// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {ITenantHierarchy} from "./GovernanceProtocolFactory.sol";

/// @title CapabilityGrant — HIC envelopes on chain
/// @notice citrate-quorum QRM-S6.5. Planset `03_GOVERNANCE_CONTRACTS.md` §7,
/// the on-chain half of `04_HIC_MODEL.md`.
///
/// **What a human authorized an agent to do** — in what scope, at what HIC
/// level, until when, with what budget — and every consumption of it.
///
/// ## This mirrors Rust, and the mirror is the point
///
/// `quorum-policy`'s `CapabilityGrant` enforces these same rules in process, in
/// citrate-quorum's agent adapter. Two implementations of one rule set is a
/// standing invitation to drift, so every rule below names its Rust counterpart
/// and the shapes are kept deliberately identical:
///
/// | Here | `quorum-policy` |
/// |---|---|
/// | `isLive` | `CapabilityGrant::is_live` |
/// | `covers` | `CapabilityGrant::covers` |
/// | `remaining` | `CapabilityGrant::remaining` (saturating) |
/// | `consume` | `CapabilityGrant::consume` (refuses, leaves state unchanged) |
/// | `refund` | `CapabilityGrant::refund` (saturating) |
/// | `revoke` | `CapabilityGrant::revoke` (idempotent) |
///
/// Two unit decisions exist only to keep the mirror true:
///
/// **Time is milliseconds.** The Rust side is epoch-ms; `block.timestamp` is
/// seconds. Storing seconds here would put a truncation between the two
/// implementations, and a grant that expired at slightly different instants on
/// each side is exactly the sort of divergence nobody notices until it decides
/// something. So expiry is `uint64` ms, compared against `block.timestamp *
/// 1000`, and `>` matches `expires_at_ms > now_ms` exactly.
///
/// **Budgets are capped at `type(uint64).max`.** The struct says `uint256`
/// (planset §7), but the Rust budget is `u64`. A grant that cannot round-trip
/// into the implementation that enforces it in process is not a grant, it is a
/// future incident, so a larger one is refused at issue.
///
/// ## The four invariants
///
/// **CG-1 `consumed <= budget`.** `consume` refuses and leaves state untouched
/// rather than clamping — a partially-charged action is a lie about what
/// happened.
///
/// **CG-2 revoke is immediate.** Not "at next expiry", not "after in-flight work
/// drains". A revoked grant is dead on the next block, regardless of expiry, and
/// revoking twice is a no-op rather than an error (the second caller wanted the
/// same end state).
///
/// **CG-3 every recorded agent decision references a live grant, or is flagged
/// `ungoverned`.** That is a property of the recording site, not of this
/// contract — enforced in quorum's ledger and `AgentDecisionRegistryV2`. What
/// this contract owes CG-3 is a cheap, unambiguous answer to "is there a live
/// grant covering this?", which is [`covers`]. It is stated here so nobody reads
/// CG-3 as something this contract enforces on its own.
///
/// **CG-4 the HIC level moves toward more autonomy only by an explicit principal
/// action.** Tightening (toward more human control) may be done by the principal
/// or by a tenant admin, because that direction is always safe and sometimes
/// urgent. Loosening is the principal alone, never an agent request — an agent
/// that could ask for more autonomy and get it has no envelope at all.
///
/// ## Who may do what, and why `issuedBy` is recorded separately
///
/// Anyone may issue a grant **for themselves**. Issuing one **on someone else's
/// behalf** requires being an admin of the tenant. Both cases record `issuedBy`
/// alongside `principal`, so a reader can always see whether a grant was
/// self-issued or delegated — this contract cannot tell whether an address is a
/// person, so it records the provenance rather than pretending to judge it.
///
/// Consumption is charged by one nominated `consumer` address per grant — the
/// enforcement point. Without that, any address could drain any agent's budget,
/// and "consumed" would stop meaning "work was done".
contract CapabilityGrant {
    /// How a principal's control is exercised. Ordered by AUTONOMY ascending, so
    /// `>` means "more autonomous" — the direction CG-4 restricts. Matches
    /// `quorum_policy::GrantHic`.
    enum Hic {
        /// HIC-1: every action under this grant pauses for a signature.
        ApproveEach,
        /// HIC-2: budgeted autonomy — act within scope, budget and expiry.
        Budgeted,
        /// HIC-3: act, with a post-hoc review window.
        PostHoc
    }

    struct Grant {
        uint256 agentSbtId;
        address principal;
        /// Who actually sent the issuing transaction. Equal to `principal` for a
        /// self-issued grant; a tenant admin otherwise.
        address issuedBy;
        /// The only address that may charge against this grant.
        address consumer;
        bytes32 tenantScope;
        bytes32[] actionClasses;
        Hic hic;
        uint8 classificationCeiling;
        uint256 budgetUnits;
        uint256 consumed;
        /// Epoch MILLISECONDS. See the header for why this is not seconds.
        uint64 expiresAtMs;
        /// The governance protocol that authorized this grant, as a hash — the
        /// grant is evidence of an authorization, and this is what it points back
        /// to. Zero when a grant was issued outside a protocol, which is a
        /// legitimate state and a visible one.
        bytes32 protocolAddrHash;
        bool revoked;
        bool exists;
    }

    uint256 public constant MAX_ACTION_CLASSES = 32;

    ITenantHierarchy public immutable tenants;

    mapping(bytes32 => Grant) private _grants;
    /// principal → grants issued for them, in issue order.
    mapping(address => bytes32[]) private _byPrincipal;
    /// principal → issue counter, so ids cannot collide.
    mapping(address => uint256) public issueNonce;

    error UnknownGrant(bytes32 grantId);
    error NotPrincipal(bytes32 grantId, address caller);
    error NotConsumer(bytes32 grantId, address caller);
    error NotPrincipalOrTenantAdmin(bytes32 grantId, address caller);
    error MayNotIssueForAnother(bytes32 tenantScope, address caller);
    error ZeroPrincipal();
    error ZeroConsumer();
    error NoActionClasses();
    error TooManyActionClasses(uint256 count);
    error DuplicateActionClass(bytes32 actionClass);
    error BudgetTooLarge(uint256 budgetUnits);
    error ClassificationAboveTenant(uint8 requested, uint8 tenantMax);
    error AlreadyExpired(uint64 expiresAtMs, uint64 nowMs);
    error OverBudget(bytes32 grantId, uint256 requested, uint256 remaining);
    error GrantNotLive(bytes32 grantId);
    error AutonomyIncreaseIsPrincipalOnly(bytes32 grantId, address caller);

    event GrantIssued(
        bytes32 indexed grantId,
        address indexed principal,
        uint256 indexed agentSbtId,
        bytes32 tenantScope,
        Hic hic,
        uint256 budgetUnits,
        uint64 expiresAtMs,
        address issuedBy,
        bytes32 protocolAddrHash
    );
    event GrantConsumed(bytes32 indexed grantId, uint256 units, uint256 consumedTotal, bytes32 correlationId);
    event GrantRefunded(bytes32 indexed grantId, uint256 units, uint256 consumedTotal, bytes32 correlationId);
    event GrantRevoked(bytes32 indexed grantId, address indexed by);
    event GrantHicChanged(bytes32 indexed grantId, Hic from, Hic to, address by);

    constructor(ITenantHierarchy tenants_) {
        tenants = tenants_;
    }

    // ── Issue ───────────────────────────────────────────────────────

    /// Authorize an agent. Returns the grant id.
    ///
    /// `consumer` is the enforcement point that will charge against this grant.
    /// Pass the principal's own address for a grant nobody else settles.
    function issue(
        uint256 agentSbtId,
        address principal,
        address consumer,
        bytes32 tenantScope,
        bytes32[] calldata actionClasses,
        Hic hic,
        uint8 classificationCeiling,
        uint256 budgetUnits,
        uint64 expiresAtMs,
        bytes32 protocolAddrHash
    ) external returns (bytes32 grantId) {
        if (principal == address(0)) revert ZeroPrincipal();
        if (consumer == address(0)) revert ZeroConsumer();
        // Granting to yourself is always allowed; granting on someone else's
        // behalf is a tenant-administration act.
        if (msg.sender != principal && !_isTenantAdmin(tenantScope, msg.sender)) {
            revert MayNotIssueForAnother(tenantScope, msg.sender);
        }
        if (actionClasses.length == 0) revert NoActionClasses();
        if (actionClasses.length > MAX_ACTION_CLASSES) revert TooManyActionClasses(actionClasses.length);
        for (uint256 i = 0; i < actionClasses.length; ++i) {
            for (uint256 j = i + 1; j < actionClasses.length; ++j) {
                // A duplicate does not widen the grant, but it makes the scope
                // list misdescribe itself to anyone reading it.
                if (actionClasses[i] == actionClasses[j]) revert DuplicateActionClass(actionClasses[i]);
            }
        }
        // See the header: the in-process implementation carries a u64 budget.
        if (budgetUnits > type(uint64).max) revert BudgetTooLarge(budgetUnits);

        // A grant may not authorize above the tenant's own ceiling. `getNode`
        // reverts for an unknown tenant, which is the correct fail-closed
        // behaviour — you cannot grant into a tenant that does not exist.
        ITenantHierarchy.TenantNode memory node = tenants.getNode(tenantScope);
        if (classificationCeiling > node.classification_max) {
            revert ClassificationAboveTenant(classificationCeiling, node.classification_max);
        }

        uint64 nowMs = uint64(block.timestamp * 1000);
        // An already-dead grant is not a grant. Issuing one would put a
        // permanently-refusing envelope in the record and read, to anyone
        // scanning, like an authorization that exists.
        if (expiresAtMs <= nowMs) revert AlreadyExpired(expiresAtMs, nowMs);

        grantId = keccak256(abi.encode(address(this), tenantScope, principal, agentSbtId, issueNonce[principal]++));

        Grant storage g = _grants[grantId];
        g.agentSbtId = agentSbtId;
        g.principal = principal;
        g.issuedBy = msg.sender;
        g.consumer = consumer;
        g.tenantScope = tenantScope;
        g.hic = hic;
        g.classificationCeiling = classificationCeiling;
        g.budgetUnits = budgetUnits;
        g.expiresAtMs = expiresAtMs;
        g.protocolAddrHash = protocolAddrHash;
        g.exists = true;
        for (uint256 i = 0; i < actionClasses.length; ++i) {
            g.actionClasses.push(actionClasses[i]);
        }
        _byPrincipal[principal].push(grantId);

        emit GrantIssued(
            grantId, principal, agentSbtId, tenantScope, hic, budgetUnits, expiresAtMs, msg.sender, protocolAddrHash
        );
    }

    // ── Spend ───────────────────────────────────────────────────────

    /// Charge `units` against a grant. CG-1.
    ///
    /// Refuses and leaves state untouched if it would exceed the budget, exactly
    /// as `quorum_policy::CapabilityGrant::consume` does — a partially-charged
    /// action would be a lie about what happened.
    function consume(bytes32 grantId, uint256 units, bytes32 correlationId) external {
        Grant storage g = _live(grantId);
        if (msg.sender != g.consumer) revert NotConsumer(grantId, msg.sender);

        uint256 left = g.budgetUnits - g.consumed;
        if (units > left) revert OverBudget(grantId, units, left);
        g.consumed += units;

        emit GrantConsumed(grantId, units, g.consumed, correlationId);
    }

    /// Give back units a charge took. Saturating, matching the Rust.
    ///
    /// This exists for one specific case: an action was charged, escalated to a
    /// human, and the human said no. Without a refund the agent's envelope would
    /// be quietly eaten by an approval that never happened.
    ///
    /// Allowed on a revoked or expired grant on purpose — refusing there would
    /// mean revoking a grant permanently absorbs whatever was in flight, which
    /// makes the record wrong in the one direction that disadvantages the agent's
    /// principal.
    function refund(bytes32 grantId, uint256 units, bytes32 correlationId) external {
        Grant storage g = _get(grantId);
        if (msg.sender != g.consumer) revert NotConsumer(grantId, msg.sender);

        g.consumed = units >= g.consumed ? 0 : g.consumed - units;
        emit GrantRefunded(grantId, units, g.consumed, correlationId);
    }

    // ── Control ─────────────────────────────────────────────────────

    /// Revoke immediately. CG-2. Idempotent.
    ///
    /// The principal or a tenant admin — pulling the plug must not require
    /// finding one specific person at 3am.
    function revoke(bytes32 grantId) external {
        Grant storage g = _get(grantId);
        if (msg.sender != g.principal && !_isTenantAdmin(g.tenantScope, msg.sender)) {
            revert NotPrincipalOrTenantAdmin(grantId, msg.sender);
        }
        if (g.revoked) return; // the second caller wanted the same end state
        g.revoked = true;
        emit GrantRevoked(grantId, msg.sender);
    }

    /// Change the HIC level. CG-4.
    ///
    /// Toward MORE autonomy: the principal alone, as an explicit act. Toward
    /// more human control: the principal or a tenant admin, because that
    /// direction is always safe and is sometimes urgent.
    ///
    /// There is deliberately no path by which an agent asks for this. An agent
    /// that could request more autonomy and receive it has no envelope at all.
    function setHic(bytes32 grantId, Hic newHic) external {
        Grant storage g = _get(grantId);
        Hic old = g.hic;
        if (old == newHic) return;

        if (uint8(newHic) > uint8(old)) {
            if (msg.sender != g.principal) revert AutonomyIncreaseIsPrincipalOnly(grantId, msg.sender);
        } else if (msg.sender != g.principal && !_isTenantAdmin(g.tenantScope, msg.sender)) {
            revert NotPrincipalOrTenantAdmin(grantId, msg.sender);
        }

        g.hic = newHic;
        emit GrantHicChanged(grantId, old, newHic, msg.sender);
    }

    // ── The questions a gate asks ───────────────────────────────────

    /// Not revoked, not expired. Mirrors `is_live`; CG-2 means a revoked grant
    /// is dead regardless of expiry.
    function isLive(bytes32 grantId) public view returns (bool) {
        Grant storage g = _grants[grantId];
        if (!g.exists) return false;
        return !g.revoked && g.expiresAtMs > uint64(block.timestamp * 1000);
    }

    /// Does this grant cover such an action? Mirrors `covers`.
    ///
    /// Returns false for an unknown grant rather than reverting: a gate asks
    /// about ids that may not exist, and "no" is the answer to all of them.
    function covers(bytes32 grantId, bytes32 actionClass, uint8 classification, uint256 cost)
        external
        view
        returns (bool)
    {
        if (!isLive(grantId)) return false;
        Grant storage g = _grants[grantId];
        if (classification > g.classificationCeiling) return false;
        if (cost > g.budgetUnits - g.consumed) return false;
        for (uint256 i = 0; i < g.actionClasses.length; ++i) {
            if (g.actionClasses[i] == actionClass) return true;
        }
        return false;
    }

    /// Budget left. Saturating, matching `remaining`.
    function remaining(bytes32 grantId) external view returns (uint256) {
        Grant storage g = _grants[grantId];
        return g.consumed >= g.budgetUnits ? 0 : g.budgetUnits - g.consumed;
    }

    // ── Views ───────────────────────────────────────────────────────

    /// Reverts for an unknown id rather than returning a zeroed struct, so
    /// "no such grant" cannot be mistaken for "a grant with no budget".
    function grantOf(bytes32 grantId) external view returns (Grant memory) {
        return _get(grantId);
    }

    function actionClassesOf(bytes32 grantId) external view returns (bytes32[] memory) {
        return _get(grantId).actionClasses;
    }

    function grantCount(address principal) external view returns (uint256) {
        return _byPrincipal[principal].length;
    }

    function grantAt(address principal, uint256 index) external view returns (bytes32) {
        return _byPrincipal[principal][index];
    }

    // ── Internal ────────────────────────────────────────────────────

    function _get(bytes32 grantId) private view returns (Grant storage g) {
        g = _grants[grantId];
        if (!g.exists) revert UnknownGrant(grantId);
    }

    function _live(bytes32 grantId) private view returns (Grant storage g) {
        g = _get(grantId);
        if (!isLive(grantId)) revert GrantNotLive(grantId);
    }

    /// Membership, matching `TenantHierarchy._isAdmin` and the documented
    /// membership-only (not M-of-N) semantics the factory uses.
    function _isTenantAdmin(bytes32 tenantScope, address who) private view returns (bool) {
        ITenantHierarchy.TenantNode memory node = tenants.getNode(tenantScope);
        for (uint256 i = 0; i < node.admins.length; ++i) {
            if (node.admins[i] == who) return true;
        }
        return false;
    }
}
