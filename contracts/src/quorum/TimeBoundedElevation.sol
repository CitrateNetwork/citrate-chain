// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {QuorumIdentity} from "./QuorumIdentity.sol";

/// Minimal view of the deployed `RoleEscalation` (DPF-02, `rbac/`).
interface IRoleEscalation {
    struct RoleGrant {
        bytes32 user;
        bytes32 tenant;
        bytes32 role;
        uint64 granted_at;
        uint64 expires_at;
        bytes32 corr_id;
        bytes32 reauth_proof_hash;
        string reauth_proof_kind;
        bool active;
    }

    function isActiveNow(bytes32 user, bytes32 tenant) external view returns (bool);
    function latestGrant(bytes32 user, bytes32 tenant) external view returns (RoleGrant memory);
    function grantCount(bytes32 user, bytes32 tenant) external view returns (uint256);
}

/// @title TimeBoundedElevation — the capability only exists while you are elevated
/// @notice citrate-quorum QRM-S6.7. Seed template 5 of 8.
///
/// Wraps the deployed `RoleEscalation` for one scoped capability: an action in
/// this class proceeds only while the acting principal holds a live elevation to
/// the required role. When the window closes, the capability closes with it —
/// nothing has to be revoked, because nothing was granted permanently.
///
/// ## Why `RequireApproval` rather than `Deny`
///
/// "You are not elevated" is not a refusal of the action, it is a missing step
/// before it. The remedy is a human ceremony — `RoleEscalation.requestElevation`
/// with its re-auth proof — which is precisely what `RequireApproval` means in
/// this interface: a human must act before this proceeds. Returning `Deny` would
/// tell an operator to give up on something they can legitimately do in thirty
/// seconds.
///
/// The exception is a principal with **no grant history at all** in this tenant.
/// That is a different problem — they are not a member with a base role, so
/// there is nothing to elevate — and it is a `Deny`, because the fix is
/// administrative rather than a ceremony the operator can perform.
///
/// ## What it reads, and the one thing it does not trust
///
/// `isActiveNow` answers "is there an unexpired active grant", but not "for
/// which role". A capability that accepted *any* elevation would let an
/// elevation obtained for one purpose authorise a different one — the classic
/// confused-deputy — so this also reads `latestGrant` and requires the role to
/// match, and requires it to still be within its own window rather than
/// trusting the stored `active` flag alone (`RoleEscalation` documents that its
/// view "does NOT auto-expire").
contract TimeBoundedElevation is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("TBE_WRONG_TENANT");
    bytes32 public constant REASON_NOT_ELEVATED = bytes32("TBE_NOT_ELEVATED");
    bytes32 public constant REASON_WRONG_ROLE = bytes32("TBE_WRONG_ROLE");
    bytes32 public constant REASON_NO_MEMBERSHIP = bytes32("TBE_NO_MEMBERSHIP");
    bytes32 public constant REASON_ELEVATED = bytes32("TBE_ELEVATED");

    bytes32 public immutable tenant;
    IRoleEscalation public immutable escalations;
    /// The role an elevation must be TO. Not "any elevation".
    bytes32 public immutable requiredRole;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroEscalations();
    error ZeroRole();
    error EmptySpec();

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address escalations_,
        bytes32 requiredRole_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (escalations_ == address(0)) revert ZeroEscalations();
        // A protocol that required "any role" would be a confused deputy by
        // construction.
        if (requiredRole_ == bytes32(0)) revert ZeroRole();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        escalations = IRoleEscalation(escalations_);
        requiredRole = requiredRole_;
    }

    /// @inheritdoc IGovernanceProtocol
    function check(bytes32 tenantId, bytes32, ActionContext calldata ctx)
        external
        view
        override
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        requiredSigners = new bytes32[](0);
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, requiredSigners);
        }

        bytes32 user = QuorumIdentity.subjectKey(ctx.principal);

        // No history at all: not a member with a base role, so there is nothing
        // to elevate. Administrative, not a ceremony.
        if (escalations.grantCount(user, tenantId) == 0) {
            return (Verdict.Deny, REASON_NO_MEMBERSHIP, requiredSigners);
        }
        if (!escalations.isActiveNow(user, tenantId)) {
            bytes32[] memory role = new bytes32[](1);
            role[0] = requiredRole;
            return (Verdict.RequireApproval, REASON_NOT_ELEVATED, role);
        }

        IRoleEscalation.RoleGrant memory g = escalations.latestGrant(user, tenantId);
        // Belt and braces on the window: `isActiveNow` is documented as not
        // auto-expiring, and a capability that outlived its window would be the
        // one thing this template exists to prevent.
        if (!g.active || g.expires_at <= block.timestamp) {
            bytes32[] memory role = new bytes32[](1);
            role[0] = requiredRole;
            return (Verdict.RequireApproval, REASON_NOT_ELEVATED, role);
        }
        if (g.role != requiredRole) {
            bytes32[] memory role = new bytes32[](1);
            role[0] = requiredRole;
            return (Verdict.RequireApproval, REASON_WRONG_ROLE, role);
        }

        return (Verdict.Allow, REASON_ELEVATED, requiredSigners);
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }
}
