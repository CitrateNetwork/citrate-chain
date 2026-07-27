// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";

/// @title BudgetedAutonomy — act unattended up to a line, sign above it
/// @notice citrate-quorum QRM-S6.7. Seed template 3 of 8.
///
/// The per-action half of budgeted autonomy: an agent acts unattended while each
/// action costs less than a stated ceiling, and anything above it pauses for a
/// human signature **regardless of how much budget is left**.
///
/// This is `quorum-policy::Action::hic1_cost_threshold` on chain — the PRT-004
/// C2 pattern — including its reason for existing: an agent with a large
/// remaining envelope should still not be able to spend it all on one action
/// nobody looked at.
///
/// ## What lives here, and what deliberately does not
///
/// **The per-window envelope is not here. It is `CapabilityGrant`.** A protocol's
/// `check` is a `view` with no grant id in its context, so it has no consumption
/// source to meter a window against; a "budget per window" implemented in here
/// would have to invent its own accounting, and two meters for one envelope is
/// exactly the drift this sprint keeps designing against. `CapabilityGrant`
/// carries `budgetUnits`/`consumed` and is the answer to "how much is left".
/// This template answers the different question: "is this ONE action small
/// enough to go unattended?"
///
/// The two compose the way the Rust does: `evaluate` escalates to HIC-1 when the
/// action exceeds the single-action ceiling **or** the grant is approve-each,
/// and otherwise allows within the envelope.
///
/// ## Mandatory-signature classes
///
/// Some action classes always need a human no matter how cheap they are —
/// chain, money, keys, grants, classification (L-1 of the HIC model, and
/// `Action::mandatory_hic1` in the Rust). Those are named at construction, so a
/// board can read which categories were declared unattendable rather than
/// trusting that the number was set low enough.
contract BudgetedAutonomy is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("BA_WRONG_TENANT");
    bytes32 public constant REASON_UNATTENDED = bytes32("BA_UNATTENDED");
    bytes32 public constant REASON_OVER_CEILING = bytes32("BA_OVER_CEILING");
    bytes32 public constant REASON_ALWAYS_SIGNED = bytes32("BA_ALWAYS_SIGNED");

    bytes32 public immutable tenant;
    /// Cost at or below which an action may proceed unattended. A ceiling of 0
    /// means "nothing is unattended", which is a legitimate and legible setting.
    uint256 public immutable perActionCeiling;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;
    /// Classes that always require a signature, whatever they cost.
    bytes32[] private _alwaysSigned;
    /// Who signs when this escalates.
    bytes32[] private _approvers;

    error ZeroTenant();
    error ZeroTemplate();
    error EmptySpec();
    error EmptyApproverSet();
    error TooManyEntries(uint256 count);

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        uint256 perActionCeiling_,
        bytes32[] memory alwaysSigned_,
        bytes32[] memory approvers_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        // An escalation with nobody to escalate to is a Deny that calls itself
        // an approval.
        if (approvers_.length == 0) revert EmptyApproverSet();
        if (alwaysSigned_.length > 64 || approvers_.length > 64) {
            revert TooManyEntries(alwaysSigned_.length + approvers_.length);
        }

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        perActionCeiling = perActionCeiling_;
        _alwaysSigned = alwaysSigned_;
        _approvers = approvers_;
    }

    /// @inheritdoc IGovernanceProtocol
    function check(bytes32 tenantId, bytes32 actionClass, ActionContext calldata ctx)
        external
        view
        override
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        if (tenantId != tenant) {
            return (Verdict.Deny, REASON_WRONG_TENANT, new bytes32[](0));
        }
        // Checked before the ceiling: a mandatory class is not cheap-enough-able,
        // and the operator needs to be told which rule applied, not merely that
        // one did.
        for (uint256 i = 0; i < _alwaysSigned.length; ++i) {
            if (_alwaysSigned[i] == actionClass) {
                return (Verdict.RequireApproval, REASON_ALWAYS_SIGNED, _approvers);
            }
        }
        if (ctx.cost > perActionCeiling) {
            return (Verdict.RequireApproval, REASON_OVER_CEILING, _approvers);
        }
        return (Verdict.Allow, REASON_UNATTENDED, new bytes32[](0));
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    function policy() external view returns (uint256 ceiling, bytes32[] memory alwaysSigned, bytes32[] memory approvers) {
        return (perActionCeiling, _alwaysSigned, _approvers);
    }
}
