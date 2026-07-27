// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {ITenantHierarchy} from "./GovernanceProtocolFactory.sol";

/// Minimal view of the deployed `ClassificationRegistry` (DPF-02, `rbac/`).
///
/// Imported as an interface, not the contract, so a customer may point a
/// protocol at their own clearance source. `getClearance` returns
/// `(Public, false)` for a subject with no record rather than reverting — see
/// the gate's header for why that default is safe here and dangerous elsewhere.
interface IClassificationRegistry {
    enum ClassLevel {
        Public,
        Proprietary,
        CUI,
        ITAR
    }

    function getClearance(bytes32 user) external view returns (ClassLevel, bool);
}

/// @title ClassificationGate — clearance ≥ level, under two ceilings
/// @notice citrate-quorum QRM-S6.3. Seed template 2 of 8. Planset
/// `03_GOVERNANCE_CONTRACTS.md` §1 ("action requires clearance ≥ L and tenant
/// ceiling ≥ L").
///
/// The `Deny` shape of the seed set, and the on-chain counterpart of the rule
/// citrate-quorum already enforces in process. Four things must hold for an
/// action to pass:
///
/// 1. the action's classification is a level this ladder recognises;
/// 2. it does not exceed the ceiling this protocol was deployed with;
/// 3. it does not exceed the tenant's own `classification_max`;
/// 4. the accountable principal is cleared to at least that level.
///
/// Each failure has its own reason code, because "denied" without which of the
/// four failed is unactionable: the fixes are *reclassify*, *redeploy*,
/// *raise the tenant*, and *clear the person* — four different people's jobs.
///
/// ## Its Rust counterpart, named so a divergence is visible
///
/// This mirrors `mr4_admits` in citrate-quorum's `src-tauri/src/rooms.rs` and
/// the `ClearanceReader` in its `quorum-clearance` crate — same ladder, same
/// fail-closed defaults, same three refusal shapes (unknown level, over ceiling,
/// undercleared). Sprint risk R-D is that the two drift. Two things hold them
/// together: this citation, and `subjectKey` below, which reproduces
/// `chain.rs::clearance_subject` exactly — `keccak256` of the **lowercase
/// "0x"-prefixed hex string**, not of the 20 address bytes. A mismatch there
/// would not fail loudly; it would silently read a different subject's record
/// and report `Public` for everyone, which is a fail-open dressed as a default.
/// It is pinned by a test vector on both sides.
///
/// ## Why an unrecorded subject means `Public`
///
/// `ClassificationRegistry.getClearance` returns `(Public, false)` for a subject
/// it has never heard of. Treating that as a clearance of zero is correct HERE:
/// this gate only ever compares clearance *upward* against a required level, so
/// an unrecorded subject is denied everything above Public and permitted only
/// what is public anyway. The same default would be dangerous in a contract that
/// read it as "no restriction" — which is why this gate never asks whether a
/// record exists, only whether the level is high enough.
///
/// ## Foreign-national handling is configuration, not a regime
///
/// The registry tracks a `foreign_national` flag. This gate can refuse it at or
/// above a configured level (`foreignNationalFloor`), and 4 disables the rule
/// entirely. The level is a **deployment parameter**: this contract does not
/// encode ITAR, EAR, or any other regime's rules, and **nothing here is a claim
/// that a deployment satisfies any of them.** That is a legal conclusion and no
/// engineering decision can supply it. What this contract does is enforce the
/// rule an operator configured, and record which rule refused.
///
/// ## Enforcement class
///
/// Pure function of on-chain state, so it is honest in all three positions of
/// `IGovernanceProtocol`'s table: **binding** when an on-chain contract calls it
/// before acting, **advisory** when quorum's gate calls it before an off-chain
/// action, and **attested** when the verdict is recorded with the decision.
/// Unlike `ThresholdApproval` it carries no trust boundary of its own — it
/// inherits exactly the trust already placed in `ClassificationRegistry`'s HR
/// oracle signers and in `TenantHierarchy`.
contract ClassificationGate is IGovernanceProtocol {
    bytes32 public constant REASON_WRONG_TENANT = bytes32("CG_WRONG_TENANT");
    bytes32 public constant REASON_UNKNOWN_LEVEL = bytes32("CG_UNKNOWN_LEVEL");
    bytes32 public constant REASON_ABOVE_PROTOCOL = bytes32("CG_ABOVE_PROTOCOL");
    bytes32 public constant REASON_ABOVE_TENANT = bytes32("CG_ABOVE_TENANT");
    bytes32 public constant REASON_NO_TENANT = bytes32("CG_NO_TENANT");
    bytes32 public constant REASON_NO_PRINCIPAL = bytes32("CG_NO_PRINCIPAL");
    bytes32 public constant REASON_UNDERCLEARED = bytes32("CG_UNDERCLEARED");
    bytes32 public constant REASON_FOREIGN_NATIONAL = bytes32("CG_FOREIGN_NATIONAL");
    bytes32 public constant REASON_CLEARED = bytes32("CG_CLEARED");

    /// Highest level this ladder recognises (Public..ITAR = 0..3), matching
    /// `ClassificationRegistry.ClassLevel` and `TenantHierarchy.classification_max`.
    uint8 public constant MAX_LEVEL = 3;
    /// `foreignNationalFloor == NO_FOREIGN_NATIONAL_RULE` disables the rule.
    uint8 public constant NO_FOREIGN_NATIONAL_RULE = 4;

    bytes32 public immutable tenant;
    IClassificationRegistry public immutable classifications;
    ITenantHierarchy public immutable tenants;
    /// The ceiling this protocol was deployed with. The factory (GF-4) already
    /// refused to deploy it above the tenant's own maximum; this is the
    /// protocol's own, possibly stricter, limit.
    uint8 public immutable ceiling;
    /// Level at or above which a subject recorded as a foreign national is
    /// refused. 4 = no such rule.
    uint8 public immutable foreignNationalFloor;

    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    string private _specCID;

    error ZeroTenant();
    error ZeroTemplate();
    error ZeroRegistry();
    error ZeroHierarchy();
    error EmptySpec();
    error CeilingAboveLadder(uint8 ceiling);
    error ForeignNationalFloorAboveLadder(uint8 floor);

    constructor(
        bytes32 tenantId,
        bytes32 templateId_,
        uint32 version_,
        bytes32 specHash_,
        string memory specCID_,
        address classifications_,
        address tenants_,
        uint8 ceiling_,
        uint8 foreignNationalFloor_
    ) {
        if (tenantId == bytes32(0)) revert ZeroTenant();
        if (templateId_ == bytes32(0)) revert ZeroTemplate();
        if (classifications_ == address(0)) revert ZeroRegistry();
        if (tenants_ == address(0)) revert ZeroHierarchy();
        if (specHash_ == bytes32(0) || bytes(specCID_).length == 0) revert EmptySpec();
        // A ceiling above the ladder would be a rule that can never bind — worse
        // than no rule, because it reads like one.
        if (ceiling_ > MAX_LEVEL) revert CeilingAboveLadder(ceiling_);
        if (foreignNationalFloor_ > NO_FOREIGN_NATIONAL_RULE) {
            revert ForeignNationalFloorAboveLadder(foreignNationalFloor_);
        }

        tenant = tenantId;
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        _specCID = specCID_;
        classifications = IClassificationRegistry(classifications_);
        tenants = ITenantHierarchy(tenants_);
        ceiling = ceiling_;
        foreignNationalFloor = foreignNationalFloor_;
    }

    /// The `ClassificationRegistry` key for an address.
    ///
    /// Reproduces citrate-quorum's `chain.rs::clearance_subject`:
    /// `keccak256` over the **lowercase "0x"-prefixed hex string**, not over the
    /// 20 raw bytes. Exposed publicly so the app and any verifier can confirm
    /// the two sides agree instead of assuming it.
    function subjectKey(address who) public pure returns (bytes32) {
        bytes16 hexDigits = "0123456789abcdef";
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        uint160 v = uint160(who);
        for (uint256 i = 0; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            s[2 + i * 2] = hexDigits[b >> 4];
            s[3 + i * 2] = hexDigits[b & 0x0f];
        }
        return keccak256(s);
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
        // An unrecognised level is refused, never coerced down to something this
        // ladder does understand. Quorum's `mr4_admits` refuses the same way, for
        // the same reason: silently treating an unknown classification as Public
        // is how controlled material ends up in an uncontrolled room.
        if (ctx.classification > MAX_LEVEL) {
            return (Verdict.Deny, REASON_UNKNOWN_LEVEL, requiredSigners);
        }
        if (ctx.classification > ceiling) {
            return (Verdict.Deny, REASON_ABOVE_PROTOCOL, requiredSigners);
        }
        // `IGovernanceProtocol` states a governed action always has a principal;
        // an action without one is `ungoverned`, which quorum records and alerts
        // on. If one reaches here anyway, it is denied rather than evaluated
        // against the zero address's (empty, therefore Public) record.
        if (ctx.principal == address(0)) {
            return (Verdict.Deny, REASON_NO_PRINCIPAL, requiredSigners);
        }

        // `getNode` reverts for an unknown tenant. Caught, because a gate that
        // reverts tells the operator nothing, and "this tenant is not in the
        // hierarchy" is a different problem from "you are not cleared".
        try tenants.getNode(tenantId) returns (ITenantHierarchy.TenantNode memory node) {
            if (ctx.classification > node.classification_max) {
                return (Verdict.Deny, REASON_ABOVE_TENANT, requiredSigners);
            }
        } catch {
            return (Verdict.Deny, REASON_NO_TENANT, requiredSigners);
        }

        (IClassificationRegistry.ClassLevel level, bool foreignNational) =
            classifications.getClearance(subjectKey(ctx.principal));
        if (uint8(level) < ctx.classification) {
            return (Verdict.Deny, REASON_UNDERCLEARED, requiredSigners);
        }
        if (
            foreignNationalFloor != NO_FOREIGN_NATIONAL_RULE
                && ctx.classification >= foreignNationalFloor && foreignNational
        ) {
            return (Verdict.Deny, REASON_FOREIGN_NATIONAL, requiredSigners);
        }

        return (Verdict.Allow, REASON_CLEARED, requiredSigners);
    }

    /// @inheritdoc IGovernanceProtocol
    function template() external view override returns (bytes32 templateId, uint32 version) {
        return (_templateId, _version);
    }

    /// @inheritdoc IGovernanceProtocol
    function spec() external view override returns (bytes32 specHash, string memory specCID) {
        return (_specHash, _specCID);
    }

    /// The rule in force, for the app to render next to the spec.
    function policy() external view returns (uint8 protocolCeiling, uint8 fnFloor) {
        return (ceiling, foreignNationalFloor);
    }
}
