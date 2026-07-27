// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ClassificationGate, IClassificationRegistry} from "../src/quorum/ClassificationGate.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";
import {ClassificationRegistry} from "../src/rbac/ClassificationRegistry.sol";
import {TenantHierarchy} from "../src/rbac/TenantHierarchy.sol";

/// @title ClassificationGate — invariant tests (QRM-S6.3)
///
/// Run against the **real `ClassificationRegistry` and `TenantHierarchy`**. The
/// gate is a reader; a stubbed source would test only that the reader can read
/// something, which is not the claim.
contract ClassificationGateTest is Test {
    ClassificationRegistry registry;
    TenantHierarchy tenants;
    ClassificationGate gate;

    bytes32 constant ROOT = keccak256("Citrate");
    bytes32 constant CHILD = keccak256("Citrate/Wichita");
    bytes32 constant OTHER_TENANT = keccak256("SomeoneElse");
    bytes32 constant TEMPLATE_ID = keccak256(abi.encode("ClassificationGate", uint32(1)));
    bytes32 constant SPEC_HASH = keccak256("the spec text");
    string constant SPEC_CID = "bafyClassificationGateSpecV1";
    bytes32 constant ACTION = keccak256("document.read");

    address constant CLEARED_HUMAN = address(0xA11CE);
    address constant UNCLEARED_HUMAN = address(0xB0B);
    address constant NEVER_SEEN = address(0xDEADBEEF);

    uint8 constant PUBLIC_ = 0;
    uint8 constant PROPRIETARY = 1;
    uint8 constant CUI = 2;
    uint8 constant ITAR = 3;
    /// `foreignNationalFloor` value that disables the rule.
    uint8 constant NO_FN_RULE = 4;

    function setUp() public {
        registry = new ClassificationRegistry(address(this));
        registry.addOracleSigner(address(this));

        tenants = new TenantHierarchy();
        address[] memory admins = new address[](1);
        admins[0] = address(this);
        // Root is cleared to ITAR; the child deliberately is not, so "above the
        // tenant" can be exercised without inventing a fake hierarchy.
        tenants.initRoot(ROOT, "Citrate", keccak256("salt"), admins, 1, ITAR);
        tenants.createNode(ROOT, CHILD, "Wichita", 1, keccak256("salt2"), admins, 1, PROPRIETARY);

        _clear(CLEARED_HUMAN, ClassificationRegistry.ClassLevel.ITAR, false);
        _clear(UNCLEARED_HUMAN, ClassificationRegistry.ClassLevel.Public, false);

        gate = _deploy(ROOT, ITAR, NO_FN_RULE);
    }

    uint256 private _clearTick;

    function _clear(address who, ClassificationRegistry.ClassLevel level, bool foreignNational) internal {
        // Timestamps must strictly increase per subject (HistoryMonotonic).
        // Warped to an absolute value, not `block.timestamp + 1`: solc caches
        // `block.timestamp` within a call frame, so two relative warps in one
        // test would silently land on the same instant.
        vm.warp(1_700_000_000 + ++_clearTick);
        registry.setClearance(_subject(who), level, foreignNational, hex"5163");
    }

    /// The same derivation citrate-quorum uses, written out independently of the
    /// contract's hex loop so this is a real cross-check and not a tautology.
    function _subject(address who) internal pure returns (bytes32) {
        return keccak256(bytes(_lowerHex(who)));
    }

    function _lowerHex(address who) internal pure returns (string memory) {
        bytes16 digits = "0123456789abcdef";
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        uint160 v = uint160(who);
        for (uint256 i = 0; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            s[2 + i * 2] = digits[b >> 4];
            s[3 + i * 2] = digits[b & 0x0f];
        }
        return string(s);
    }

    function _deploy(bytes32 tenantId, uint8 ceiling, uint8 fnFloor) internal returns (ClassificationGate) {
        return new ClassificationGate(
            tenantId, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(registry), address(tenants), ceiling, fnFloor
        );
    }

    function _ctx(address principal, uint8 classification)
        internal
        pure
        returns (IGovernanceProtocol.ActionContext memory)
    {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 0,
            principal: principal,
            classification: classification,
            cost: 0,
            paramsHash: keccak256("params"),
            correlationId: keccak256("corr")
        });
    }

    function _verdict(ClassificationGate g, bytes32 tenantId, address principal, uint8 classification)
        internal
        view
        returns (IGovernanceProtocol.Verdict v, bytes32 reason)
    {
        (v, reason,) = g.check(tenantId, ACTION, _ctx(principal, classification));
    }

    // ── The four ways this can refuse, each with its own reason ─────

    /// Each refusal has a different fix and a different owner: reclassify the
    /// action, redeploy the protocol, raise the tenant, clear the person. A gate
    /// that returned a bare `Deny` would send every one of those to the same
    /// support queue.
    function test_eachRefusalIsDistinguishable() public view {
        (IGovernanceProtocol.Verdict v1, bytes32 r1) = _verdict(gate, ROOT, CLEARED_HUMAN, 4);
        assertEq(uint8(v1), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r1, gate.REASON_UNKNOWN_LEVEL(), "a level off the ladder is refused, not coerced down");

        (IGovernanceProtocol.Verdict v2, bytes32 r2) = _verdict(gate, ROOT, UNCLEARED_HUMAN, CUI);
        assertEq(uint8(v2), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r2, gate.REASON_UNDERCLEARED());

        (IGovernanceProtocol.Verdict v3, bytes32 r3) = _verdict(gate, OTHER_TENANT, CLEARED_HUMAN, PUBLIC_);
        assertEq(uint8(v3), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r3, gate.REASON_WRONG_TENANT());

        (IGovernanceProtocol.Verdict v4, bytes32 r4) = _verdict(gate, ROOT, address(0), PUBLIC_);
        assertEq(uint8(v4), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r4, gate.REASON_NO_PRINCIPAL(), "an action with no accountable human is not evaluated");
    }

    function test_clearedPrincipalIsAllowedAtEveryLevelUpToTheirClearance() public view {
        for (uint8 level = PUBLIC_; level <= ITAR; ++level) {
            (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(gate, ROOT, CLEARED_HUMAN, level);
            assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow), "ITAR clearance covers the whole ladder");
            assertEq(reason, gate.REASON_CLEARED());
        }
    }

    /// The protocol's own ceiling binds even when the tenant and the person
    /// would both allow it — that is what deploying a stricter protocol for a
    /// narrower purpose means.
    function test_protocolCeilingBindsBelowTheTenantAndThePerson() public {
        ClassificationGate strict = _deploy(ROOT, PROPRIETARY, 4);

        (IGovernanceProtocol.Verdict ok,) = _verdict(strict, ROOT, CLEARED_HUMAN, PROPRIETARY);
        assertEq(uint8(ok), uint8(IGovernanceProtocol.Verdict.Allow));

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(strict, ROOT, CLEARED_HUMAN, CUI);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, strict.REASON_ABOVE_PROTOCOL());
    }

    /// The tenant's own `classification_max` binds even when the protocol and
    /// the person would allow it. This is the ceiling a customer sets once for a
    /// whole part of their org, and it must not be escapable by deploying a
    /// permissive protocol into it.
    function test_tenantCeilingBindsEvenWithAPermissiveProtocolAndAClearedPerson() public {
        ClassificationGate onChild = _deploy(CHILD, ITAR, 4);

        (IGovernanceProtocol.Verdict ok,) = _verdict(onChild, CHILD, CLEARED_HUMAN, PROPRIETARY);
        assertEq(uint8(ok), uint8(IGovernanceProtocol.Verdict.Allow));

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(onChild, CHILD, CLEARED_HUMAN, CUI);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, onChild.REASON_ABOVE_TENANT(), "the child tenant tops out at Proprietary");
    }

    /// `TenantHierarchy.getNode` reverts for a tenant it has never heard of. A
    /// gate that let that propagate would tell the operator nothing; "this
    /// tenant is not in the hierarchy" is a different problem from "you are not
    /// cleared" and needs a different person.
    function test_unknownTenantIsADistinctRefusalNotARevert() public {
        bytes32 ghost = keccak256("NeverCreated");
        ClassificationGate orphan = _deploy(ghost, ITAR, 4);

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(orphan, ghost, CLEARED_HUMAN, PROPRIETARY);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, orphan.REASON_NO_TENANT());
    }

    // ── Fail-closed defaults ────────────────────────────────────────

    /// A subject the registry has never seen reads as `Public`. That is safe
    /// HERE because the gate only ever compares upward: unrecorded gets exactly
    /// what is public anyway, and nothing above it.
    function test_anUnrecordedSubjectGetsPublicAndNothingMore() public view {
        (IGovernanceProtocol.Verdict pub, bytes32 rp) = _verdict(gate, ROOT, NEVER_SEEN, PUBLIC_);
        assertEq(uint8(pub), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(rp, gate.REASON_CLEARED());

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(gate, ROOT, NEVER_SEEN, PROPRIETARY);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, gate.REASON_UNDERCLEARED());
    }

    /// Losing clearance takes effect on the next call. There is no cache, and no
    /// grandfathering — which is the whole point of reading the registry live
    /// rather than snapshotting it at deploy time.
    function test_revokingClearanceTakesEffectImmediately() public {
        (IGovernanceProtocol.Verdict before_,) = _verdict(gate, ROOT, CLEARED_HUMAN, ITAR);
        assertEq(uint8(before_), uint8(IGovernanceProtocol.Verdict.Allow));

        _clear(CLEARED_HUMAN, ClassificationRegistry.ClassLevel.Public, false);

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(gate, ROOT, CLEARED_HUMAN, ITAR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, gate.REASON_UNDERCLEARED());
    }

    // ── The subject key, where a silent fail-open would live ────────

    /// `subjectKey` must reproduce citrate-quorum's `chain.rs::clearance_subject`
    /// exactly: keccak256 of the lowercase "0x"-prefixed hex STRING, not of the
    /// 20 address bytes.
    ///
    /// This is the highest-consequence line in the contract. A mismatch would
    /// not revert — it would read a different subject's record, find nothing,
    /// and report `Public` for everyone. A fail-open wearing a default's
    /// clothing. So it is pinned three ways: against a literal string, against
    /// the raw-bytes hash it must NOT equal, and against a live clearance being
    /// found through it.
    function test_subjectKeyMatchesQuorumsDerivation() public view {
        address who = address(uint160(0xab));

        assertEq(
            gate.subjectKey(who),
            keccak256(bytes("0x00000000000000000000000000000000000000ab")),
            "lowercase, 0x-prefixed, hashed as text"
        );
        // The same number is asserted in citrate-quorum's
        // `chain::tests::clearance_subject_matches_the_on_chain_vector`. Two
        // repositories, one literal: if either derivation moves, one of the two
        // tests goes red, which is the only way a cross-repo agreement stays
        // true without a shared build.
        assertEq(
            gate.subjectKey(who),
            0x549328a5435660214b49079937321d53a0b2204070da2b803319218631a426db,
            "shared vector with citrate-quorum"
        );
        assertTrue(
            gate.subjectKey(who) != keccak256(abi.encodePacked(who)), "hashing the raw bytes is the failure mode"
        );
        assertTrue(
            gate.subjectKey(who) != keccak256(bytes("0x00000000000000000000000000000000000000AB")),
            "uppercase hex is a different subject"
        );
    }

    /// The end-to-end version of the same claim: a clearance written under
    /// quorum's derivation is found by the gate.
    function test_aClearanceWrittenUnderQuorumsKeyIsFoundByTheGate() public view {
        (IGovernanceProtocol.Verdict v,) = _verdict(gate, ROOT, CLEARED_HUMAN, ITAR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow), "the gate found the record setUp wrote");
    }

    // ── Foreign-national handling is configuration ──────────────────

    /// The rule is a deployment parameter, not a regime. Off by default, it
    /// changes nothing; set to a level, it refuses at and above that level and
    /// says so with its own reason code.
    ///
    /// Nothing here is a claim that any deployment satisfies any export-control
    /// regime. That is a legal conclusion; this contract enforces the rule an
    /// operator configured.
    function test_foreignNationalRuleAppliesOnlyWhenConfigured() public {
        address foreignCleared = address(0xF0E1);
        _clear(foreignCleared, ClassificationRegistry.ClassLevel.ITAR, true);

        // Disabled: clearance alone decides.
        (IGovernanceProtocol.Verdict off,) = _verdict(gate, ROOT, foreignCleared, ITAR);
        assertEq(uint8(off), uint8(IGovernanceProtocol.Verdict.Allow));

        // Configured at ITAR: refused at ITAR, untouched below it.
        ClassificationGate restricted = _deploy(ROOT, ITAR, ITAR);
        (IGovernanceProtocol.Verdict below,) = _verdict(restricted, ROOT, foreignCleared, CUI);
        assertEq(uint8(below), uint8(IGovernanceProtocol.Verdict.Allow), "the rule starts at the configured level");

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _verdict(restricted, ROOT, foreignCleared, ITAR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, restricted.REASON_FOREIGN_NATIONAL());

        // …and it is about the flag, not the person: the same level passes for a
        // domestic subject with the same clearance.
        (IGovernanceProtocol.Verdict domestic,) = _verdict(restricted, ROOT, CLEARED_HUMAN, ITAR);
        assertEq(uint8(domestic), uint8(IGovernanceProtocol.Verdict.Allow));
    }

    // ── Construction ────────────────────────────────────────────────

    function test_constructorRefusesARuleThatCouldNeverBind() public {
        // A ceiling above the ladder reads like a rule and can never refuse.
        vm.expectRevert(abi.encodeWithSelector(ClassificationGate.CeilingAboveLadder.selector, uint8(4)));
        _deploy(ROOT, 4, 4);

        vm.expectRevert(abi.encodeWithSelector(ClassificationGate.ForeignNationalFloorAboveLadder.selector, uint8(5)));
        _deploy(ROOT, ITAR, 5);

        vm.expectRevert(ClassificationGate.ZeroTenant.selector);
        _deploy(bytes32(0), ITAR, 4);

        vm.expectRevert(ClassificationGate.ZeroRegistry.selector);
        new ClassificationGate(ROOT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(0), address(tenants), ITAR, 4);

        vm.expectRevert(ClassificationGate.ZeroHierarchy.selector);
        new ClassificationGate(ROOT, TEMPLATE_ID, 1, SPEC_HASH, SPEC_CID, address(registry), address(0), ITAR, 4);

        vm.expectRevert(ClassificationGate.EmptySpec.selector);
        new ClassificationGate(ROOT, TEMPLATE_ID, 1, SPEC_HASH, "", address(registry), address(tenants), ITAR, 4);
    }

    function test_provenanceIsReadableFromTheProtocolItself() public view {
        (bytes32 templateId, uint32 version) = gate.template();
        assertEq(templateId, TEMPLATE_ID);
        assertEq(version, 1);

        (bytes32 specHash, string memory cid) = gate.spec();
        assertEq(specHash, SPEC_HASH);
        assertEq(cid, SPEC_CID);

        (uint8 ceiling, uint8 fnFloor) = gate.policy();
        assertEq(ceiling, ITAR);
        assertEq(fnFloor, 4);
    }
}
