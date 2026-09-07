// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {PolicyBinding} from "../src/quorum/PolicyBinding.sol";
import {GovernanceProtocolFactory, ITenantHierarchy} from "../src/quorum/GovernanceProtocolFactory.sol";
import {GovernanceTemplateRegistry} from "../src/quorum/GovernanceTemplateRegistry.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";
import {ThresholdApproval} from "../src/quorum/ThresholdApproval.sol";
import {ClassificationGate} from "../src/quorum/ClassificationGate.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";
import {ClassificationRegistry} from "../src/rbac/ClassificationRegistry.sol";
import {TenantHierarchy} from "../src/rbac/TenantHierarchy.sol";

/// A protocol that always demands a vote. Real — it implements the interface and
/// is deployed through the real factory from a registered template — but its
/// answer is constant, because the combination rule is what is under test here,
/// not the answer.
contract AlwaysVote is IGovernanceProtocol {
    bytes32 public immutable voterRole;

    constructor(bytes32 voterRole_) {
        voterRole = voterRole_;
    }

    function check(bytes32, bytes32, ActionContext calldata)
        external
        view
        returns (Verdict, bytes32, bytes32[] memory)
    {
        bytes32[] memory who = new bytes32[](1);
        who[0] = voterRole;
        return (Verdict.RequireVote, bytes32("AV_VOTE"), who);
    }

    function template() external pure returns (bytes32, uint32) {
        return (keccak256(abi.encode("AlwaysVote", uint32(1))), 1);
    }

    function spec() external pure returns (bytes32, string memory) {
        return (keccak256("always vote"), "bafyAlwaysVote");
    }
}

/// A protocol whose `check` reverts. Models the real failure modes — a source
/// contract that went away, a bug, an unbounded internal loop — for PB-6.
contract BrokenProtocol is IGovernanceProtocol {
    error Broken();

    function check(bytes32, bytes32, ActionContext calldata)
        external
        pure
        returns (Verdict, bytes32, bytes32[] memory)
    {
        revert Broken();
    }

    function template() external pure returns (bytes32, uint32) {
        return (keccak256(abi.encode("BrokenProtocol", uint32(1))), 1);
    }

    function spec() external pure returns (bytes32, string memory) {
        return (keccak256("broken"), "bafyBroken");
    }
}

/// @title PolicyBinding — invariant tests (QRM-S6.4)
///
/// End-to-end through the whole chain this sprint has been building: an audited
/// template is registered, the factory deploys a protocol from its pinned
/// bytecode, the protocol is bound to an action class, and a check consults it.
/// Nothing is stubbed — the registry, factory, tenant hierarchy, clearance
/// registry and envelope contract are all the real ones.
contract PolicyBindingTest is Test {
    GovernanceTemplateRegistry registry;
    GovernanceProtocolFactory factory;
    TenantHierarchy tenants;
    ClassificationRegistry classifications;
    MultiSigEnvelope envelopes;
    PolicyBinding binding;

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant OTHER_TENANT = keccak256("Rival");
    bytes32 constant ACTION = keccak256("repo.write");
    bytes32 constant SPEC_HASH = keccak256("spec");
    string constant SPEC_CID = "bafySpec";
    bytes32 constant SCHEMA = keccak256("schema");

    address constant GOV = address(0x60F);
    address constant ADMIN = address(0xAD);
    address constant OTHER_ADMIN = address(0xAD2);
    address constant STRANGER = address(0xBEEF);
    address constant PRINCIPAL = address(0xA11CE);

    // CHAIN-B-C008: MultiSigEnvelope binds sign() to the caller's own subjectKey,
    // so ALICE/BOB must be the subjectKey of a real address we prank as. Assigned
    // in setUp via `_subject` (the same derivation as QuorumIdentity.subjectKey).
    address constant ALICE_ADDR = address(0xA11CE5);
    address constant BOB_ADDR = address(0xB0B5);
    bytes32 ALICE;
    bytes32 BOB;
    bytes32 constant VOTERS = keccak256("role:shareholders");

    function setUp() public {
        ALICE = _subject(ALICE_ADDR);
        BOB = _subject(BOB_ADDR);
        registry = new GovernanceTemplateRegistry(GOV);
        tenants = new TenantHierarchy();
        classifications = new ClassificationRegistry(address(this));
        classifications.addOracleSigner(address(this));
        envelopes = new MultiSigEnvelope();

        address[] memory admins = new address[](1);
        admins[0] = ADMIN;
        tenants.initRoot(TENANT, "Citrate", keccak256("salt"), admins, 1, 3);
        address[] memory others = new address[](1);
        others[0] = OTHER_ADMIN;
        vm.prank(ADMIN);
        tenants.createNode(TENANT, OTHER_TENANT, "Rival", 1, keccak256("s2"), others, 1, 3);

        // The principal is cleared to the top of the ladder, so a
        // ClassificationGate in these tests refuses for the reason under test
        // (a ceiling) rather than incidentally for an unset clearance.
        vm.warp(block.timestamp + 1);
        classifications.setClearance(
            _subject(PRINCIPAL), ClassificationRegistry.ClassLevel.ITAR, false, hex"5163"
        );

        factory = new GovernanceProtocolFactory(registry, ITenantHierarchy(address(tenants)));
        binding = new PolicyBinding(factory, ITenantHierarchy(address(tenants)));
    }

    /// citrate-quorum's `clearance_subject` derivation — see
    /// `ClassificationGate.t.sol` for the pinned vector.
    function _subject(address who) internal pure returns (bytes32) {
        bytes16 digits = "0123456789abcdef";
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 v = uint160(who);
        for (uint256 i = 0; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            out[2 + i * 2] = digits[b >> 4];
            out[3 + i * 2] = digits[b & 0x0f];
        }
        return keccak256(out);
    }

    // ── Deploying real protocols through the real factory ───────────

    function _register(string memory name, bytes memory creationCode) internal returns (bytes32 id) {
        vm.prank(GOV);
        id = registry.register(name, 1, keccak256(creationCode), SCHEMA, "bafyAudit");
    }

    function _deploy(bytes32 tenantId, address admin, bytes32 templateId, bytes memory creationCode, bytes memory params, bytes32 salt)
        internal
        returns (address)
    {
        vm.prank(admin);
        return factory.deployProtocol(
            tenantId, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 3, salt, keccak256("corr")
        );
    }

    function _thresholdApproval(bytes32 tenantId, address admin, bytes32 salt) internal returns (address) {
        bytes memory code = type(ThresholdApproval).creationCode;
        bytes32 id = _register(string(abi.encodePacked("ThresholdApproval", salt)), code);
        bytes32[] memory approvers = new bytes32[](2);
        approvers[0] = ALICE;
        approvers[1] = BOB;
        bytes memory params = abi.encode(
            tenantId, id, uint32(1), SPEC_HASH, SPEC_CID, address(envelopes), approvers, uint8(2)
        );
        return _deploy(tenantId, admin, id, code, params, salt);
    }

    function _classificationGate(uint8 ceiling, bytes32 salt) internal returns (address) {
        bytes memory code = type(ClassificationGate).creationCode;
        bytes32 id = _register(string(abi.encodePacked("ClassificationGate", salt)), code);
        bytes memory params = abi.encode(
            TENANT, id, uint32(1), SPEC_HASH, SPEC_CID, address(classifications), address(tenants), ceiling, uint8(4)
        );
        return _deploy(TENANT, ADMIN, id, code, params, salt);
    }

    function _alwaysVote(bytes32 salt) internal returns (address) {
        bytes memory code = type(AlwaysVote).creationCode;
        bytes32 id = _register(string(abi.encodePacked("AlwaysVote", salt)), code);
        return _deploy(TENANT, ADMIN, id, code, abi.encode(VOTERS), salt);
    }

    function _broken(bytes32 salt) internal returns (address) {
        bytes memory code = type(BrokenProtocol).creationCode;
        bytes32 id = _register(string(abi.encodePacked("BrokenProtocol", salt)), code);
        return _deploy(TENANT, ADMIN, id, code, "", salt);
    }

    function _ctx(uint8 classification) internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 1,
            principal: PRINCIPAL,
            classification: classification,
            cost: 0,
            paramsHash: keccak256("params"),
            correlationId: keccak256("corr")
        });
    }

    function _check(uint8 classification)
        internal
        view
        returns (IGovernanceProtocol.Verdict v, bytes32 reason, bytes32[] memory signers)
    {
        return binding.check(TENANT, ACTION, _ctx(classification));
    }

    function _bind(address protocol) internal {
        vm.prank(ADMIN);
        binding.bind(TENANT, ACTION, protocol);
    }

    // ── PB-4: unbound is an answer, and a distinguishable one ───────

    /// An unbound action class is `Allow` — but with a reason the caller must
    /// not confuse with a governed allow. Quorum's rule 5 turns this into an
    /// `ungoverned` record and an alert; a caller that treated it as
    /// `PB_ALLOWED` would silently lose the only signal that nothing was
    /// checked.
    function test_unboundIsAllowedButNamedUngoverned() public view {
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, binding.REASON_UNGOVERNED());
        assertTrue(reason != binding.REASON_ALLOWED(), "ungoverned must not read as allowed");
    }

    /// A tenant that wants fail-closed opts in, and then unbound is a refusal
    /// with its own reason.
    function test_defaultDenyMakesUnboundARefusal() public {
        vm.prank(ADMIN);
        binding.setDefaultDeny(TENANT, true);

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, binding.REASON_NO_BINDING());

        vm.prank(ADMIN);
        binding.setDefaultDeny(TENANT, false);
        (IGovernanceProtocol.Verdict back,,) = _check(0);
        assertEq(uint8(back), uint8(IGovernanceProtocol.Verdict.Allow));
    }

    function test_onlyTenantAdminsMayChangeTheFailureMode() public {
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.NotTenantAdmin.selector, TENANT, STRANGER));
        binding.setDefaultDeny(TENANT, true);
    }

    // ── PB-2/PB-3: only what the factory built, only where it belongs ──

    /// The audit chain has to reach the enforcement point. A binding that could
    /// name arbitrary code would make "only audited bytecode governs" true of
    /// deployment and false of enforcement — which is the half that matters.
    function test_onlyFactoryDeployedProtocolsMayBeBound() public {
        // A perfectly good protocol, deployed with `new` instead of through the
        // factory: same bytecode, no provenance.
        AlwaysVote rogue = new AlwaysVote(VOTERS);

        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.NotFactoryDeployed.selector, address(rogue)));
        binding.bind(TENANT, ACTION, address(rogue));
    }

    /// One tenant's admin cannot bind another tenant's protocol, in either
    /// direction — the protocol carries the tenant it was deployed for and the
    /// binding must agree with it.
    function test_aProtocolCannotBeBoundIntoAnotherTenant() public {
        address theirs = _thresholdApproval(OTHER_TENANT, OTHER_ADMIN, keccak256("theirs"));

        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyBinding.WrongTenantForProtocol.selector, theirs, TENANT, OTHER_TENANT)
        );
        binding.bind(TENANT, ACTION, theirs);
    }

    function test_onlyTenantAdminsMayBindOrUnbind() public {
        address p = _alwaysVote(keccak256("v1"));

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.NotTenantAdmin.selector, TENANT, STRANGER));
        binding.bind(TENANT, ACTION, p);

        _bind(p);
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.NotTenantAdmin.selector, TENANT, STRANGER));
        binding.unbind(TENANT, ACTION, p);
    }

    // ── PB-1: most restrictive wins ─────────────────────────────────

    /// Two protocols bound to one action class means BOTH, not either. A single
    /// `Deny` ends it no matter what else allows.
    function test_denyOutranksEverythingElse() public {
        address gate = _classificationGate(1, keccak256("cg"));
        address vote = _alwaysVote(keccak256("av"));
        _bind(vote);
        _bind(gate);

        // Below the gate's ceiling: the vote is the strictest thing said.
        (IGovernanceProtocol.Verdict low, bytes32 lowReason,) = _check(1);
        assertEq(uint8(low), uint8(IGovernanceProtocol.Verdict.RequireVote));
        assertEq(lowReason, bytes32("AV_VOTE"));

        // Above it: the gate denies, and a demand for a vote cannot soften that.
        (IGovernanceProtocol.Verdict high, bytes32 highReason,) = _check(2);
        assertEq(uint8(high), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(highReason, ClassificationGate(gate).REASON_ABOVE_PROTOCOL());
    }

    /// A vote is a heavier demand than an approval, so it outranks one.
    function test_voteOutranksApproval() public {
        _bind(_thresholdApproval(TENANT, ADMIN, keccak256("ta")));
        _bind(_alwaysVote(keccak256("av2")));

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireVote));
        assertEq(reason, bytes32("AV_VOTE"));
    }

    /// Binding order must not change the answer. A combination rule that
    /// depended on it would make governance a function of who configured it
    /// first.
    function test_theAnswerDoesNotDependOnBindingOrder() public {
        address gate = _classificationGate(1, keccak256("cg2"));
        address vote = _alwaysVote(keccak256("av3"));

        _bind(gate);
        _bind(vote);
        (IGovernanceProtocol.Verdict a,,) = _check(2);

        vm.prank(ADMIN);
        binding.unbind(TENANT, ACTION, gate);
        vm.prank(ADMIN);
        binding.unbind(TENANT, ACTION, vote);
        _bind(vote);
        _bind(gate);
        (IGovernanceProtocol.Verdict b,,) = _check(2);

        assertEq(uint8(a), uint8(b), "order changed the verdict");
        assertEq(uint8(a), uint8(IGovernanceProtocol.Verdict.Deny));
    }

    /// Two protocols asking for the same class of action both have to be
    /// satisfied, so their outstanding sets merge rather than the first one
    /// winning. Duplicates collapse — the same person is not asked twice.
    function test_outstandingSignersMergeAcrossProtocols() public {
        _bind(_thresholdApproval(TENANT, ADMIN, keccak256("ta-a")));
        _bind(_thresholdApproval(TENANT, ADMIN, keccak256("ta-b")));

        (IGovernanceProtocol.Verdict v,, bytes32[] memory signers) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(signers.length, 2, "alice and bob, once each");
        assertEq(signers[0], ALICE);
        assertEq(signers[1], BOB);
    }

    /// Everything allowing is `Allow` with the governed reason — distinct from
    /// the ungoverned one.
    function test_allAllowingIsAGovernedAllow() public {
        _bind(_classificationGate(3, keccak256("cg3")));

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, binding.REASON_ALLOWED());
    }

    // ── PB-6: a broken protocol is a refusal, not a gap ─────────────

    /// A protocol that reverts must not be skipped. Skipping would mean the way
    /// to escape a rule is to break the contract that enforces it.
    function test_aRevertingProtocolDeniesRatherThanBeingSkipped() public {
        _bind(_broken(keccak256("bad")));

        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, binding.REASON_PROTOCOL_FAILED());
    }

    /// …and it does not take the whole check down with it: the other protocols
    /// are still consulted, and `explain` still reports each one.
    function test_aBrokenProtocolDoesNotBreakTheCheckItself() public {
        address gate = _classificationGate(3, keccak256("cg4"));
        _bind(gate);
        _bind(_broken(keccak256("bad2")));

        (address[] memory protocols, IGovernanceProtocol.Verdict[] memory verdicts, bytes32[] memory reasons) =
            binding.explain(TENANT, ACTION, _ctx(0));

        assertEq(protocols.length, 2);
        assertEq(uint8(verdicts[0]), uint8(IGovernanceProtocol.Verdict.Allow), "the healthy one still answers");
        assertEq(reasons[0], ClassificationGate(gate).REASON_CLEARED());
        assertEq(uint8(verdicts[1]), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reasons[1], binding.REASON_PROTOCOL_FAILED());
    }

    /// `check` answers, `explain` explains. An operator refused by one of
    /// several protocols needs to know which one — reconstructing that from a
    /// single combined reason code is guesswork.
    function test_explainAttributesEachVerdictToItsProtocol() public {
        address gate = _classificationGate(1, keccak256("cg5"));
        address vote = _alwaysVote(keccak256("av4"));
        _bind(gate);
        _bind(vote);

        (address[] memory protocols, IGovernanceProtocol.Verdict[] memory verdicts, bytes32[] memory reasons) =
            binding.explain(TENANT, ACTION, _ctx(2));

        assertEq(protocols[0], gate);
        assertEq(uint8(verdicts[0]), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reasons[0], ClassificationGate(gate).REASON_ABOVE_PROTOCOL());
        assertEq(protocols[1], vote);
        assertEq(uint8(verdicts[1]), uint8(IGovernanceProtocol.Verdict.RequireVote));
    }

    // ── Bookkeeping ─────────────────────────────────────────────────

    /// Unbinding is possible on purpose: a rule a tenant can never withdraw is
    /// not governance. What makes it safe is that the removal is an event with
    /// an actor on it.
    function test_unbindingRemovesTheRuleAndIsRecorded() public {
        address p = _alwaysVote(keccak256("av5"));
        _bind(p);
        assertTrue(binding.isBound(TENANT, ACTION, p));

        vm.expectEmit(true, true, true, true);
        emit PolicyBinding.ProtocolUnbound(TENANT, ACTION, p, ADMIN);
        vm.prank(ADMIN);
        binding.unbind(TENANT, ACTION, p);

        assertFalse(binding.isBound(TENANT, ACTION, p));
        assertEq(binding.protocolCount(TENANT, ACTION), 0);
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = _check(0);
        assertEq(reason, binding.REASON_UNGOVERNED(), "back to ungoverned, not silently allowed");
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
    }

    function test_unbindingSomethingNotBoundIsRefused() public {
        address p = _alwaysVote(keccak256("av6"));
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.NotBound.selector, TENANT, ACTION, p));
        binding.unbind(TENANT, ACTION, p);
    }

    function test_bindingTheSameProtocolTwiceIsRefused() public {
        address p = _alwaysVote(keccak256("av7"));
        _bind(p);
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.AlreadyBound.selector, TENANT, ACTION, p));
        binding.bind(TENANT, ACTION, p);
    }

    /// Bindings are per action class. A protocol governing `repo.write` says
    /// nothing about `repo.delete` — the fan-out is deliberate, not incidental.
    function test_bindingsAreScopedToTheirActionClass() public {
        address gate = _classificationGate(0, keccak256("cg6"));
        _bind(gate);

        (IGovernanceProtocol.Verdict governed, bytes32 r1,) = binding.check(TENANT, ACTION, _ctx(2));
        assertEq(uint8(governed), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r1, ClassificationGate(gate).REASON_ABOVE_PROTOCOL());

        (IGovernanceProtocol.Verdict other, bytes32 r2,) =
            binding.check(TENANT, keccak256("repo.delete"), _ctx(2));
        assertEq(uint8(other), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r2, binding.REASON_UNGOVERNED());
    }

    /// The fan-out is bounded. An unbounded list would make a binding
    /// enforcement site un-callable at some size — a denial of service that
    /// arrives silently, long after the binding that caused it.
    function test_fanOutIsBounded() public {
        for (uint256 i = 0; i < binding.MAX_PROTOCOLS_PER_ACTION(); ++i) {
            _bind(_alwaysVote(keccak256(abi.encode("fill", i))));
        }
        address oneMore = _alwaysVote(keccak256("overflow"));
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyBinding.TooManyProtocols.selector, TENANT, ACTION));
        binding.bind(TENANT, ACTION, oneMore);
    }

    // ── End to end ──────────────────────────────────────────────────

    /// The whole chain in one test: audited template → factory-deployed
    /// protocol → binding → a check that moves from `RequireApproval` to
    /// `Allow` as real approvals land in the real envelope contract.
    function test_theWholeChainFromAuditedTemplateToAGovernedAction() public {
        address ta = _thresholdApproval(TENANT, ADMIN, keccak256("e2e"));
        _bind(ta);

        (IGovernanceProtocol.Verdict before_, bytes32 r1, bytes32[] memory who) = _check(0);
        assertEq(uint8(before_), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, ThresholdApproval(ta).REASON_NOT_PROPOSED());
        assertEq(who.length, 2);

        bytes32 envelopeId =
            ThresholdApproval(ta).approvalEnvelopeId(ACTION, keccak256("params"), keccak256("corr"));
        bytes32[] memory required = new bytes32[](2);
        required[0] = ALICE;
        required[1] = BOB;
        envelopes.draft(envelopeId, ALICE, keccak256("artifact"), "bafyArtifact", required, 2, 0, keccak256("corr"));
        vm.prank(ALICE_ADDR);
        envelopes.sign(envelopeId, ALICE, hex"ab", "ceremony");

        (IGovernanceProtocol.Verdict half, bytes32 r2, bytes32[] memory outstanding) = _check(0);
        assertEq(uint8(half), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, ThresholdApproval(ta).REASON_PENDING());
        assertEq(outstanding.length, 1);
        assertEq(outstanding[0], BOB);

        vm.prank(BOB_ADDR);
        envelopes.sign(envelopeId, BOB, hex"cd", "ceremony");

        // The binding's own answer is `PB_ALLOWED`: a combined allow is the
        // binding's conclusion, not any one protocol's sentence. Which protocol
        // said what stays available through `explain` — that separation is why
        // both exist.
        (IGovernanceProtocol.Verdict after_, bytes32 r3,) = _check(0);
        assertEq(uint8(after_), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r3, binding.REASON_ALLOWED());

        (,, bytes32[] memory perProtocol) = binding.explain(TENANT, ACTION, _ctx(0));
        assertEq(perProtocol[0], ThresholdApproval(ta).REASON_SATISFIED());
    }
}
