// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {GovernanceTemplateRegistry} from "../src/quorum/GovernanceTemplateRegistry.sol";
import {GovernanceProtocolFactory, ITenantHierarchy} from "../src/quorum/GovernanceProtocolFactory.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";

/// A minimal real protocol, used as the audited template's bytecode.
///
/// Not a mock of the factory's dependencies — it is a genuine
/// `IGovernanceProtocol` that the factory really deploys and that really
/// answers. The factory's behaviour is exercised against actual CREATE2 output.
contract TestProtocol is IGovernanceProtocol {
    bytes32 private immutable _templateId;
    uint32 private immutable _version;
    bytes32 private immutable _specHash;
    uint8 public immutable maxClassification;

    constructor(bytes32 templateId_, uint32 version_, bytes32 specHash_, uint8 maxClassification_) {
        _templateId = templateId_;
        _version = version_;
        _specHash = specHash_;
        maxClassification = maxClassification_;
    }

    function check(bytes32, bytes32, ActionContext calldata ctx)
        external
        view
        returns (Verdict, bytes32, bytes32[] memory)
    {
        bytes32[] memory none = new bytes32[](0);
        if (ctx.classification > maxClassification) {
            return (Verdict.Deny, keccak256("ABOVE_CEILING"), none);
        }
        return (Verdict.Allow, keccak256("OK"), none);
    }

    function template() external view returns (bytes32, uint32) {
        return (_templateId, _version);
    }

    function spec() external view returns (bytes32, string memory) {
        return (_specHash, "bafySpec");
    }
}

/// A `TenantHierarchy` stand-in returning a fixed node.
///
/// The real contract is 300 lines of tree management this factory does not
/// touch; what GF-4 needs is `admins` and `classification_max`, and this returns
/// exactly those with the same revert-on-unknown behaviour. Confined to the test
/// file, never wired as a default anywhere.
contract TenantsStub is ITenantHierarchy {
    mapping(bytes32 => TenantNode) private _nodes;

    error NodeDoesNotExist(bytes32 tenant_id);

    function setNode(bytes32 id, address[] memory admins, uint8 threshold, uint8 classMax) external {
        TenantNode storage n = _nodes[id];
        n.self = id;
        n.admins = admins;
        n.admin_threshold = threshold;
        n.classification_max = classMax;
        n.exists = true;
    }

    function getNode(bytes32 tenant_id) external view returns (TenantNode memory) {
        if (!_nodes[tenant_id].exists) revert NodeDoesNotExist(tenant_id);
        return _nodes[tenant_id];
    }
}

/// @title GovernanceProtocolFactory — GF-1..5 (QRM-S6.2)
contract GovernanceProtocolFactoryTest is Test {
    GovernanceTemplateRegistry reg;
    GovernanceProtocolFactory factory;
    TenantsStub tenants;

    address constant GOV = address(0x60F);
    address constant ADMIN = address(0xAD3);
    address constant STRANGER = address(0xBEEF);

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant SPEC_HASH = keccak256("the plain-English spec");
    string constant SPEC_CID = "bafyGovernanceSpecV1";
    bytes32 constant CORRELATION = keccak256("X-7104");

    bytes32 templateId;
    bytes creationCode;
    bytes params;

    function setUp() public {
        reg = new GovernanceTemplateRegistry(GOV);
        tenants = new TenantsStub();
        factory = new GovernanceProtocolFactory(reg, tenants);

        address[] memory admins = new address[](1);
        admins[0] = ADMIN;
        // CUI ceiling (2), matching the seeded Citrate root on 40204.
        tenants.setNode(TENANT, admins, 1, 2);

        creationCode = type(TestProtocol).creationCode;
        templateId = reg.templateId("TestProtocol", 1);
        params = abi.encode(templateId, uint32(1), SPEC_HASH, uint8(2));

        vm.prank(GOV);
        reg.register("TestProtocol", 1, keccak256(creationCode), keccak256("schema"), "bafyAudit");
    }

    function _deploy(bytes32 salt) internal returns (address) {
        vm.prank(ADMIN);
        return factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 2, salt, CORRELATION
        );
    }

    // ── GF-1 deterministic ──────────────────────────────────────────

    /// The address is computable BEFORE the deploy. This is what lets the
    /// SignatureCeremony show the human the exact address they are authorising
    /// rather than "a protocol will be created somewhere".
    function test_GF1_addressIsPredictableBeforeDeploying() public {
        bytes32 salt = keccak256("v1");
        address predicted = factory.predict(creationCode, params, salt);
        address actual = _deploy(salt);
        assertEq(actual, predicted, "the ceremony would have shown the wrong address");
        assertTrue(actual.code.length > 0, "and something is actually there");
    }

    /// Different params are a different protocol and must not collide. If params
    /// were left out of the init-code hash, two deployments from one template at
    /// one salt would fight over an address.
    function test_GF1_paramsChangeTheAddress() public view {
        bytes32 salt = keccak256("v1");
        bytes memory other = abi.encode(templateId, uint32(1), SPEC_HASH, uint8(1));
        assertTrue(
            factory.predict(creationCode, params, salt) != factory.predict(creationCode, other, salt),
            "params must be bound into the address"
        );
    }

    // ── GF-2 template-bounded (the audit boundary) ──────────────────

    /// Creation code that does not hash to the registered template is refused.
    /// **This is the whole audit story**: without it, "deployed from audited
    /// bytecode" is a claim about paperwork, not about the bytes that run.
    function test_GF2_creationCodeMustHashToTheRegisteredTemplate() public {
        bytes memory tampered = abi.encodePacked(creationCode, hex"00");
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(
                GovernanceProtocolFactory.CreationCodeMismatch.selector,
                templateId,
                keccak256(tampered),
                keccak256(creationCode)
            )
        );
        factory.deployProtocol(
            TENANT, templateId, tampered, params, SPEC_HASH, SPEC_CID, 2, keccak256("x"), CORRELATION
        );
    }

    /// A deprecated template stops new deploys — and says so distinctly from a
    /// code mismatch, because they need different fixes.
    function test_GF2_deprecatedTemplateCannotBeDeployed() public {
        vm.prank(GOV);
        reg.deprecate(templateId);
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(GovernanceProtocolFactory.UnknownOrInactiveTemplate.selector, templateId)
        );
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 2, keccak256("x"), CORRELATION
        );
    }

    function test_GF2_unknownTemplateIsRefused() public {
        bytes32 ghost = reg.templateId("NeverAudited", 1);
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(GovernanceProtocolFactory.UnknownOrInactiveTemplate.selector, ghost)
        );
        factory.deployProtocol(
            TENANT, ghost, creationCode, params, SPEC_HASH, SPEC_CID, 2, keccak256("x"), CORRELATION
        );
    }

    // ── GF-3 spec-bound ─────────────────────────────────────────────

    /// A protocol nobody can explain must not exist. Both halves are required.
    function test_GF3_cannotDeployWithoutASpec() public {
        vm.startPrank(ADMIN);
        vm.expectRevert(GovernanceProtocolFactory.EmptySpecHash.selector);
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, bytes32(0), SPEC_CID, 2, keccak256("a"), CORRELATION
        );
        vm.expectRevert(GovernanceProtocolFactory.EmptySpecCID.selector);
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, "", 2, keccak256("b"), CORRELATION
        );
        vm.stopPrank();
    }

    /// The spec is readable from the deployment record afterwards — "what we
    /// said this does" next to "what it does".
    function test_GF3_specIsRecordedAndReadableAfterwards() public {
        address p = _deploy(keccak256("v1"));
        GovernanceProtocolFactory.Deployment memory d = factory.deploymentOf(p);
        assertEq(d.specHash, SPEC_HASH);
        assertEq(d.specCID, SPEC_CID);
        assertEq(d.templateId, templateId);
        assertEq(d.deployer, ADMIN);
    }

    // ── GF-4 tenant-gated ───────────────────────────────────────────

    /// A stranger cannot deploy a protocol that governs someone else's agents.
    function test_GF4_onlyATenantAdminMayDeploy() public {
        vm.prank(STRANGER);
        vm.expectRevert(
            abi.encodeWithSelector(GovernanceProtocolFactory.NotTenantAdmin.selector, TENANT, STRANGER)
        );
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 2, keccak256("x"), CORRELATION
        );
    }

    /// A protocol cannot operate above what its tenant is cleared for — the same
    /// monotonicity `TenantHierarchy` enforces down the tree, applied to what
    /// governs the tenant's agents.
    function test_GF4_ceilingCannotExceedTheTenantMax() public {
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(GovernanceProtocolFactory.CeilingExceedsTenant.selector, uint8(3), uint8(2))
        );
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 3, keccak256("x"), CORRELATION
        );
    }

    /// Deploying into a tenant that does not exist fails closed at the tree.
    function test_GF4_unknownTenantIsRefused() public {
        vm.prank(ADMIN);
        vm.expectRevert();
        factory.deployProtocol(
            keccak256("NoSuchTenant"),
            templateId,
            creationCode,
            params,
            SPEC_HASH,
            SPEC_CID,
            2,
            keccak256("x"),
            CORRELATION
        );
    }

    // ── GF-5 single-owner-per-salt ──────────────────────────────────

    /// The same salt cannot be reused. Version bumps change the salt; the
    /// registry keeps the lineage.
    function test_GF5_redeployAtTheSameSaltIsRefused() public {
        bytes32 salt = keccak256("v1");
        address first = _deploy(salt);
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(GovernanceProtocolFactory.AlreadyDeployedAtSalt.selector, first)
        );
        factory.deployProtocol(
            TENANT, templateId, creationCode, params, SPEC_HASH, SPEC_CID, 2, salt, CORRELATION
        );
    }

    function test_GF5_aDifferentSaltIsADifferentProtocol() public {
        address a = _deploy(keccak256("v1"));
        address b = _deploy(keccak256("v2"));
        assertTrue(a != b);
        assertEq(factory.protocolCount(TENANT), 2);
        assertEq(factory.protocolAt(TENANT, 0), a);
        assertEq(factory.protocolAt(TENANT, 1), b);
    }

    // ── What was deployed is a real, working protocol ────────────────

    /// End to end: the factory's output actually answers `check`, and answers it
    /// with the parameters it was constructed with. A factory that deployed
    /// something inert would pass every test above.
    function test_theDeployedProtocolAnswersCheckWithItsParameters() public {
        address p = _deploy(keccak256("v1"));
        IGovernanceProtocol proto = IGovernanceProtocol(p);

        (bytes32 tid, uint32 ver) = proto.template();
        assertEq(tid, templateId, "the protocol knows which template it came from");
        assertEq(ver, 1);

        IGovernanceProtocol.ActionContext memory ctx = IGovernanceProtocol.ActionContext({
            agentSbtId: 41,
            principal: ADMIN,
            classification: 1, // Proprietary — under the ceiling
            cost: 0,
            paramsHash: keccak256("args"),
            correlationId: CORRELATION
        });
        (IGovernanceProtocol.Verdict v,,) = proto.check(TENANT, keccak256("repo.write"), ctx);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));

        ctx.classification = 3; // ITAR — above the ceiling it was built with
        (IGovernanceProtocol.Verdict denied, bytes32 reason,) =
            proto.check(TENANT, keccak256("repo.write"), ctx);
        assertEq(uint8(denied), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, keccak256("ABOVE_CEILING"), "a verdict always carries a reason");
    }

    /// The schema hash is COPIED at deploy time, not referenced. A template row
    /// registered later must not be able to change what an existing deployment
    /// was supposed to have been checked against.
    function test_paramSchemaHashIsSnapshottedNotReferenced() public {
        address p = _deploy(keccak256("v1"));
        assertEq(factory.deploymentOf(p).paramSchemaHash, keccak256("schema"));

        // A v2 with a different schema does not touch v1's record.
        vm.prank(GOV);
        reg.register("TestProtocol", 2, keccak256("v2 code"), keccak256("OTHER schema"), "bafyAudit2");
        assertEq(factory.deploymentOf(p).paramSchemaHash, keccak256("schema"));
    }

    /// An address this factory never deployed is not "ours with empty fields".
    function test_unknownProtocolIsNotReportedAsOurs() public {
        assertFalse(factory.wasDeployedHere(address(0xDEAD)));
        vm.expectRevert(GovernanceProtocolFactory.DeploymentFailed.selector);
        factory.deploymentOf(address(0xDEAD));
    }
}
