// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {DeployV060Genesis} from "../../script/DeployV060Genesis.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {V060GenesisSpec} from "../../script/lib/V060GenesisSpec.sol";
import {V060GovernanceSpec} from "../../script/lib/V060GovernanceSpec.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";
import {GuardianCancellerV2} from "../../src/genesis/GuardianCancellerV2.sol";
import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {UsageReceipts} from "../../src/amc/UsageReceipts.sol";
import {OrgBudgets, IOrganizationSBT} from "../../src/amc/OrgBudgets.sol";
import {WorkAttestations, IAgentSBT} from "../../src/amc/WorkAttestations.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {FLRoundVerifier, IFederatedRoundLedgerReads} from "../../src/work/FLRoundVerifier.sol";
import {TaskVerifier} from "../../src/work/TaskVerifier.sol";
import {DatasetRegistry} from "../../src/data/DatasetRegistry.sol";
import {GuardianRecoveryModuleV2, IGuardianRecoveryModuleV1} from "../../src/aa/recovery/GuardianRecoveryModuleV2.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {FederatedRoundLedger} from "../../src/FederatedRoundLedger.sol";
import {OrganizationSBT} from "../../src/cit_agent/OrganizationSBT.sol";
import {AgentSBT} from "../../src/cit_agent/AgentSBT.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {Salts} from "../../script/Salts.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {RoleLogArchive, RecordedRoleHistory} from "./RoleHistoryHarness.sol";
import {GovernanceWithNode, GateWithNode, BookCancellerChecks, NodeStub} from "./NodeChainIdHarness.sol";

/// The builder over the test's recorded timelock role history, with a node stand-in that reports
/// forge's chain id (forge test has no fork; see NodeChainIdHarness and RoleHistoryHarness).
contract V060WithNode is DeployV060Genesis, RecordedRoleHistory, NodeStub {
    function _timelockRoleHistory(address timelock)
        internal
        override(AdminChecks, RecordedRoleHistory)
        returns (bool, string memory, RoleEvent[] memory)
    {
        return RecordedRoleHistory._timelockRoleHistory(timelock);
    }

    function _nodeChainId() internal view override returns (bool, uint256) {
        return _stubNode();
    }
}

// Test-only coordinator bond amounts. They are NOT the genesis values: those are pending the
// tokenomics decision, and the builder refuses to run without them being given explicitly.
uint128 constant TEST_MIN_BOND = 3 ether;
uint128 constant TEST_DEFAULT_BOND = 7 ether;

/// @title V060GenesisSpec.t: the 0.6.0 ceremony genesis spec
/// @notice Builds the ceremony the way the 0.6.0 genesis does on chain 40204 (genesis profile):
///         P1 in its v2-canceller mode (ProviderRegistry + GuardianCancellerV2 hold the guardian
///         veto; v1 is never deployed), the existing block-0 inputs the 0.6.0 contracts read (the
///         FederatedRoundLedger, the V1 GuardianRecoveryModule, OrganizationSBT and AgentSBT), and
///         then DeployV060Genesis. It then asserts, independently of the scripts:
///           - every 0.6.0 genesis contract sits at CREATE2(Arachnid, "citrate.v1." ++ salt name,
///             keccak256(creationCode ++ args)) with args written out here, not taken from the
///             spec library, and its runtime code hash equals this build's reference instance;
///           - every constructor argument reads back;
///           - the role wiring: GOVERNANCE timelock everywhere governance is named, slashSink =
///             GOVERNANCE timelock, the guardian council (GUARDIAN timelock) as every block-0
///             guardian seat, CANCELLER_ROLE on GOVERNANCE held by v2 and not by v1;
///           - the builder refuses to run without the pending coordinator bonds.
contract V060GenesisSpecTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    RoleLogArchive internal archive;
    GovernanceWithNode internal govScript;
    DeployGenesisGovernance.Deployed internal gov;
    address internal registryP1;
    FederatedRoundLedger internal frl;
    GuardianRecoveryModule internal recoveryV1;
    OrganizationSBT internal orgSbt;
    AgentSBT internal agentSbt;
    CitrateMemberSBT internal memberSbt;

    function setUp() public {
        vm.recordLogs(); // the gate replays the timelocks' role history (RoleHistoryHarness)
        archive = new RoleLogArchive();
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        vm.chainId(40204);
        govScript = new GovernanceWithNode();
        DeployGenesisGovernance.Council memory gc = _council(0xA000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory rc = _council(0xB000, 3, 2, 1 hours);
        gov = govScript.deployWithV060(SENDER, gc, rc, false, false, _keys(gc, rc));
        registryP1 = govScript.providerRegistry();
        // The block-0 contracts the 0.6.0 set reads. The ledger (P4) and the V1 module (P2) are
        // deployed as their phases deploy them, by CREATE2 under their own salts, because the
        // builder checks their identity; P3L's HUP registries only need their owner and wiring.
        // Through the Arachnid factory itself, so the address does not depend on how a forge
        // version routes a salted `new` from a test contract.
        frl = FederatedRoundLedger(_viaFactory("FederatedRoundLedger", type(FederatedRoundLedger).creationCode));
        recoveryV1 =
            GuardianRecoveryModule(_viaFactory("GuardianRecoveryModule", type(GuardianRecoveryModule).creationCode));
        memberSbt = new CitrateMemberSBT(gov.governanceTimelock);
        orgSbt = new OrganizationSBT(gov.governanceTimelock);
        agentSbt = new AgentSBT(gov.governanceTimelock, orgSbt, IERC721(address(memberSbt)));
    }

    /// Deploy `init` under Salts.salt(name) through the Arachnid factory (calldata = salt ++ init).
    function _viaFactory(string memory name, bytes memory init) internal returns (address a) {
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(Salts.salt(name), init));
        require(ok && ret.length == 20, "Arachnid factory deploy failed");
        a = address(bytes20(ret));
        require(a == _at(name, init), "factory deploy is not at its CREATE2 address");
    }

    function _council(uint256 base, uint256 n, uint256 m, uint256 delay)
        internal
        pure
        returns (DeployGenesisGovernance.Council memory c)
    {
        c.owners = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            c.owners[i] = address(uint160(base + i));
        }
        c.threshold = m;
        c.minDelay = delay;
        c.proposalTtl = 14 days;
    }

    /// Test-only stand-ins for the retired r1006 keys (D-K3). The real list is the owner's input.
    function _retired() internal returns (address[] memory r) {
        r = new address[](3);
        r[0] = makeAddr("retired-r1006-treasury");
        r[1] = makeAddr("retired-r1006-deployer");
        r[2] = makeAddr("retired-r1006-grantor");
    }

    /// Test-only key parameters: the role-tagged inventory has the GOVERNANCE owners under
    /// GOV_OWNERS and the GUARDIAN owners under GRD_OWNERS (the deployer is the throwaway
    /// ceremony key, so it is not in it), the retired stand-ins, and a 1 h veto margin. The
    /// real values are the owner's.
    function _keys(DeployGenesisGovernance.Council memory gc, DeployGenesisGovernance.Council memory rc)
        internal
        returns (V060GovernanceSpec.KeyParams memory k)
    {
        k.governanceOwners = gc.owners;
        k.guardianOwners = rc.owners;
        k.retiredKeys = _retired();
        k.guardianVetoMargin = 2 hours; // owner decision 2026-11-11
    }

    function _setupKeys() internal returns (V060GovernanceSpec.KeyParams memory) {
        return _keys(_council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours));
    }

    function _builder() internal returns (DeployV060Genesis s) {
        V060WithNode h = new V060WithNode();
        h.useArchive(archive);
        archive.absorb();
        s = h;
    }

    /// `vm.expectRevert`, after moving the recorded logs into the archive from THIS frame (a
    /// reverted call would roll back an absorb made inside it).
    function _expectRevert(bytes memory reason) internal {
        archive.absorb();
        vm.expectRevert(reason);
    }

    function _inputs() internal returns (DeployV060Genesis.Inputs memory i) {
        i.governanceTimelock = gov.governanceTimelock;
        i.governanceMultisig = gov.governanceMultisig;
        i.guardianTimelock = gov.guardianTimelock;
        i.guardianMultisig = gov.guardianMultisig;
        i.keys = _setupKeys();
        i.guardianCanceller = gov.guardianCanceller;
        i.federatedRoundLedger = address(frl);
        i.guardianRecoveryModule = address(recoveryV1);
        i.organizationSbt = address(orgSbt);
        i.agentSbt = address(agentSbt);
        i.minCoordinatorBond = TEST_MIN_BOND;
        i.defaultCoordinatorBond = TEST_DEFAULT_BOND;
    }

    function _build() internal returns (DeployV060Genesis s, DeployV060Genesis.Deployed memory d) {
        s = _builder();
        d = s.deployWith(SENDER, _inputs());
    }

    /// The CREATE2 address, from first principles (Salts: keccak256("citrate.v1." ++ name)).
    function _at(string memory name, bytes memory init) internal pure returns (address) {
        bytes32 salt = keccak256(abi.encodePacked("citrate.v1.", name));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), FACTORY, salt, keccak256(init))))));
    }

    function _verifiers(address a, address b) internal pure returns (address[] memory v) {
        v = new address[](2);
        (v[0], v[1]) = (a, b);
    }

    function _assertAt(string memory label, address got, address want, bytes32 refCodehash) internal view {
        assertEq(got, want, string.concat(label, ": not at its CREATE2 address"));
        assertGt(got.code.length, 0, string.concat(label, ": no code"));
        assertEq(got.codehash, refCodehash, string.concat(label, ": runtime code is not this build's"));
    }

    // ------------------------------------------------------------------ code hash at CREATE2

    function test_every_genesis_contract_has_this_builds_code_at_its_create2_address() public {
        (, DeployV060Genesis.Deployed memory d) = _build();
        address gt = gov.governanceTimelock;
        address rt = gov.guardianTimelock;

        address reg = _at(
            "Genesis.ProviderRegistry",
            abi.encodePacked(type(ProviderRegistry).creationCode, abi.encode(gt, rt, uint64(24 hours)))
        );
        _assertAt("ProviderRegistry", d.providerRegistry, reg, address(new ProviderRegistry(gt, rt, 24 hours)).codehash);
        assertEq(registryP1, reg, "P1 deployed the registry the canceller commits to");

        _assertAt(
            "GuardianCancellerV2",
            d.guardianCancellerV2,
            _at(
                "Genesis.GuardianCancellerV2",
                abi.encodePacked(type(GuardianCancellerV2).creationCode, abi.encode(gt, rt, reg))
            ),
            address(new GuardianCancellerV2(gt, rt, reg)).codehash
        );
        assertEq(gov.guardianCanceller, d.guardianCancellerV2, "P1's canceller seat is v2");

        address flv =
            _at("Genesis.FLRoundVerifier", abi.encodePacked(type(FLRoundVerifier).creationCode, abi.encode(address(frl))));
        _assertAt(
            "FLRoundVerifier",
            d.flRoundVerifier,
            flv,
            address(new FLRoundVerifier(IFederatedRoundLedgerReads(address(frl)))).codehash
        );

        address tv = _at("Genesis.TaskVerifier", abi.encodePacked(type(TaskVerifier).creationCode, abi.encode(uint64(72 hours))));
        _assertAt("TaskVerifier", d.taskVerifier, tv, address(new TaskVerifier(72 hours)).codehash);

        _assertAt(
            "WorkMarket",
            d.workMarket,
            _at(
                "Genesis.WorkMarket",
                abi.encodePacked(
                    type(WorkMarket).creationCode,
                    abi.encode(gt, rt, gt, TEST_DEFAULT_BOND, TEST_MIN_BOND, _verifiers(flv, tv))
                )
            ),
            address(new WorkMarket(gt, rt, gt, TEST_DEFAULT_BOND, TEST_MIN_BOND, _verifiers(flv, tv))).codehash
        );

        _assertAt(
            "DatasetRegistry",
            d.datasetRegistry,
            _at("Genesis.DatasetRegistry", abi.encodePacked(type(DatasetRegistry).creationCode, abi.encode(gt))),
            address(new DatasetRegistry(gt)).codehash
        );

        _assertAt(
            "GuardianRecoveryModuleV2",
            d.guardianRecoveryModuleV2,
            _at(
                "Genesis.GuardianRecoveryModuleV2",
                abi.encodePacked(type(GuardianRecoveryModuleV2).creationCode, abi.encode(address(recoveryV1)))
            ),
            address(new GuardianRecoveryModuleV2(IGuardianRecoveryModuleV1(address(recoveryV1)))).codehash
        );

        _assertAt(
            "UsageReceipts",
            d.usageReceipts,
            _at("Genesis.UsageReceipts", abi.encodePacked(type(UsageReceipts).creationCode, abi.encode(uint32(90)))),
            address(new UsageReceipts(90)).codehash
        );

        _assertAt(
            "OrgBudgets",
            d.orgBudgets,
            _at("Genesis.OrgBudgets", abi.encodePacked(type(OrgBudgets).creationCode, abi.encode(gt, address(orgSbt)))),
            address(new OrgBudgets(gt, IOrganizationSBT(address(orgSbt)))).codehash
        );

        _assertAt(
            "WorkAttestations",
            d.workAttestations,
            _at("Genesis.WorkAttestations", abi.encodePacked(type(WorkAttestations).creationCode, abi.encode(address(agentSbt)))),
            address(new WorkAttestations(IAgentSBT(address(agentSbt)))).codehash
        );
    }

    /// The prediction the genesis spec publishes (before any deploy) is where the build lands.
    function test_predicted_addresses_equal_the_deployed_ones() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Deployed memory p = s.predict(_inputs());
        DeployV060Genesis.Deployed memory d = s.deployWith(SENDER, _inputs());
        assertEq(abi.encode(p), abi.encode(d));
    }

    // ------------------------------------------------------------------ constructor arguments

    function test_constructor_arguments_read_back() public {
        (, DeployV060Genesis.Deployed memory d) = _build();
        address gt = gov.governanceTimelock;
        address rt = gov.guardianTimelock;

        ProviderRegistry reg = ProviderRegistry(d.providerRegistry);
        assertEq(reg.governance(), gt);
        assertEq(reg.guardian(), rt);
        assertEq(reg.vetoWindow(), 24 hours);

        GuardianCancellerV2 c = GuardianCancellerV2(d.guardianCancellerV2);
        assertEq(c.governanceTimelock(), gt);
        assertEq(c.guardian(), rt);
        assertEq(c.providerRegistry(), d.providerRegistry);

        assertEq(address(FLRoundVerifier(d.flRoundVerifier).frl()), address(frl));
        assertEq(TaskVerifier(d.taskVerifier).reviewWindow(), 72 hours);

        WorkMarket m = WorkMarket(payable(d.workMarket));
        assertEq(m.governance(), gt);
        assertEq(m.guardian(), rt);
        assertEq(m.slashSink(), gt, "slashSink is the GOVERNANCE timelock (treasury)");
        assertEq(m.minCoordinatorBond(), TEST_MIN_BOND);
        assertEq(m.defaultCoordinatorBond(), TEST_DEFAULT_BOND);
        assertTrue(m.verifierAllowed(d.flRoundVerifier));
        assertTrue(m.verifierAllowed(d.taskVerifier));

        assertEq(DatasetRegistry(d.datasetRegistry).governance(), gt);
        assertEq(address(GuardianRecoveryModuleV2(d.guardianRecoveryModuleV2).v1()), address(recoveryV1));
        assertEq(UsageReceipts(d.usageReceipts).maxBackfillDays(), 90);
        assertEq(OrgBudgets(d.orgBudgets).governance(), gt);
        assertEq(address(OrgBudgets(d.orgBudgets).orgs()), address(orgSbt));
        assertEq(address(WorkAttestations(d.workAttestations).agents()), address(agentSbt));
    }

    // ------------------------------------------------------------------ role wiring

    function test_canceller_role_is_held_by_v2_and_not_by_v1() public {
        (, DeployV060Genesis.Deployed memory d) = _build();
        TimelockController gt = TimelockController(payable(gov.governanceTimelock));
        bytes32 canceller = gt.CANCELLER_ROLE();
        assertTrue(gt.hasRole(canceller, d.guardianCancellerV2), "v2 holds CANCELLER on GOVERNANCE");
        address v1 = _at(
            "Genesis.GuardianCanceller",
            abi.encodePacked(type(GuardianCanceller).creationCode, abi.encode(gov.governanceTimelock, gov.guardianTimelock))
        );
        assertFalse(gt.hasRole(canceller, v1), "v1 holds no CANCELLER seat");
        assertEq(v1.code.length, 0, "v1 is not deployed in the 0.6.0 genesis");
        // v2 holds nothing else; the guardian council holds no GOVERNANCE seat at all.
        bytes32[3] memory denied = [gt.DEFAULT_ADMIN_ROLE(), gt.PROPOSER_ROLE(), gt.EXECUTOR_ROLE()];
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(gt.hasRole(denied[i], d.guardianCancellerV2));
        }
        bytes32[4] memory all = [gt.DEFAULT_ADMIN_ROLE(), gt.PROPOSER_ROLE(), gt.EXECUTOR_ROLE(), canceller];
        for (uint256 i = 0; i < 4; i++) {
            assertFalse(gt.hasRole(all[i], gov.guardianTimelock));
            assertFalse(gt.hasRole(all[i], gov.guardianMultisig));
            assertFalse(gt.hasRole(all[i], SENDER), "the deployer holds no GOVERNANCE role");
        }
    }

    /// Q9 (a): the guardian council is every guardian seat at block 0; the registry's seat moves
    /// to RegistryGuardian2of3 only after genesis, by governance.
    function test_guardian_council_holds_every_guardian_seat_at_block_0() public {
        (, DeployV060Genesis.Deployed memory d) = _build();
        assertEq(ProviderRegistry(d.providerRegistry).guardian(), gov.guardianTimelock);
        assertEq(GuardianCancellerV2(d.guardianCancellerV2).guardian(), gov.guardianTimelock);
        assertEq(WorkMarket(payable(d.workMarket)).guardian(), gov.guardianTimelock);
        assertLt(
            TimelockController(payable(gov.guardianTimelock)).getMinDelay(),
            ProviderRegistry(d.providerRegistry).vetoWindow(),
            "the council can veto a listing inside the registry's window"
        );
    }

    /// The governance book records the v2 seat, and the shared on-chain check accepts it.
    function test_governance_book_names_the_v2_canceller_and_it_verifies() public {
        string memory book = govScript.bookJson(SENDER, gov, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours));
        assertEq(vm.parseJsonAddress(book, ".contracts.GuardianCanceller"), gov.guardianCanceller);
        assertEq(vm.parseJsonAddress(book, ".contracts.ProviderRegistry"), registryP1);
        assertEq(vm.parseJsonUint(book, ".params.guardianCancellerVersion"), 2);
        BookCancellerChecks h = new BookCancellerChecks();
        h.useArchive(archive);
        archive.absorb();
        (string memory p, address got) = h.problem(book, gov.governanceTimelock);
        assertEq(p, "");
        assertEq(got, gov.guardianCanceller);
    }

    /// The same book without the version field is checked as v1 and fails closed (no downgrade).
    function test_a_v2_seat_in_a_book_without_the_version_fails_closed() public {
        string memory book = string.concat(
            '{"chainId":40204,"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(gov.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(gov.governanceMultisig),
            '","GuardianTimelock":"',
            vm.toString(gov.guardianTimelock),
            '","GuardianMultisig":"',
            vm.toString(gov.guardianMultisig),
            '","GuardianCanceller":"',
            vm.toString(gov.guardianCanceller),
            '"},"aaStack":{},"params":{}}'
        );
        BookCancellerChecks h = new BookCancellerChecks();
        h.useArchive(archive);
        archive.absorb();
        (string memory p,) = h.problem(book, gov.governanceTimelock);
        assertEq(p, "GuardianCanceller is not at its CREATE2 address for (GovernanceTimelock, GuardianTimelock)");
    }

    /// The deploy-admin gate (P5's CheckDeployedAdmins, genesis profile) passes over the 0.6.0
    /// book with the governance book beside it, every address with code.
    function test_the_genesis_admin_gate_passes_over_the_v060_book() public {
        (DeployV060Genesis s, DeployV060Genesis.Deployed memory d) = _build();
        string memory book = s.bookJson(SENDER, d, _inputs());
        string[] memory extras = new string[](1);
        extras[0] =
            govScript.bookJson(SENDER, gov, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours));
        GateWithNode g = new GateWithNode();
        g.useArchive(archive);
        archive.absorb();
        g.checkAll(book, extras, true);
    }

    // ------------------------------------------------------------------ refusals

    function test_builder_refuses_without_the_pending_coordinator_bonds() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.minCoordinatorBond = 0;
        i.defaultCoordinatorBond = 0;
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_COORDINATOR_BONDS));
        s.deployWith(SENDER, i);
        i = _inputs();
        i.minCoordinatorBond = 0;
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_COORDINATOR_BONDS));
        s.deployWith(SENDER, i);
        i = _inputs();
        i.defaultCoordinatorBond = TEST_MIN_BOND - 1;
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_COORDINATOR_BONDS));
        s.deployWith(SENDER, i);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// `run()` has no fallback: with the bond inputs unset it refuses before reading anything else.
    function test_run_refuses_when_the_bond_inputs_are_unset() public {
        DeployV060Genesis s = _builder();
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_COORDINATOR_BONDS));
        s.run();
    }

    /// A governance built with the v1 canceller (the r1006/r1007 shape) is not the 0.6.0 genesis.
    function test_builder_refuses_a_v1_canceller_governance() public {
        GovernanceWithNode g1 = new GovernanceWithNode();
        DeployGenesisGovernance.Deployed memory v1gov = g1.deployWith(
            SENDER, _council(0xC000, 5, 3, 49 hours), _council(0xD000, 3, 2, 2 hours), false, false
        );
        DeployV060Genesis.Inputs memory i = _inputs();
        i.governanceTimelock = v1gov.governanceTimelock;
        i.governanceMultisig = v1gov.governanceMultisig;
        i.guardianTimelock = v1gov.guardianTimelock;
        i.guardianMultisig = v1gov.guardianMultisig;
        i.guardianCanceller = v1gov.guardianCanceller;
        i.keys = _keys(_council(0xC000, 5, 3, 49 hours), _council(0xD000, 3, 2, 2 hours));
        DeployV060Genesis s = _builder();
        vm.expectRevert(bytes("ProviderRegistry: not live at its CREATE2 address for (GOVERNANCE, GUARDIAN); run P1 with GENESIS_V060=1"));
        s.deployWith(SENDER, i);
    }

    function test_builder_refuses_inputs_without_code_or_owned_elsewhere() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.federatedRoundLedger = makeAddr("no-code");
        vm.expectRevert(bytes("FederatedRoundLedger: no code"));
        s.deployWith(SENDER, i);

        i = _inputs();
        i.guardianRecoveryModule = makeAddr("no-code");
        vm.expectRevert(bytes("GuardianRecoveryModule (V1): no code"));
        s.deployWith(SENDER, i);

        i = _inputs();
        i.organizationSbt = address(new OrganizationSBT(makeAddr("someone-else")));
        vm.expectRevert(bytes("OrganizationSBT: owner is not the GOVERNANCE timelock"));
        s.deployWith(SENDER, i);

        i = _inputs();
        i.agentSbt = address(new AgentSBT(gov.governanceTimelock, new OrganizationSBT(gov.governanceTimelock), IERC721(address(memberSbt))));
        vm.expectRevert(bytes("AgentSBT: reads another OrganizationSBT"));
        s.deployWith(SENDER, i);
    }

    /// Re-running the builder on a chain where the set is live reuses every address.
    function test_rerun_reuses_every_address() public {
        (DeployV060Genesis s, DeployV060Genesis.Deployed memory d) = _build();
        DeployV060Genesis.Deployed memory again = s.deployWith(SENDER, _inputs());
        assertEq(abi.encode(again), abi.encode(d));
    }

    // ------------------------------------------------------------------ D-K3: rotated keys

    /// The wiring names only the ceremony's parameters: the council owners given to P1, and
    /// timelocks built from them. No 0.6.0 contract names the deployer or a retired key.
    function test_wiring_names_only_the_ceremony_parameters_and_no_retired_key() public {
        (, DeployV060Genesis.Deployed memory d) = _build();
        DeployGenesisGovernance.Council memory g = _council(0xA000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory r = _council(0xB000, 3, 2, 1 hours);
        assertEq(abi.encode(MultisigProposer(gov.governanceMultisig).owners()), abi.encode(g.owners));
        assertEq(abi.encode(MultisigProposer(gov.guardianMultisig).owners()), abi.encode(r.owners));
        WorkMarket m = WorkMarket(payable(d.workMarket));
        address[8] memory named = [
            m.governance(),
            m.guardian(),
            m.slashSink(),
            ProviderRegistry(d.providerRegistry).guardian(),
            ProviderRegistry(d.providerRegistry).governance(),
            DatasetRegistry(d.datasetRegistry).governance(),
            OrgBudgets(d.orgBudgets).governance(),
            GuardianCancellerV2(d.guardianCancellerV2).guardian()
        ];
        address[] memory retired = _retired();
        for (uint256 k = 0; k < named.length; k++) {
            assertTrue(named[k] == gov.governanceTimelock || named[k] == gov.guardianTimelock, "only the councils");
            assertTrue(named[k] != SENDER, "never the deployer");
            for (uint256 j = 0; j < retired.length; j++) {
                assertTrue(named[k] != retired[j], "never a retired key");
            }
        }
    }

    // P1 (0.6.0 mode) refusals, on a fresh pair of councils (other delays: other addresses).

    function _p1(V060GovernanceSpec.KeyParams memory k, DeployGenesisGovernance.Council memory gc, DeployGenesisGovernance.Council memory rc) internal {
        GovernanceWithNode g = new GovernanceWithNode();
        g.deployWithV060(SENDER, gc, rc, false, false, k);
    }

    function _gc() internal pure returns (DeployGenesisGovernance.Council memory) {
        return _council(0xC000, 5, 3, 49 hours);
    }

    function _rc() internal pure returns (DeployGenesisGovernance.Council memory) {
        return _council(0xD000, 3, 2, 2 hours);
    }

    function test_p1_v060_refuses_without_each_key_parameter() public {
        uint64 nonceBefore = vm.getNonce(SENDER);
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        k.governanceOwners = new address[](0);
        k.guardianOwners = new address[](0);
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_KEY_INVENTORY));
        this.p1(k, _gc(), _rc());
        k = _keys(_gc(), _rc());
        k.retiredKeys = new address[](0);
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_RETIRED_KEYS));
        this.p1(k, _gc(), _rc());
        k = _keys(_gc(), _rc());
        k.guardianVetoMargin = 0;
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_VETO_MARGIN));
        this.p1(k, _gc(), _rc());
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function p1(V060GovernanceSpec.KeyParams memory k, DeployGenesisGovernance.Council memory gc, DeployGenesisGovernance.Council memory rc) external {
        _p1(k, gc, rc);
    }

    /// A typo in a council owner: the inventory has the right key, the council input does not.
    function test_p1_v060_refuses_a_typod_council_owner() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        DeployGenesisGovernance.Council memory gc = _gc();
        gc.owners[1] = address(uint160(0xC011)); // 0xC001 mistyped
        vm.expectRevert(bytes("GOVERNANCE owner is not in GENESIS_KEY_INVENTORY with role GOV_OWNERS"));
        this.p1(k, gc, _rc());
    }

    /// A stale r1006 key that the retired list forgot: the allowlist still refuses it.
    function test_p1_v060_refuses_a_stale_key_absent_from_the_retired_list() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        DeployGenesisGovernance.Council memory rc = _rc();
        rc.owners[2] = makeAddr("r1006-guardian-owner-not-on-the-retired-list");
        vm.expectRevert(bytes("GUARDIAN owner is not in GENESIS_KEY_INVENTORY with role GRD_OWNERS"));
        this.p1(k, _gc(), rc);
    }

    /// An inventory that omits a council owner is refused.
    function test_p1_v060_refuses_an_inventory_omission() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        address[] memory inv = new address[](k.guardianOwners.length - 1);
        for (uint256 i = 0; i < inv.length; i++) {
            inv[i] = k.guardianOwners[i]; // drops the last guardian owner
        }
        k.guardianOwners = inv;
        vm.expectRevert(bytes("GUARDIAN owner is not in GENESIS_KEY_INVENTORY with role GRD_OWNERS"));
        this.p1(k, _gc(), _rc());
    }

    function test_p1_v060_refuses_a_retired_council_owner_or_deployer() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        address[] memory retired = new address[](1);
        k.retiredKeys = retired;
        retired[0] = _gc().owners[2];
        vm.expectRevert(
            bytes("GOVERNANCE owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        this.p1(k, _gc(), _rc());
        retired[0] = _rc().owners[0];
        vm.expectRevert(
            bytes("GUARDIAN owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        this.p1(k, _gc(), _rc());
        retired[0] = SENDER;
        vm.expectRevert(bytes("deployer is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one"));
        this.p1(k, _gc(), _rc());
    }

    /// The guardian-delay check lives in P1, with the owner's margin (decided 2026-11-11: 2 h).
    function test_p1_v060_refuses_a_guardian_delay_without_the_margin() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        DeployGenesisGovernance.Council memory rc = _rc();
        rc.minDelay = 22 hours + 1; // + 2 h margin > 24 h
        vm.expectRevert(bytes(V060GovernanceSpec.VETO_MARGIN_TOO_SMALL));
        this.p1(k, _gc(), rc);
        rc.minDelay = 22 hours; // exactly fits: accepted
        this.p1(k, _gc(), rc);
    }

    /// The margin is a decided ceremony input (owner 2026-11-11: 7200 s), not a default: an
    /// unset margin is still refused (above), and any other value is refused too.
    function test_p1_and_the_builder_refuse_a_margin_other_than_the_decided_value() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        k.guardianVetoMargin = 1 hours;
        vm.expectRevert(bytes(V060GovernanceSpec.VETO_MARGIN_NOT_DECIDED));
        this.p1(k, _gc(), _rc());
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.keys.guardianVetoMargin = 3 hours;
        vm.expectRevert(bytes(V060GovernanceSpec.VETO_MARGIN_NOT_DECIDED));
        s.deployWith(SENDER, i);
        assertEq(V060GovernanceSpec.DECIDED_GUARDIAN_VETO_MARGIN, 7200);
    }

    function test_governance_book_records_the_veto_margin() public view {
        string memory book =
            govScript.bookJson(SENDER, gov, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours));
        assertEq(vm.parseJsonUint(book, ".params.guardianVetoMargin"), 2 hours);
    }

    // Builder refusals.

    function test_builder_refuses_without_each_key_parameter() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.keys.governanceOwners = new address[](0);
        i.keys.guardianOwners = new address[](0);
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_KEY_INVENTORY));
        s.deployWith(SENDER, i);
        i = _inputs();
        i.keys.retiredKeys = new address[](0);
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_RETIRED_KEYS));
        s.deployWith(SENDER, i);
        i = _inputs();
        i.keys.guardianVetoMargin = 0;
        vm.expectRevert(bytes(V060GovernanceSpec.PENDING_VETO_MARGIN));
        s.deployWith(SENDER, i);
    }

    /// The builder reads the councils' owners on chain and holds them to the inventory.
    function test_builder_refuses_an_on_chain_owner_missing_from_the_inventory() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        address[] memory inv = new address[](i.keys.governanceOwners.length);
        for (uint256 k = 0; k < inv.length; k++) {
            inv[k] = i.keys.governanceOwners[k];
        }
        inv[1] = address(uint160(0xA011)); // 0xA001 mistyped in the inventory
        i.keys.governanceOwners = inv;
        vm.expectRevert(bytes("GOVERNANCE owner is not in GENESIS_KEY_INVENTORY with role GOV_OWNERS"));
        s.deployWith(SENDER, i);
    }

    function test_builder_refuses_a_council_owner_or_deployer_on_the_retired_list() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.keys.retiredKeys = new address[](1);
        i.keys.retiredKeys[0] = address(uint160(0xA003));
        vm.expectRevert(
            bytes("GOVERNANCE owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        s.deployWith(SENDER, i);
        i.keys.retiredKeys[0] = address(uint160(0xB001));
        vm.expectRevert(
            bytes("GUARDIAN owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        s.deployWith(SENDER, i);
        i.keys.retiredKeys[0] = SENDER;
        vm.expectRevert(bytes("deployer is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one"));
        s.deployWith(SENDER, i);
    }

    function test_builder_rechecks_the_veto_margin_on_chain() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        // The live GUARDIAN delay is 1 h; raise it past 22 h through the GUARDIAN timelock itself.
        TimelockController rt = TimelockController(payable(gov.guardianTimelock));
        vm.prank(gov.guardianTimelock);
        rt.updateDelay(22 hours + 1);
        vm.expectRevert(bytes(V060GovernanceSpec.VETO_MARGIN_TOO_SMALL));
        s.deployWith(SENDER, i);
    }

    // P2-2: the inputs are identified, not only "has code".

    function test_builder_refuses_a_ledger_or_v1_module_that_is_not_the_ceremonys() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.federatedRoundLedger = address(new FederatedRoundLedger()); // plain CREATE, same code
        vm.expectRevert(bytes("FederatedRoundLedger: not this build's ledger at its CREATE2 address"));
        s.deployWith(SENDER, i);
        i = _inputs();
        i.guardianRecoveryModule = address(new GuardianRecoveryModule());
        vm.expectRevert(bytes("GuardianRecoveryModule (V1): not this build's module at its CREATE2 address"));
        s.deployWith(SENDER, i);
    }

    /// The governance-book provenance checks apply to the timelocks the builder reads: a rogue
    /// extra proposer on GOVERNANCE (granted by the timelock itself) is refused.
    function test_builder_refuses_a_governance_timelock_with_an_extra_holder() public {
        TimelockController gt = TimelockController(payable(gov.governanceTimelock));
        bytes32 proposer = gt.PROPOSER_ROLE();
        vm.prank(gov.governanceTimelock);
        gt.grantRole(proposer, makeAddr("rogue-proposer"));
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        try s.deployWith(SENDER, i) {
            fail();
        } catch Error(string memory reason) {
            assertTrue(_startsWith(reason, "GOVERNANCE timelock: "), reason);
        }
    }

    function _startsWith(string memory s_, string memory prefix) internal pure returns (bool) {
        bytes memory a = bytes(s_);
        bytes memory b = bytes(prefix);
        if (a.length < b.length) return false;
        for (uint256 k = 0; k < b.length; k++) {
            if (a[k] != b[k]) return false;
        }
        return true;
    }

    // P2-1: the standalone on-chain verify step.

    function test_verify_rereads_the_chain_and_catches_a_change() public {
        (DeployV060Genesis s, DeployV060Genesis.Deployed memory d) = _build();
        DeployV060Genesis.Inputs memory i = _inputs();
        s.verify(i, d);
        vm.prank(gov.governanceTimelock);
        WorkMarket(payable(d.workMarket)).setVerifierAllowed(d.taskVerifier, false);
        vm.expectRevert(bytes("WorkMarket: verifier allowlist"));
        s.verify(i, d);
    }

    // P3: an unknown canceller version fails closed.

    function test_an_unknown_guardian_canceller_version_fails_closed() public {
        string memory book = govScript.bookJson(SENDER, gov, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours));
        book = vm.replace(book, '"guardianCancellerVersion":2', '"guardianCancellerVersion":3');
        BookCancellerChecks h = new BookCancellerChecks();
        h.useArchive(archive);
        archive.absorb();
        (string memory p,) = h.problem(book, gov.governanceTimelock);
        assertEq(p, "governance book names an unknown guardianCancellerVersion");
    }

    // Role-tagged inventory (round 2): a key on the inventory under another role is refused.

    /// A key tagged GOV_OWNERS only may not sit on the GUARDIAN council.
    function test_p1_v060_refuses_a_key_inventoried_under_another_role() public {
        V060GovernanceSpec.KeyParams memory k = _keys(_gc(), _rc());
        DeployGenesisGovernance.Council memory rc = _rc();
        rc.owners[0] = address(uint160(0xC0FF)); // not a GOVERNANCE owner, but tagged GOV_OWNERS:
        address[] memory gov_ = new address[](k.governanceOwners.length + 1);
        for (uint256 n = 0; n < k.governanceOwners.length; n++) {
            gov_[n] = k.governanceOwners[n];
        }
        gov_[k.governanceOwners.length] = rc.owners[0];
        k.governanceOwners = gov_;
        vm.expectRevert(bytes("GUARDIAN owner is not in GENESIS_KEY_INVENTORY with role GRD_OWNERS"));
        this.p1(k, _gc(), rc);
    }

    function test_builder_refuses_a_key_inventoried_under_another_role() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        // Swap the tags: every owner is on the inventory, each under the other council's role.
        (i.keys.governanceOwners, i.keys.guardianOwners) = (i.keys.guardianOwners, i.keys.governanceOwners);
        vm.expectRevert(bytes("GOVERNANCE owner is not in GENESIS_KEY_INVENTORY with role GOV_OWNERS"));
        s.deployWith(SENDER, i);
    }

    /// The env form: GENESIS_KEY_INVENTORY is JSON {address: [roles]}; GOV_OWNERS and GRD_OWNERS
    /// entries become the two lists, other roles are left to P0.
    function test_the_inventory_json_is_split_by_role() public {
        DeployV060Genesis s = _builder();
        string memory inv = string.concat(
            '{"', vm.toString(address(0xA0)), '":["GOV_OWNERS"],"', vm.toString(address(0xB0)),
            '":["GRD_OWNERS","TREASURY"],"', vm.toString(address(0xC0)), '":["MEMBERSHIP_GRANTOR"]}'
        );
        (address[] memory g, address[] memory r) = s.inventoryRoles(inv);
        assertEq(g.length, 1);
        assertEq(g[0], address(0xA0));
        assertEq(r.length, 1);
        assertEq(r[0], address(0xB0));
    }

    /// An exactly repeated address in the inventory JSON is an error, not a silent merge (JSON
    /// parsers keep one of the two entries).
    function test_an_exactly_repeated_inventory_address_is_refused() public {
        DeployV060Genesis s = _builder();
        string memory a = vm.toString(address(0xA0));
        string memory inv = string.concat('{"', a, '":["GOV_OWNERS"],"', a, '":["GRD_OWNERS"]}');
        vm.expectRevert(bytes(string.concat("GENESIS_KEY_INVENTORY: ", a, " appears more than once")));
        s.inventoryRoles(inv);
    }

    /// The same address in two spellings (checksummed and lower case) is refused too.
    function test_a_repeated_inventory_address_in_another_case_is_refused() public {
        DeployV060Genesis s = _builder();
        address who = 0x00000000000000000000000000000000000aBcDe;
        string memory inv = string.concat(
            '{"', vm.toString(who), '":["GOV_OWNERS"],"0x00000000000000000000000000000000000abcde":["GRD_OWNERS"]}'
        );
        vm.expectRevert(bytes(string.concat("GENESIS_KEY_INVENTORY: ", vm.toString(who), " appears more than once")));
        s.inventoryRoles(inv);
    }
}
