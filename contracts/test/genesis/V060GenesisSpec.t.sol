// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {DeployV060Genesis} from "../../script/DeployV060Genesis.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {V060GenesisSpec} from "../../script/lib/V060GenesisSpec.sol";
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
import {RoleLogArchive} from "./RoleHistoryHarness.sol";
import {GovernanceWithNode, GateWithNode, BookCancellerChecks} from "./NodeChainIdHarness.sol";

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
        gov = govScript.deployWithV060(
            SENDER, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours), false, false, _retired()
        );
        registryP1 = govScript.providerRegistry();
        // The block-0 contracts the 0.6.0 set reads (P2's AA stack, P3L's HUP registries, P4's
        // ledger). Their own provenance is checked by their phases; here they only need code.
        frl = new FederatedRoundLedger();
        recoveryV1 = new GuardianRecoveryModule();
        memberSbt = new CitrateMemberSBT(gov.governanceTimelock);
        orgSbt = new OrganizationSBT(gov.governanceTimelock);
        agentSbt = new AgentSBT(gov.governanceTimelock, orgSbt, IERC721(address(memberSbt)));
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

    function _inputs() internal returns (DeployV060Genesis.Inputs memory i) {
        i.governanceTimelock = gov.governanceTimelock;
        i.governanceMultisig = gov.governanceMultisig;
        i.guardianTimelock = gov.guardianTimelock;
        i.guardianMultisig = gov.guardianMultisig;
        i.retiredKeys = _retired();
        i.guardianCanceller = gov.guardianCanceller;
        i.federatedRoundLedger = address(frl);
        i.guardianRecoveryModule = address(recoveryV1);
        i.organizationSbt = address(orgSbt);
        i.agentSbt = address(agentSbt);
        i.minCoordinatorBond = TEST_MIN_BOND;
        i.defaultCoordinatorBond = TEST_DEFAULT_BOND;
    }

    function _build() internal returns (DeployV060Genesis s, DeployV060Genesis.Deployed memory d) {
        s = new DeployV060Genesis();
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
        DeployV060Genesis s = new DeployV060Genesis();
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
        DeployV060Genesis s = new DeployV060Genesis();
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
        DeployV060Genesis s = new DeployV060Genesis();
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
        DeployV060Genesis s = new DeployV060Genesis();
        vm.expectRevert(bytes("ProviderRegistry: not live at its CREATE2 address for (GOVERNANCE, GUARDIAN); run P1 with GENESIS_V060=1"));
        s.deployWith(SENDER, i);
    }

    function test_builder_refuses_inputs_without_code_or_owned_elsewhere() public {
        DeployV060Genesis s = new DeployV060Genesis();
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

    function test_p1_v060_refuses_without_the_retired_keys() public {
        GovernanceWithNode g = new GovernanceWithNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_RETIRED_KEYS));
        g.deployWithV060(
            SENDER, _council(0xC000, 5, 3, 49 hours), _council(0xD000, 3, 2, 2 hours), false, false, new address[](0)
        );
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_p1_v060_refuses_a_retired_council_owner_or_deployer() public {
        GovernanceWithNode g = new GovernanceWithNode();
        address[] memory retired = _retired();
        DeployGenesisGovernance.Council memory gc = _council(0xC000, 5, 3, 49 hours);
        DeployGenesisGovernance.Council memory rc = _council(0xD000, 3, 2, 2 hours);
        address[] memory withOwner = new address[](retired.length + 1);
        for (uint256 k = 0; k < retired.length; k++) {
            withOwner[k] = retired[k];
        }
        withOwner[retired.length] = gc.owners[2];
        vm.expectRevert(
            bytes("GOVERNANCE owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        g.deployWithV060(SENDER, gc, rc, false, false, withOwner);
        withOwner[retired.length] = rc.owners[0];
        vm.expectRevert(
            bytes("GUARDIAN owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        g.deployWithV060(SENDER, gc, rc, false, false, withOwner);
        withOwner[retired.length] = SENDER;
        vm.expectRevert(bytes("deployer is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one"));
        g.deployWithV060(SENDER, gc, rc, false, false, withOwner);
    }

    function test_builder_refuses_without_the_retired_keys() public {
        DeployV060Genesis s = new DeployV060Genesis();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.retiredKeys = new address[](0);
        vm.expectRevert(bytes(V060GenesisSpec.PENDING_RETIRED_KEYS));
        s.deployWith(SENDER, i);
    }

    /// The builder reads the councils' owners on chain, so a council built with a key that is
    /// on the retired list (here: a list that names one of setUp's owners) is refused.
    function test_builder_refuses_a_council_owner_or_deployer_on_the_retired_list() public {
        DeployV060Genesis s = new DeployV060Genesis();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.retiredKeys = new address[](1);
        i.retiredKeys[0] = address(uint160(0xA003));
        vm.expectRevert(
            bytes("GOVERNANCE owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        s.deployWith(SENDER, i);
        i.retiredKeys[0] = address(uint160(0xB001));
        vm.expectRevert(
            bytes("GUARDIAN owner is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
        );
        s.deployWith(SENDER, i);
        i.retiredKeys[0] = SENDER;
        vm.expectRevert(bytes("deployer is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one"));
        s.deployWith(SENDER, i);
    }
}
