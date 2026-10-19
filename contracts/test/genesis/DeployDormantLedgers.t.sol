// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {DeployDormantLedgers} from "../../script/DeployDormantLedgers.s.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {FederatedRoundLedger} from "../../src/FederatedRoundLedger.sol";
import {PatronageLedger} from "../../src/coop/PatronageLedger.sol";
import {MembershipSBT} from "../../src/coop/MembershipSBT.sol";
import {Auth} from "../../src/coop/lib/Auth.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";

/// @title DeployDormantLedgers.t: FederatedRoundLedger + PatronageLedger at genesis (C2 D9 / C4)
contract DeployDormantLedgersTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    DeployGenesisGovernance.Deployed internal gov;
    address[] internal govOwners;
    KYCRegistry internal kyc;
    MembershipSBT internal membership;

    function setUp() public {
        govOwners = new address[](5);
        address[] memory grdOwners = new address[](3);
        for (uint256 i = 0; i < 5; i++) {
            govOwners[i] = address(uint160(0xA000 + i));
        }
        for (uint256 i = 0; i < 3; i++) {
            grdOwners[i] = address(uint160(0xB000 + i));
        }
        DeployGenesisGovernance g = new DeployGenesisGovernance();
        gov = g.deployWith(
            SENDER,
            DeployGenesisGovernance.Council({owners: govOwners, threshold: 3, minDelay: 48 hours}),
            DeployGenesisGovernance.Council({owners: grdOwners, threshold: 2, minDelay: 1 hours}),
            false
        );
        kyc = new KYCRegistry(address(0), makeAddr("kyc-admin"));
        membership = new MembershipSBT(address(kyc), new bytes32[](0), makeAddr("sbt-admin"), makeAddr("sbt-registrar"));
    }

    function _deploy() internal returns (DeployDormantLedgers.Deployed memory d) {
        DeployDormantLedgers s = new DeployDormantLedgers();
        d = s.deployWith(SENDER, gov.governanceTimelock, address(kyc), address(membership));
    }

    function test_patronage_ledger_is_governed_by_the_timelock_and_dormant() public {
        DeployDormantLedgers.Deployed memory d = _deploy();
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        assertTrue(l.hasRole(l.DEFAULT_ADMIN_ROLE(), gov.governanceTimelock));
        assertFalse(l.hasRole(l.DEFAULT_ADMIN_ROLE(), SENDER), "deployer never holds admin");
        assertFalse(l.hasRole(l.DEFAULT_ADMIN_ROLE(), 0x4e59b44847b379578588920cA78FbF26c0B4956C));
        bytes32[3] memory ops = [l.SETTLER_ROLE(), l.COOP_ROLE(), l.YEAR_KEEPER_ROLE()];
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(l.hasRole(ops[i], SENDER));
            assertFalse(l.hasRole(ops[i], gov.governanceTimelock));
        }
        assertEq(address(l.kyc()), address(kyc));
        assertEq(address(l.membership()), address(membership));
        assertEq(l.totalUnits(), 0);
        assertEq(l.currentYear(), 0);
        assertTrue(l.contributionsOpen());
    }

    function test_dormant_patronage_ledger_refuses_every_operator_call() public {
        DeployDormantLedgers.Deployed memory d = _deploy();
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        (bytes32 settler, bytes32 coop, bytes32 keeper, bytes32 admin) =
            (l.SETTLER_ROLE(), l.COOP_ROLE(), l.YEAR_KEEPER_ROLE(), l.DEFAULT_ADMIN_ROLE());
        vm.startPrank(SENDER);
        vm.expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, settler, SENDER));
        l.commitRound(keccak256("r"), keccak256("h"));
        vm.expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, coop, SENDER));
        l.creditRevenue(1);
        vm.expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, keeper, SENDER));
        l.advanceYear();
        vm.expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, admin, SENDER));
        l.grantRole(settler, SENDER);
        vm.stopPrank();
    }

    /// Waking the ledger is a GOVERNANCE operation: 3-of-5 schedule, 48 h, 3-of-5 execute.
    function test_governance_wakes_the_ledger_through_the_timelock() public {
        DeployDormantLedgers.Deployed memory d = _deploy();
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        TimelockController tl = TimelockController(payable(gov.governanceTimelock));
        MultisigProposer ms = MultisigProposer(gov.governanceMultisig);
        address settler = makeAddr("settler");
        bytes memory payload = abi.encodeCall(l.grantRole, (l.SETTLER_ROLE(), settler));

        _pass(ms, abi.encodeCall(tl.schedule, (address(l), 0, payload, bytes32(0), 0, 48 hours)));
        vm.warp(block.timestamp + 48 hours);
        _pass(ms, abi.encodeCall(tl.execute, (address(l), 0, payload, bytes32(0), 0)));
        assertTrue(l.hasRole(l.SETTLER_ROLE(), settler));

        vm.prank(settler);
        l.commitRound(keccak256("round-0"), keccak256("merged"));
        assertEq(l.roundMergedHash(keccak256("round-0")), keccak256("merged"));
    }

    function _pass(MultisigProposer ms, bytes memory data) internal {
        vm.prank(govOwners[0]);
        bytes32 id = ms.propose(data);
        vm.prank(govOwners[1]);
        ms.approve(id);
        vm.prank(govOwners[2]);
        ms.approve(id);
        vm.prank(govOwners[0]);
        ms.execute(id);
    }

    function test_federated_round_ledger_is_create2_keep_live_and_empty() public {
        DeployDormantLedgers.Deployed memory d1 = _deploy();
        DeployDormantLedgers.Deployed memory d2 = _deploy();
        assertEq(d1.federatedRoundLedger, d2.federatedRoundLedger, "keep-live reuse");
        assertTrue(d1.patronageLedger != d2.patronageLedger, "PatronageLedger is CREATE: a re-run deploys anew");
        bytes32 salt = keccak256(abi.encodePacked("citrate.v1.", "FederatedRoundLedger"));
        address expected = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(0x4e59b44847b379578588920cA78FbF26c0B4956C),
                            salt,
                            keccak256(type(FederatedRoundLedger).creationCode)
                        )
                    )
                )
            )
        );
        assertEq(d1.federatedRoundLedger, expected);
        FederatedRoundLedger f = FederatedRoundLedger(d1.federatedRoundLedger);
        bytes32 cid = f.clusterIdOf(makeAddr("coordinator"), bytes32(0));
        assertEq(f.getCluster(cid).coordinator, address(0), "no cluster registered");
        assertFalse(f.isAccepted(f.roundIdOf(cid, 0)));
    }

    function test_rejects_governance_that_is_not_a_timelock() public {
        DeployDormantLedgers s = new DeployDormantLedgers();
        vm.expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, gov.governanceMultisig, address(kyc), address(membership));
        vm.expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, makeAddr("eoa"), address(kyc), address(membership));
        vm.expectRevert(bytes("GOVERNANCE_TIMELOCK cannot be the deployer"));
        s.deployWith(SENDER, SENDER, address(kyc), address(membership));
    }

    function test_rejects_codeless_kyc_or_membership() public {
        DeployDormantLedgers s = new DeployDormantLedgers();
        vm.expectRevert(bytes("PATRONAGE_KYC_REGISTRY has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, makeAddr("nokyc"), address(membership));
        vm.expectRevert(bytes("PATRONAGE_MEMBERSHIP has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, address(kyc), makeAddr("nomember"));
    }

    /// The only test that sets GOVERNANCE_TIMELOCK / PATRONAGE_* / DORMANT_LEDGERS_OUT.
    function test_run_requires_env_then_writes_a_gated_book() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        DeployDormantLedgers s = new DeployDormantLedgers();
        vm.expectRevert();
        s.run(); // GOVERNANCE_TIMELOCK unset
        vm.setEnv("GOVERNANCE_TIMELOCK", vm.toString(gov.governanceTimelock));
        vm.setEnv("PATRONAGE_KYC_REGISTRY", vm.toString(address(kyc)));
        vm.expectRevert();
        s.run(); // PATRONAGE_MEMBERSHIP unset
        vm.setEnv("PATRONAGE_MEMBERSHIP", vm.toString(address(membership)));
        vm.expectRevert();
        s.run(); // DORMANT_LEDGERS_OUT unset

        vm.createDir("genesis", true);
        string memory out = "genesis/test-dormant-ledgers.json";
        vm.setEnv("DORMANT_LEDGERS_OUT", out);
        DeployDormantLedgers.Deployed memory d = s.run();
        string memory book = vm.readFile(out);
        assertEq(vm.parseJsonAddress(book, ".contracts.PatronageLedger"), d.patronageLedger);
        assertEq(vm.parseJsonAddress(book, ".contracts.FederatedRoundLedger"), d.federatedRoundLedger);
        assertEq(vm.parseJsonAddress(book, ".params.governance"), gov.governanceTimelock);

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        c.check(book, true);
        assertEq(c.deployerAdmin(), 0, "DEPLOYER-ADMIN reads 0 after hand-over");
        assertEq(c.factoryAdmin(), 0);
        vm.removeFile(out);
    }

    /// chain#320 P1 regression: DEPLOYER_ADDRESS names A but Forge broadcasts as B. The script
    /// must refuse before sending anything (previously B became the constructor admin, "revoked"
    /// A who never held it, and every check that only looked at A passed).
    function test_reverts_when_broadcaster_is_not_the_configured_deployer() public {
        address configured = makeAddr("configured-deployer-A");
        DeployDormantLedgers s = new DeployDormantLedgers();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(configured, gov.governanceTimelock, address(kyc), address(membership)); // broadcasts as SENDER (B)
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    // No env-driven (`run`) variant: DEPLOYER_ADDRESS is process-global and other suites set it
    // concurrently. `run` passes deployerAddress() straight to deployWith, so the check above
    // is the same code path.

    /// The admin postcondition checks the ACTUAL deploy accounts, not only the configured one:
    /// a ledger whose admin is the broadcaster / factory / anyone but governance is refused.
    function test_sole_admin_postcondition_rejects_any_deploy_account_admin() public {
        AdminChecksHarness h = new AdminChecksHarness();
        address b = makeAddr("broadcaster-B");
        address[] memory others = new address[](3);
        (others[0], others[1], others[2]) = (SENDER, b, 0x4e59b44847b379578588920cA78FbF26c0B4956C);

        PatronageLedger good = new PatronageLedger(address(kyc), address(membership), gov.governanceTimelock);
        h.soleAdminAmong(address(good), gov.governanceTimelock, others); // passes

        PatronageLedger heldByB = new PatronageLedger(address(kyc), address(membership), b);
        vm.expectRevert(bytes("PatronageLedger: intended key lacks DEFAULT_ADMIN_ROLE"));
        h.soleAdminAmong(address(heldByB), gov.governanceTimelock, others);

        // B is admin AND governance was granted too: still refused (B kept admin).
        vm.prank(b);
        heldByB.grantRole(0x00, gov.governanceTimelock);
        vm.expectRevert(bytes("PatronageLedger: a deploy account holds DEFAULT_ADMIN_ROLE"));
        h.soleAdminAmong(address(heldByB), gov.governanceTimelock, others);
    }

    /// The gate catches a deployer-administered PatronageLedger.
    function test_admin_gate_flags_a_ledger_still_held_by_the_deployer() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        address deployer = makeAddr("deployer");
        PatronageLedger held = new PatronageLedger(address(kyc), address(membership), deployer);
        string memory book = string.concat(
            '{"deployer":"',
            vm.toString(deployer),
            '","contracts":{"PatronageLedger":"',
            vm.toString(address(held)),
            '"},"aaStack":{}}'
        );
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        vm.expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)"));
        c.check(book, false);
    }

    /// Governance cannot strand the genesis ledger / SBT: an admin grant to the zero address or
    /// the CREATE2 relay reverts (so it cannot inflate the admin count), and the sole usable admin
    /// still cannot revoke itself.
    function test_sole_admin_cannot_be_stranded_via_unusable_admin_grant() public {
        address relay = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        DeployDormantLedgers.Deployed memory d = _deploy();
        Auth[2] memory surfaces = [Auth(d.patronageLedger), Auth(address(membership))];
        address[2] memory admins = [gov.governanceTimelock, makeAddr("sbt-admin")];
        bytes32 adminRole = 0x00;
        for (uint256 i = 0; i < 2; i++) {
            vm.startPrank(admins[i]);
            vm.expectRevert(Auth.ZeroRoleHolder.selector);
            surfaces[i].grantRole(adminRole, address(0));
            vm.expectRevert(Auth.Create2DeployerAsHolder.selector);
            surfaces[i].grantRole(adminRole, relay);
            vm.expectRevert(Auth.LastAdmin.selector);
            surfaces[i].revokeRole(adminRole, admins[i]);
            vm.stopPrank();
            assertTrue(surfaces[i].hasRole(adminRole, admins[i]), "sole usable admin lost");
            assertFalse(surfaces[i].hasRole(adminRole, address(0)));
            assertFalse(surfaces[i].hasRole(adminRole, relay));
        }
    }

    /// Operator roles are validated too: no role can be granted to the zero address or the relay.
    function test_operator_role_grant_to_unusable_holder_reverts() public {
        address relay = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        DeployDormantLedgers.Deployed memory d = _deploy();
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        bytes32[3] memory ops = [l.SETTLER_ROLE(), l.COOP_ROLE(), l.YEAR_KEEPER_ROLE()];
        vm.startPrank(gov.governanceTimelock);
        for (uint256 i = 0; i < 3; i++) {
            vm.expectRevert(Auth.ZeroRoleHolder.selector);
            l.grantRole(ops[i], address(0));
            vm.expectRevert(Auth.Create2DeployerAsHolder.selector);
            l.grantRole(ops[i], relay);
        }
        vm.stopPrank();
        bytes32 reg = membership.REGISTRAR_ROLE();
        vm.startPrank(makeAddr("sbt-admin"));
        vm.expectRevert(Auth.ZeroRoleHolder.selector);
        membership.grantRole(reg, address(0));
        vm.expectRevert(Auth.Create2DeployerAsHolder.selector);
        membership.grantRole(reg, relay);
        vm.stopPrank();
    }
}

contract AdminChecksHarness is AdminChecks {
    function soleAdminAmong(address target, address expected, address[] memory others) external view {
        _assertSoleAdminAmong("PatronageLedger", target, expected, others);
    }
}
