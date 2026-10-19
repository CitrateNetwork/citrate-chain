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
import {Salts} from "../../script/Salts.sol";
import {
    RoleLogArchive,
    DormantWithHistory,
    GateWithHistory,
    HolderChecksWithHistory,
    HolderChecksLive
} from "./RoleHistoryHarness.sol";

/// @title DeployDormantLedgers.t: FederatedRoundLedger + PatronageLedger at genesis (C2 D9 / C4)
contract DeployDormantLedgersTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    DeployGenesisGovernance.Deployed internal gov;
    address[] internal govOwners;
    KYCRegistry internal kyc;
    MembershipSBT internal membership;
    RoleLogArchive internal archive;

    function setUp() public {
        // The timelock role history the scripts replay (no node in forge test: RoleHistoryHarness).
        vm.recordLogs();
        archive = new RoleLogArchive();
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

    /// `vm.expectRevert`, after moving the recorded logs into the archive from THIS frame: a
    /// reverted script call would roll back an absorb made inside it (RoleHistoryHarness).
    function _expectRevert(bytes memory reason) internal {
        archive.absorb();
        vm.expectRevert(reason);
    }

    function _expectRevert(bytes4 selector) internal {
        archive.absorb();
        vm.expectRevert(selector);
    }

    function _expectRevert() internal {
        archive.absorb();
        vm.expectRevert();
    }

    function _dormant() internal returns (DeployDormantLedgers s) {
        DormantWithHistory h = new DormantWithHistory();
        h.useArchive(archive);
        s = h;
    }

    function _gate() internal returns (CheckDeployedAdmins c) {
        GateWithHistory g = new GateWithHistory();
        g.useArchive(archive);
        c = g;
    }

    function _deploy() internal returns (DeployDormantLedgers.Deployed memory d) {
        DeployDormantLedgers s = _dormant();
        d = s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, address(kyc), address(membership));
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
        _expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, settler, SENDER));
        l.commitRound(keccak256("r"), keccak256("h"));
        _expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, coop, SENDER));
        l.creditRevenue(1);
        _expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, keeper, SENDER));
        l.advanceYear();
        _expectRevert(abi.encodeWithSelector(Auth.Unauthorized.selector, admin, SENDER));
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
        DeployDormantLedgers s = _dormant();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, gov.governanceMultisig, gov.governanceMultisig, address(kyc), address(membership));
        _expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, makeAddr("eoa"), gov.governanceMultisig, address(kyc), address(membership));
        _expectRevert(bytes("GOVERNANCE_TIMELOCK cannot be the deployer"));
        s.deployWith(SENDER, SENDER, gov.governanceMultisig, address(kyc), address(membership));
    }

    function test_rejects_codeless_kyc_or_membership() public {
        DeployDormantLedgers s = _dormant();
        _expectRevert(bytes("PATRONAGE_KYC_REGISTRY has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, makeAddr("nokyc"), address(membership));
        _expectRevert(bytes("PATRONAGE_MEMBERSHIP has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, address(kyc), makeAddr("nomember"));
    }

    /// The only test that sets GOVERNANCE_TIMELOCK / PATRONAGE_* / DORMANT_LEDGERS_OUT.
    function test_run_requires_env_then_writes_a_gated_book() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        DeployDormantLedgers s = _dormant();
        _expectRevert();
        s.run(); // GOVERNANCE_TIMELOCK unset
        vm.setEnv("GOVERNANCE_TIMELOCK", vm.toString(gov.governanceTimelock));
        _expectRevert();
        s.run(); // GOVERNANCE_MULTISIG unset
        vm.setEnv("GOVERNANCE_MULTISIG", vm.toString(gov.governanceMultisig));
        vm.setEnv("PATRONAGE_KYC_REGISTRY", vm.toString(address(kyc)));
        _expectRevert();
        s.run(); // PATRONAGE_MEMBERSHIP unset
        vm.setEnv("PATRONAGE_MEMBERSHIP", vm.toString(address(membership)));
        _expectRevert();
        s.run(); // DORMANT_LEDGERS_OUT unset

        vm.createDir("genesis", true);
        string memory out = "genesis/test-dormant-ledgers.json";
        vm.setEnv("DORMANT_LEDGERS_OUT", out);
        DeployDormantLedgers.Deployed memory d = s.run();
        string memory book = vm.readFile(out);
        assertEq(vm.parseJsonAddress(book, ".contracts.PatronageLedger"), d.patronageLedger);
        assertEq(vm.parseJsonAddress(book, ".contracts.FederatedRoundLedger"), d.federatedRoundLedger);
        assertEq(vm.parseJsonAddress(book, ".params.governance"), gov.governanceTimelock);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceTimelock"), gov.governanceTimelock);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceMultisig"), gov.governanceMultisig);

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = _gate();
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
        DeployDormantLedgers s = _dormant();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(configured, gov.governanceTimelock, gov.governanceMultisig, address(kyc), address(membership)); // broadcasts as SENDER (B)
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    // No env-driven (`run`) variant: DEPLOYER_ADDRESS is process-global and other suites set it
    // concurrently. `run` passes deployerAddress() straight to deployWith, so the check above
    // is the same code path.

    // ---- governance pre-checks: the timelock the ledger is handed to must really be governance ----

    /// Codex P2 regression: a zero-delay OZ timelock whose admin / proposer / executor is the
    /// deployer answers getMinDelay() like a real one. It must be refused before anything is sent.
    function test_rejects_deployer_controlled_zero_delay_timelock() public {
        address[] memory me = new address[](1);
        me[0] = SENDER;
        TimelockController weak = new TimelockController(0, me, me, SENDER);
        MultisigProposer ms = _ceremonyMultisig(GOV_SALT, address(weak), govOwners, 3);
        DeployDormantLedgers s = _dormant();

        // As-is: the multisig holds no seat and the deployer administers the timelock.
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: deployer EOA holds DEFAULT_ADMIN_ROLE"));
        s.deployWith(SENDER, address(weak), address(ms), address(kyc), address(membership));

        // The multisig is wired in too, but the deployer keeps its seats: still refused.
        _grantCouncil(weak, address(ms));
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: deployer EOA holds DEFAULT_ADMIN_ROLE"));
        s.deployWith(SENDER, address(weak), address(ms), address(kyc), address(membership));

        // Admin renounced, deployer still proposer / executor: refused.
        vm.startPrank(SENDER);
        weak.renounceRole(weak.DEFAULT_ADMIN_ROLE(), SENDER);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: deployer EOA holds timelock PROPOSER_ROLE"));
        s.deployWith(SENDER, address(weak), address(ms), address(kyc), address(membership));
        weak.renounceRole(weak.PROPOSER_ROLE(), SENDER);
        weak.renounceRole(weak.CANCELLER_ROLE(), SENDER);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: deployer EOA holds timelock EXECUTOR_ROLE"));
        s.deployWith(SENDER, address(weak), address(ms), address(kyc), address(membership));
        weak.renounceRole(weak.EXECUTOR_ROLE(), SENDER);
        vm.stopPrank();
        uint64 nonceBefore = vm.getNonce(SENDER);

        // Fully handed over to the multisig, but the delay is zero: refused on the delay floor.
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: minDelay below the 1 h rehearsal floor"));
        s.deployWith(SENDER, address(weak), address(ms), address(kyc), address(membership));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_rejects_council_that_is_not_the_timelocks_multisig() public {
        DeployDormantLedgers s = _dormant();
        // A multisig with no seat on the timelock.
        MultisigProposer stranger = new MultisigProposer(gov.governanceTimelock, govOwners, 3);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: multisig lacks a timelock role"));
        s.deployWith(SENDER, gov.governanceTimelock, address(stranger), address(kyc), address(membership));
        _expectRevert(bytes("GOVERNANCE_MULTISIG has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, makeAddr("nomultisig"), address(kyc), address(membership));
    }

    /// Execution open to everyone (executor = address(0)) is not governance either.
    function test_rejects_timelock_with_open_execution() public {
        address[] memory none = new address[](0);
        TimelockController tl = new TimelockController(48 hours, none, none, SENDER);
        MultisigProposer ms = new MultisigProposer(address(tl), govOwners, 3);
        _grantCouncil(tl, address(ms));
        vm.startPrank(SENDER);
        tl.grantRole(tl.EXECUTOR_ROLE(), address(0));
        tl.renounceRole(tl.DEFAULT_ADMIN_ROLE(), SENDER);
        vm.stopPrank();
        DeployDormantLedgers s = _dormant();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: timelock execution is open to anyone"));
        s.deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
    }

    /// A correctly handed-over rehearsal council (2-of-3, 1 h) passes off the genesis chain and
    /// the genesis profile refuses it. The floor is chosen by chain id alone (no env override).
    function test_genesis_profile_floor_is_48h_and_3_of_5() public {
        DeployGenesisGovernance.Deployed memory weakDelay = _council(3, 5, 24 hours);
        // 72 h: the timelock's CREATE2 address depends on (deployer, delay), and setUp owns 48 h.
        DeployGenesisGovernance.Deployed memory weakCouncil = _council(2, 3, 72 hours);
        DeployDormantLedgers s = _dormant();
        s.deployWith(
            SENDER, weakDelay.governanceTimelock, weakDelay.governanceMultisig, address(kyc), address(membership)
        );
        s.deployWith(
            SENDER, weakCouncil.governanceTimelock, weakCouncil.governanceMultisig, address(kyc), address(membership)
        );

        vm.chainId(40204);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: minDelay below the 48 h genesis floor"));
        s.deployWith(
            SENDER, weakDelay.governanceTimelock, weakDelay.governanceMultisig, address(kyc), address(membership)
        );
        _expectRevert(bytes("GOVERNANCE_MULTISIG: below the 3-of-5 genesis floor"));
        s.deployWith(
            SENDER, weakCouncil.governanceTimelock, weakCouncil.governanceMultisig, address(kyc), address(membership)
        );
    }

    /// The correct genesis council (3-of-5, 48 h, self-administered, no deploy-account seat)
    /// passes on the genesis profile, and the ledger is handed to it.
    function test_correct_genesis_council_passes_on_genesis_profile() public {
        vm.chainId(40204);
        DeployDormantLedgers.Deployed memory d = _deploy();
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        assertTrue(l.hasRole(l.DEFAULT_ADMIN_ROLE(), gov.governanceTimelock));
    }

    /// The governance timelock / multisig are in the book, so the gate sees a deployer seat there.
    function test_admin_gate_flags_a_deployer_seat_on_the_governance_timelock() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        address[] memory me = new address[](1);
        me[0] = SENDER;
        TimelockController weak = new TimelockController(0, me, me, address(0));
        DeployDormantLedgers.Deployed memory d = _deploy();
        DeployDormantLedgers s = _dormant();
        string memory book = s.bookJson(SENDER, address(weak), gov.governanceMultisig, d);
        CheckDeployedAdmins c = _gate();
        _expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)"));
        c.check(book, false);
    }

    // ---- chain#320 P1: complete holder sets, not only the named accounts ----

    /// A genuine OZ timelock, 48 h, handed to a 3-of-5 MultisigProposer by SENDER, with SENDER's
    /// admin renounced: what an operator might pass as GOVERNANCE_TIMELOCK. The caller adds
    /// whatever extra seats it wants before `_finish`.
    function _handedTimelock() internal returns (TimelockController tl, MultisigProposer ms) {
        tl = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        ms = _ceremonyMultisig(GOV_SALT, address(tl), govOwners, 3);
        _grantCouncil(tl, address(ms));
    }

    string internal constant GOV_SALT = "Genesis.GovernanceMultisig";
    string internal constant GRD_SALT = "Genesis.GuardianMultisig";
    address internal constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// A MultisigProposer deployed the way DeployGenesisGovernance deploys one: through the
    /// Arachnid factory under `Salts.salt(saltName)`, so it carries the ceremony's CREATE2 provenance.
    function _ceremonyMultisig(string memory saltName, address tl, address[] memory owners, uint256 threshold)
        internal
        returns (MultisigProposer)
    {
        bytes memory init = abi.encodePacked(type(MultisigProposer).creationCode, abi.encode(tl, owners, threshold));
        (bool ok, bytes memory ret) = ARACHNID.call(abi.encodePacked(Salts.salt(saltName), init));
        require(ok && ret.length == 20, "factory deploy failed");
        return MultisigProposer(address(bytes20(ret)));
    }

    function _finish(TimelockController tl) internal {
        bytes32 adminRole = tl.DEFAULT_ADMIN_ROLE();
        vm.prank(SENDER);
        tl.renounceRole(adminRole, SENDER);
    }

    function _grantAs(TimelockController tl, bytes32 role, address who) internal {
        vm.prank(SENDER);
        tl.grantRole(role, who);
    }

    /// The Codex finding verbatim: 48 h, 3-of-5, plus an unrelated EOA holding DEFAULT_ADMIN_ROLE.
    /// No deploy account holds anything, so the named-account checks pass; the complete set does not.
    function test_rejects_unrelated_admin_on_an_otherwise_correct_timelock() public {
        vm.chainId(40204);
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        _grantAs(tl, tl.DEFAULT_ADMIN_ROLE(), makeAddr("eve"));
        _finish(tl);
        DeployDormantLedgers s = _dormant();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: DEFAULT_ADMIN_ROLE holders are not exactly the timelock itself"));
        s.deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_rejects_extra_proposer_executor_or_canceller() public {
        vm.chainId(40204);
        bytes32[3] memory roles = [keccak256("PROPOSER_ROLE"), keccak256("EXECUTOR_ROLE"), keccak256("CANCELLER_ROLE")];
        string[3] memory reasons = [
            "GOVERNANCE_TIMELOCK: PROPOSER_ROLE holders are not exactly the multisig",
            "GOVERNANCE_TIMELOCK: EXECUTOR_ROLE holders are not exactly the multisig",
            "GOVERNANCE_TIMELOCK: CANCELLER_ROLE is held by an account other than the multisig"
        ];
        DeployDormantLedgers s = _dormant();
        for (uint256 i = 0; i < 3; i++) {
            (TimelockController tl, MultisigProposer ms) = _handedTimelock();
            _grantAs(tl, roles[i], makeAddr("operator"));
            _finish(tl);
            _expectRevert(bytes(reasons[i]));
            s.deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
        }
    }

    /// A holder that was granted and later revoked (or renounced) holds nothing: accepted.
    function test_granted_then_revoked_holders_are_accepted() public {
        vm.chainId(40204);
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        address eve = makeAddr("eve");
        _grantAs(tl, tl.DEFAULT_ADMIN_ROLE(), eve);
        _grantAs(tl, tl.PROPOSER_ROLE(), eve);
        _grantAs(tl, tl.CANCELLER_ROLE(), makeAddr("temp-canceller"));
        (bytes32 proposer, bytes32 canceller) = (tl.PROPOSER_ROLE(), tl.CANCELLER_ROLE());
        address temp = makeAddr("temp-canceller");
        vm.startPrank(SENDER);
        tl.revokeRole(proposer, eve);
        tl.revokeRole(canceller, temp);
        vm.stopPrank();
        bytes32 adminRole = tl.DEFAULT_ADMIN_ROLE();
        vm.prank(eve);
        tl.renounceRole(adminRole, eve);
        _finish(tl);

        DeployDormantLedgers.Deployed memory d =
            _dormant().deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
        PatronageLedger l = PatronageLedger(d.patronageLedger);
        assertTrue(l.hasRole(l.DEFAULT_ADMIN_ROLE(), address(tl)));
    }

    /// The clean pipeline council (DeployGenesisGovernance) is established exactly, for both councils.
    function test_clean_pipeline_councils_have_exact_holder_sets() public {
        HolderChecksWithHistory h = new HolderChecksWithHistory();
        h.useArchive(archive);
        assertEq(h.problem(gov.governanceTimelock, gov.governanceMultisig, new address[](0)), "");
        assertEq(h.problem(gov.guardianTimelock, gov.guardianMultisig, new address[](0)), "");
        // The wrong council for a timelock is not its holder set.
        assertEq(
            h.problem(gov.governanceTimelock, gov.guardianMultisig, new address[](0)),
            "PROPOSER_ROLE holders are not exactly the multisig"
        );
        vm.chainId(40204);
        _deploy();
    }

    /// An extra canceller is accepted only when the caller names it (a guardian canceller seat).
    function test_named_extra_canceller_is_allowed_and_only_that_one() public {
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        address guardian = makeAddr("guardian-canceller");
        _grantAs(tl, tl.CANCELLER_ROLE(), guardian);
        _finish(tl);
        HolderChecksWithHistory h = new HolderChecksWithHistory();
        h.useArchive(archive);
        address[] memory extra = new address[](1);
        extra[0] = guardian;
        assertEq(h.problem(address(tl), address(ms), extra), "");
        assertEq(
            h.problem(address(tl), address(ms), new address[](0)),
            "CANCELLER_ROLE is held by an account other than the multisig"
        );
        extra[0] = makeAddr("someone-else");
        assertEq(
            h.problem(address(tl), address(ms), extra), "CANCELLER_ROLE is held by an account other than the multisig"
        );
    }

    /// No node (the production history source under forge test): fails closed, nothing sent.
    function test_missing_history_fails_closed() public {
        string memory noNode =
            string.concat("role history unavailable: eth_getLogs failed for blocks 0-", vm.toString(block.number));
        assertEq(new HolderChecksLive().problem(gov.governanceTimelock, gov.governanceMultisig), noNode);

        DeployDormantLedgers live = new DeployDormantLedgers();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(bytes(string.concat("GOVERNANCE_TIMELOCK: ", noNode)));
        live.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, address(kyc), address(membership));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");

        // A harness that was never given a history: same.
        DormantWithHistory blind = new DormantWithHistory();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: role history unavailable: no archive"));
        blind.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, address(kyc), address(membership));
    }

    /// A history that starts after the timelock was built (a late TIMELOCK_HISTORY_FROM_BLOCK, a
    /// pruned range) cannot establish the set, even when every later event is present.
    function test_history_that_misses_the_construction_fails_closed() public {
        archive.absorb();
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        vm.getRecordedLogs(); // the construction and the council grants never reach the archive
        (bytes32 proposer, address later) = (tl.PROPOSER_ROLE(), makeAddr("later"));
        _grantAs(tl, proposer, later);
        vm.prank(SENDER);
        tl.revokeRole(proposer, later);
        _finish(tl);
        DeployDormantLedgers s = _dormant();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: role history does not start at the timelock's construction"));
        s.deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
    }

    /// A history with a gap (here: a lost revoke) disagrees with the live state: fails closed.
    function test_history_that_disagrees_with_live_state_fails_closed() public {
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        address eve = makeAddr("eve");
        bytes32 executor = tl.EXECUTOR_ROLE();
        _grantAs(tl, executor, eve);
        archive.absorb();
        vm.prank(SENDER);
        tl.revokeRole(executor, eve);
        vm.getRecordedLogs(); // the revoke is lost
        _finish(tl);
        DeployDormantLedgers s = _dormant();
        _expectRevert(
            bytes("GOVERNANCE_TIMELOCK: role history disagrees with the live hasRole state (incomplete history)")
        );
        s.deployWith(SENDER, address(tl), address(ms), address(kyc), address(membership));
    }

    /// A contract that only imitates a timelock (getMinDelay / hasRole) is not the OZ build.
    function test_rejects_non_oz_timelock_code() public {
        HolderChecksWithHistory h = new HolderChecksWithHistory();
        h.useArchive(archive);
        assertEq(
            h.problem(gov.governanceMultisig, gov.governanceMultisig, new address[](0)),
            "runtime code is not this build's OZ TimelockController"
        );
    }

    // ---- chain#320 P1: the council is authenticated before its getters are trusted ----

    /// A genuine 48 h OZ timelock whose sole proposer / executor / canceller is a single-signer
    /// forwarder that reports 3-of-5, fronts the timelock, and owns no deploy account.
    function _forwardedTimelock() internal returns (TimelockController tl, SelfReportingForwarder fwd) {
        tl = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        fwd = new SelfReportingForwarder(address(tl), makeAddr("lone-signer"), govOwners);
        _grantCouncil(tl, address(fwd));
        _finish(tl);
    }

    function test_rejects_self_reporting_forwarder_council() public {
        vm.chainId(40204);
        (TimelockController tl, SelfReportingForwarder fwd) = _forwardedTimelock();
        // Everything it reports is compliant, and the timelock's holder sets are exactly it.
        MultisigProposer asCouncil = MultisigProposer(address(fwd));
        assertEq(asCouncil.threshold(), 3);
        assertEq(asCouncil.owners().length, 5);
        assertEq(asCouncil.timelock(), address(tl));
        HolderChecksWithHistory h = new HolderChecksWithHistory();
        h.useArchive(archive);
        assertEq(h.problem(address(tl), address(fwd), new address[](0)), "");
        // ...yet one key schedules on the timelock alone.
        bytes memory op = abi.encodeCall(TimelockController.updateDelay, (0));
        vm.prank(makeAddr("lone-signer"));
        fwd.forward(abi.encodeCall(TimelockController.schedule, (address(tl), 0, op, bytes32(0), bytes32(0), 48 hours)));

        DeployDormantLedgers s = _dormant();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(
            bytes(
                "GOVERNANCE_MULTISIG: not the MultisigProposer the ceremony deploys (Genesis.GovernanceMultisig) for this timelock, owners and threshold"
            )
        );
        s.deployWith(SENDER, address(tl), address(fwd), address(kyc), address(membership));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_admin_gate_rejects_self_reporting_forwarder_council() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        DeployDormantLedgers.Deployed memory d = _deploy();
        (TimelockController tl, SelfReportingForwarder fwd) = _forwardedTimelock();
        AdminChecksHarness a = new AdminChecksHarness();
        assertEq(
            a.multisigProblem(address(fwd), address(tl), GOV_SALT),
            "not the MultisigProposer the ceremony deploys (Genesis.GovernanceMultisig) for this timelock, owners and threshold"
        );
        string memory book = _dormant().bookJson(SENDER, address(tl), address(fwd), d);
        CheckDeployedAdmins c = _gate();
        _expectRevert(bytes("CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"));
        c.check(book, false);
    }

    /// Genuine MultisigProposer code is not enough: it must be the ceremony's instance for this
    /// timelock (right salt, right args). The genuine 3-of-5 pipeline councils pass.
    function test_council_authentication_requires_ceremony_provenance_and_args() public {
        AdminChecksHarness a = new AdminChecksHarness();
        assertEq(a.multisigProblem(gov.governanceMultisig, gov.governanceTimelock, GOV_SALT), "");
        assertEq(a.multisigProblem(gov.guardianMultisig, gov.guardianTimelock, GRD_SALT), "");
        string memory bad =
            "not the MultisigProposer the ceremony deploys (Genesis.GovernanceMultisig) for this timelock, owners and threshold";
        // The right council for the wrong timelock, and under the wrong salt.
        assertEq(a.multisigProblem(gov.governanceMultisig, gov.guardianTimelock, GOV_SALT), bad);
        assertEq(a.multisigProblem(gov.guardianMultisig, gov.guardianTimelock, GOV_SALT), bad);
        assertEq(a.multisigProblem(makeAddr("nomultisig"), gov.governanceTimelock, GOV_SALT), "no code at address");
        assertEq(a.multisigProblem(address(kyc), gov.governanceTimelock, GOV_SALT), "threshold() unreadable");

        vm.chainId(40204);
        TimelockController tl = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        // Genuine 3-of-5 code and args, plain CREATE (no ceremony provenance): refused.
        MultisigProposer plain = new MultisigProposer(address(tl), govOwners, 3);
        _grantCouncil(tl, address(plain));
        _finish(tl);
        assertEq(a.multisigProblem(address(plain), address(tl), GOV_SALT), bad);
        DeployDormantLedgers s = _dormant();
        _expectRevert(bytes(string.concat("GOVERNANCE_MULTISIG: ", bad)));
        s.deployWith(SENDER, address(tl), address(plain), address(kyc), address(membership));

        // Genuine code under the GUARDIAN salt, fronting the governance timelock: refused.
        TimelockController tl2 = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        MultisigProposer wrongSalt = _ceremonyMultisig(GRD_SALT, address(tl2), govOwners, 3);
        _grantCouncil(tl2, address(wrongSalt));
        _finish(tl2);
        _expectRevert(bytes(string.concat("GOVERNANCE_MULTISIG: ", bad)));
        s.deployWith(SENDER, address(tl2), address(wrongSalt), address(kyc), address(membership));

        // Ceremony provenance with 2-of-5 args: authenticated, so its threshold is real, and the
        // genesis floor refuses it.
        TimelockController tl3 = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        MultisigProposer twoOfFive = _ceremonyMultisig(GOV_SALT, address(tl3), govOwners, 2);
        _grantCouncil(tl3, address(twoOfFive));
        _finish(tl3);
        assertEq(a.multisigProblem(address(twoOfFive), address(tl3), GOV_SALT), "");
        _expectRevert(bytes("GOVERNANCE_MULTISIG: below the 3-of-5 genesis floor"));
        s.deployWith(SENDER, address(tl3), address(twoOfFive), address(kyc), address(membership));

        // The genuine 3-of-5 pipeline council passes the deploy and the gate.
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        DeployDormantLedgers.Deployed memory d = _deploy();
        CheckDeployedAdmins c = _gate();
        c.check(s.bookJson(SENDER, gov.governanceTimelock, gov.governanceMultisig, d), false);
        assertEq(c.timelockHolders(), 0);
    }

    /// The post-deploy gate establishes the complete sets on every timelock in the book.
    function test_admin_gate_flags_an_unrelated_admin_on_the_governance_timelock() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        DeployDormantLedgers.Deployed memory d = _deploy();
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        _grantAs(tl, tl.DEFAULT_ADMIN_ROLE(), makeAddr("eve"));
        _finish(tl);
        DeployDormantLedgers s = _dormant();
        CheckDeployedAdmins clean = _gate();
        clean.check(s.bookJson(SENDER, gov.governanceTimelock, gov.governanceMultisig, d), false);
        assertEq(clean.timelockHolders(), 0);

        string memory book = s.bookJson(SENDER, address(tl), address(ms), d);
        CheckDeployedAdmins c = _gate();
        _expectRevert(bytes("CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"));
        c.check(book, false);
    }

    function test_admin_gate_requires_a_paired_multisig_and_a_history() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        string memory unpaired = string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"Gov":"',
            vm.toString(gov.governanceTimelock),
            '","GovernanceTimelock":"',
            vm.toString(gov.governanceTimelock),
            '"},"aaStack":{}}'
        );
        CheckDeployedAdmins c = _gate();
        _expectRevert(bytes("CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"));
        c.check(unpaired, false);

        // A correct book, but no node to read the history from: the gate fails closed.
        DeployDormantLedgers.Deployed memory d = _deploy();
        string memory book = _dormant().bookJson(SENDER, gov.governanceTimelock, gov.governanceMultisig, d);
        CheckDeployedAdmins live = new CheckDeployedAdmins();
        _expectRevert(bytes("CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"));
        live.check(book, false);
    }

    function _grantCouncil(TimelockController tl, address ms) internal {
        vm.startPrank(SENDER);
        tl.grantRole(tl.PROPOSER_ROLE(), ms);
        tl.grantRole(tl.EXECUTOR_ROLE(), ms);
        tl.grantRole(tl.CANCELLER_ROLE(), ms);
        vm.stopPrank();
    }

    function _council(uint256 threshold, uint256 n, uint256 delay)
        internal
        returns (DeployGenesisGovernance.Deployed memory)
    {
        address[] memory owners = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            owners[i] = address(uint160(0xC000 + (threshold << 8) + (n << 4) + i));
        }
        address[] memory grdOwners = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            grdOwners[i] = address(uint160(0xB000 + i));
        }
        return new DeployGenesisGovernance()
            .deployWith(
                SENDER,
                DeployGenesisGovernance.Council({owners: owners, threshold: threshold, minDelay: delay}),
                DeployGenesisGovernance.Council({owners: grdOwners, threshold: 2, minDelay: 1 hours}),
                false
            );
    }

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
        _expectRevert(bytes("PatronageLedger: intended key lacks DEFAULT_ADMIN_ROLE"));
        h.soleAdminAmong(address(heldByB), gov.governanceTimelock, others);

        // B is admin AND governance was granted too: still refused (B kept admin).
        vm.prank(b);
        heldByB.grantRole(0x00, gov.governanceTimelock);
        _expectRevert(bytes("PatronageLedger: a deploy account holds DEFAULT_ADMIN_ROLE"));
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
        CheckDeployedAdmins c = _gate();
        _expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)"));
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
            _expectRevert(Auth.ZeroRoleHolder.selector);
            surfaces[i].grantRole(adminRole, address(0));
            _expectRevert(Auth.Create2DeployerAsHolder.selector);
            surfaces[i].grantRole(adminRole, relay);
            _expectRevert(Auth.LastAdmin.selector);
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
            _expectRevert(Auth.ZeroRoleHolder.selector);
            l.grantRole(ops[i], address(0));
            _expectRevert(Auth.Create2DeployerAsHolder.selector);
            l.grantRole(ops[i], relay);
        }
        vm.stopPrank();
        bytes32 reg = membership.REGISTRAR_ROLE();
        vm.startPrank(makeAddr("sbt-admin"));
        _expectRevert(Auth.ZeroRoleHolder.selector);
        membership.grantRole(reg, address(0));
        _expectRevert(Auth.Create2DeployerAsHolder.selector);
        membership.grantRole(reg, relay);
        vm.stopPrank();
    }
}

contract AdminChecksHarness is AdminChecks {
    function soleAdminAmong(address target, address expected, address[] memory others) external view {
        _assertSoleAdminAmong("PatronageLedger", target, expected, others);
    }

    function multisigProblem(address multisig, address timelock, string memory saltName)
        external
        view
        returns (string memory)
    {
        return _multisigProposerProblem(multisig, timelock, saltName);
    }
}

/// chain#320 P1 regression: one key runs the timelock through this contract, while its getters
/// describe a compliant council (3-of-5, fronting the timelock, no deploy account an owner).
contract SelfReportingForwarder {
    address public immutable timelock;
    address internal immutable signer;
    address[] internal _reported;

    constructor(address timelock_, address signer_, address[] memory reportedOwners) {
        (timelock, signer, _reported) = (timelock_, signer_, reportedOwners);
    }

    function threshold() external pure returns (uint256) {
        return 3;
    }

    function owners() external view returns (address[] memory) {
        return _reported;
    }

    function isOwner(address) external pure returns (bool) {
        return false;
    }

    /// The real control path: a single signature, no approvals.
    function forward(bytes calldata data) external returns (bytes memory ret) {
        require(msg.sender == signer, "not signer");
        bool ok;
        (ok, ret) = timelock.call(data);
        require(ok, "forward failed");
    }
}
