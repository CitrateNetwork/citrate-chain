// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";

contract GovAdminChecksHarness is AdminChecks {
    function deployerProblem(address target, address deployer) external view returns (string memory) {
        return _deployerAdminProblem(target, deployer);
    }

    function factoryProblem(address target) external view returns (string memory) {
        return _factoryAdminProblem(target);
    }
}

/// @title DeployGenesisGovernance.t: the C2 D5 GOVERNANCE / GUARDIAN ceremony
contract DeployGenesisGovernanceTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function _addrs(uint256 base, uint256 n) internal pure returns (address[] memory o) {
        o = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            o[i] = address(uint160(base + i));
        }
    }

    function _gov() internal pure returns (DeployGenesisGovernance.Council memory) {
        return DeployGenesisGovernance.Council({owners: _addrs(0xA000, 5), threshold: 3, minDelay: 48 hours});
    }

    function _grd() internal pure returns (DeployGenesisGovernance.Council memory) {
        return DeployGenesisGovernance.Council({owners: _addrs(0xB000, 3), threshold: 2, minDelay: 1 hours});
    }

    function test_deploys_3of5_and_2of3_and_hands_over() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false);

        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        TimelockController rt = TimelockController(payable(d.guardianTimelock));
        assertEq(gt.getMinDelay(), 48 hours);
        assertEq(rt.getMinDelay(), 1 hours);
        assertEq(MultisigProposer(d.governanceMultisig).threshold(), 3);
        assertEq(MultisigProposer(d.guardianMultisig).threshold(), 2);
        assertEq(MultisigProposer(d.governanceMultisig).timelock(), d.governanceTimelock);
        assertEq(MultisigProposer(d.guardianMultisig).timelock(), d.guardianTimelock);

        bytes32[4] memory roles = [gt.DEFAULT_ADMIN_ROLE(), gt.PROPOSER_ROLE(), gt.EXECUTOR_ROLE(), gt.CANCELLER_ROLE()];
        for (uint256 i = 0; i < 4; i++) {
            assertFalse(gt.hasRole(roles[i], SENDER), "deployer keeps a GOVERNANCE timelock role");
            assertFalse(rt.hasRole(roles[i], SENDER), "deployer keeps a GUARDIAN timelock role");
        }
        for (uint256 i = 1; i < 4; i++) {
            assertTrue(gt.hasRole(roles[i], d.governanceMultisig));
            assertTrue(rt.hasRole(roles[i], d.guardianMultisig));
        }
        assertTrue(gt.hasRole(roles[0], d.governanceTimelock), "timelock administers itself");
        assertFalse(gt.hasRole(gt.EXECUTOR_ROLE(), address(0)), "execution is not open");

        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(d.governanceTimelock, SENDER), "");
        assertEq(h.deployerProblem(d.governanceMultisig, SENDER), "");
        assertEq(h.factoryProblem(d.guardianTimelock), "");
    }

    function test_addresses_are_create2_deterministic_and_rerun_reuses() public {
        DeployGenesisGovernance a = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d1 = a.deployWith(SENDER, _gov(), _grd(), false);
        DeployGenesisGovernance b = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d2 = b.deployWith(SENDER, _gov(), _grd(), false);
        assertEq(d1.governanceTimelock, d2.governanceTimelock);
        assertEq(d1.governanceMultisig, d2.governanceMultisig);
        assertEq(d1.guardianTimelock, d2.guardianTimelock);
        assertEq(d1.guardianMultisig, d2.guardianMultisig);
        // Arachnid CREATE2 address of the timelock, from (salt, init code) alone.
        address[] memory none = new address[](0);
        bytes memory init =
            abi.encodePacked(type(TimelockController).creationCode, abi.encode(uint256(48 hours), none, none, SENDER));
        bytes32 salt = keccak256(abi.encodePacked("citrate.v1.", "Genesis.GovernanceTimelock"));
        address expected = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), address(0x4e59b44847b379578588920cA78FbF26c0B4956C), salt, keccak256(init)
                        )
                    )
                )
            )
        );
        assertEq(d1.governanceTimelock, expected);
    }

    function test_rerun_with_a_different_owner_set_fails_closed() public {
        DeployGenesisGovernance a = new DeployGenesisGovernance();
        a.deployWith(SENDER, _gov(), _grd(), false);
        DeployGenesisGovernance.Council memory gov2 = _gov();
        gov2.owners[4] = address(0xA0FF);
        DeployGenesisGovernance b = new DeployGenesisGovernance();
        // The timelock is reused (same deployer + delay) but is already handed to the
        // first multisig; the new multisig gets no roles and the run reverts.
        vm.expectRevert(bytes("GOVERNANCE: multisig lacks a timelock role"));
        b.deployWith(SENDER, gov2, _grd(), false);
    }

    function test_rejects_delay_below_floor() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.minDelay = 1 hours - 1;
        vm.expectRevert(bytes("GUARDIAN: minDelay below the 1 hour floor"));
        s.deployWith(SENDER, _gov(), grd, false);
    }

    function test_rejects_threshold_above_owner_count_and_zero() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.threshold = 6;
        vm.expectRevert(bytes("GOVERNANCE: threshold must be 1..owners"));
        s.deployWith(SENDER, gov, _grd(), false);
        gov.threshold = 0;
        vm.expectRevert(bytes("GOVERNANCE: threshold must be 1..owners"));
        s.deployWith(SENDER, gov, _grd(), false);
    }

    function test_rejects_more_than_ten_owners() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov =
            DeployGenesisGovernance.Council({owners: _addrs(0xA000, 11), threshold: 6, minDelay: 48 hours});
        vm.expectRevert(bytes("GOVERNANCE: owner count must be 1..10"));
        s.deployWith(SENDER, gov, _grd(), false);
    }

    function test_rejects_duplicate_and_zero_owner() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners[3] = gov.owners[1];
        vm.expectRevert(bytes("GOVERNANCE: duplicate owner"));
        s.deployWith(SENDER, gov, _grd(), false);
        gov = _gov();
        gov.owners[0] = address(0);
        vm.expectRevert(bytes("GOVERNANCE: zero owner"));
        s.deployWith(SENDER, gov, _grd(), false);
    }

    function test_rejects_deployer_as_owner() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners[2] = SENDER;
        vm.expectRevert(bytes("GUARDIAN: the deployer cannot be an owner"));
        s.deployWith(SENDER, _gov(), grd, false);
    }

    /// Signer-mismatch regression: DEPLOYER_ADDRESS names A but Forge broadcasts as B, and B
    /// sits on a council. The script must revert before deploying anything.
    function test_reverts_when_broadcaster_is_not_the_configured_deployer() public {
        address configured = makeAddr("configured-deployer-A");
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners[4] = SENDER; // the actual broadcaster (B)
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(configured, gov, _grd(), false); // broadcasts as SENDER (B)
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// Same mismatch with councils that name neither account: still refused, nothing sent.
    function test_reverts_on_signer_mismatch_even_with_clean_councils() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(makeAddr("configured-deployer-A"), _gov(), _grd(), false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_shared_holder_rejected_unless_allowed() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners[0] = _gov().owners[2];
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        vm.expectRevert(bytes("owner sits on both GOVERNANCE and GUARDIAN"));
        s.deployWith(SENDER, _gov(), grd, false);
        DeployGenesisGovernance s2 = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s2.deployWith(SENDER, _gov(), grd, true);
        assertTrue(MultisigProposer(d.guardianMultisig).isOwner(_gov().owners[2]));
    }

    /// GOVERNANCE actually governs: a 3-of-5 schedule, the 48 h wait, a 3-of-5 execute.
    function test_governance_council_runs_a_timelocked_operation() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false);
        TimelockController tl = TimelockController(payable(d.governanceTimelock));
        MultisigProposer ms = MultisigProposer(d.governanceMultisig);
        address[] memory o = _gov().owners;
        bytes memory payload = abi.encodeCall(tl.updateDelay, (72 hours));

        bytes32 id = _passed(ms, o, abi.encodeCall(tl.schedule, (address(tl), 0, payload, bytes32(0), 0, 48 hours)));
        assertTrue(id != bytes32(0));
        vm.warp(block.timestamp + 48 hours);
        _passed(ms, o, abi.encodeCall(tl.execute, (address(tl), 0, payload, bytes32(0), 0)));
        assertEq(tl.getMinDelay(), 72 hours);
    }

    function _passed(MultisigProposer ms, address[] memory o, bytes memory data) internal returns (bytes32 id) {
        vm.prank(o[0]);
        id = ms.propose(data);
        vm.prank(o[1]);
        ms.approve(id);
        vm.prank(o[2]);
        ms.approve(id);
        vm.prank(o[0]);
        ms.execute(id);
    }

    /// run(): every input is required, the output is a book CheckDeployedAdmins passes.
    /// (The only test that sets GOV_* / GRD_* / GENESIS_GOVERNANCE_OUT: vm.setEnv is
    /// process-global and forge runs tests in parallel.)
    function test_run_requires_env_then_writes_a_book_the_admin_gate_passes() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        vm.expectRevert();
        s.run(); // GOV_OWNERS unset

        vm.setEnv("GOV_OWNERS", _csv(_gov().owners));
        vm.setEnv("GOV_THRESHOLD", "3");
        vm.setEnv("GOV_MIN_DELAY", "172800");
        vm.setEnv("GRD_OWNERS", _csv(_grd().owners));
        vm.setEnv("GRD_THRESHOLD", "2");
        vm.expectRevert();
        s.run(); // GRD_MIN_DELAY unset

        vm.setEnv("GRD_MIN_DELAY", "3600");
        vm.expectRevert();
        s.run(); // GENESIS_GOVERNANCE_OUT unset

        vm.createDir("genesis", true);
        string memory out = "genesis/test-governance.json";
        vm.setEnv("GENESIS_GOVERNANCE_OUT", out);
        DeployGenesisGovernance.Deployed memory d = s.run();

        string memory book = vm.readFile(out);
        assertEq(vm.parseJsonAddress(book, ".deployer"), SENDER);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceTimelock"), d.governanceTimelock);
        assertEq(vm.parseJsonAddress(book, ".contracts.GuardianMultisig"), d.guardianMultisig);
        assertEq(vm.parseJsonUint(book, ".params.governance.threshold"), 3);
        assertEq(vm.parseJsonUint(book, ".params.guardian.minDelay"), 3600);

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        c.check(book, true);
        assertEq(c.deployerAdmin(), 0, "DEPLOYER-ADMIN reads 0 after hand-over");
        assertEq(c.factoryAdmin(), 0);
        assertEq(c.noCode(), 0);
        vm.removeFile(out);
    }

    function _csv(address[] memory a) internal pure returns (string memory s) {
        for (uint256 i = 0; i < a.length; i++) {
            s = string.concat(s, i == 0 ? "" : ",", vm.toString(a[i]));
        }
    }
}

/// The DEPLOYER-ADMIN gate now covers the timelock seats and m-of-n owner seats.
contract GenesisAdminGateTest is Test {
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    address deployer = makeAddr("deployer");

    function _book(string memory body) internal view returns (string memory) {
        return string.concat('{"deployer":"', vm.toString(deployer), '","contracts":{', body, '},"aaStack":{}}');
    }

    function test_flags_deployer_still_holding_timelock_admin() public {
        address[] memory none = new address[](0);
        TimelockController tl = new TimelockController(1 hours, none, none, deployer);
        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(address(tl), deployer), "deployer EOA holds DEFAULT_ADMIN_ROLE");
    }

    function test_flags_deployer_as_timelock_proposer() public {
        address[] memory me = new address[](1);
        me[0] = deployer;
        TimelockController tl = new TimelockController(1 hours, me, new address[](0), address(0));
        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(address(tl), deployer), "deployer EOA holds timelock PROPOSER_ROLE");

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        vm.expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)"));
        c.check(_book(string.concat('"Tl":"', vm.toString(address(tl)), '"')), false);
    }

    function test_flags_deployer_as_timelock_executor() public {
        address[] memory me = new address[](1);
        me[0] = deployer;
        TimelockController tl = new TimelockController(1 hours, new address[](0), me, address(0));
        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(address(tl), deployer), "deployer EOA holds timelock EXECUTOR_ROLE");
    }

    function test_flags_deployer_as_multisig_owner() public {
        address[] memory none = new address[](0);
        TimelockController tl = new TimelockController(1 hours, none, none, address(0));
        address[] memory o = new address[](2);
        o[0] = deployer;
        o[1] = makeAddr("other");
        MultisigProposer ms = new MultisigProposer(address(tl), o, 2);
        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(address(ms), deployer), "deployer EOA is a multisig owner");
        assertEq(h.deployerProblem(address(ms), makeAddr("nobody")), "");
    }

    function test_extra_books_are_swept_and_must_share_the_deployer() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        address[] memory me = new address[](1);
        me[0] = deployer;
        TimelockController bad = new TimelockController(1 hours, me, new address[](0), address(0));
        string[] memory extras = new string[](1);
        extras[0] = _book(string.concat('"Tl":"', vm.toString(address(bad)), '"'));

        CheckDeployedAdmins c = new CheckDeployedAdmins();
        vm.expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)"));
        c.checkAll(_book(""), extras, false);

        extras[0] = string.concat('{"deployer":"', vm.toString(makeAddr("someone")), '","contracts":{}}');
        CheckDeployedAdmins c2 = new CheckDeployedAdmins();
        vm.expectRevert(bytes("CheckDeployedAdmins: extra address book names a different deployer"));
        c2.checkAll(_book(""), extras, false);
    }
}
