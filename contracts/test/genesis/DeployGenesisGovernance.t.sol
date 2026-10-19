// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {RoleLogArchive, GateWithHistory} from "./RoleHistoryHarness.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";
import {GovernanceWithNode, GateWithNode, BookCancellerChecks} from "./NodeChainIdHarness.sol";

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
        return DeployGenesisGovernance.Council({
            owners: _addrs(0xA000, 5), threshold: 3, minDelay: 48 hours, proposalTtl: 7 days
        });
    }

    function _grd() internal pure returns (DeployGenesisGovernance.Council memory) {
        return DeployGenesisGovernance.Council({
            owners: _addrs(0xB000, 3), threshold: 2, minDelay: 1 hours, proposalTtl: 7 days
        });
    }

    function test_deploys_3of5_and_2of3_and_hands_over() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);

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
        // Guardian veto: CANCELLER (only) on GOVERNANCE, held by the GuardianCanceller, which
        // answers to the GUARDIAN timelock.
        assertTrue(gt.hasRole(gt.CANCELLER_ROLE(), d.guardianCanceller), "guardian can cancel governance");
        assertEq(GuardianCanceller(d.guardianCanceller).guardian(), d.guardianTimelock);
        assertEq(GuardianCanceller(d.guardianCanceller).governanceTimelock(), d.governanceTimelock);
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(gt.hasRole(roles[i], d.guardianCanceller), "guardian holds more than canceller");
        }
        for (uint256 i = 0; i < 4; i++) {
            assertFalse(gt.hasRole(roles[i], d.guardianTimelock), "guardian timelock holds a governance seat");
            assertFalse(gt.hasRole(roles[i], d.guardianMultisig), "guardian multisig holds a governance seat");
            assertFalse(rt.hasRole(roles[i], d.governanceTimelock), "governance holds a guardian seat");
        }
        assertEq(MultisigProposer(d.governanceMultisig).proposalTtl(), 7 days);
        assertFalse(gt.hasRole(gt.EXECUTOR_ROLE(), address(0)), "execution is not open");

        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(d.governanceTimelock, SENDER), "");
        assertEq(h.deployerProblem(d.governanceMultisig, SENDER), "");
        assertEq(h.factoryProblem(d.guardianTimelock), "");
    }

    function test_addresses_are_create2_deterministic_and_rerun_reuses() public {
        DeployGenesisGovernance a = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d1 = a.deployWith(SENDER, _gov(), _grd(), false, false);
        DeployGenesisGovernance b = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d2 = b.deployWith(SENDER, _gov(), _grd(), false, false);
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
        a.deployWith(SENDER, _gov(), _grd(), false, false);
        DeployGenesisGovernance.Council memory gov2 = _gov();
        gov2.owners[4] = address(0xA0FF);
        DeployGenesisGovernance b = new DeployGenesisGovernance();
        // The timelock is reused (same deployer + delay) but is already handed to the
        // first multisig; the new multisig gets no roles and the run reverts.
        vm.expectRevert(bytes("GOVERNANCE: multisig lacks a timelock role"));
        b.deployWith(SENDER, gov2, _grd(), false, false);
    }

    function test_rejects_delay_below_floor() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.minDelay = 1 hours - 1;
        vm.expectRevert(bytes("GUARDIAN: minDelay below the 1 hour floor"));
        s.deployWith(SENDER, _gov(), grd, false, false);
    }

    function test_rejects_threshold_above_owner_count_and_zero() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.threshold = 6;
        vm.expectRevert(bytes("GOVERNANCE: threshold must be 1..owners"));
        s.deployWith(SENDER, gov, _grd(), false, false);
        gov.threshold = 0;
        vm.expectRevert(bytes("GOVERNANCE: threshold must be 1..owners"));
        s.deployWith(SENDER, gov, _grd(), false, false);
    }

    function test_rejects_more_than_ten_owners() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = DeployGenesisGovernance.Council({
            owners: _addrs(0xA000, 11), threshold: 6, minDelay: 48 hours, proposalTtl: 7 days
        });
        vm.expectRevert(bytes("GOVERNANCE: owner count must be 1..10"));
        s.deployWith(SENDER, gov, _grd(), false, false);
    }

    function test_rejects_duplicate_and_zero_owner() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners[3] = gov.owners[1];
        vm.expectRevert(bytes("GOVERNANCE: duplicate owner"));
        s.deployWith(SENDER, gov, _grd(), false, false);
        gov = _gov();
        gov.owners[0] = address(0);
        vm.expectRevert(bytes("GOVERNANCE: zero owner"));
        s.deployWith(SENDER, gov, _grd(), false, false);
    }

    function test_rejects_deployer_as_owner() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners[2] = SENDER;
        vm.expectRevert(bytes("GUARDIAN: the deployer cannot be an owner"));
        s.deployWith(SENDER, _gov(), grd, false, false);
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
        s.deployWith(configured, gov, _grd(), false, false); // broadcasts as SENDER (B)
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// Same mismatch with councils that name neither account: still refused, nothing sent.
    function test_reverts_on_signer_mismatch_even_with_clean_councils() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(makeAddr("configured-deployer-A"), _gov(), _grd(), false, false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    function test_shared_holder_rejected_unless_allowed() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners[0] = _gov().owners[2];
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        vm.expectRevert(bytes("owner sits on both GOVERNANCE and GUARDIAN"));
        s.deployWith(SENDER, _gov(), grd, false, false);
        DeployGenesisGovernance s2 = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s2.deployWith(SENDER, _gov(), grd, true, false);
        assertTrue(MultisigProposer(d.guardianMultisig).isOwner(_gov().owners[2]));
    }

    /// GOVERNANCE actually governs: a 3-of-5 schedule, the 48 h wait, a 3-of-5 execute.
    function test_governance_council_runs_a_timelocked_operation() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
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

    // ── guardian veto ───────────────────────────────────────────────

    /// GUARDIAN 2-of-3 cancels a queued GOVERNANCE operation through its own 1 h timelock,
    /// well inside the 48 h GOVERNANCE delay; the operation can then never execute.
    function test_guardian_vetoes_a_queued_governance_operation() public {
        uint256 t0 = 2_000_000; // fixed: via-IR may reorder `block.timestamp` reads around vm.warp
        vm.warp(t0);
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        TimelockController rt = TimelockController(payable(d.guardianTimelock));
        bytes memory payload = abi.encodeCall(gt.updateDelay, (72 hours));

        _passed(
            MultisigProposer(d.governanceMultisig),
            _gov().owners,
            abi.encodeCall(gt.schedule, (address(gt), 0, payload, bytes32(0), 0, 48 hours))
        );
        bytes32 opId = gt.hashOperation(address(gt), 0, payload, bytes32(0), 0);
        assertTrue(gt.isOperationPending(opId));

        bytes memory veto = abi.encodeCall(GuardianCanceller.cancel, (address(gt), 0, payload, bytes32(0), 0));
        _passed2(
            MultisigProposer(d.guardianMultisig),
            _grd().owners,
            abi.encodeCall(rt.schedule, (d.guardianCanceller, 0, veto, bytes32(0), 0, 1 hours))
        );
        vm.warp(t0 + 1 hours);
        _passed2(
            MultisigProposer(d.guardianMultisig),
            _grd().owners,
            abi.encodeCall(rt.execute, (d.guardianCanceller, 0, veto, bytes32(0), 0))
        );
        assertFalse(gt.isOperation(opId), "vetoed");

        vm.warp(t0 + 1 hours + 48 hours);
        MultisigProposer gm = MultisigProposer(d.governanceMultisig);
        address[] memory o = _gov().owners;
        vm.prank(o[0]);
        bytes32 id = gm.propose(abi.encodeCall(gt.execute, (address(gt), 0, payload, bytes32(0), 0)));
        vm.prank(o[1]);
        gm.approve(id);
        vm.prank(o[2]);
        gm.approve(id);
        vm.prank(o[0]);
        vm.expectPartialRevert(MultisigProposer.ExecutionFailed.selector);
        gm.execute(id);
        assertEq(gt.getMinDelay(), 48 hours);
    }

    /// The GUARDIAN can only cancel: neither its timelock nor its multisig can schedule or
    /// execute on GOVERNANCE.
    function test_guardian_cannot_propose_or_execute_governance() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        TimelockController rt = TimelockController(payable(d.guardianTimelock));
        bytes memory payload = abi.encodeCall(gt.updateDelay, (0));

        // Through the guardian's own timelock: the queued call itself reverts on GOVERNANCE.
        bytes memory sched = abi.encodeCall(gt.schedule, (address(gt), 0, payload, bytes32(0), 0, 48 hours));
        _passed2(
            MultisigProposer(d.guardianMultisig),
            _grd().owners,
            abi.encodeCall(rt.schedule, (address(gt), 0, sched, bytes32(0), 0, 1 hours))
        );
        vm.warp(block.timestamp + 1 hours);
        MultisigProposer gm = MultisigProposer(d.guardianMultisig);
        address[] memory o = _grd().owners;
        vm.prank(o[0]);
        bytes32 id = gm.propose(abi.encodeCall(rt.execute, (address(gt), 0, sched, bytes32(0), 0)));
        vm.prank(o[1]);
        gm.approve(id);
        vm.prank(o[0]);
        vm.expectPartialRevert(MultisigProposer.ExecutionFailed.selector);
        gm.execute(id);
        assertFalse(gt.isOperation(gt.hashOperation(address(gt), 0, payload, bytes32(0), 0)));

        // Directly, as any guardian contract.
        address[3] memory guardian = [d.guardianTimelock, d.guardianMultisig, d.guardianCanceller];
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(guardian[i]);
            vm.expectRevert();
            gt.schedule(address(gt), 0, payload, bytes32(0), 0, 48 hours);
            vm.prank(guardian[i]);
            vm.expectRevert();
            gt.execute(address(gt), 0, payload, bytes32(0), 0);
        }
        assertEq(gt.getMinDelay(), 48 hours);
    }

    /// A GOVERNANCE timelock handed over by an earlier run without the guardian canceller
    /// fails the postcondition instead of shipping without a veto.
    function test_postcondition_requires_the_guardian_canceller() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        bytes32 role = gt.CANCELLER_ROLE();
        vm.prank(address(gt));
        gt.revokeRole(role, d.guardianCanceller);
        DeployGenesisGovernance s2 = new DeployGenesisGovernance();
        vm.expectRevert(bytes("GUARDIAN: guardian canceller cannot cancel GOVERNANCE operations"));
        s2.deployWith(SENDER, _gov(), _grd(), false, false);
    }

    // ── production-strength guards ──────────────────────────────────

    function _expectWeak(
        DeployGenesisGovernance.Council memory gov,
        DeployGenesisGovernance.Council memory grd,
        string memory reason
    ) internal {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        vm.expectRevert(bytes(reason));
        s.deployWith(SENDER, gov, grd, false, false);
        // The explicit override deploys the same parameters.
        DeployGenesisGovernance s2 = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s2.deployWith(SENDER, gov, grd, false, true);
        assertEq(MultisigProposer(d.governanceMultisig).threshold(), gov.threshold);
        assertEq(MultisigProposer(d.guardianMultisig).threshold(), grd.threshold);
    }

    function test_weak_governance_threshold_below_three() public {
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners = _addrs(0xA000, 3);
        gov.threshold = 2;
        _expectWeak(gov, _grd(), "GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    function test_weak_governance_threshold_not_a_majority() public {
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners = _addrs(0xA000, 6);
        gov.threshold = 3;
        _expectWeak(
            gov, _grd(), "GOVERNANCE: threshold must be a majority of owners (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
    }

    function test_weak_governance_delay_below_48h() public {
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.minDelay = 48 hours - 1;
        _expectWeak(gov, _grd(), "GOVERNANCE: minDelay must be >= 48 hours (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    /// 3-of-4 is a majority with m >= 3, but GOVERNANCE needs at least 5 owners.
    function test_weak_governance_fewer_than_five_owners() public {
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.owners = _addrs(0xA000, 4);
        _expectWeak(gov, _grd(), "GOVERNANCE: owners must be >= 5 (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    /// 2-of-2 is a majority with m >= 2, but GUARDIAN needs at least 3 owners.
    function test_weak_guardian_fewer_than_three_owners() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners = _addrs(0xB000, 2);
        _expectWeak(_gov(), grd, "GUARDIAN: owners must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    function test_weak_guardian_threshold_below_two() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners = _addrs(0xB000, 1);
        grd.threshold = 1;
        _expectWeak(_gov(), grd, "GUARDIAN: threshold must be >= 2 (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    function test_weak_guardian_threshold_not_a_majority() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.owners = _addrs(0xB000, 4);
        grd.threshold = 2;
        _expectWeak(_gov(), grd, "GUARDIAN: threshold must be a majority of owners (ALLOW_WEAK_GOVERNANCE=1 to waive)");
    }

    function test_weak_guardian_delay_not_shorter_than_governance() public {
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.minDelay = 48 hours;
        _expectWeak(
            _gov(),
            grd,
            "GUARDIAN: minDelay must be shorter than GOVERNANCE minDelay (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
    }

    /// The 1 h floor and structural checks hold even with the override.
    function test_override_does_not_waive_the_floor_or_structure() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.minDelay = 1 hours - 1;
        vm.expectRevert(bytes("GUARDIAN: minDelay below the 1 hour floor"));
        s.deployWith(SENDER, _gov(), grd, false, true);
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.threshold = 0;
        vm.expectRevert(bytes("GOVERNANCE: threshold must be 1..owners"));
        s.deployWith(SENDER, gov, _grd(), false, true);
    }

    function test_rejects_proposal_ttl_out_of_bounds() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        address[] memory none = new address[](0);
        MultisigProposer probe = new MultisigProposer(
            address(new TimelockController(1 hours, none, none, address(0))), _addrs(0xC000, 1), 1, 1 days
        );
        assertEq(s.PROPOSAL_TTL_MIN(), probe.MIN_PROPOSAL_TTL(), "script and contract bounds agree");
        assertEq(s.PROPOSAL_TTL_MAX(), probe.MAX_PROPOSAL_TTL(), "script and contract bounds agree");
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.proposalTtl = 1 days - 1;
        vm.expectRevert(bytes("GOVERNANCE: proposalTtl must be 1..30 days"));
        s.deployWith(SENDER, gov, _grd(), false, true);
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.proposalTtl = 30 days + 1;
        vm.expectRevert(bytes("GUARDIAN: proposalTtl must be 1..30 days"));
        s.deployWith(SENDER, _gov(), grd, false, true);
    }

    // ── genesis profile (chain 40204 / GENESIS_PROFILE=1) ───────────

    string constant OVERRIDE_REFUSED =
        "ALLOW_WEAK_GOVERNANCE is refused on the genesis profile (chain 40204 or GENESIS_PROFILE=1)";
    string constant SHARED_REFUSED =
        "ALLOW_SHARED_HOLDERS is refused on the genesis profile (chain 40204 or GENESIS_PROFILE=1)";
    string constant NEEDS_NODE = "genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)";

    /// The ceremony with an honest node stand-in (eth_chainId == forge's simulated id).
    function _withNode() internal returns (GovernanceWithNode) {
        return new GovernanceWithNode();
    }

    /// GOVERNANCE / GUARDIAN with the fixed genesis TTL.
    function _genesis(DeployGenesisGovernance.Council memory c)
        internal
        pure
        returns (DeployGenesisGovernance.Council memory)
    {
        c.proposalTtl = 14 days;
        return c;
    }

    function _weakGov() internal pure returns (DeployGenesisGovernance.Council memory) {
        return DeployGenesisGovernance.Council({
            owners: _addrs(0xA000, 3), threshold: 2, minDelay: 24 hours, proposalTtl: 14 days
        });
    }

    function test_genesis_profile_is_chain_40204_or_forced() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        assertEq(s.GENESIS_CHAIN_ID(), 40204);
        assertFalse(s.isGenesisProfile(false));
        assertTrue(s.isGenesisProfile(true));
        vm.chainId(40204);
        assertTrue(s.isGenesisProfile(false));
    }

    /// 40204, 2-of-3 / 24 h GOVERNANCE: refused by the production-strength floors.
    function test_40204_rejects_2of3_24h_governance() public {
        vm.chainId(40204);
        DeployGenesisGovernance s = _withNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
        s.deployWith(SENDER, _weakGov(), _genesis(_grd()), false, false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// 40204 with the override: refused for weak AND for production-strength parameters.
    function test_40204_refuses_the_weak_override() public {
        vm.chainId(40204);
        DeployGenesisGovernance s = _withNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.deployWith(SENDER, _weakGov(), _grd(), false, true);
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.deployWith(SENDER, _gov(), _grd(), false, true);
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.deployWith(SENDER, _gov(), _grd(), false, true, false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// GENESIS_PROFILE forces the same refusal on any other chain id.
    function test_forced_genesis_profile_refuses_the_weak_override() public {
        vm.chainId(1337);
        DeployGenesisGovernance s = _withNode();
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.deployWith(SENDER, _weakGov(), _grd(), false, true, true);
        vm.expectRevert(bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
        s.deployWith(SENDER, _weakGov(), _genesis(_grd()), false, false, true);
    }

    /// 40204, GOVERNANCE 3-of-5 / 48 h + GUARDIAN 2-of-3 / 1 h, 14-day TTL: deploys and every
    /// postcondition holds.
    function test_40204_deploys_3of5_48h_with_guardian_2of3() public {
        vm.chainId(40204);
        DeployGenesisGovernance s = _withNode();
        DeployGenesisGovernance.Council memory gov = _gov();
        DeployGenesisGovernance.Council memory grd = _grd();
        gov.proposalTtl = s.DEFAULT_PROPOSAL_TTL();
        grd.proposalTtl = s.DEFAULT_PROPOSAL_TTL();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, gov, grd, false, false);

        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        TimelockController rt = TimelockController(payable(d.guardianTimelock));
        MultisigProposer gm = MultisigProposer(d.governanceMultisig);
        MultisigProposer rm = MultisigProposer(d.guardianMultisig);
        assertEq(gt.getMinDelay(), 48 hours);
        assertEq(rt.getMinDelay(), 1 hours);
        assertEq(gm.threshold(), 3);
        assertEq(gm.owners().length, 5);
        assertEq(rm.threshold(), 2);
        assertEq(rm.owners().length, 3);
        assertEq(gm.proposalTtl(), 14 days);
        assertEq(rm.proposalTtl(), 14 days);

        bytes32[4] memory roles = [gt.DEFAULT_ADMIN_ROLE(), gt.PROPOSER_ROLE(), gt.EXECUTOR_ROLE(), gt.CANCELLER_ROLE()];
        for (uint256 i = 0; i < 4; i++) {
            assertFalse(gt.hasRole(roles[i], SENDER), "deployer keeps a GOVERNANCE timelock role");
            assertFalse(rt.hasRole(roles[i], SENDER), "deployer keeps a GUARDIAN timelock role");
            assertFalse(gt.hasRole(roles[i], d.guardianMultisig), "guardian multisig holds a governance seat");
        }
        assertTrue(gt.hasRole(gt.CANCELLER_ROLE(), d.guardianCanceller), "guardian can cancel governance");
        for (uint256 i = 0; i < 4; i++) {
            assertFalse(gt.hasRole(roles[i], d.guardianTimelock), "guardian timelock holds a governance seat");
            if (i < 3) assertFalse(gt.hasRole(roles[i], d.guardianCanceller), "guardian holds more than canceller");
        }
        GovAdminChecksHarness h = new GovAdminChecksHarness();
        assertEq(h.deployerProblem(d.governanceTimelock, SENDER), "");
        assertEq(h.deployerProblem(d.guardianMultisig, SENDER), "");
        assertEq(h.factoryProblem(d.governanceMultisig), "");
    }

    /// Off the genesis profile the override still admits rehearsal floors (2-of-3 / 24 h,
    /// 1-of-1 guardian); the 1 h floor and structure still hold.
    function test_non_genesis_chain_override_allows_lower_floors() public {
        vm.chainId(1337);
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory grd = DeployGenesisGovernance.Council({
            owners: _addrs(0xB000, 1), threshold: 1, minDelay: 1 hours, proposalTtl: 1 days
        });
        vm.expectRevert(bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
        s.deployWith(SENDER, _weakGov(), grd, false, false);
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _weakGov(), grd, false, true);
        assertEq(MultisigProposer(d.governanceMultisig).threshold(), 2);
        assertEq(TimelockController(payable(d.governanceTimelock)).getMinDelay(), 24 hours);
        assertEq(MultisigProposer(d.guardianMultisig).threshold(), 1);
    }

    function test_proposal_ttl_default_is_14_days_within_bounds() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        assertEq(s.DEFAULT_PROPOSAL_TTL(), 1209600);
        assertGe(s.DEFAULT_PROPOSAL_TTL(), s.PROPOSAL_TTL_MIN());
        assertLe(s.DEFAULT_PROPOSAL_TTL(), s.PROPOSAL_TTL_MAX());
    }

    /// The rehearsal bounds still hold on the genesis profile (checked first).
    function test_40204_enforces_proposal_ttl_bounds() public {
        vm.chainId(40204);
        DeployGenesisGovernance s = _withNode();
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.proposalTtl = 30 days + 1;
        vm.expectRevert(bytes("GOVERNANCE: proposalTtl must be 1..30 days"));
        s.deployWith(SENDER, gov, _genesis(_grd()), false, false);
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.proposalTtl = 1 days - 1;
        vm.expectRevert(bytes("GUARDIAN: proposalTtl must be 1..30 days"));
        s.deployWith(SENDER, _genesis(_gov()), grd, false, false);
    }

    // ── chain id: the node's eth_chainId vs forge's simulated id (GenesisProfile) ──

    string constant MISMATCH_40204_VS_1 =
        "chain id mismatch: node reports 40204, forge simulates 1 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)";

    /// The reported bypass: a node at 40204, forge simulating chain 1 (what `--chain-id 1`,
    /// `--chain 1` and FOUNDRY_CHAIN_ID=1 each produce), ALLOW_WEAK_GOVERNANCE=1 and a 2-of-3 /
    /// 24 h GOVERNANCE. Refused before anything is broadcast.
    function test_simulated_chain_1_against_a_40204_node_is_refused_before_broadcast() public {
        GovernanceWithNode s = _withNode();
        s.nodeReports(40204);
        vm.chainId(1);
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes(MISMATCH_40204_VS_1));
        s.deployWith(SENDER, _weakGov(), _grd(), false, true);
        // The forced-profile and shared-holder variants hit the same check first.
        vm.expectRevert(bytes(MISMATCH_40204_VS_1));
        s.deployWith(SENDER, _weakGov(), _grd(), true, true, false);
        vm.expectRevert(bytes(MISMATCH_40204_VS_1));
        s.deployWith(SENDER, _gov(), _grd(), false, false, true);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// The other direction: a rehearsal node, forge simulating 40204.
    function test_simulated_40204_against_another_node_is_refused() public {
        GovernanceWithNode s = _withNode();
        s.nodeReports(31337);
        vm.chainId(40204);
        vm.expectRevert(
            bytes(
                "chain id mismatch: node reports 31337, forge simulates 40204 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
            )
        );
        s.deployWith(SENDER, _genesis(_gov()), _genesis(_grd()), false, false);
    }

    function testFuzz_any_node_vs_simulated_mismatch_is_refused(uint64 node, uint64 simulated) public {
        vm.assume(node != simulated && simulated != 0);
        GovernanceWithNode s = _withNode();
        s.nodeReports(node);
        vm.chainId(simulated);
        vm.expectPartialRevert(bytes4(keccak256("Error(string)")));
        s.deployWith(SENDER, _weakGov(), _grd(), false, true);
    }

    /// No node to ask (no --rpc-url): the genesis profile fails closed, by chain id or forced;
    /// a rehearsal simulation still runs. Uses the real eth_chainId read (no fork in forge test).
    function test_genesis_profile_fails_closed_without_a_node() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        vm.chainId(40204);
        vm.expectRevert(bytes(NEEDS_NODE));
        s.deployWith(SENDER, _genesis(_gov()), _genesis(_grd()), false, false);
        vm.chainId(31337);
        vm.expectRevert(bytes(NEEDS_NODE));
        s.deployWith(SENDER, _genesis(_gov()), _genesis(_grd()), false, false, true);
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        assertTrue(d.governanceTimelock.code.length != 0, "rehearsal simulation runs without a node");
        (bool genesis, bool checked,,,) = s.runProfile();
        assertFalse(genesis);
        assertFalse(checked, "no node was asked");
    }

    function test_eth_chainId_response_decoding() public {
        GovernanceWithNode s = _withNode();
        assertEq(s.decodeChainId(hex"9d0c"), 40204);
        assertEq(s.decodeChainId(hex"01"), 1);
        assertEq(s.decodeChainId(hex"7a69"), 31337);
        vm.expectRevert(bytes("eth_chainId: unreadable response"));
        s.decodeChainId(hex"");
        vm.expectRevert(bytes("eth_chainId: unreadable response"));
        s.decodeChainId(new bytes(33));
    }

    /// The book records the profile, the node id and every override.
    function test_book_records_profile_and_overrides() public {
        vm.chainId(40204);
        GovernanceWithNode g = _withNode();
        DeployGenesisGovernance.Council memory gov = _genesis(_gov());
        DeployGenesisGovernance.Council memory grd = _genesis(_grd());
        DeployGenesisGovernance.Deployed memory d = g.deployWith(SENDER, gov, grd, false, false);
        string memory book = g.bookJson(SENDER, d, gov, grd);
        assertTrue(vm.parseJsonBool(book, ".params.genesisProfile"));
        assertTrue(vm.parseJsonBool(book, ".params.nodeChainIdChecked"));
        assertEq(vm.parseJsonUint(book, ".params.nodeChainId"), 40204);
        assertFalse(vm.parseJsonBool(book, ".params.overrides.allowWeakGovernance"));
        assertFalse(vm.parseJsonBool(book, ".params.overrides.allowSharedHolders"));
        assertFalse(vm.parseJsonBool(book, ".params.overrideUsed"));
        assertEq(vm.parseJsonAddress(book, ".contracts.GuardianCanceller"), d.guardianCanceller);

        vm.chainId(1337);
        GovernanceWithNode r = _withNode();
        DeployGenesisGovernance.Deployed memory w = r.deployWith(SENDER, _weakGov(), grd, true, true);
        book = r.bookJson(SENDER, w, _weakGov(), grd);
        assertFalse(vm.parseJsonBool(book, ".params.genesisProfile"));
        assertEq(vm.parseJsonUint(book, ".params.nodeChainId"), 1337);
        assertTrue(vm.parseJsonBool(book, ".params.overrides.allowWeakGovernance"));
        assertTrue(vm.parseJsonBool(book, ".params.overrides.allowSharedHolders"));
        assertTrue(vm.parseJsonBool(book, ".params.overrideUsed"));
    }

    // ── proposal TTL (owner decision 2026-10-19: fixed at 14 days on 40204) ──

    string constant GOV_TTL_FIXED = "GOVERNANCE: proposalTtl is fixed at 1209600 (14 days) on the genesis profile";
    string constant GRD_TTL_FIXED = "GUARDIAN: proposalTtl is fixed at 1209600 (14 days) on the genesis profile";

    function test_genesis_profile_ttl_is_fixed_at_14_days() public {
        vm.chainId(40204);
        GovernanceWithNode s = _withNode();
        uint256[5] memory others = [uint256(1 days), 7 days, 14 days - 1, 14 days + 1, 30 days];
        for (uint256 i = 0; i < others.length; i++) {
            DeployGenesisGovernance.Council memory gov = _genesis(_gov());
            gov.proposalTtl = others[i];
            vm.expectRevert(bytes(GOV_TTL_FIXED));
            s.deployWith(SENDER, gov, _genesis(_grd()), false, false);
            DeployGenesisGovernance.Council memory grd = _genesis(_grd());
            grd.proposalTtl = others[i];
            vm.expectRevert(bytes(GRD_TTL_FIXED));
            s.deployWith(SENDER, _genesis(_gov()), grd, false, false);
        }
        DeployGenesisGovernance.Deployed memory d =
            s.deployWith(SENDER, _genesis(_gov()), _genesis(_grd()), false, false);
        assertEq(MultisigProposer(d.governanceMultisig).proposalTtl(), 1209600);
        assertEq(MultisigProposer(d.guardianMultisig).proposalTtl(), 1209600);
    }

    /// GENESIS_PROFILE=1 on another chain fixes the TTL the same way.
    function test_forced_genesis_profile_ttl_is_fixed() public {
        vm.chainId(1337);
        GovernanceWithNode s = _withNode();
        vm.expectRevert(bytes(GOV_TTL_FIXED));
        s.deployWith(SENDER, _gov(), _genesis(_grd()), false, false, true);
    }

    /// Rehearsal profiles accept any TTL within 1..30 days (inclusive) and nothing outside.
    function test_rehearsal_ttl_accepts_1_to_30_days_only() public {
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Council memory gov = _gov();
        DeployGenesisGovernance.Council memory grd = _grd();
        (gov.proposalTtl, grd.proposalTtl) = (1 days, 30 days);
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, gov, grd, false, false);
        assertEq(MultisigProposer(d.governanceMultisig).proposalTtl(), 1 days);
        assertEq(MultisigProposer(d.guardianMultisig).proposalTtl(), 30 days);
        // Distinct delays: the timelock's CREATE2 address depends on (deployer, delay).
        (gov.minDelay, grd.minDelay, gov.proposalTtl, grd.proposalTtl) = (49 hours, 2 hours, 30 days, 1 days);
        d = s.deployWith(SENDER, gov, grd, false, false);
        assertEq(MultisigProposer(d.governanceMultisig).proposalTtl(), 30 days);
        uint256[4] memory outside = [uint256(0), 1 days - 1, 30 days + 1, 365 days];
        for (uint256 i = 0; i < outside.length; i++) {
            gov.proposalTtl = outside[i];
            vm.expectRevert(bytes("GOVERNANCE: proposalTtl must be 1..30 days"));
            s.deployWith(SENDER, gov, grd, false, false);
        }
    }

    // ── ALLOW_SHARED_HOLDERS on the genesis profile ──

    function test_genesis_profile_refuses_shared_holders() public {
        DeployGenesisGovernance.Council memory grd = _genesis(_grd());
        grd.owners[0] = _gov().owners[2];
        vm.chainId(40204);
        GovernanceWithNode s = _withNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes(SHARED_REFUSED));
        s.deployWith(SENDER, _genesis(_gov()), grd, true, false);
        // Refused even when no owner is actually shared: the switch itself is not allowed.
        vm.expectRevert(bytes(SHARED_REFUSED));
        s.deployWith(SENDER, _genesis(_gov()), _genesis(_grd()), true, false);
        vm.chainId(1337);
        vm.expectRevert(bytes(SHARED_REFUSED));
        s.deployWith(SENDER, _genesis(_gov()), grd, true, false, true);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    // ── guardian veto exemption (owner decision 2026-10-19, fed#331) ──

    /// A full 2-of-3 GUARDIAN quorum tries to cancel a queued GOVERNANCE operation that
    /// removes the guardian, and fails; the removal executes after the 48 h delay.
    function test_guardian_quorum_cannot_cancel_its_own_removal() public {
        uint256 t0 = 2_000_000;
        vm.warp(t0);
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        TimelockController rt = TimelockController(payable(d.guardianTimelock));
        MultisigProposer gm = MultisigProposer(d.governanceMultisig);
        MultisigProposer rm = MultisigProposer(d.guardianMultisig);
        address[] memory g = _gov().owners;
        address[] memory r = _grd().owners;

        bytes memory removal = abi.encodeCall(gt.revokeRole, (gt.CANCELLER_ROLE(), d.guardianCanceller));
        _passed(gm, g, abi.encodeCall(gt.schedule, (address(gt), 0, removal, bytes32(0), 0, 48 hours)));
        bytes32 opId = gt.hashOperation(address(gt), 0, removal, bytes32(0), 0);
        assertTrue(gt.isOperationPending(opId));

        // Two guardian keys: schedule the cancel on the guardian timelock, wait, execute.
        bytes memory veto = abi.encodeCall(GuardianCanceller.cancel, (address(gt), 0, removal, bytes32(0), 0));
        _passed2(rm, r, abi.encodeCall(rt.schedule, (d.guardianCanceller, 0, veto, bytes32(0), 0, 1 hours)));
        vm.warp(t0 + 1 hours);
        vm.prank(r[0]);
        bytes32 pid = rm.propose(abi.encodeCall(rt.execute, (d.guardianCanceller, 0, veto, bytes32(0), 0)));
        vm.prank(r[1]);
        rm.approve(pid);
        vm.prank(r[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                MultisigProposer.ExecutionFailed.selector,
                abi.encodeWithSelector(GuardianCanceller.GuardianRemovalNotCancellable.selector, opId)
            )
        );
        rm.execute(pid);
        assertTrue(gt.isOperationPending(opId), "the removal is still queued");

        // The removal runs after 48 h, and the guardian path is gone.
        vm.warp(t0 + 48 hours);
        _passed(gm, g, abi.encodeCall(gt.execute, (address(gt), 0, removal, bytes32(0), 0)));
        assertTrue(gt.isOperationDone(opId));
        assertFalse(gt.hasRole(gt.CANCELLER_ROLE(), d.guardianCanceller), "guardian removed");

        // With the role gone, the guardian cannot cancel even an ordinary operation.
        bytes memory payload = abi.encodeCall(gt.updateDelay, (72 hours));
        _passed(gm, g, abi.encodeCall(gt.schedule, (address(gt), 0, payload, bytes32(0), 0, 48 hours)));
        vm.prank(d.guardianTimelock);
        vm.expectRevert();
        GuardianCanceller(d.guardianCanceller).cancel(address(gt), 0, payload, bytes32(0), 0);
    }

    /// Replacing the guardian (grant the new canceller, revoke the old, one batch) is outside
    /// the veto too; a removal bundled with any other call stays cancellable.
    function test_guardian_replacement_batch_is_exempt_but_a_bundled_action_is_not() public {
        uint256 t0 = 2_000_000;
        vm.warp(t0);
        DeployGenesisGovernance s = new DeployGenesisGovernance();
        DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, _gov(), _grd(), false, false);
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        MultisigProposer gm = MultisigProposer(d.governanceMultisig);
        GuardianCanceller c = GuardianCanceller(d.guardianCanceller);
        address[] memory g = _gov().owners;
        GuardianCanceller next = new GuardianCanceller(address(gt), makeAddr("new-guardian"));
        bytes32 canceller = gt.CANCELLER_ROLE();

        address[] memory targets = new address[](2);
        (targets[0], targets[1]) = (address(gt), address(gt));
        uint256[] memory values = new uint256[](2);
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = abi.encodeCall(gt.grantRole, (canceller, address(next)));
        payloads[1] = abi.encodeCall(gt.revokeRole, (canceller, address(c)));
        _passed(gm, g, abi.encodeCall(gt.scheduleBatch, (targets, values, payloads, bytes32(0), 0, 48 hours)));
        bytes32 replaceId = gt.hashOperationBatch(targets, values, payloads, bytes32(0), 0);

        // Bundled: the same removal plus a delay change, under another salt.
        bytes[] memory bundled = new bytes[](2);
        bundled[0] = payloads[1];
        bundled[1] = abi.encodeCall(gt.updateDelay, (0));
        _passed(
            gm,
            g,
            abi.encodeCall(gt.scheduleBatch, (targets, values, bundled, bytes32(0), bytes32(uint256(1)), 48 hours))
        );
        bytes32 bundledId = gt.hashOperationBatch(targets, values, bundled, bytes32(0), bytes32(uint256(1)));

        vm.startPrank(d.guardianTimelock);
        vm.expectRevert(abi.encodeWithSelector(GuardianCanceller.GuardianRemovalNotCancellable.selector, replaceId));
        c.cancelBatch(targets, values, payloads, bytes32(0), 0);
        c.cancelBatch(targets, values, bundled, bytes32(0), bytes32(uint256(1)));
        vm.stopPrank();
        assertFalse(gt.isOperation(bundledId), "bundled action vetoed");

        vm.warp(t0 + 48 hours);
        _passed(gm, g, abi.encodeCall(gt.executeBatch, (targets, values, payloads, bytes32(0), 0)));
        assertTrue(gt.hasRole(canceller, address(next)), "replacement canceller seated");
        assertFalse(gt.hasRole(canceller, address(c)), "old canceller removed");
    }

    /// 2-of-n pass (GUARDIAN): propose by owner 0, approve by owner 1, execute.
    function _passed2(MultisigProposer ms, address[] memory o, bytes memory data) internal returns (bytes32 id) {
        vm.prank(o[0]);
        id = ms.propose(data);
        vm.prank(o[1]);
        ms.approve(id);
        vm.prank(o[0]);
        ms.execute(id);
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

    /// run(): required inputs, the TTL default, the 0 / 1 switches and the genesis-profile
    /// refusal; the output is a book CheckDeployedAdmins passes. (The only test that sets
    /// GOV_* / GRD_* / GENESIS_GOVERNANCE_OUT / ALLOW_WEAK_GOVERNANCE / GENESIS_PROFILE:
    /// vm.setEnv is process-global and forge runs tests in parallel.)
    function test_run_requires_env_then_writes_a_book_the_admin_gate_passes() public {
        vm.recordLogs(); // the gate replays the timelocks' role history (RoleHistoryHarness)
        RoleLogArchive archive = new RoleLogArchive();
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        GovernanceWithNode s = _withNode();
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
        s.run(); // GENESIS_GOVERNANCE_OUT unset (GOV_/GRD_PROPOSAL_TTL are optional)

        vm.createDir("genesis", true);
        string memory out = "genesis/test-governance.json";
        vm.setEnv("GENESIS_GOVERNANCE_OUT", out);

        // Weak parameters are refused unless ALLOW_WEAK_GOVERNANCE=1. (Distinct delays from
        // the production run below, so the two runs do not share CREATE2 timelocks.)
        vm.setEnv("GOV_THRESHOLD", "2");
        vm.setEnv("GOV_MIN_DELAY", "7200");
        vm.setEnv("GRD_MIN_DELAY", "5400");
        vm.expectRevert(bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
        s.run();
        // A malformed switch is rejected rather than read as off / on.
        vm.setEnv("ALLOW_WEAK_GOVERNANCE", "yes");
        vm.expectRevert(bytes("ALLOW_WEAK_GOVERNANCE must be 0 or 1"));
        s.run();
        vm.setEnv("ALLOW_WEAK_GOVERNANCE", "1");
        // The reported bypass through run(): ALLOW_WEAK_GOVERNANCE=1 and a simulated chain id
        // that differs from the node's (a 40204 node, forge at 31337): refused.
        s.nodeReports(40204);
        vm.expectRevert(
            bytes(
                "chain id mismatch: node reports 40204, forge simulates 31337 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
            )
        );
        s.run();
        s.honestNode();
        // ALLOW_SHARED_HOLDERS is a strict 0 / 1 switch.
        vm.setEnv("ALLOW_SHARED_HOLDERS", "yes");
        vm.expectRevert(bytes("ALLOW_SHARED_HOLDERS must be 0 or 1"));
        s.run();
        vm.setEnv("ALLOW_SHARED_HOLDERS", "2");
        vm.expectRevert(bytes("ALLOW_SHARED_HOLDERS must be 0 or 1"));
        s.run();
        vm.setEnv("ALLOW_SHARED_HOLDERS", "0");
        // The override is impossible on the genesis profile: forced, then on chain 40204.
        vm.setEnv("GENESIS_PROFILE", "1");
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.run();
        vm.setEnv("GENESIS_PROFILE", "2");
        vm.expectRevert(bytes("GENESIS_PROFILE must be 0 or 1"));
        s.run();
        vm.setEnv("GENESIS_PROFILE", "0");
        vm.chainId(40204);
        vm.expectRevert(bytes(OVERRIDE_REFUSED));
        s.run();
        vm.chainId(31337); // fixed: via-IR may reorder a `block.chainid` read around vm.chainId
        // On the genesis profile, ALLOW_SHARED_HOLDERS=1 and any TTL but 1209600 are refused.
        vm.setEnv("ALLOW_WEAK_GOVERNANCE", "0");
        vm.setEnv("GENESIS_PROFILE", "1");
        vm.setEnv("ALLOW_SHARED_HOLDERS", "1");
        vm.expectRevert(bytes(SHARED_REFUSED));
        s.run();
        vm.setEnv("ALLOW_SHARED_HOLDERS", "0");
        vm.setEnv("GOV_PROPOSAL_TTL", "1209599");
        vm.expectRevert(bytes(GOV_TTL_FIXED));
        s.run();
        vm.setEnv("GOV_PROPOSAL_TTL", "1209600");
        vm.setEnv("GENESIS_PROFILE", "0");
        vm.setEnv("ALLOW_WEAK_GOVERNANCE", "1");
        // Off the genesis profile the override deploys the rehearsal parameters.
        DeployGenesisGovernance.Deployed memory weak = s.run();
        assertEq(MultisigProposer(weak.governanceMultisig).threshold(), 2);
        assertEq(TimelockController(payable(weak.governanceTimelock)).getMinDelay(), 7200);
        assertEq(MultisigProposer(weak.governanceMultisig).proposalTtl(), 14 days, "TTL defaults when unset");
        assertEq(MultisigProposer(weak.guardianMultisig).proposalTtl(), 14 days, "TTL defaults when unset");
        vm.setEnv("ALLOW_WEAK_GOVERNANCE", "0");
        vm.setEnv("GOV_THRESHOLD", "3");
        vm.setEnv("GOV_MIN_DELAY", "172800");
        vm.setEnv("GRD_MIN_DELAY", "3600");

        // An explicit TTL is bounds-checked, then used.
        vm.setEnv("GRD_PROPOSAL_TTL", "2592001");
        vm.expectRevert(bytes("GUARDIAN: proposalTtl must be 1..30 days"));
        s.run();
        vm.setEnv("GRD_PROPOSAL_TTL", "604800");

        DeployGenesisGovernance.Deployed memory d = s.run();
        assertEq(MultisigProposer(d.governanceMultisig).proposalTtl(), 14 days);
        assertEq(MultisigProposer(d.guardianMultisig).proposalTtl(), 7 days);

        string memory book = vm.readFile(out);
        assertEq(vm.parseJsonAddress(book, ".deployer"), SENDER);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceTimelock"), d.governanceTimelock);
        assertEq(vm.parseJsonAddress(book, ".contracts.GuardianMultisig"), d.guardianMultisig);
        assertEq(vm.parseJsonUint(book, ".params.governance.threshold"), 3);
        assertEq(vm.parseJsonUint(book, ".params.guardian.minDelay"), 3600);
        assertEq(vm.parseJsonUint(book, ".params.governance.proposalTtl"), 1209600);
        assertEq(vm.parseJsonUint(book, ".params.guardian.proposalTtl"), 604800);
        assertTrue(vm.parseJsonBool(book, ".params.guardianCancelsGovernance"));

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        GateWithHistory c = new GateWithHistory();
        c.useArchive(archive);
        c.check(book, true);
        assertEq(c.deployerAdmin(), 0, "DEPLOYER-ADMIN reads 0 after hand-over");
        assertEq(c.factoryAdmin(), 0);
        assertEq(c.noCode(), 0);
        assertEq(c.timelockHolders(), 0, "both councils hold their timelocks exclusively");
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
        MultisigProposer ms = new MultisigProposer(address(tl), o, 2, 7 days);
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

/// GENESIS-FLOOR: on a node reporting 40204 the gate re-reads the councils from chain.
contract GenesisFloorGateTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    string constant FLOOR = "CheckDeployedAdmins: genesis governance floor not met (see log)";
    string constant HOLDERS = "CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)";

    RoleLogArchive internal archive;

    function setUp() public {
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        // The gate replays every listed timelock's role history (RoleHistoryHarness).
        vm.recordLogs();
        archive = new RoleLogArchive();
    }

    /// A node-stubbed gate reading the test's recorded role history.
    function _gate() internal returns (GateWithNode c) {
        c = new GateWithNode();
        c.useArchive(archive);
    }

    /// `vm.expectRevert` after absorbing the recorded logs in THIS frame (a reverted gate call
    /// would roll back an absorb made inside it).
    function _expectRevert(string memory reason) internal {
        archive.absorb();
        vm.expectRevert(bytes(reason));
    }

    /// A governance book's contracts section (the five DeployGenesisGovernance entries).
    function _bareBook(DeployGenesisGovernance.Deployed memory d) internal pure returns (string memory) {
        return string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(d.governanceMultisig),
            '","GuardianTimelock":"',
            vm.toString(d.guardianTimelock),
            '","GuardianMultisig":"',
            vm.toString(d.guardianMultisig),
            '","GuardianCanceller":"',
            vm.toString(d.guardianCanceller),
            '"},"aaStack":{}}'
        );
    }

    function _addrs(uint256 base, uint256 n) internal pure returns (address[] memory o) {
        o = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            o[i] = address(uint160(base + i));
        }
    }

    function _council(uint256 base, uint256 n, uint256 m, uint256 delay)
        internal
        pure
        returns (DeployGenesisGovernance.Council memory)
    {
        return DeployGenesisGovernance.Council({
            owners: _addrs(base, n), threshold: m, minDelay: delay, proposalTtl: 14 days
        });
    }

    /// The councils DeployGenesisGovernance writes on the genesis profile pass the gate.
    function test_gate_on_40204_passes_the_genesis_councils() public {
        vm.chainId(40204);
        GovernanceWithNode g = new GovernanceWithNode();
        DeployGenesisGovernance.Council memory gov = _council(0xA000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory grd = _council(0xB000, 3, 2, 1 hours);
        DeployGenesisGovernance.Deployed memory d = g.deployWith(SENDER, gov, grd, false, false);
        GateWithNode c = _gate();
        c.check(g.bookJson(SENDER, d, gov, grd), true);
        assertEq(c.genesisFloor(), 0);
        assertEq(c.timelockHolders(), 0, "GuardianCanceller is the GOVERNANCE timelock's one allowed extra");
    }

    /// The guardian veto is required on 40204 (Codex P2 on #324 at e377bbd): with the canceller's
    /// CANCELLER revoked and its entry left out of the book, the council is the timelock's sole
    /// canceller and its holder sets are exact, but GENESIS-FLOOR refuses the missing veto. The
    /// same holds when the canceller is listed but no longer holds the role.
    function test_gate_on_40204_requires_the_guardian_veto() public {
        vm.chainId(40204);
        GovernanceWithNode g = new GovernanceWithNode();
        DeployGenesisGovernance.Council memory gov = _council(0xA000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory grd = _council(0xB000, 3, 2, 1 hours);
        DeployGenesisGovernance.Deployed memory d = g.deployWith(SENDER, gov, grd, false, false);
        bytes32 cancellerRole = keccak256("CANCELLER_ROLE");
        vm.prank(d.governanceTimelock);
        TimelockController(payable(d.governanceTimelock)).revokeRole(cancellerRole, d.guardianCanceller);
        string memory noCanceller = string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(d.governanceMultisig),
            '","GuardianTimelock":"',
            vm.toString(d.guardianTimelock),
            '","GuardianMultisig":"',
            vm.toString(d.guardianMultisig),
            '"},"aaStack":{}}'
        );
        GateWithNode c = _gate();
        _expectRevert(FLOOR);
        c.check(noCanceller, false);
        // Off the genesis profile the veto is not required, and the holder sets are exact.
        vm.chainId(1);
        GateWithNode off = _gate();
        off.check(noCanceller, false);
        assertEq(off.timelockHolders(), 0);
        // Listed, but without the role: refused on 40204 as well.
        vm.chainId(40204);
        GateWithNode c2 = _gate();
        string memory bare = _bareBook(d);
        _expectRevert(FLOOR);
        c2.check(bare, false);
    }

    /// The reported outcome (2-of-3 GOVERNANCE behind 24 h, deployed with the override while
    /// forge simulated another chain) is caught on chain by the 40204 gate, with or without
    /// the book's params.
    function test_gate_on_40204_flags_a_weak_council_deployed_off_profile() public {
        vm.chainId(1);
        GovernanceWithNode g = new GovernanceWithNode();
        DeployGenesisGovernance.Council memory gov = _council(0xA000, 3, 2, 24 hours);
        DeployGenesisGovernance.Council memory grd = _council(0xB000, 3, 2, 1 hours);
        DeployGenesisGovernance.Deployed memory d = g.deployWith(SENDER, gov, grd, false, true);
        string memory book = g.bookJson(SENDER, d, gov, grd);

        vm.chainId(40204);
        GateWithNode c = _gate();
        _expectRevert(FLOOR);
        c.check(book, false);
        // Contracts only, no params: the on-chain reads alone fail it.
        string memory bare = _bareBook(d);
        GateWithNode c2 = _gate();
        _expectRevert(FLOOR);
        c2.check(bare, false);
        // The same book off 40204 is not held to the genesis floors (its holder sets are exact).
        vm.chainId(1);
        GateWithNode c3 = _gate();
        c3.check(bare, false);
        assertEq(c3.timelockHolders(), 0);
    }

    function test_floor_problems_read_from_chain() public {
        GateHarness h = new GateHarness();
        vm.chainId(1);
        GovernanceWithNode g = new GovernanceWithNode();
        DeployGenesisGovernance.Deployed memory d =
            g.deployWith(SENDER, _council(0xA000, 3, 2, 24 hours), _council(0xB000, 2, 1, 1 hours), false, true);
        assertEq(
            h.problem(d.governanceTimelock, d.governanceMultisig, true),
            "GOVERNANCE timelock: minDelay below the 48 h genesis floor"
        );
        assertEq(
            h.problem(d.guardianTimelock, d.guardianMultisig, false),
            "GUARDIAN multisig: below the 2-of-3 genesis floor"
        );
        // 3-of-6 meets 3-of-5 but is no majority; a 7-day TTL is not the fixed value.
        DeployGenesisGovernance.Council memory six = _council(0xC000, 6, 3, 49 hours);
        DeployGenesisGovernance.Council memory seven = _council(0xD000, 5, 3, 50 hours);
        seven.proposalTtl = 7 days;
        DeployGenesisGovernance.Deployed memory d6 =
            g.deployWith(SENDER, six, _council(0xE000, 3, 2, 2 hours), false, true);
        DeployGenesisGovernance.Deployed memory d7 =
            g.deployWith(SENDER, seven, _council(0xF000, 3, 2, 3 hours), false, true);
        assertEq(
            h.problem(d6.governanceTimelock, d6.governanceMultisig, true),
            "GOVERNANCE multisig: threshold is not a majority of owners"
        );
        assertEq(
            h.problem(d7.governanceTimelock, d7.governanceMultisig, true),
            "GOVERNANCE multisig: proposalTtl is not the fixed 14-day genesis value"
        );
        assertEq(
            h.problem(d7.governanceTimelock, d6.governanceMultisig, true),
            "GOVERNANCE multisig does not front its timelock"
        );
    }

    /// The gate's own chain-id source: a mismatch reverts, and 40204 without a node fails closed.
    function test_gate_refuses_chain_id_mismatch_and_needs_a_node_on_40204() public {
        string memory empty = string.concat('{"deployer":"', vm.toString(SENDER), '","contracts":{},"aaStack":{}}');
        GateWithNode c = new GateWithNode();
        c.nodeReports(40204);
        vm.chainId(1);
        vm.expectRevert(
            bytes(
                "chain id mismatch: node reports 40204, forge simulates 1 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
            )
        );
        c.check(empty, false);
        vm.chainId(40204);
        CheckDeployedAdmins real = new CheckDeployedAdmins();
        vm.expectRevert(bytes("genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)"));
        real.check(empty, false);
    }

    /// A book recording an override or an off-profile run fails on 40204, as does a canceller
    /// that is not wired to the listed councils.
    function test_gate_flags_recorded_overrides_and_a_miswired_canceller() public {
        vm.chainId(40204);
        GovernanceWithNode g = new GovernanceWithNode();
        DeployGenesisGovernance.Council memory gov = _council(0xA000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory grd = _council(0xB000, 3, 2, 1 hours);
        DeployGenesisGovernance.Deployed memory d = g.deployWith(SENDER, gov, grd, false, false);
        string memory head = string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '","GuardianTimelock":"',
            vm.toString(d.guardianTimelock),
            '"'
        );
        GateWithNode c = _gate();
        _expectRevert(FLOOR);
        c.check(string.concat(head, '},"aaStack":{},"params":{"overrideUsed":true}}'), false);
        GateWithNode c2 = _gate();
        _expectRevert(FLOOR);
        c2.check(string.concat(head, '},"aaStack":{},"params":{"genesisProfile":false}}'), false);
        GateWithNode c3 = _gate();
        _expectRevert(FLOOR);
        c3.check(
            string.concat(
                head,
                ',"GovernanceMultisig":"',
                vm.toString(d.governanceMultisig),
                '","GuardianMultisig":"',
                vm.toString(d.guardianMultisig),
                '","GuardianCanceller":"',
                vm.toString(d.governanceMultisig),
                '"},"aaStack":{}}'
            ),
            false
        );
    }

    // ---- The GuardianCanceller is the GOVERNANCE timelock's ONLY allowed extra canceller ----

    /// A memory copy (plain assignment aliases memory structs).
    function _copy(DeployGenesisGovernance.Deployed memory d)
        internal
        pure
        returns (DeployGenesisGovernance.Deployed memory)
    {
        return DeployGenesisGovernance.Deployed({
            governanceTimelock: d.governanceTimelock,
            governanceMultisig: d.governanceMultisig,
            guardianTimelock: d.guardianTimelock,
            guardianMultisig: d.guardianMultisig,
            guardianCanceller: d.guardianCanceller
        });
    }

    function _genesisCouncils() internal returns (GovernanceWithNode g, DeployGenesisGovernance.Deployed memory d) {
        vm.chainId(40204);
        g = new GovernanceWithNode();
        d = g.deployWith(SENDER, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours), false, false);
    }

    /// A rogue extra admin or extra canceller on the GOVERNANCE timelock (granted by the timelock
    /// itself, i.e. a governance operation) is caught although the book's GuardianCanceller is
    /// allowed; the clean book passes.
    function test_gate_catches_a_rogue_admin_or_canceller_beside_the_guardian_canceller() public {
        (, DeployGenesisGovernance.Deployed memory d) = _genesisCouncils();
        string memory book = _bareBook(d);
        GateWithNode clean = _gate();
        clean.check(book, false);
        assertEq(clean.timelockHolders(), 0);

        TimelockController tl = TimelockController(payable(d.governanceTimelock));
        bytes32 canceller = tl.CANCELLER_ROLE();
        vm.prank(d.governanceTimelock);
        tl.grantRole(canceller, makeAddr("rogue-canceller"));
        GateWithNode c = _gate();
        _expectRevert(HOLDERS);
        c.check(book, false);

        vm.prank(d.governanceTimelock);
        tl.revokeRole(canceller, makeAddr("rogue-canceller"));
        GateWithNode back = _gate();
        back.check(book, false);
        assertEq(back.timelockHolders(), 0, "revoked: clean again");

        bytes32 admin = tl.DEFAULT_ADMIN_ROLE();
        vm.prank(d.governanceTimelock);
        tl.grantRole(admin, makeAddr("rogue-admin"));
        GateWithNode c2 = _gate();
        _expectRevert(HOLDERS);
        c2.check(book, false);
    }

    /// Without the governance book's GuardianCanceller entry the seat is an unexpected canceller.
    function test_gate_refuses_the_canceller_seat_when_no_book_lists_it() public {
        (, DeployGenesisGovernance.Deployed memory d) = _genesisCouncils();
        string memory book = string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(d.governanceMultisig),
            '"},"aaStack":{}}'
        );
        vm.chainId(1); // off the floors: only the holder sets are in question here
        GateWithNode c = _gate();
        _expectRevert(HOLDERS);
        c.check(book, false);
    }

    /// The book's GuardianCanceller must be the CREATE2 instance for (GOVERNANCE, GUARDIAN) with
    /// this build's code, wired to them, and the GUARDIAN timelock must have exact holders.
    function test_book_guardian_canceller_is_verified_on_chain() public {
        (, DeployGenesisGovernance.Deployed memory d) = _genesisCouncils();
        BookCancellerChecks h = new BookCancellerChecks();
        h.useArchive(archive);
        (string memory p, address got) = h.problem(_bareBook(d), d.governanceTimelock);
        assertEq(p, "");
        assertEq(got, d.guardianCanceller);

        // Same code and wiring, but not at the CREATE2 address (a plain CREATE impostor).
        GuardianCanceller impostor = new GuardianCanceller(d.governanceTimelock, d.guardianTimelock);
        DeployGenesisGovernance.Deployed memory e = _copy(d);
        e.guardianCanceller = address(impostor);
        (p,) = h.problem(_bareBook(e), d.governanceTimelock);
        assertEq(p, "GuardianCanceller is not at its CREATE2 address for (GovernanceTimelock, GuardianTimelock)");

        // Another timelock's book, or a canceller listed beside another guardian.
        (p,) = h.problem(_bareBook(d), d.guardianTimelock);
        assertEq(p, "governance book does not name this GovernanceTimelock");
        e = _copy(d);
        e.guardianTimelock = d.governanceTimelock;
        (p,) = h.problem(_bareBook(e), d.governanceTimelock);
        assertEq(p, "GuardianCanceller is not at its CREATE2 address for (GovernanceTimelock, GuardianTimelock)");

        // The right address with other code at it.
        GuardianCanceller other = new GuardianCanceller(d.guardianTimelock, makeAddr("elsewhere"));
        bytes memory real = d.guardianCanceller.code;
        vm.etch(d.guardianCanceller, address(other).code);
        (p,) = h.problem(_bareBook(d), d.governanceTimelock);
        assertEq(p, "GuardianCanceller: runtime code is not this build's GuardianCanceller");
        vm.etch(d.guardianCanceller, real);

        // Re-pointed at another guardian (setGuardian through GOVERNANCE).
        vm.prank(d.governanceTimelock);
        GuardianCanceller(d.guardianCanceller).setGuardian(makeAddr("new-guardian"));
        (p,) = h.problem(_bareBook(d), d.governanceTimelock);
        assertEq(p, "GuardianCanceller answers to another guardian");
        vm.prank(d.governanceTimelock);
        GuardianCanceller(d.guardianCanceller).setGuardian(d.guardianTimelock);

        // The GUARDIAN council must be the ceremony's MultisigProposer (CREATE2 provenance).
        e = _copy(d);
        e.guardianMultisig = address(new MultisigProposer(d.guardianTimelock, _addrs(0xB000, 3), 2, 14 days));
        (p,) = h.problem(_bareBook(e), d.governanceTimelock);
        assertEq(
            p,
            "GuardianMultisig: not the MultisigProposer the ceremony deploys (Genesis.GuardianMultisig) for this timelock, owners, threshold and proposal TTL"
        );

        // The GUARDIAN timelock itself must have exact holders.
        TimelockController gtl = TimelockController(payable(d.guardianTimelock));
        bytes32 proposer = gtl.PROPOSER_ROLE();
        vm.prank(d.guardianTimelock);
        gtl.grantRole(proposer, makeAddr("rogue-proposer"));
        (p,) = h.problem(_bareBook(d), d.governanceTimelock);
        assertEq(p, "GuardianTimelock: PROPOSER_ROLE holders are not exactly the multisig");

        // A book with the canceller but no guardian council entries.
        string memory noCouncil = string.concat(
            '{"contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '","GuardianCanceller":"',
            vm.toString(d.guardianCanceller),
            '"}}'
        );
        (p,) = h.problem(noCouncil, d.governanceTimelock);
        assertEq(p, "GuardianCanceller listed without GuardianTimelock and GuardianMultisig");
    }

    /// An impostor canceller listed in a book permits nothing (TIMELOCK-HOLDERS), and two books
    /// naming different cancellers for one GOVERNANCE timelock fail the gate.
    function test_gate_refuses_an_impostor_or_conflicting_canceller() public {
        (, DeployGenesisGovernance.Deployed memory d) = _genesisCouncils();
        vm.chainId(1);
        GuardianCanceller impostor = new GuardianCanceller(d.governanceTimelock, d.guardianTimelock);
        DeployGenesisGovernance.Deployed memory e = _copy(d);
        e.guardianCanceller = address(impostor);
        GateWithNode c = _gate();
        _expectRevert(HOLDERS);
        c.check(_bareBook(e), false);

        string[] memory extras = new string[](1);
        extras[0] = _bareBook(e);
        GateWithNode c2 = _gate();
        _expectRevert(HOLDERS);
        c2.checkAll(_bareBook(d), extras, false);
    }
}

contract GateHarness is CheckDeployedAdmins {
    function problem(address tl, address ms, bool governance) external view returns (string memory) {
        return _councilFloorProblem(governance ? "GOVERNANCE" : "GUARDIAN", tl, ms, governance);
    }
}

/// Genesis profile (chain 40204, as the node reports it): the GOVERNANCE floors (minDelay >= 48 h,
/// multisig m >= 3 of n >= 5) hold at BOTH entry points: DeployGenesisGovernance refuses a weak
/// council before it broadcasts, and CheckDeployedAdmins re-reads them from chain. GUARDIAN keeps
/// its 1 h floor; rehearsal chains keep their 1 h / 1-of-1 minimums.
contract GenesisGovernanceFloorTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    string constant GATE_FLOOR = "CheckDeployedAdmins: genesis governance floor not met (see log)";

    RoleLogArchive archive;

    function setUp() public {
        vm.recordLogs(); // the gate replays the timelocks' role history (RoleHistoryHarness)
        archive = new RoleLogArchive();
        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
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

    function _gov() internal pure returns (DeployGenesisGovernance.Council memory) {
        return _council(0xA000, 5, 3, 48 hours);
    }

    function _grd() internal pure returns (DeployGenesisGovernance.Council memory) {
        return _council(0xB000, 3, 2, 1 hours);
    }

    function _deploy(DeployGenesisGovernance.Council memory gov, DeployGenesisGovernance.Council memory grd)
        internal
        returns (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d)
    {
        s = new GovernanceWithNode();
        // Rehearsal deploys of sub-floor councils need the explicit override; it is refused on 40204.
        d = s.deployWith(SENDER, gov, grd, false, block.chainid != 40204);
    }

    function _gate() internal returns (GateWithNode g) {
        g = new GateWithNode();
        g.useArchive(archive);
    }

    function _expectDeployRefused(DeployGenesisGovernance.Council memory gov, bytes memory reason) internal {
        GovernanceWithNode s = new GovernanceWithNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(reason);
        s.deployWith(SENDER, gov, _grd(), false, false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    // ---- deploy entry point (before anything is broadcast) ----

    function test_genesis_deploy_refuses_governance_delay_below_48h() public {
        vm.chainId(40204);
        DeployGenesisGovernance.Council memory gov = _gov();
        gov.minDelay = 48 hours - 1;
        _expectDeployRefused(gov, bytes("GOVERNANCE: minDelay must be >= 48 hours (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
        gov.minDelay = 1 hours;
        _expectDeployRefused(gov, bytes("GOVERNANCE: minDelay must be >= 48 hours (ALLOW_WEAK_GOVERNANCE=1 to waive)"));
    }

    function test_genesis_deploy_refuses_single_key_governance() public {
        vm.chainId(40204);
        _expectDeployRefused(
            _council(0xA000, 1, 1, 1 hours),
            bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)")
        );
        _expectDeployRefused(
            _council(0xA000, 1, 1, 48 hours),
            bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)")
        );
    }

    function test_genesis_deploy_refuses_weak_quorum() public {
        vm.chainId(40204);
        // 2-of-5: enough owners, too low a threshold.
        _expectDeployRefused(
            _council(0xA000, 5, 2, 48 hours),
            bytes("GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)")
        );
        // 3-of-4: the threshold, too few owners.
        _expectDeployRefused(
            _council(0xA000, 4, 3, 48 hours),
            bytes("GOVERNANCE: owners must be >= 5 (ALLOW_WEAK_GOVERNANCE=1 to waive)")
        );
    }

    /// The node, not forge's simulated id, selects the profile: a weak council against a 40204
    /// node is refused on the chain id before the floors are even reached.
    function test_genesis_deploy_weak_council_cannot_dodge_by_chain_id() public {
        GovernanceWithNode s = new GovernanceWithNode();
        s.nodeReports(40204);
        vm.chainId(1);
        vm.expectRevert(
            bytes(
                "chain id mismatch: node reports 40204, forge simulates 1 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
            )
        );
        s.deployWith(SENDER, _council(0xA000, 1, 1, 1 hours), _grd(), false, false);
    }

    function test_genesis_deploy_accepts_floor_councils_and_guardian_at_1h() public {
        vm.chainId(40204);
        (, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        assertEq(TimelockController(payable(d.governanceTimelock)).getMinDelay(), 48 hours);
        assertEq(TimelockController(payable(d.guardianTimelock)).getMinDelay(), 1 hours);
        assertEq(MultisigProposer(d.governanceMultisig).threshold(), 3);
    }

    function test_rehearsal_deploy_keeps_its_minimums() public {
        (, DeployGenesisGovernance.Deployed memory d) = _deploy(_council(0xA000, 1, 1, 1 hours), _grd());
        assertEq(MultisigProposer(d.governanceMultisig).threshold(), 1);
        assertEq(TimelockController(payable(d.governanceTimelock)).getMinDelay(), 1 hours);
    }

    // ---- admin gate entry point (re-read from chain) ----

    /// A council deployed off the genesis profile, then presented to the gate on a 40204 node.
    function _gateRefusesOnGenesis(DeployGenesisGovernance.Council memory gov) internal {
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(gov, _grd());
        string memory book = s.bookJson(SENDER, d, gov, _grd());
        _gate().check(book, true); // rehearsal: passes
        vm.chainId(40204);
        GateWithNode g = _gate();
        vm.expectRevert(bytes(GATE_FLOOR));
        g.check(book, true);
    }

    function test_genesis_gate_refuses_governance_delay_below_48h() public {
        _gateRefusesOnGenesis(_council(0xA000, 5, 3, 1 hours));
    }

    function test_genesis_gate_refuses_single_key_governance() public {
        _gateRefusesOnGenesis(_council(0xA000, 1, 1, 1 hours));
    }

    function test_genesis_gate_refuses_weak_quorum() public {
        _gateRefusesOnGenesis(_council(0xA000, 5, 2, 48 hours));
    }

    function test_genesis_gate_refuses_too_few_owners() public {
        _gateRefusesOnGenesis(_council(0xA000, 4, 3, 48 hours));
    }

    /// A council that met the floors at genesis and later lowered its own delay fails the gate.
    function test_genesis_gate_refuses_governance_delay_lowered_after_deploy() public {
        vm.chainId(40204);
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        string memory book = s.bookJson(SENDER, d, _gov(), _grd());
        _gate().check(book, true);

        TimelockController tl = TimelockController(payable(d.governanceTimelock));
        MultisigProposer ms = MultisigProposer(d.governanceMultisig);
        bytes memory payload = abi.encodeCall(tl.updateDelay, (1 hours));
        _passed(ms, abi.encodeCall(tl.schedule, (address(tl), 0, payload, bytes32(0), 0, 48 hours)));
        vm.warp(block.timestamp + 48 hours);
        _passed(ms, abi.encodeCall(tl.execute, (address(tl), 0, payload, bytes32(0), 0)));
        assertEq(tl.getMinDelay(), 1 hours);

        GateWithNode g = _gate();
        vm.expectRevert(bytes(GATE_FLOOR));
        g.check(book, true);
    }

    function test_genesis_gate_passes_floor_councils() public {
        vm.chainId(40204);
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        GateWithNode g = _gate();
        g.check(s.bookJson(SENDER, d, _gov(), _grd()), true);
        assertEq(g.timelockHolders(), 0);
    }

    /// GUARDIAN lowers its own delay through its 2-of-3 council after a valid genesis deploy.
    function _guardianLowersDelay(DeployGenesisGovernance.Deployed memory d, uint256 to) internal {
        TimelockController tl = TimelockController(payable(d.guardianTimelock));
        MultisigProposer ms = MultisigProposer(d.guardianMultisig);
        uint256 delay = tl.getMinDelay();
        bytes memory payload = abi.encodeCall(tl.updateDelay, (to));
        _passedBy(ms, _grd().owners, abi.encodeCall(tl.schedule, (address(tl), 0, payload, bytes32(0), 0, delay)));
        vm.warp(block.timestamp + delay);
        _passedBy(ms, _grd().owners, abi.encodeCall(tl.execute, (address(tl), 0, payload, bytes32(0), 0)));
        assertEq(tl.getMinDelay(), to);
    }

    /// A valid genesis deployment whose GUARDIAN later sets its delay to zero fails the gate.
    function test_genesis_gate_refuses_guardian_delay_lowered_to_zero() public {
        vm.chainId(40204);
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        string memory book = s.bookJson(SENDER, d, _gov(), _grd());
        _gate().check(book, true);
        _guardianLowersDelay(d, 0);
        GateWithNode g = _gate();
        vm.expectRevert(bytes(GATE_FLOOR));
        g.check(book, true);
    }

    /// Boundary: a GUARDIAN delay of exactly 1 h passes the gate, 1 h - 1 s does not.
    function test_genesis_gate_guardian_delay_boundary() public {
        vm.chainId(40204);
        DeployGenesisGovernance.Council memory grd = _grd();
        grd.minDelay = 2 hours;
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), grd);
        string memory book = s.bookJson(SENDER, d, _gov(), grd);
        _guardianLowersDelay(d, 1 hours);
        GateWithNode ok = _gate();
        ok.check(book, true); // exactly 1 h meets the floor (check reverts otherwise)
        _guardianLowersDelay(d, 1 hours - 1);
        GateWithNode g = _gate();
        vm.expectRevert(bytes(GATE_FLOOR));
        g.check(book, true);
    }

    /// Boundary at the gate: GOVERNANCE at exactly 48 h passes, 48 h - 1 s is refused.
    function test_genesis_gate_governance_delay_boundary() public {
        _gateRefusesOnGenesis(_council(0xA000, 5, 3, 48 hours - 1));
        vm.chainId(40204); // deployed on the genesis profile: no override recorded in its book
        DeployGenesisGovernance.Council memory gov = _council(0xC000, 5, 3, 48 hours);
        DeployGenesisGovernance.Council memory grd = _council(0xD000, 3, 2, 3 hours);
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(gov, grd);
        string memory book = s.bookJson(SENDER, d, gov, grd);
        vm.chainId(40204);
        GateWithNode g = _gate();
        g.check(book, true);
    }

    /// A book that lists a council timelock without its multisig cannot skip the floor check.
    function test_genesis_gate_refuses_timelock_listed_without_its_multisig() public {
        vm.chainId(40204);
        (, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        string memory book = string.concat(
            '{"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(d.governanceTimelock),
            '"},"aaStack":{}}'
        );
        GateWithNode g = _gate();
        vm.expectRevert(bytes(GATE_FLOOR));
        g.check(book, true);
    }

    /// The gate on 40204 with no node to ask fails closed (it never falls back to rehearsal).
    function test_genesis_gate_without_a_node_fails_closed() public {
        vm.chainId(40204);
        (GovernanceWithNode s, DeployGenesisGovernance.Deployed memory d) = _deploy(_gov(), _grd());
        string memory book = s.bookJson(SENDER, d, _gov(), _grd());
        GateWithNode g = _gate();
        g.noNode();
        vm.expectRevert(bytes("genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)"));
        g.check(book, true);
    }

    /// Fuzz the deploy entry point over every legal council shape: on 40204 GOVERNANCE deploys
    /// iff m >= 3, n >= 5, m > n/2 and minDelay >= 48 h; otherwise nothing is broadcast.
    function testFuzz_genesis_deploy_governance_floor(uint8 nSeed, uint8 mSeed, uint32 delaySeed) public {
        vm.chainId(40204);
        uint256 n = bound(nSeed, 1, 10);
        uint256 m = bound(mSeed, 1, n);
        uint256 delay = bound(delaySeed, 1 hours + 1, 96 hours);
        DeployGenesisGovernance.Council memory gov = _council(0xA000, n, m, delay);
        GovernanceWithNode s = new GovernanceWithNode();
        uint64 nonceBefore = vm.getNonce(SENDER);
        bool ok = m >= 3 && n >= 5 && m * 2 > n && delay >= 48 hours;
        if (!ok) {
            vm.expectRevert();
            s.deployWith(SENDER, gov, _grd(), false, false);
            assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        } else {
            DeployGenesisGovernance.Deployed memory d = s.deployWith(SENDER, gov, _grd(), false, false);
            assertEq(TimelockController(payable(d.governanceTimelock)).getMinDelay(), delay);
            assertEq(MultisigProposer(d.governanceMultisig).threshold(), m);
        }
    }

    function _passed(MultisigProposer ms, bytes memory data) internal {
        _passedBy(ms, _gov().owners, data);
    }

    function _passedBy(MultisigProposer ms, address[] memory o, bytes memory data) internal {
        uint256 m = ms.threshold();
        vm.prank(o[0]);
        bytes32 id = ms.propose(data);
        for (uint256 i = 1; i < m; i++) {
            vm.prank(o[i]);
            ms.approve(id);
        }
        vm.prank(o[0]);
        ms.execute(id);
    }
}
