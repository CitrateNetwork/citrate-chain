// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {DeployV060Genesis} from "../../script/DeployV060Genesis.s.sol";
import {V060GovernanceSpec} from "../../script/lib/V060GovernanceSpec.sol";
import {Salts} from "../../script/Salts.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";
import {GuardianCancellerV2} from "../../src/genesis/GuardianCancellerV2.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {FederatedRoundLedger} from "../../src/FederatedRoundLedger.sol";
import {OrganizationSBT} from "../../src/cit_agent/OrganizationSBT.sol";
import {AgentSBT} from "../../src/cit_agent/AgentSBT.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {RoleLogArchive, RecordedRoleHistory} from "./RoleHistoryHarness.sol";
import {GovernanceWithNode, NodeStub} from "./NodeChainIdHarness.sol";

contract V060LiveWithNode is DeployV060Genesis, RecordedRoleHistory, NodeStub {
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

/// @title V060LiveR1007.t: the 0.6.0 contracts deployed post-genesis on r1007 (live mode)
/// @notice r1007's block 0 is r1006's state with every non-producer key rotated in storage
///         (rotate_keys.py): the councils keep their r1006 addresses, but their owners are the
///         r1007 keys, and the GOVERNANCE timelock's extra CANCELLER is GuardianCanceller v1.
///         setUp builds exactly that shape: P1 (v1 mode) with the "r1006" owners, then the
///         owners rewritten in the multisigs' storage to the "r1007" inventory keys.
///         The live mode must:
///           - authenticate a rotated multisig by its runtime code hash and its owners (the
///             CREATE2 provenance over the current owners cannot hold);
///           - deploy ProviderRegistry and GuardianCancellerV2 itself, then the other eight;
///           - verify the set pre-swap (v1 still the canceller, v2 holding nothing);
///           - give the canceller-swap proposal only once v2 has this build's code at its
///             predicted address (fed #561 review), and that proposal, executed through the
///             GOVERNANCE multisig and timelock, must make the full verify pass.
contract V060LiveR1007Test is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    uint128 constant MIN_BOND = 100 ether; // owner 2026-11-11 (rehearsal values)
    uint128 constant DEFAULT_BOND = 1000 ether;

    RoleLogArchive internal archive;
    DeployGenesisGovernance.Deployed internal gov;
    address[] internal govNew;
    address[] internal grdNew;
    FederatedRoundLedger internal frl;
    GuardianRecoveryModule internal recoveryV1;
    OrganizationSBT internal orgSbt;
    AgentSBT internal agentSbt;
    address internal liveDeployer;

    function setUp() public {
        vm.recordLogs();
        archive = new RoleLogArchive();
        vm.chainId(40204);
        GovernanceWithNode g = new GovernanceWithNode();
        // The "r1006" ceremony: v1 canceller, owners that the rotation retires.
        gov = g.deployWith(SENDER, _council(0xA000, 5, 3, 48 hours), _council(0xB000, 3, 2, 1 hours), false, false);
        // The "r1007" rotation: the same contracts, the owners rewritten in storage.
        govNew = _addrs(0xE000, 5);
        grdNew = _addrs(0xF000, 3);
        _rotate(gov.governanceMultisig, _addrs(0xA000, 5), govNew);
        _rotate(gov.guardianMultisig, _addrs(0xB000, 3), grdNew);
        frl = FederatedRoundLedger(_viaFactory("FederatedRoundLedger", type(FederatedRoundLedger).creationCode));
        recoveryV1 =
            GuardianRecoveryModule(_viaFactory("GuardianRecoveryModule", type(GuardianRecoveryModule).creationCode));
        CitrateMemberSBT member = new CitrateMemberSBT(gov.governanceTimelock);
        orgSbt = new OrganizationSBT(gov.governanceTimelock);
        agentSbt = new AgentSBT(gov.governanceTimelock, orgSbt, IERC721(address(member)));
        liveDeployer = SENDER;
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
        returns (DeployGenesisGovernance.Council memory c)
    {
        c.owners = _addrs(base, n);
        c.threshold = m;
        c.minDelay = delay;
        c.proposalTtl = 14 days;
    }

    /// rotate_keys.py on one MultisigProposer: `_owners` (slot 0) elements and `isOwner` (slot 1).
    function _rotate(address ms, address[] memory olds, address[] memory news) internal {
        bytes32 base = keccak256(abi.encode(uint256(0)));
        for (uint256 i = 0; i < olds.length; i++) {
            vm.store(ms, bytes32(uint256(base) + i), bytes32(uint256(uint160(news[i]))));
            vm.store(ms, keccak256(abi.encode(olds[i], uint256(1))), bytes32(0));
            vm.store(ms, keccak256(abi.encode(news[i], uint256(1))), bytes32(uint256(1)));
        }
        assertEq(abi.encode(MultisigProposer(ms).owners()), abi.encode(news));
    }

    function _viaFactory(string memory name, bytes memory init) internal returns (address a) {
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(Salts.salt(name), init));
        require(ok && ret.length == 20, "Arachnid factory deploy failed");
        a = address(bytes20(ret));
    }

    function _keys() internal pure returns (V060GovernanceSpec.KeyParams memory k) {
        k.governanceOwners = _addrs(0xE000, 5);
        k.guardianOwners = _addrs(0xF000, 3);
        k.retiredKeys = _addrs(0xA000, 5); // the rotated-out "r1006" owners
        k.guardianVetoMargin = 2 hours;
        k.v060Deployers = new address[](1);
        k.v060Deployers[0] = SENDER;
    }

    function _inputs() internal view returns (DeployV060Genesis.Inputs memory i) {
        i.governanceTimelock = gov.governanceTimelock;
        i.governanceMultisig = gov.governanceMultisig;
        i.guardianTimelock = gov.guardianTimelock;
        i.guardianMultisig = gov.guardianMultisig;
        i.guardianCanceller = gov.guardianCanceller; // v1 on r1007
        i.federatedRoundLedger = address(frl);
        i.guardianRecoveryModule = address(recoveryV1);
        i.organizationSbt = address(orgSbt);
        i.agentSbt = address(agentSbt);
        i.minCoordinatorBond = MIN_BOND;
        i.defaultCoordinatorBond = DEFAULT_BOND;
        i.keys = _keys();
    }

    /// The rotation (CHAIN-INTEG's second leg): the r1006 constructor owners the council addresses
    /// commit to, and the rotated r1007 owners, in order, that owners() must equal.
    function _rot() internal pure returns (AdminChecks.Rotation memory r) {
        r.fromGov = _addrs(0xA000, 5);
        r.fromGrd = _addrs(0xB000, 3);
        r.toGov = _addrs(0xE000, 5);
        r.toGrd = _addrs(0xF000, 3);
    }

    function _builder() internal returns (DeployV060Genesis s) {
        V060LiveWithNode h = new V060LiveWithNode();
        h.useArchive(archive);
        archive.absorb();
        s = h;
    }

    function _expectRevert(bytes memory reason) internal {
        archive.absorb();
        vm.expectRevert(reason);
    }

    // ------------------------------------------------------------------ the r1007 shape

    /// The CREATE2-provenance rule the genesis builder uses cannot hold on a rotated council.
    function test_the_genesis_mode_refuses_r1007s_shape() public {
        DeployV060Genesis s = _builder();
        _expectRevert(
            bytes("ProviderRegistry: not live at its CREATE2 address for (GOVERNANCE, GUARDIAN); run P1 with GENESIS_V060=1")
        );
        s.deployWith(SENDER, _inputs());
    }

    function test_live_mode_deploys_the_set_at_its_predicted_addresses_and_verifies_pre_swap() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        DeployV060Genesis.Deployed memory p = s.predict(i);
        DeployV060Genesis.Deployed memory d = s.deployLive(liveDeployer, i, _rot());
        assertEq(abi.encode(d), abi.encode(p));
        s.verifyLive(i, d);
        // Pre-swap, v1 is still the canceller; the full (post-swap) verify must not pass yet.
        vm.expectRevert(bytes("GuardianCancellerV2 lacks CANCELLER on GOVERNANCE"));
        s.verify(i, d);
    }

    function test_live_mode_refuses_a_deployer_not_inventoried_as_v060_deployer() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.keys.v060Deployers = new address[](0);
        _expectRevert(bytes(V060GovernanceSpec.PENDING_V060_DEPLOYER));
        s.deployLive(liveDeployer, i, _rot());
        i.keys.v060Deployers = new address[](1);
        i.keys.v060Deployers[0] = makeAddr("another-deployer");
        _expectRevert(bytes("deployer is not in GENESIS_KEY_INVENTORY with role V060_DEPLOYER"));
        s.deployLive(liveDeployer, i, _rot());
    }

    function test_live_mode_refuses_a_rotated_owner_off_the_inventory() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.keys.governanceOwners = _addrs(0xE001, 4); // 0xE000 is no longer on the inventory
        _expectRevert(bytes("GOVERNANCE owner is not in GENESIS_KEY_INVENTORY with role GOV_OWNERS"));
        s.deployLive(liveDeployer, i, _rot());
    }

    /// A MultisigProposer with the same immutables has the same code hash, but it is not at the
    /// CREATE2 address the ceremony deployed for the original owners: refused by provenance.
    function test_live_mode_refuses_an_unwired_multisig_with_the_right_code() public {
        MultisigProposer copy = new MultisigProposer(gov.governanceTimelock, govNew, 3, 14 days);
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.governanceMultisig = address(copy);
        _expectRevert(bytes("GovernanceMultisig: not the MultisigProposer the ceremony deployed for these original owners, threshold and TTL"));
        s.deployLive(liveDeployer, i, _rot());
    }

    function test_live_mode_refuses_a_multisig_that_is_not_a_multisig_proposer() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        i.guardianMultisig = address(frl); // code, but not a MultisigProposer
        archive.absorb();
        vm.expectRevert();
        s.deployLive(liveDeployer, i, _rot());
    }

    // ------------------------------------------------------------------ the canceller swap

    function test_the_swap_proposal_waits_for_v2s_code() public {
        DeployV060Genesis s = _builder();
        vm.expectRevert(bytes(V060GovernanceSpec.SWAP_NEEDS_V2_CODE));
        s.swapProposal(_inputs());
    }

    /// The proposal, run through the GOVERNANCE multisig (3 of 5 rotated owners) and timelock
    /// (48 h), retires v1 and seats v2; the GUARDIAN council cannot cancel it through v1; the
    /// full verify then passes and the pre-swap verify no longer does.
    function test_the_swap_proposal_executes_and_the_full_verify_passes() public {
        DeployV060Genesis s = _builder();
        DeployV060Genesis.Inputs memory i = _inputs();
        DeployV060Genesis.Deployed memory d = s.deployLive(liveDeployer, i, _rot());
        (bytes memory scheduleData, bytes memory executeData, bytes32 opId) = s.swapProposal(i);
        TimelockController gt = TimelockController(payable(gov.governanceTimelock));
        MultisigProposer ms = MultisigProposer(gov.governanceMultisig);

        _multisig(ms, scheduleData);
        assertTrue(gt.isOperationPending(opId), "queued");

        // The guardian council cannot veto its own replacement through v1.
        (address[] memory t, uint256[] memory v, bytes[] memory pl) = _swapBatch(d.guardianCancellerV2);
        vm.prank(gov.guardianTimelock);
        vm.expectRevert();
        GuardianCanceller(gov.guardianCanceller).cancelBatch(t, v, pl, bytes32(0), V060GovernanceSpec.SWAP_SALT);

        vm.warp(block.timestamp + 48 hours);
        _multisig(ms, executeData);
        assertTrue(gt.isOperationDone(opId), "executed");
        assertTrue(gt.hasRole(gt.CANCELLER_ROLE(), d.guardianCancellerV2));
        assertFalse(gt.hasRole(gt.CANCELLER_ROLE(), gov.guardianCanceller));
        s.verify(i, d);
        vm.expectRevert(bytes("GuardianCanceller v1 no longer holds CANCELLER: use the full verify"));
        s.verifyLive(i, d);
    }

    function _swapBatch(address v2) internal view returns (address[] memory t, uint256[] memory v, bytes[] memory p) {
        TimelockController gt = TimelockController(payable(gov.governanceTimelock));
        t = new address[](2);
        (t[0], t[1]) = (gov.governanceTimelock, gov.governanceTimelock);
        v = new uint256[](2);
        p = new bytes[](2);
        p[0] = abi.encodeCall(gt.revokeRole, (gt.CANCELLER_ROLE(), gov.guardianCanceller));
        p[1] = abi.encodeCall(gt.grantRole, (gt.CANCELLER_ROLE(), v2));
    }

    function _multisig(MultisigProposer ms, bytes memory data) internal {
        vm.prank(govNew[0]);
        bytes32 id = ms.propose(data);
        vm.prank(govNew[1]);
        ms.approve(id);
        vm.prank(govNew[2]);
        ms.approve(id);
        vm.prank(govNew[0]);
        ms.execute(id);
    }


    // CHAIN-INTEG's second leg: CREATE2 provenance against the r1006 constructor owners, then
    // owners() exactly the rotated r1007 set, in order.

    function test_live_mode_refuses_a_rotation_whose_original_owners_do_not_match() public {
        DeployV060Genesis s = _builder();
        AdminChecks.Rotation memory r = _rot();
        r.fromGov = _addrs(0xA100, 5); // not the owners the GOVERNANCE multisig's address commits to
        _expectRevert(bytes("GovernanceMultisig: not the MultisigProposer the ceremony deployed for these original owners, threshold and TTL"));
        s.deployLive(liveDeployer, _inputs(), r);
    }

    function test_live_mode_refuses_rotated_owners_in_another_order() public {
        DeployV060Genesis s = _builder();
        AdminChecks.Rotation memory r = _rot();
        (r.toGrd[0], r.toGrd[1]) = (r.toGrd[1], r.toGrd[0]);
        _expectRevert(bytes("GuardianMultisig: owners() is not exactly the rotated set, in order"));
        s.deployLive(liveDeployer, _inputs(), r);
    }
}
