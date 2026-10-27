// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AmcTestBase} from "./AmcTestBase.sol";
import {WorkAttestations, IAgentSBT} from "../../src/amc/WorkAttestations.sol";
import {AgentSBT} from "../../src/cit_agent/AgentSBT.sol";
import {OrganizationSBT} from "../../src/cit_agent/OrganizationSBT.sol";
import {BenchmarkRegistry} from "../../src/cit_agent/BenchmarkRegistry.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

abstract contract WorkAttestationsSetup is Test {
    OrganizationSBT internal orgSbt;
    AgentSBT internal agentSbt;
    WorkAttestations internal wa;
    address internal sbtAdmin = makeAddr("sbtAdmin");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    uint256 internal aliceAgent;
    uint256 internal bobAgent;

    function _setUpSbts() internal {
        vm.warp(1_800_000_000);
        orgSbt = new OrganizationSBT(sbtAdmin);
        agentSbt = new AgentSBT(sbtAdmin, orgSbt, IERC721(address(orgSbt)));
        vm.startPrank(sbtAdmin);
        uint256 org = orgSbt.mintOrg(sbtAdmin, keccak256("did:org"), sbtAdmin, new bytes32[](0));
        aliceAgent = agentSbt.mintAgent(alice, org, keccak256("did:agent:alice"), keccak256("fp-a"));
        bobAgent = agentSbt.mintAgent(bob, org, keccak256("did:agent:bob"), keccak256("fp-b"));
        vm.stopPrank();
        wa = new WorkAttestations(IAgentSBT(address(agentSbt)));
    }

    function _work(uint256 agentId, address attester, bytes32 task)
        internal
        view
        returns (WorkAttestations.Attestation memory)
    {
        return WorkAttestations.Attestation({
            agentId: agentId,
            taskHash: task,
            artifactRoot: keccak256(abi.encode("artifact", task)),
            receiptRef: bytes32(0),
            verifierBits: 0x3,
            modelClass: 2,
            completedAt: uint64(vm.getBlockTimestamp()),
            attester: attester
        });
    }
}

contract WorkAttestationsTest is AmcTestBase, WorkAttestationsSetup {
    function setUp() public {
        _setUpSbts();
    }

    function test_constructorRefusesNoCode() public {
        vm.expectRevert(WorkAttestations.AgentsHasNoCode.selector);
        new WorkAttestations(IAgentSBT(makeAddr("eoa")));
    }

    function test_attestRecordsTheClaim() public {
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, keccak256("task-1"));
        bytes32 expected = keccak256(abi.encode(a));
        vm.expectEmit(true, true, true, true, address(wa));
        emit WorkAttestations.Attested(expected, aliceAgent, alice, a.taskHash);
        vm.prank(alice);
        bytes32 id = wa.attest(a);
        assertEq(id, expected);
        (WorkAttestations.Attestation memory got, bool revoked) = wa.get(id);
        assertEq(got.taskHash, a.taskHash);
        assertEq(got.artifactRoot, a.artifactRoot);
        assertEq(got.verifierBits, 0x3);
        assertEq(got.modelClass, 2);
        assertEq(got.attester, alice);
        assertFalse(revoked);
        assertEq(wa.countByAgent(aliceAgent), 1);
        assertEq(wa.byAgent(aliceAgent, 0, 10)[0], id);
    }

    function test_onlyTheAgentOwnerAttestsAsItself() public {
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, keccak256("t"));
        vm.prank(bob);
        vm.expectRevert(WorkAttestations.NotAttester.selector);
        wa.attest(a); // bob submits alice's claim
        a.attester = bob;
        vm.prank(bob);
        vm.expectRevert(WorkAttestations.NotAgentOwner.selector);
        wa.attest(a); // bob claims for alice's agent
    }

    function test_quarantinedAgentCannotAttest() public {
        vm.prank(sbtAdmin);
        agentSbt.quarantine(aliceAgent);
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, keccak256("t"));
        vm.prank(alice);
        vm.expectRevert(WorkAttestations.AgentQuarantined.selector);
        wa.attest(a);
    }

    function test_unknownAgentReverts() public {
        WorkAttestations.Attestation memory a = _work(99, alice, keccak256("t"));
        vm.prank(alice);
        vm.expectRevert(); // ERC721NonexistentToken
        wa.attest(a);
    }

    function test_inputRules() public {
        vm.startPrank(alice);
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, bytes32(0));
        vm.expectRevert(WorkAttestations.ZeroHash.selector);
        wa.attest(a);
        a = _work(aliceAgent, alice, keccak256("t"));
        a.artifactRoot = bytes32(0);
        vm.expectRevert(WorkAttestations.ZeroHash.selector);
        wa.attest(a);
        a = _work(aliceAgent, alice, keccak256("t"));
        a.modelClass = 5;
        vm.expectRevert(WorkAttestations.BadModelClass.selector);
        wa.attest(a);
        a.modelClass = 4;
        a.completedAt = uint64(vm.getBlockTimestamp()) + 1;
        vm.expectRevert(WorkAttestations.FutureCompletion.selector);
        wa.attest(a);
        vm.stopPrank();
    }

    function test_duplicateRefused() public {
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, keccak256("t"));
        vm.startPrank(alice);
        bytes32 id = wa.attest(a);
        vm.expectRevert(abi.encodeWithSelector(WorkAttestations.AlreadyAttested.selector, id));
        wa.attest(a);
        vm.stopPrank();
    }

    function test_revokeIsAttesterOnlyAndSticky() public {
        vm.prank(alice);
        bytes32 id = wa.attest(_work(aliceAgent, alice, keccak256("t")));
        vm.prank(bob);
        vm.expectRevert(WorkAttestations.NotAttester.selector);
        wa.revoke(id, 1);
        vm.prank(alice);
        wa.revoke(id, 7);
        (, bool revoked) = wa.get(id);
        assertTrue(revoked);
        assertEq(wa.revokedCount(aliceAgent), 1);
        vm.prank(alice);
        vm.expectRevert(WorkAttestations.AlreadyRevoked.selector);
        wa.revoke(id, 7);
        vm.prank(bob);
        vm.expectRevert(WorkAttestations.AlreadyRevoked.selector);
        wa.acknowledge(id);
    }

    function test_acknowledgeRules() public {
        vm.prank(alice);
        bytes32 id = wa.attest(_work(aliceAgent, alice, keccak256("t")));
        vm.prank(alice);
        vm.expectRevert(WorkAttestations.SelfAcknowledge.selector);
        wa.acknowledge(id);
        vm.prank(bob);
        wa.acknowledge(id);
        assertTrue(wa.acknowledged(id, bob));
        vm.prank(bob);
        vm.expectRevert(WorkAttestations.AlreadyAcknowledged.selector);
        wa.acknowledge(id);
        bytes32 nope = keccak256("nope");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(WorkAttestations.UnknownAttestation.selector, nope));
        wa.acknowledge(nope);
    }

    /// Benchmarks are joined by the shared AgentSBT id, not copied: the attester's own
    /// BenchmarkRegistry series for the same agent is readable next to its attestations.
    function test_benchmarkJoinByAgentId() public {
        BenchmarkRegistry bench = new BenchmarkRegistry();
        bytes32 capsule = keccak256("capsule");
        bytes32 metric = keccak256("task_success_rate_bps");
        vm.startPrank(alice);
        bytes32 id = wa.attest(_work(aliceAgent, alice, keccak256("t")));
        bench.record(aliceAgent, capsule, metric, 9_500);
        vm.stopPrank();
        (WorkAttestations.Attestation memory a,) = wa.get(id);
        assertEq(bench.metricCount(a.attester, a.agentId, capsule, metric), 1);
        assertEq(bench.getMetric(a.attester, a.agentId, capsule, metric, 0, 1)[0].value, 9_500);
    }

    function test_holdsNoValue() public {
        _assertRejectsValue(address(wa));
    }

    function testFuzz_idIsTheHashOfTheWholeClaim(bytes32 task, bytes32 receiptRef, uint32 bits, uint8 cls) public {
        vm.assume(task != bytes32(0));
        cls = uint8(bound(cls, 0, 4));
        WorkAttestations.Attestation memory a = _work(aliceAgent, alice, task);
        a.receiptRef = receiptRef;
        a.verifierBits = bits;
        a.modelClass = cls;
        vm.startPrank(alice);
        bytes32 id = wa.attest(a);
        assertEq(id, keccak256(abi.encode(a)));
        // Any change to any field is a different claim.
        a.verifierBits = bits ^ 1;
        bytes32 id2 = wa.attest(a);
        assertTrue(id2 != id);
        vm.stopPrank();
    }
}

contract WorkAttestationsHandler is Test {
    WorkAttestations public wa;
    IAgentSBT public agents;
    address[2] public actors;
    uint256[2] public agentIds;
    bytes32[] public ids;
    mapping(bytes32 => bool) public revokedGhost;
    mapping(uint256 => uint256) public revokedByAgent;
    bool public violation;

    constructor(WorkAttestations wa_, IAgentSBT agents_, address a, address b, uint256 ia, uint256 ib) {
        wa = wa_;
        agents = agents_;
        actors = [a, b];
        agentIds = [ia, ib];
    }

    function idCount() external view returns (uint256) {
        return ids.length;
    }

    function attest(uint256 who, uint256 whichAgent, bytes32 task) external {
        address a = actors[who % 2];
        uint256 agentId = agentIds[whichAgent % 2];
        if (task == bytes32(0)) task = keccak256("t0");
        WorkAttestations.Attestation memory w = WorkAttestations.Attestation({
            agentId: agentId,
            taskHash: task,
            artifactRoot: keccak256(abi.encode(task)),
            receiptRef: bytes32(0),
            verifierBits: 1,
            modelClass: 0,
            completedAt: uint64(vm.getBlockTimestamp()),
            attester: a
        });
        vm.prank(a);
        try wa.attest(w) returns (bytes32 id) {
            if (agents.ownerOf(agentId) != a) violation = true;
            ids.push(id);
        } catch {}
    }

    function revoke(uint256 i, uint256 who) external {
        if (ids.length == 0) return;
        bytes32 id = ids[i % ids.length];
        address a = actors[who % 2];
        (WorkAttestations.Attestation memory w,) = wa.get(id);
        vm.prank(a);
        try wa.revoke(id, 1) {
            if (w.attester != a || revokedGhost[id]) violation = true;
            revokedGhost[id] = true;
            revokedByAgent[w.agentId] += 1;
        } catch {}
    }

    function acknowledge(uint256 i, uint256 who) external {
        if (ids.length == 0) return;
        bytes32 id = ids[i % ids.length];
        vm.prank(actors[who % 2]);
        try wa.acknowledge(id) {
            if (revokedGhost[id]) violation = true;
        } catch {}
    }

    function warp(uint32 dt) external {
        vm.warp(vm.getBlockTimestamp() + bound(dt, 0, 1 days));
    }
}

contract WorkAttestationsInvariantTest is WorkAttestationsSetup {
    WorkAttestationsHandler internal handler;

    function setUp() public {
        _setUpSbts();
        handler = new WorkAttestationsHandler(wa, IAgentSBT(address(agentSbt)), alice, bob, aliceAgent, bobAgent);
        targetContract(address(handler));
    }

    /// The attester owned the agent; revoked stays revoked; counters match.
    function invariant_attesterOwnsAgentAndRevokedIsSticky() public view {
        assertFalse(handler.violation());
        uint256 n = handler.idCount();
        if (n > 0) {
            bytes32 id = handler.ids(n - 1);
            (WorkAttestations.Attestation memory a, bool revoked) = wa.get(id);
            assertEq(agentSbt.ownerOf(a.agentId), a.attester);
            assertEq(revoked, handler.revokedGhost(id));
        }
        assertEq(wa.revokedCount(aliceAgent), handler.revokedByAgent(aliceAgent));
        assertEq(wa.revokedCount(bobAgent), handler.revokedByAgent(bobAgent));
        assertEq(wa.countByAgent(aliceAgent) + wa.countByAgent(bobAgent), n);
    }

    function invariant_holdsNoValue() public view {
        assertEq(address(wa).balance, 0);
    }
}
