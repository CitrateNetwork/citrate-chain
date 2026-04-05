// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {Forwarder} from "../../src/edu/Forwarder.sol";
import {IForwarder} from "../../src/edu/interfaces/IForwarder.sol";
import {ClassroomClusterV1} from "../../src/edu/ClassroomClusterV1.sol";
import {InstitutionalVault} from "../../src/edu/InstitutionalVault.sol";
import {IClassroomCluster} from "../../src/edu/interfaces/IClassroomCluster.sol";

/// @notice Simple counter target for forwarded calls
contract Counter {
    uint256 public count;
    function increment() external { count++; }
}

contract ForwarderTest is Test {
    Forwarder forwarder;
    ClassroomClusterV1 cluster;
    InstitutionalVault vault;
    Counter counter;

    address governance = address(0x1000);
    address relayer = address(0x2000);
    address admin = address(0x1);
    address itAdmin = address(0x2);
    address teacher = address(0x3);
    address student = address(0x10);
    address nobody = address(0xBEEF);

    bytes32 orgPrincipal = keccak256("student-hmac-001");
    bytes32 deviceCert = keccak256("device-001");

    function setUp() public {
        // Deploy dependencies
        address[] memory signers = new address[](1);
        signers[0] = governance;
        vault = new InstitutionalVault(signers, 1);

        cluster = new ClassroomClusterV1(governance);
        forwarder = new Forwarder(governance, address(cluster), address(vault));
        counter = new Counter();

        // Setup roles
        vm.startPrank(governance);
        cluster.grantOrgRole(admin, IClassroomCluster.OrgRole.Admin);
        cluster.grantOrgRole(itAdmin, IClassroomCluster.OrgRole.IT);
        forwarder.addRelayer(relayer);
        vm.stopPrank();

        // Create classroom + register device
        vm.prank(admin);
        cluster.createClassroom("Bio 101", teacher);

        vm.prank(itAdmin);
        cluster.registerDevice(deviceCert, student);

        // Add student to classroom
        vm.prank(teacher);
        cluster.grantClassroomRole(0, student, IClassroomCluster.ClassroomRole.Student);
    }

    // Helper to build a valid request
    function _makeRequest(uint256 nonce) internal view returns (IForwarder.ForwardRequest memory) {
        return IForwarder.ForwardRequest({
            orgPrincipalId: orgPrincipal,
            classroomId: 0,
            nonce: nonce,
            sessionExpiry: block.timestamp + 3600, // 1 hour
            deviceCertHash: deviceCert,
            target: address(counter),
            data: abi.encodeWithSelector(Counter.increment.selector)
        });
    }

    // ===================================================================
    // UNIT TESTS
    // ===================================================================

    function test_execute_increments_counter() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        forwarder.execute(req, "");
        assertEq(counter.count(), 1);
    }

    function test_execute_increments_nonce() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        forwarder.execute(req, "");
        assertEq(forwarder.getNonce(orgPrincipal, 0), 1);
    }

    function test_sequential_executions() public {
        for (uint256 i = 0; i < 5; i++) {
            IForwarder.ForwardRequest memory req = _makeRequest(i);
            vm.prank(relayer);
            forwarder.execute(req, "");
        }
        assertEq(counter.count(), 5);
        assertEq(forwarder.getNonce(orgPrincipal, 0), 5);
    }

    function test_non_relayer_reverts() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(nobody);
        vm.expectRevert(); // NotAuthorizedRelayer
        forwarder.execute(req, "");
    }

    // ===================================================================
    // INVARIANT TESTS — Q-006 TLA+ MAPPING
    // ===================================================================

    // Invariant 1: NonceMonotonic
    function test_invariant_nonce_monotonic() public {
        // Skip nonce 0, try nonce 1 directly — should fail
        IForwarder.ForwardRequest memory req = _makeRequest(1);
        vm.prank(relayer);
        vm.expectRevert(); // InvalidNonce
        forwarder.execute(req, "");
    }

    // Invariant 2: NoReplayAccepted
    function test_invariant_no_replay() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        forwarder.execute(req, "");

        // Same request again (even with correct nonce 1 — but different tx hash)
        // Actually test exact replay: same nonce should fail
        IForwarder.ForwardRequest memory req2 = _makeRequest(0);
        vm.prank(relayer);
        vm.expectRevert(); // InvalidNonce (nonce already consumed, now expects 1)
        forwarder.execute(req2, "");
    }

    // Invariant 3: DeviceBindingEnforced
    function test_invariant_device_binding() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.deviceCertHash = keccak256("unknown-device");

        vm.prank(relayer);
        vm.expectRevert(); // DeviceRevoked (device not registered)
        forwarder.execute(req, "");
    }

    // Invariant 4: SessionExpiryEnforced
    function test_invariant_session_expired() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.sessionExpiry = block.timestamp - 1; // Already expired

        vm.prank(relayer);
        vm.expectRevert(); // SessionExpired
        forwarder.execute(req, "");
    }

    // Invariant 5: RevocationBarrierDouble (on-chain)
    function test_invariant_revoked_device_rejected() public {
        // Revoke the device
        vm.prank(itAdmin);
        cluster.revokeDevice(deviceCert);

        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        vm.expectRevert(); // DeviceRevoked
        forwarder.execute(req, "");
    }

    // Invariant 6: RelayerCannotCallVault
    function test_invariant_relayer_cannot_call_vault() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.target = address(vault); // Try to target the vault

        vm.prank(relayer);
        vm.expectRevert(); // TargetIsVault
        forwarder.execute(req, "");
    }

    // Invariant 7: OfflineQueueFlushSafe
    function test_invariant_offline_queue_flush_safe() public {
        // Execute once
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        forwarder.execute(req, "");

        // Revoke device after execution
        vm.prank(itAdmin);
        cluster.revokeDevice(deviceCert);

        // Try to flush another queued item — should fail (device revoked)
        IForwarder.ForwardRequest memory req2 = _makeRequest(1);
        vm.prank(relayer);
        vm.expectRevert(); // DeviceRevoked
        forwarder.execute(req2, "");

        // Counter only incremented once
        assertEq(counter.count(), 1);
    }

    // ===================================================================
    // ADVERSARIAL TESTS
    // ===================================================================

    function test_adversarial_relayer_drains_vault() public {
        // Fund vault
        vm.deal(address(vault), 10 ether);

        // Relayer tries to call vault.executeCashout directly through forwarder
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.target = address(vault);
        req.data = abi.encodeWithSignature("executeCashout(uint256)", 0);

        vm.prank(relayer);
        vm.expectRevert(); // TargetIsVault
        forwarder.execute(req, "");
    }

    function test_adversarial_nonce_skip_attack() public {
        // Attacker tries to skip ahead to consume future nonces
        IForwarder.ForwardRequest memory req = _makeRequest(100);
        vm.prank(relayer);
        vm.expectRevert(); // InvalidNonce
        forwarder.execute(req, "");
    }

    function test_adversarial_different_classroom_nonce() public {
        // Nonces are per (orgPrincipal, classroomId)
        // Execute in classroom 0
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        vm.prank(relayer);
        forwarder.execute(req, "");

        // Nonce for classroom 0 is now 1
        assertEq(forwarder.getNonce(orgPrincipal, 0), 1);

        // Nonce for classroom 1 is still 0 (independent)
        assertEq(forwarder.getNonce(orgPrincipal, 1), 0);
    }

    // ===================================================================
    // ADMIN TESTS
    // ===================================================================

    function test_add_relayer() public {
        vm.prank(governance);
        forwarder.addRelayer(address(0x9999));
        assertTrue(forwarder.isAuthorizedRelayer(address(0x9999)));
    }

    function test_remove_relayer() public {
        vm.prank(governance);
        forwarder.removeRelayer(relayer);
        assertFalse(forwarder.isAuthorizedRelayer(relayer));
    }

    function test_non_governance_cannot_add_relayer() public {
        vm.prank(nobody);
        vm.expectRevert();
        forwarder.addRelayer(address(0x9999));
    }

    function test_update_cluster_contract() public {
        address newCluster = address(0x7777);
        vm.prank(governance);
        forwarder.setClusterContract(newCluster);
        assertEq(forwarder.clusterContract(), newCluster);
    }

    function test_update_vault_address() public {
        address newVault = address(0x8888);
        vm.prank(governance);
        forwarder.setVaultAddress(newVault);
        assertEq(forwarder.vaultAddress(), newVault);
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_nonce_always_increments(uint8 iterations) public {
        vm.assume(iterations > 0 && iterations < 20);

        for (uint256 i = 0; i < iterations; i++) {
            IForwarder.ForwardRequest memory req = _makeRequest(i);
            vm.prank(relayer);
            forwarder.execute(req, "");
        }

        assertEq(forwarder.getNonce(orgPrincipal, 0), iterations);
        assertEq(counter.count(), iterations);
    }

    function testFuzz_expired_session_always_reverts(uint256 expiryTime) public {
        // Ensure expiry is strictly in the past
        expiryTime = bound(expiryTime, 0, block.timestamp > 0 ? block.timestamp - 1 : 0);

        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.sessionExpiry = expiryTime;

        vm.prank(relayer);
        vm.expectRevert();
        forwarder.execute(req, "");
    }
}
