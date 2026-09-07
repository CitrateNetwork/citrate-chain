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

/// @notice FWA-C3-03: an ERC-2771-aware target that recovers the real
/// sender from the trailing 20 bytes the trusted forwarder appends.
contract Sender2771Target {
    address public lastSeenSender;

    function recordSender() external {
        lastSeenSender = _msgSender();
    }

    function _msgSender() internal view returns (address sender) {
        if (msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }
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
    uint256 studentKey = 0xA11CE;
    uint256 attackerKey = 0xB0B;
    address student;
    address attacker;
    address nobody = address(0xBEEF);

    bytes32 orgPrincipal = keccak256("student-hmac-001");
    bytes32 deviceCert = keccak256("device-001");

    function setUp() public {
        student = vm.addr(studentKey);
        attacker = vm.addr(attackerKey);

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
        forwarder.setTargetAllowed(address(counter), true);
        vm.stopPrank();

        // Create classroom + register device
        vm.prank(admin);
        cluster.createClassroom("Bio 101", teacher, 10, 2026, "A");

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

    function _signRequest(IForwarder.ForwardRequest memory req, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 digest = forwarder.hashForwardRequest(req);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _studentSignature(IForwarder.ForwardRequest memory req) internal view returns (bytes memory) {
        return _signRequest(req, studentKey);
    }

    function _executeAsRelayer(
        IForwarder.ForwardRequest memory req,
        bytes memory signature
    ) internal returns (bool) {
        vm.prank(relayer);
        return forwarder.execute(req, signature);
    }

    function _executeStudentRequest(IForwarder.ForwardRequest memory req) internal returns (bool) {
        return _executeAsRelayer(req, _studentSignature(req));
    }

    // ===================================================================
    // UNIT TESTS
    // ===================================================================

    function test_execute_increments_counter() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        _executeStudentRequest(req);
        assertEq(counter.count(), 1);
    }

    function test_execute_increments_nonce() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        _executeStudentRequest(req);
        assertEq(forwarder.getNonce(orgPrincipal, 0), 1);
    }

    function test_sequential_executions() public {
        for (uint256 i = 0; i < 5; i++) {
            IForwarder.ForwardRequest memory req = _makeRequest(i);
            _executeStudentRequest(req);
        }
        assertEq(counter.count(), 5);
        assertEq(forwarder.getNonce(orgPrincipal, 0), 5);
    }

    // ── FWA-C3-03: EIP-2771 sender append ──

    /// Pre-fix: execute() called `target.call(request.data)` with NO sender
    /// appended, so a 2771-aware target saw msg.sender == Forwarder. Post-fix:
    /// the authenticated principal (deviceUser == student) is appended, and a
    /// 2771-aware target recovers it via _msgSender().
    function test_C3_03_forwarder_appends_2771_sender() public {
        Sender2771Target target = new Sender2771Target();
        vm.prank(governance);
        forwarder.setTargetAllowed(address(target), true);

        IForwarder.ForwardRequest memory req = IForwarder.ForwardRequest({
            orgPrincipalId: orgPrincipal,
            classroomId: 0,
            nonce: 0,
            sessionExpiry: block.timestamp + 3600,
            deviceCertHash: deviceCert,
            target: address(target),
            data: abi.encodeWithSelector(Sender2771Target.recordSender.selector)
        });

        _executeAsRelayer(req, _studentSignature(req));

        // The target must see the real principal (student), NOT the forwarder.
        assertEq(target.lastSeenSender(), student, "2771 sender appended == authenticated principal");
        assertTrue(target.lastSeenSender() != address(forwarder), "target must NOT see forwarder as sender");
    }

    function test_non_relayer_reverts() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        bytes memory signature = _studentSignature(req);
        vm.prank(nobody);
        vm.expectRevert(); // NotAuthorizedRelayer
        forwarder.execute(req, signature);
    }

    // ===================================================================
    // INVARIANT TESTS — Q-006 TLA+ MAPPING
    // ===================================================================

    // Invariant 1: NonceMonotonic
    function test_invariant_nonce_monotonic() public {
        // Skip nonce 0, try nonce 1 directly — should fail
        IForwarder.ForwardRequest memory req = _makeRequest(1);
        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // InvalidNonce
        _executeAsRelayer(req, signature);
    }

    // Invariant 2: NoReplayAccepted
    function test_invariant_no_replay() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        _executeStudentRequest(req);

        // Same request again (even with correct nonce 1 — but different tx hash)
        // Actually test exact replay: same nonce should fail
        IForwarder.ForwardRequest memory req2 = _makeRequest(0);
        bytes memory signature = _studentSignature(req2);
        vm.expectRevert(); // InvalidNonce (nonce already consumed, now expects 1)
        _executeAsRelayer(req2, signature);
    }

    // Invariant 3: DeviceBindingEnforced
    function test_invariant_device_binding() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.deviceCertHash = keccak256("unknown-device");

        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // DeviceRevoked (device not registered)
        _executeAsRelayer(req, signature);
    }

    // Invariant 4: SessionExpiryEnforced
    function test_invariant_session_expired() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.sessionExpiry = block.timestamp - 1; // Already expired

        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // SessionExpired
        _executeAsRelayer(req, signature);
    }

    // Invariant 5: RevocationBarrierDouble (on-chain)
    function test_invariant_revoked_device_rejected() public {
        // Revoke the device
        vm.prank(itAdmin);
        cluster.revokeDevice(deviceCert);

        IForwarder.ForwardRequest memory req = _makeRequest(0);
        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // DeviceRevoked
        _executeAsRelayer(req, signature);
    }

    // Invariant 6: RelayerCannotCallVault
    function test_invariant_relayer_cannot_call_vault() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.target = address(vault); // Try to target the vault

        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // TargetIsVault
        _executeAsRelayer(req, signature);
    }

    // Invariant 7: OfflineQueueFlushSafe
    function test_invariant_offline_queue_flush_safe() public {
        // Execute once
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        _executeStudentRequest(req);

        // Revoke device after execution
        vm.prank(itAdmin);
        cluster.revokeDevice(deviceCert);

        // Try to flush another queued item — should fail (device revoked)
        IForwarder.ForwardRequest memory req2 = _makeRequest(1);
        bytes memory signature = _studentSignature(req2);
        vm.expectRevert(); // DeviceRevoked
        _executeAsRelayer(req2, signature);

        // Counter only incremented once
        assertEq(counter.count(), 1);
    }

    // ===================================================================
    // ADVERSARIAL TESTS
    // ===================================================================

    function test_t0_01_unsigned_request_reverts() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);

        vm.prank(relayer);
        vm.expectRevert(Forwarder.InvalidSignature.selector);
        forwarder.execute(req, "");
    }

    function test_t0_01_wrong_signer_reverts() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        bytes memory signature = _signRequest(req, attackerKey);

        vm.expectRevert(Forwarder.InvalidSignature.selector);
        _executeAsRelayer(req, signature);
    }

    function test_t0_01_modified_target_after_signing_reverts() public {
        Counter otherCounter = new Counter();
        vm.prank(governance);
        forwarder.setTargetAllowed(address(otherCounter), true);

        IForwarder.ForwardRequest memory req = _makeRequest(0);
        bytes memory signature = _studentSignature(req);
        req.target = address(otherCounter);

        vm.prank(relayer);
        vm.expectRevert(Forwarder.InvalidSignature.selector);
        forwarder.execute(req, signature);
        assertEq(counter.count(), 0);
        assertEq(otherCounter.count(), 0);
    }

    function test_t0_01_disallowed_target_reverts() public {
        Counter unlistedCounter = new Counter();
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.target = address(unlistedCounter);
        bytes memory signature = _studentSignature(req);

        vm.expectRevert(Forwarder.TargetNotAllowed.selector);
        _executeAsRelayer(req, signature);
    }

    function test_t0_01_governance_controls_target_allowlist() public {
        Counter target = new Counter();
        assertFalse(forwarder.isAllowedTarget(address(target)));

        vm.prank(nobody);
        vm.expectRevert(Forwarder.NotGovernance.selector);
        forwarder.setTargetAllowed(address(target), true);

        vm.prank(governance);
        forwarder.setTargetAllowed(address(target), true);
        assertTrue(forwarder.isAllowedTarget(address(target)));

        vm.prank(governance);
        forwarder.setTargetAllowed(address(target), false);
        assertFalse(forwarder.isAllowedTarget(address(target)));
    }

    function test_t0_01_domain_changes_with_chain_id() public {
        bytes32 originalDomain = forwarder.DOMAIN_SEPARATOR();

        vm.chainId(block.chainid + 1);
        bytes32 forkDomain = forwarder.DOMAIN_SEPARATOR();

        assertTrue(originalDomain != forkDomain);
    }

    function test_adversarial_relayer_drains_vault() public {
        // Fund vault
        vm.deal(address(vault), 10 ether);

        // Relayer tries to call vault.executeCashout directly through forwarder
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.target = address(vault);
        req.data = abi.encodeWithSignature("executeCashout(uint256)", 0);
        bytes memory signature = _studentSignature(req);

        vm.expectRevert(); // TargetIsVault
        _executeAsRelayer(req, signature);
    }

    function test_adversarial_nonce_skip_attack() public {
        // Attacker tries to skip ahead to consume future nonces
        IForwarder.ForwardRequest memory req = _makeRequest(100);
        bytes memory signature = _studentSignature(req);
        vm.expectRevert(); // InvalidNonce
        _executeAsRelayer(req, signature);
    }

    function test_adversarial_different_classroom_nonce() public {
        // Nonces are per (orgPrincipal, classroomId)
        // Execute in classroom 0
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        _executeStudentRequest(req);

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
            _executeStudentRequest(req);
        }

        assertEq(forwarder.getNonce(orgPrincipal, 0), iterations);
        assertEq(counter.count(), iterations);
    }

    function testFuzz_expired_session_always_reverts(uint256 expiryTime) public {
        // Ensure expiry is strictly in the past
        expiryTime = bound(expiryTime, 0, block.timestamp > 0 ? block.timestamp - 1 : 0);

        IForwarder.ForwardRequest memory req = _makeRequest(0);
        req.sessionExpiry = expiryTime;
        bytes memory signature = _studentSignature(req);

        vm.expectRevert();
        _executeAsRelayer(req, signature);
    }

    // ── CHAIN-B-C042: account revocation stops meta-transactions ──
    //
    // RED (pre-fix): the RevocationBarrier only checked getDeviceUser != 0,
    // which setAccountStatus never clears — so suspending/expelling the
    // principal did NOT stop forwarded meta-transactions. GREEN: a
    // non-Active account status now revokes the barrier.
    function test_C042_suspendedAccountBlocksMetaTx() public {
        IForwarder.ForwardRequest memory req = _makeRequest(0);
        bytes memory signature = _studentSignature(req);

        // Suspend the device-bound principal (admin has OrgRole.Admin).
        vm.prank(admin);
        cluster.setAccountStatus(student, IClassroomCluster.AccountStatus.Suspended);

        vm.prank(relayer);
        vm.expectRevert(Forwarder.PrincipalRevoked.selector);
        forwarder.execute(req, signature);
    }
}
