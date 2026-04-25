// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HeartbeatMonitor} from "../src/HeartbeatMonitor.sol";
import {Governable} from "../src/lib/Governable.sol";

/// @notice Mock NematocystSlashing for integration testing.
contract MockSlashing {
    struct SlashRecord {
        address provider;
        uint8 tier;
        bytes evidence;
    }

    SlashRecord[] public slashes;
    bool public shouldRevert;

    function slash(address provider, uint8 tier, bytes calldata evidence) external {
        if (shouldRevert) revert("MockSlashing: forced revert");
        slashes.push(SlashRecord(provider, tier, evidence));
    }

    function slashCount() external view returns (uint256) {
        return slashes.length;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }
}

contract HeartbeatMonitorTest is Test {
    HeartbeatMonitor internal monitor;
    MockSlashing internal mockSlashing;

    address internal governance = address(this);
    address internal provider1 = address(0xA001);
    address internal provider2 = address(0xA002);
    address internal provider3 = address(0xA003);
    address internal outsider = address(0xBAD1);

    uint256 internal constant INTERVAL = 100;
    uint256 internal constant MAX_MISSED = 3;

    /// @dev Tracks the current block number for explicit block advancement.
    uint256 internal currentBlock;

    function setUp() public {
        // Start at block 1 (Forge default)
        currentBlock = 1;
        vm.roll(currentBlock);

        monitor = new HeartbeatMonitor(INTERVAL, MAX_MISSED);
        mockSlashing = new MockSlashing();
        monitor.setSlashingContract(address(mockSlashing));
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _register(address provider) internal {
        vm.prank(provider);
        monitor.register();
    }

    function _heartbeat(address provider) internal {
        vm.prank(provider);
        monitor.heartbeat();
    }

    function _advanceBlocks(uint256 n) internal {
        currentBlock += n;
        vm.roll(currentBlock);
    }

    /// @dev Suspends provider1 by triggering MAX_MISSED missed heartbeats.
    function _suspendProvider1() internal {
        for (uint256 i = 0; i < MAX_MISSED; i++) {
            _advanceBlocks(INTERVAL + 1);
            monitor.checkHeartbeat(provider1);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Registration Tests
    // ══════════════════════════════════════════════════════════════════

    function test_register_sets_initial_state() public {
        _register(provider1);

        assertTrue(monitor.registered(provider1));
        assertTrue(monitor.isActive(provider1));

        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertEq(h.lastHeartbeat, currentBlock);
        assertEq(h.missedCount, 0);
        assertFalse(h.suspended);
        assertEq(h.suspendedAt, 0);
    }

    function test_register_already_registered_reverts() public {
        _register(provider1);

        vm.prank(provider1);
        vm.expectRevert("Already registered");
        monitor.register();
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-2: HeartbeatResets — heartbeat received => missedCount = 0
    // ══════════════════════════════════════════════════════════════════

    function test_heartbeat_resets_missed_count() public {
        _register(provider1);

        // Advance past heartbeat interval and detect missed
        _advanceBlocks(INTERVAL + 1);
        monitor.checkHeartbeat(provider1);

        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertEq(h.missedCount, 1);

        // Send heartbeat — INV-2: missedCount must reset to 0
        _heartbeat(provider1);

        h = monitor.getHealth(provider1);
        assertEq(h.missedCount, 0);
        assertEq(h.lastHeartbeat, currentBlock);
    }

    function test_heartbeat_updates_last_heartbeat() public {
        _register(provider1);

        _advanceBlocks(50);
        _heartbeat(provider1);

        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertEq(h.lastHeartbeat, currentBlock);
    }

    function test_heartbeat_not_registered_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("Not registered");
        monitor.heartbeat();
    }

    function test_heartbeat_suspended_reverts() public {
        _register(provider1);

        // Get suspended
        _suspendProvider1();

        vm.prank(provider1);
        vm.expectRevert("Provider is suspended");
        monitor.heartbeat();
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-3: MissedBounded — missedCount <= maxMissed
    // ══════════════════════════════════════════════════════════════════

    function test_missed_count_bounded_by_max() public {
        _register(provider1);

        // Trigger MAX_MISSED missed heartbeats
        _suspendProvider1();

        // Provider should be suspended at maxMissed
        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertEq(h.missedCount, MAX_MISSED);
        assertTrue(h.suspended);

        // Can't check again — already suspended
        _advanceBlocks(INTERVAL + 1);
        vm.expectRevert("Already suspended");
        monitor.checkHeartbeat(provider1);
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-4: SuspensionAutomatic — missedCount >= maxMissed => suspended
    // ══════════════════════════════════════════════════════════════════

    function test_suspension_automatic_at_max_missed() public {
        _register(provider1);

        for (uint256 i = 0; i < MAX_MISSED - 1; i++) {
            _advanceBlocks(INTERVAL + 1);
            monitor.checkHeartbeat(provider1);
            assertFalse(monitor.getHealth(provider1).suspended);
        }

        // One more miss triggers suspension
        _advanceBlocks(INTERVAL + 1);
        monitor.checkHeartbeat(provider1);

        assertTrue(monitor.getHealth(provider1).suspended);
        assertFalse(monitor.isActive(provider1));
    }

    function test_suspension_triggers_slash() public {
        _register(provider1);

        _suspendProvider1();

        // NematocystSlashing should have been called
        assertEq(mockSlashing.slashCount(), 1);
        (address slashedProvider, uint8 tier, ) = mockSlashing.slashes(0);
        assertEq(slashedProvider, provider1);
        assertEq(tier, 0); // SlashTier.Latency
    }

    // ══════════════════════════════════════════════════════════════════
    // INV-7: ActiveHasHeartbeat — active providers have lastHeartbeat >= 1
    // ══════════════════════════════════════════════════════════════════

    function test_active_provider_has_valid_heartbeat() public {
        _register(provider1);

        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertTrue(h.lastHeartbeat >= 1);
        assertTrue(monitor.isActive(provider1));
    }

    // ══════════════════════════════════════════════════════════════════
    // Reactivation Tests
    // ══════════════════════════════════════════════════════════════════

    function test_reactivate_resets_state() public {
        _register(provider1);

        // Get suspended
        _suspendProvider1();
        assertTrue(monitor.getHealth(provider1).suspended);

        // Reactivate
        vm.prank(provider1);
        monitor.reactivate();

        HeartbeatMonitor.ProviderHealth memory h = monitor.getHealth(provider1);
        assertFalse(h.suspended);
        assertEq(h.missedCount, 0);
        assertEq(h.lastHeartbeat, currentBlock);
        assertEq(h.suspendedAt, 0);
        assertTrue(monitor.isActive(provider1));
    }

    function test_reactivate_not_suspended_reverts() public {
        _register(provider1);

        vm.prank(provider1);
        vm.expectRevert("Not suspended");
        monitor.reactivate();
    }

    function test_reactivate_not_registered_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("Not registered");
        monitor.reactivate();
    }

    // ══════════════════════════════════════════════════════════════════
    // CheckHeartbeat Edge Cases
    // ══════════════════════════════════════════════════════════════════

    function test_check_heartbeat_not_yet_due_reverts() public {
        _register(provider1);

        _advanceBlocks(INTERVAL); // exactly at interval, not past
        vm.expectRevert("Heartbeat not yet due");
        monitor.checkHeartbeat(provider1);
    }

    function test_check_heartbeat_not_registered_reverts() public {
        vm.expectRevert("Not registered");
        monitor.checkHeartbeat(outsider);
    }

    function test_check_heartbeat_increments_once_per_interval() public {
        _register(provider1);

        // First miss
        _advanceBlocks(INTERVAL + 1);
        monitor.checkHeartbeat(provider1);
        assertEq(monitor.getHealth(provider1).missedCount, 1);

        // Immediately trying again should fail (lastHeartbeat was updated)
        vm.expectRevert("Heartbeat not yet due");
        monitor.checkHeartbeat(provider1);

        // Must wait another interval
        _advanceBlocks(INTERVAL + 1);
        monitor.checkHeartbeat(provider1);
        assertEq(monitor.getHealth(provider1).missedCount, 2);
    }

    // ══════════════════════════════════════════════════════════════════
    // Query Functions
    // ══════════════════════════════════════════════════════════════════

    function test_isActive_unregistered() public view {
        assertFalse(monitor.isActive(outsider));
    }

    function test_isHeartbeatOverdue() public {
        _register(provider1);

        assertFalse(monitor.isHeartbeatOverdue(provider1));

        _advanceBlocks(INTERVAL + 1);
        assertTrue(monitor.isHeartbeatOverdue(provider1));

        // After heartbeat, no longer overdue
        _heartbeat(provider1);
        assertFalse(monitor.isHeartbeatOverdue(provider1));
    }

    function test_blocksUntilDue() public {
        _register(provider1);

        uint256 due = monitor.blocksUntilDue(provider1);
        assertEq(due, INTERVAL);

        _advanceBlocks(50);
        assertEq(monitor.blocksUntilDue(provider1), INTERVAL - 50);

        _advanceBlocks(60); // past due
        assertEq(monitor.blocksUntilDue(provider1), 0);
    }

    function test_blocksUntilDue_unregistered() public view {
        assertEq(monitor.blocksUntilDue(outsider), 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // Governance Tests
    // ══════════════════════════════════════════════════════════════════

    function test_setHeartbeatInterval() public {
        monitor.setHeartbeatInterval(200);
        assertEq(monitor.heartbeatInterval(), 200);
    }

    function test_setHeartbeatInterval_zero_reverts() public {
        vm.expectRevert("Interval must be >= 1");
        monitor.setHeartbeatInterval(0);
    }

    function test_setMaxMissed() public {
        monitor.setMaxMissed(5);
        assertEq(monitor.maxMissed(), 5);
    }

    function test_setMaxMissed_zero_reverts() public {
        vm.expectRevert("MaxMissed must be >= 1");
        monitor.setMaxMissed(0);
    }

    function test_non_governance_cannot_set_interval() public {
        vm.prank(outsider);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        monitor.setHeartbeatInterval(200);
    }

    function test_transferGovernance() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        monitor.transferGovernance(provider1);
        assertEq(monitor.pendingGovernance(), provider1);
        vm.prank(provider1);
        monitor.acceptGovernance();
        assertEq(monitor.governance(), provider1);

        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        monitor.setMaxMissed(10);

        vm.prank(provider1);
        monitor.setMaxMissed(10);
        assertEq(monitor.maxMissed(), 10);
    }

    function test_transferGovernance_zero_address_reverts() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        monitor.transferGovernance(address(0));
    }

    // ══════════════════════════════════════════════════════════════════
    // Adversarial: Heartbeat Gaming (from AdversarialCompute.tla)
    // ══════════════════════════════════════════════════════════════════

    function test_adversarial_heartbeat_gaming_detected() public {
        // Provider registers but never actually does work — just sends heartbeats
        _register(provider1);

        // Provider sends heartbeats to stay alive
        for (uint256 i = 0; i < 5; i++) {
            _advanceBlocks(INTERVAL - 1);
            _heartbeat(provider1);
        }

        // If they stop sending heartbeats (hardware failure revealed), they get caught
        _suspendProvider1();

        assertTrue(monitor.getHealth(provider1).suspended);
        assertEq(mockSlashing.slashCount(), 1);
    }

    function test_slash_failure_does_not_prevent_suspension() public {
        mockSlashing.setShouldRevert(true);

        _register(provider1);

        _suspendProvider1();

        // Provider should still be suspended even if slash reverts
        assertTrue(monitor.getHealth(provider1).suspended);
    }

    // ══════════════════════════════════════════════════════════════════
    // Constructor Validation
    // ══════════════════════════════════════════════════════════════════

    function test_constructor_zero_interval_reverts() public {
        vm.expectRevert("Interval must be >= 1");
        new HeartbeatMonitor(0, 3);
    }

    function test_constructor_zero_maxMissed_reverts() public {
        vm.expectRevert("MaxMissed must be >= 1");
        new HeartbeatMonitor(100, 0);
    }
}
