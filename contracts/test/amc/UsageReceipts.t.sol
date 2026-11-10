// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AmcTestBase} from "./AmcTestBase.sol";
import {UsageReceipts} from "../../src/amc/UsageReceipts.sol";

contract UsageReceiptsTest is AmcTestBase {
    UsageReceipts internal ur;
    address internal member = makeAddr("member");
    uint64 internal constant T0 = 1_800_000_000; // a moment inside UTC day 20833
    uint32 internal today;

    function setUp() public {
        vm.warp(T0);
        ur = new UsageReceipts(90);
        today = uint32(T0 / 1 days);
    }

    function test_commitAClosedDay() public {
        bytes32 root = keccak256("root-yesterday");
        uint8 v1 = ur.SCHEMA_V1();
        vm.expectEmit(true, true, false, true, address(ur));
        emit UsageReceipts.ReceiptCommitted(member, today - 1, root, 1);
        vm.prank(member);
        ur.commit(today - 1, root, v1);
        UsageReceipts.Receipt memory r = ur.rootOf(member, today - 1);
        assertEq(r.root, root);
        assertEq(r.committedAt, T0);
        assertEq(r.blockNumber, block.number);
        assertEq(r.schema, 1);
        assertTrue(ur.isCommitted(member, today - 1));
        assertEq(ur.dayCount(member), 1);
        assertEq(ur.daysOf(member, 0, 10)[0], today - 1);
    }

    function test_onlyRootDaySchemaAndCommitterAreStored() public {
        vm.recordLogs();
        vm.prank(member);
        ur.commit(today - 1, keccak256("r"), 1);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        // Topics: event sig, committer, day. Data: root and schema only (two words).
        assertEq(logs[0].topics.length, 3);
        assertEq(logs[0].data.length, 64);
    }

    function test_dayMustBeClosed() public {
        vm.startPrank(member);
        vm.expectRevert(UsageReceipts.DayNotClosed.selector);
        ur.commit(today, keccak256("r"), 1);
        vm.expectRevert(UsageReceipts.DayNotClosed.selector);
        ur.commit(today + 1, keccak256("r"), 1);
        vm.expectRevert(UsageReceipts.DayNotClosed.selector);
        ur.commit(type(uint32).max, keccak256("r"), 1);
        // The first second of the next day closes `today`.
        vm.warp(uint256(today + 1) * 1 days);
        ur.commit(today, keccak256("r"), 1);
        vm.stopPrank();
    }

    function test_onePerCommitterPerDay() public {
        vm.startPrank(member);
        ur.commit(today - 1, keccak256("r1"), 1);
        vm.expectRevert(UsageReceipts.AlreadyCommitted.selector);
        ur.commit(today - 1, keccak256("r2"), 1);
        vm.stopPrank();
        assertEq(ur.rootOf(member, today - 1).root, keccak256("r1"));
    }

    function test_committersAreNamespaced() public {
        bytes32 root = keccak256("same root");
        vm.prank(stranger);
        ur.commit(today - 1, root, 1);
        assertFalse(ur.isCommitted(member, today - 1));
        vm.prank(member);
        ur.commit(today - 1, root, 1);
        assertEq(ur.dayCount(member), 1);
        assertEq(ur.dayCount(stranger), 1);
    }

    function test_zeroRootAndZeroSchemaRefused() public {
        vm.startPrank(member);
        vm.expectRevert(UsageReceipts.ZeroRoot.selector);
        ur.commit(today - 1, bytes32(0), 1);
        vm.expectRevert(UsageReceipts.BadSchema.selector);
        ur.commit(today - 1, keccak256("r"), 0);
        vm.stopPrank();
    }

    function test_missingDayReadsAllZero() public view {
        UsageReceipts.Receipt memory r = ur.rootOf(member, today - 5);
        assertEq(r.root, bytes32(0));
        assertEq(r.committedAt, 0);
        assertFalse(ur.isCommitted(member, today - 5));
    }

    function test_pagingClampsTail() public {
        vm.startPrank(member);
        for (uint32 d = 1; d <= 5; d++) {
            ur.commit(today - d, keccak256(abi.encode(d)), 1);
        }
        vm.stopPrank();
        assertEq(ur.daysOf(member, 3, type(uint256).max).length, 2);
        assertEq(ur.daysOf(member, 3, 1)[0], today - 4);
        assertEq(ur.daysOf(member, 5, 1).length, 0);
        assertEq(ur.daysOf(member, type(uint256).max, type(uint256).max).length, 0);
    }

    /// Backfill cap (owner, 2026-10-26): 90 days in the deploy profile, a bounded deploy-time
    /// parameter.
    function test_backfillIsCapped() public {
        vm.startPrank(member);
        ur.commit(today - 90, keccak256("oldest allowed"), 1);
        vm.expectRevert(abi.encodeWithSelector(UsageReceipts.DayTooOld.selector, today - 90));
        ur.commit(today - 91, keccak256("too old"), 1);
        vm.stopPrank();
        assertEq(ur.maxBackfillDays(), ur.DEFAULT_MAX_BACKFILL_DAYS());
        assertEq(ur.DEFAULT_MAX_BACKFILL_DAYS(), 90);
    }

    function test_backfillBounds() public {
        vm.expectRevert(UsageReceipts.BadBackfill.selector);
        new UsageReceipts(0);
        vm.expectRevert(UsageReceipts.BadBackfill.selector);
        new UsageReceipts(367);
        UsageReceipts one = new UsageReceipts(1);
        vm.prank(member);
        vm.expectRevert(abi.encodeWithSelector(UsageReceipts.DayTooOld.selector, today - 1));
        one.commit(today - 2, keccak256("r"), 1);
        vm.prank(member);
        one.commit(today - 1, keccak256("r"), 1);
    }

    function test_holdsNoValue() public {
        _assertRejectsValue(address(ur));
    }

    function testFuzz_closedDayRule(uint32 day, bytes32 root, uint8 schema) public {
        vm.assume(root != bytes32(0) && schema != 0);
        vm.prank(member);
        uint256 t = T0 / 1 days;
        if (uint256(day) >= t) {
            vm.expectRevert(UsageReceipts.DayNotClosed.selector);
        } else if (uint256(day) + 90 < t) {
            vm.expectRevert(abi.encodeWithSelector(UsageReceipts.DayTooOld.selector, uint32(t - 90)));
        }
        ur.commit(day, root, schema);
    }
}

contract UsageReceiptsHandler is Test {
    UsageReceipts public ur;
    address[3] public actors = [address(0xA1), address(0xA2), address(0xA3)];
    mapping(address => uint256) public commits;
    mapping(address => mapping(uint32 => bool)) public seen;
    bool public violation;

    constructor(UsageReceipts ur_) {
        ur = ur_;
    }

    function warp(uint32 dt) external {
        vm.warp(vm.getBlockTimestamp() + bound(dt, 0, 3 days));
    }

    function commit(uint256 who, uint32 back, bytes32 root) external {
        address a = actors[who % 3];
        uint32 today = uint32(vm.getBlockTimestamp() / 1 days);
        // Mostly closed days, sometimes today or the future.
        uint32 day = uint32(bound(uint256(back), 0, 12));
        day = day <= 10 ? today - 1 - day : today + (day - 11);
        if (root == bytes32(0)) root = keccak256(abi.encode(who, back));
        vm.prank(a);
        try ur.commit(day, root, 1) {
            if (seen[a][day] || day >= today) violation = true;
            seen[a][day] = true;
            commits[a] += 1;
        } catch {
            if (!seen[a][day] && day < today) violation = true;
        }
    }
}

contract UsageReceiptsInvariantTest is Test {
    UsageReceipts internal ur;
    UsageReceiptsHandler internal handler;

    function setUp() public {
        vm.warp(1_800_000_000);
        ur = new UsageReceipts(90);
        handler = new UsageReceiptsHandler(ur);
        targetContract(address(handler));
    }

    /// At most one receipt per (committer, day); never a day that had not closed when committed.
    /// Receipts never change once written, so checking each actor's newest one after every call
    /// covers every receipt once.
    function invariant_onePerDayAndOnlyClosedDays() public view {
        assertFalse(handler.violation());
        for (uint256 i = 0; i < 3; i++) {
            address a = handler.actors(i);
            uint256 n = ur.dayCount(a);
            assertEq(n, handler.commits(a));
            if (n == 0) continue;
            uint32 day = ur.daysOf(a, n - 1, 1)[0];
            UsageReceipts.Receipt memory r = ur.rootOf(a, day);
            assertLt(uint256(day), uint256(r.committedAt) / 1 days);
            assertTrue(handler.seen(a, day));
        }
    }

    function invariant_holdsNoValue() public view {
        assertEq(address(ur).balance, 0);
    }
}
