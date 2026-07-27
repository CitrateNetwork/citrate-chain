// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/ValidatorRegistry.sol";

/// @notice Targeted fuzz tests for ValidatorRegistry (campaign track 4/4), driving the REAL
///         contract. Complements the handler-based invariant suite: these pin down the ACCESS,
///         EMISSION-CAP, STAKING and PARAM-BOUND properties as parameterized single-shot fuzzes,
///         and (with the ed25519 precompile mock OFF for one case) the bad-signature rejection.
contract ValidatorRegistryFuzzTest is Test {
    ValidatorRegistry reg;

    address gov = address(0x6011);
    address slasher = address(0x5142);
    address minter = address(0x11d7);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    bytes32 constant PK_A = bytes32(uint256(0xAAAA));
    uint256 constant MIN = 32_000 ether;
    bytes SIG = new bytes(64);

    function setUp() public {
        reg = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 5000, 10_000 ether);
        _mockVerify(true);
        vm.roll(10_000);
        vm.deal(address(this), 1e12 ether);
        vm.deal(alice, 1e12 ether);
        vm.deal(bob, 1e12 ether);
    }

    function _mockVerify(bool ok) internal {
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(ok ? 1 : 0)));
    }

    function _register(address who, bytes32 pk, uint256 amount) internal {
        vm.deal(who, amount + 1 ether);
        vm.prank(who);
        reg.registerValidator{value: amount}(pk, SIG);
    }

    // ── ACCESS (#3): only the sentinel rewardMinter may creditReward ──────────
    function testFuzz_creditReward_onlyMinter(address caller, uint96 amt) public {
        vm.assume(caller != minter);
        _register(alice, PK_A, MIN);
        vm.deal(caller, uint256(amt) + 1 ether);
        vm.prank(caller);
        vm.expectRevert(ValidatorRegistry.NotMinter.selector);
        reg.creditReward{value: amt}(PK_A, amt);
    }

    // ── ACCESS (#3): only the slasher may drive the non-equivocation slash tiers ─
    function testFuzz_slash_onlySlasher(address caller, uint8 tierSeed) public {
        vm.assume(caller != slasher);
        _register(alice, PK_A, MIN);
        ValidatorRegistry.SlashTier tier = ValidatorRegistry.SlashTier(uint8(bound(tierSeed, 0, 2)));
        vm.prank(caller);
        vm.expectRevert(ValidatorRegistry.NotSlasher.selector);
        reg.slash(PK_A, tier, "x");
    }

    // ── ACCESS (#3): only governance may queue params ─────────────────────────
    function testFuzz_queueParam_onlyGovernance(address caller, uint256 v) public {
        vm.assume(caller != gov);
        uint256 value = bound(v, MIN, reg.MIN_STAKE_CEIL()); // resolve view before the guarded call
        vm.prank(caller);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.queueParam(keccak256("minStake"), value);
    }

    // ── EMISSION CAP (#2): credit either stays within the cap (and is ETH-backed) or reverts ─
    function testFuzz_creditReward_neverOvermints(uint256 amt) public {
        _register(alice, PK_A, MIN);
        amt = bound(amt, 0, 1_000_000 ether);
        vm.deal(minter, amt);
        uint256 ep = reg.currentEpoch();
        vm.prank(minter);
        try reg.creditReward{value: amt}(PK_A, amt) {
            assertLe(reg.emittedInEpoch(ep), reg.maxEpochEmission(), "emitted past cap");
            (,, uint256 rewards,,,,,,,) = reg.validatorInfo(PK_A);
            assertEq(rewards, amt, "vested != credited");
            assertLe(rewards, address(reg).balance, "vested not ETH-backed");
        } catch {
            // The only reachable failure at this point is the cap (msg.value==amt, Active).
            assertGt(amt, reg.maxEpochEmission(), "credit reverted for a non-cap reason");
        }
    }

    // ── EMISSION CAP (#2): a multi-credit sequence in one epoch never crosses the cap ─
    function testFuzz_creditReward_sequenceRespectsCap(uint256 a, uint256 b, uint256 c) public {
        _register(alice, PK_A, MIN);
        uint256 ep = reg.currentEpoch();
        uint256[3] memory amts = [bound(a, 0, 8_000 ether), bound(b, 0, 8_000 ether), bound(c, 0, 8_000 ether)];
        for (uint256 i = 0; i < 3; i++) {
            vm.deal(minter, amts[i]);
            vm.prank(minter);
            try reg.creditReward{value: amts[i]}(PK_A, amts[i]) {} catch {}
            assertLe(reg.emittedInEpoch(ep), reg.maxEpochEmission(), "epoch emission crossed cap mid-sequence");
        }
    }

    // ── STAKING (#4): registration stake threshold is exactly enforced ────────
    function testFuzz_register_belowMinReverts(uint256 stake) public {
        stake = bound(stake, 0, MIN - 1);
        vm.deal(alice, stake);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadStake.selector);
        reg.registerValidator{value: stake}(PK_A, SIG);
    }

    function testFuzz_register_atOrAboveMinSucceeds(uint256 stake) public {
        stake = bound(stake, MIN, MIN + 500_000 ether);
        _register(alice, PK_A, stake);
        assertTrue(reg.isActive(PK_A));
        assertEq(reg.stakeOf(PK_A), stake);
    }

    // ── STAKING (#4): full unbond then withdraw pays back EXACTLY the bond, never more ─
    function testFuzz_fullUnbond_withdrawExact(uint256 stake) public {
        stake = bound(stake, MIN, MIN + 500_000 ether);
        _register(alice, PK_A, stake);
        vm.prank(alice);
        reg.initiateUnbond(PK_A, stake);
        assertFalse(reg.isActive(PK_A));

        vm.roll(block.number + reg.EXIT_LOCK_EPOCHS() * reg.EPOCH());
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        reg.withdraw(PK_A);
        assertEq(alice.balance - balBefore, stake, "withdrew != escrowed bond");

        // A second withdraw pays nothing (no double-withdraw / underflow).
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.NothingToWithdraw.selector);
        reg.withdraw(PK_A);
    }

    // ── STAKING (#4): partial unbond must never breach admission minStake or exceed bond ─
    function testFuzz_partialUnbond_boundaries(uint256 extra, uint256 unbondAmt) public {
        extra = bound(extra, 0, 500_000 ether);
        uint256 stake = MIN + extra;
        _register(alice, PK_A, stake);
        unbondAmt = bound(unbondAmt, 1, stake + 1_000 ether); // may exceed bond → must revert

        uint256 remaining = unbondAmt > stake ? type(uint256).max : stake - unbondAmt;
        bool shouldRevert = unbondAmt > stake || (remaining != 0 && remaining < MIN);

        vm.prank(alice);
        if (shouldRevert) {
            vm.expectRevert(ValidatorRegistry.BadStake.selector);
            reg.initiateUnbond(PK_A, unbondAmt);
        } else {
            reg.initiateUnbond(PK_A, unbondAmt);
            (, uint256 bonded,, uint256 escrow,,,,,,) = reg.validatorInfo(PK_A);
            assertEq(escrow, unbondAmt, "escrow != unbonded amount");
            assertEq(bonded, stake - unbondAmt, "bond not reduced exactly");
            assertLe(escrow, address(reg).balance, "escrow not backed");
        }
    }

    // ── REGISTRATION (#6): a bad ed25519 signature is rejected (precompile mock OFF) ──
    function testFuzz_badSig_rejected(bytes32 pk) public {
        vm.assume(pk != bytes32(0));
        _mockVerify(false); // precompile returns invalid for every input
        vm.deal(alice, MIN + 1 ether);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadSig.selector);
        reg.registerValidator{value: MIN}(pk, SIG);
    }

    // ── REGISTRATION (#6): a registered pubkey is single-use (uniqueness) ─────
    function testFuzz_pubkey_singleUse(bytes32 pk) public {
        vm.assume(pk != bytes32(0));
        _register(alice, pk, MIN);
        vm.deal(bob, MIN + 1 ether);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.PubkeyTaken.selector);
        reg.registerValidator{value: MIN}(pk, SIG);
    }

    // ── PARAM BOUNDS (#5): priorityFeeShareBps in the ctor admits exactly 10000, rejects >10000 ─
    function testFuzz_ctor_priorityFeeShareBound(uint256 bps) public {
        bps = bound(bps, 0, 25_000);
        if (bps > 10000) {
            vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
            new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, bps, 10_000 ether);
        } else {
            ValidatorRegistry r = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, bps, 10_000 ether);
            assertEq(r.priorityFeeShareBps(), bps, "share not stored");
        }
    }

    // ── PARAM BOUNDS (#5): queueing priorityFeeShareBps respects both the 100% ceiling and delta ─
    function testFuzz_queueParam_priorityFeeShareBps(uint256 v) public {
        // Fresh registry starting at 8000 bps: delta bound admits [4000,12000], intersected with
        // the <=10000 absolute ceiling => queue succeeds exactly on [4000,10000], else OutOfBounds.
        ValidatorRegistry r = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 8000, 10_000 ether);
        v = bound(v, 0, 15_000);
        bytes32 name = keccak256("priorityFeeShareBps");
        bool ok = (v >= 4000 && v <= 10000);
        vm.prank(gov);
        if (ok) {
            r.queueParam(name, v);
            (uint256 pending,, bool exists) = r.pendingParam(name);
            assertTrue(exists, "queue did not take");
            assertEq(pending, v, "queued value wrong");
        } else {
            vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
            r.queueParam(name, v);
        }
    }

    // ── PARAM BOUNDS (#5): maxEpochEmission stays under its absolute ceiling on queue ─
    function testFuzz_queueParam_maxEpochEmissionCeil(uint256 v) public {
        // Start near the ceiling (900k) so the 50% delta can reach the 1M ceiling; anything above
        // the ceiling must revert OutOfBounds regardless of delta.
        ValidatorRegistry r = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 5000, 900_000 ether);
        v = bound(v, 450_000 ether, 2_000_000 ether);
        bytes32 name = keccak256("maxEpochEmission");
        uint256 ceil = r.MAX_EPOCH_EMISSION_CEIL();
        uint256 maxDelta = (900_000 ether * r.GOV_MAX_DELTA_BPS()) / 10000;
        bool withinDelta = v <= 900_000 ether + maxDelta && (v >= 900_000 ether || 900_000 ether - v <= maxDelta);
        vm.prank(gov);
        if (v <= ceil && withinDelta) {
            r.queueParam(name, v);
            (uint256 pending,,) = r.pendingParam(name);
            assertEq(pending, v);
            assertLe(pending, ceil, "queued maxEpochEmission over ceiling");
        } else {
            vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
            r.queueParam(name, v);
        }
    }

    // ── PARAM BOUNDS (#5): a queued param only applies after the timelock, and lands in-bounds ─
    function testFuzz_paramApply_timelockAndBounds(uint256 raiseBps, uint256 wait) public {
        // Raise minStake by a bounded, in-delta amount; it must not apply before eta.
        uint256 cur = reg.minStake();
        uint256 maxUp = (cur * reg.GOV_MAX_DELTA_BPS()) / 10000;
        uint256 target = bound(raiseBps, cur, cur + maxUp);
        target = target > reg.MIN_STAKE_CEIL() ? reg.MIN_STAKE_CEIL() : target;
        bytes32 name = keccak256("minStake");
        vm.prank(gov);
        reg.queueParam(name, target);

        uint256 timelock = reg.GOV_TIMELOCK(); // resolve view before the pranked/guarded call
        wait = bound(wait, 0, timelock * 2);
        vm.warp(block.timestamp + wait);
        vm.prank(gov);
        if (wait < timelock) {
            vm.expectRevert(ValidatorRegistry.Timelock.selector);
            reg.executeParam(name);
        } else {
            reg.executeParam(name);
            assertEq(reg.minStake(), target, "applied value wrong");
            assertGe(reg.minStake(), reg.MIN_STAKE_FLOOR());
            assertLe(reg.minStake(), reg.MIN_STAKE_CEIL());
        }
    }
}
