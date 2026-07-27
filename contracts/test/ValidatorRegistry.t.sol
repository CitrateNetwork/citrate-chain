// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/ValidatorRegistry.sol";

/// @notice Unit tests for ValidatorRegistry. The 0x0120 ed25519-verify precompile is
///         mocked with vm.mockCall — verify semantics themselves are covered by the Rust
///         precompile tests (core/execution/src/precompiles/ed25519.rs).
contract ValidatorRegistryTest is Test {
    ValidatorRegistry reg;

    address gov = address(0x6011);
    address slasher = address(0x5142);
    address minter = address(0x11d7);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address carol = address(0xCA401);

    bytes32 constant PK_A = bytes32(uint256(0xAAAA));
    bytes32 constant PK_B = bytes32(uint256(0xBBBB));
    bytes32 constant PK_C = bytes32(uint256(0xCCCC));

    uint256 constant MIN = 32_000 ether;
    bytes SIG = new bytes(64); // content irrelevant; precompile is mocked

    function setUp() public {
        reg = new ValidatorRegistry(
            gov,
            slasher,
            minter,
            MIN,             // minStake
            1 ether,         // blockSubsidy
            5000,            // priorityFeeShareBps (50%)
            10_000 ether     // maxEpochEmission
        );
        _mockVerify(true);
        vm.roll(10_000);
        vm.deal(alice, 10_000_000 ether);
        vm.deal(bob, 10_000_000 ether);
        vm.deal(carol, 10_000_000 ether);
    }

    // Make the ed25519 precompile return valid(1) or invalid(0) for ALL inputs.
    function _mockVerify(bool ok) internal {
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(ok ? 1 : 0)));
    }

    function _register(address who, bytes32 pk, uint256 amount) internal {
        vm.prank(who);
        reg.registerValidator{value: amount}(pk, SIG);
    }

    // ── Registration ────────────────────────────────────────────────────────
    function test_register_happy() public {
        _register(alice, PK_A, MIN);
        assertTrue(reg.isActive(PK_A));
        assertEq(reg.stakeOf(PK_A), MIN);
        assertEq(reg.pubkeyOfStaker(alice), PK_A);
        assertEq(reg.activeCount(), 1);
    }

    function test_register_belowMinStake_reverts() public {
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadStake.selector);
        reg.registerValidator{value: MIN - 1}(PK_A, SIG);
    }

    function test_register_badSig_reverts() public {
        _mockVerify(false);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadSig.selector);
        reg.registerValidator{value: MIN}(PK_A, SIG);
    }

    function test_register_shortSig_reverts() public {
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadSig.selector);
        reg.registerValidator{value: MIN}(PK_A, new bytes(63));
    }

    function test_register_dupPubkey_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.PubkeyTaken.selector);
        reg.registerValidator{value: MIN}(PK_A, SIG);
    }

    function test_register_stakerAlreadyHasValidator_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.StakerHasValidator.selector);
        reg.registerValidator{value: MIN}(PK_B, SIG);
    }

    function test_register_incrementsNonce() public {
        assertEq(reg.registrationNonce(alice), 0);
        _register(alice, PK_A, MIN);
        assertEq(reg.registrationNonce(alice), 1);
    }

    // ── Stake management ─────────────────────────────────────────────────────
    function test_increaseStake() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        reg.increaseStake{value: 1000 ether}(PK_A);
        assertEq(reg.stakeOf(PK_A), MIN + 1000 ether);
    }

    function test_increaseStake_notStaker_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.NotStaker.selector);
        reg.increaseStake{value: 1 ether}(PK_A);
    }

    function test_partialUnbond_escrowsAndLocks() public {
        _register(alice, PK_A, MIN + 5000 ether);
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        reg.initiateUnbond(PK_A, 5000 ether);
        // stays Active with reduced bond, funds are ESCROWED (not refunded), still slashable
        assertTrue(reg.isActive(PK_A));
        assertEq(reg.stakeOf(PK_A), MIN);
        assertEq(alice.balance, balBefore); // NOT refunded yet
        (, , , uint256 escrow, , , , , ,) = reg.validatorInfo(PK_A);
        assertEq(escrow, 5000 ether);

        // cannot withdraw before the lock
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.Locked.selector);
        reg.withdraw(PK_A);

        // after the lock, escrow is withdrawable; validator remains Active
        vm.roll(block.number + reg.EXIT_LOCK_EPOCHS() * reg.EPOCH());
        vm.prank(alice);
        reg.withdraw(PK_A);
        assertEq(alice.balance, balBefore + 5000 ether);
        assertTrue(reg.isActive(PK_A));
    }

    function test_partialUnbond_belowAdmissionMin_reverts() public {
        _register(alice, PK_A, MIN + 100 ether);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.BadStake.selector);
        reg.initiateUnbond(PK_A, 200 ether); // would leave < admission minStake but > 0
    }

    function test_partialUnbond_slashEvasionClosed() public {
        // The core fix: a validator with a large bond cannot pull most of it out risk-free.
        _register(alice, PK_A, 1_000_000 ether); // whale
        vm.prank(alice);
        reg.initiateUnbond(PK_A, 968_000 ether); // pull down to minStake
        // Byzantine slash lands within the window — escrow is STILL slashable.
        vm.prank(bob);
        reg.submitEquivocation(PK_A, 7, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
        // 100% of bond + escrow seized; escrow no longer withdrawable (Slashed)
        (, uint256 bonded, , uint256 escrow, , , , , ,) = reg.validatorInfo(PK_A);
        assertEq(bonded, 0);
        assertEq(escrow, 0);
        assertTrue(reg.slashedPubkey(PK_A));
        vm.roll(block.number + reg.EXIT_LOCK_EPOCHS() * reg.EPOCH());
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.AlreadySlashed.selector);
        reg.withdraw(PK_A);
    }

    function test_fullUnbond_thenWithdraw_afterLock() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        reg.initiateUnbond(PK_A, MIN);
        assertFalse(reg.isActive(PK_A));
        assertEq(reg.activeCount(), 0);

        // before the unbond+evidence window → Locked
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.Locked.selector);
        reg.withdraw(PK_A);

        vm.roll(block.number + reg.EXIT_LOCK_EPOCHS() * reg.EPOCH());
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        reg.withdraw(PK_A);
        assertEq(alice.balance, balBefore + MIN);
    }

    function test_withdraw_notStaker_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        reg.initiateUnbond(PK_A, MIN);
        vm.roll(block.number + reg.EXIT_LOCK_EPOCHS() * reg.EPOCH());
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.NotStaker.selector);
        reg.withdraw(PK_A);
    }

    // ── Equivocation slashing ────────────────────────────────────────────────
    function test_equivocation_slashesAndBans() public {
        _register(alice, PK_A, MIN);

        vm.prank(bob);
        reg.submitEquivocation(PK_A, 12345, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);

        assertTrue(reg.slashedPubkey(PK_A));
        assertTrue(reg.slashedStaker(alice));
        assertFalse(reg.isActive(PK_A));

        // bounty is pull-payment: accrued, then claimed
        uint256 expected = (MIN * reg.BOUNTY_BPS()) / 10000;
        assertEq(reg.claimable(bob), expected);
        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        reg.claimBounty();
        assertEq(bob.balance, bobBefore + expected);
        assertEq(reg.claimable(bob), 0);
    }

    function test_bounty_revertingReporter_doesNotBlockSlash() public {
        _register(alice, PK_A, MIN);
        RevertingReporter r = new RevertingReporter(reg);
        // slash still succeeds even though the reporter can't receive ETH
        r.report(PK_A);
        assertTrue(reg.slashedPubkey(PK_A));
        assertEq(reg.claimable(address(r)), (MIN * reg.BOUNTY_BPS()) / 10000);
        // its claim reverts on transfer, but the slash already stuck
        vm.expectRevert();
        r.claim();
    }

    function test_equivocation_selfReport_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.SelfReport.selector);
        reg.submitEquivocation(PK_A, 1, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
    }

    function test_equivocation_sameHash_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.BadEvidence.selector);
        reg.submitEquivocation(PK_A, 1, bytes32(uint256(1)), SIG, bytes32(uint256(1)), SIG);
    }

    function test_equivocation_dup_reverts() public {
        _register(alice, PK_A, MIN);
        vm.prank(bob);
        reg.submitEquivocation(PK_A, 1, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
        // already slashed → status check fires first
        vm.prank(carol);
        vm.expectRevert(ValidatorRegistry.BadEvidence.selector);
        reg.submitEquivocation(PK_A, 1, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
    }

    function test_equivocation_badSig_reverts() public {
        _register(alice, PK_A, MIN);
        _mockVerify(false);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.BadEvidence.selector);
        reg.submitEquivocation(PK_A, 1, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
    }

    // ── Slasher-gated slash ──────────────────────────────────────────────────
    function test_slash_onlySlasher() public {
        _register(alice, PK_A, MIN);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.NotSlasher.selector);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Inconsistency, "x");
    }

    function test_slash_inconsistency_demotesBelowAdmissionMin() public {
        // At exactly MIN, a 20% Inconsistency slash drops below admission minStake → demote.
        _register(alice, PK_A, MIN);
        vm.prank(slasher);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Inconsistency, "x");
        assertFalse(reg.isActive(PK_A)); // demoted out of the set
        (, uint256 bonded, , uint256 escrow, , , , , ValidatorRegistry.Status status,) = reg.validatorInfo(PK_A);
        assertEq(bonded, 0);
        assertEq(escrow, MIN - (MIN * 2000) / 10000); // remaining bond escrowed, still slashable
        assertEq(uint8(status), uint8(ValidatorRegistry.Status.Exiting));
    }

    function test_slash_inconsistency_staysActiveIfAboveMin() public {
        // With a cushion above minStake, a 20% slash keeps it Active.
        _register(alice, PK_A, 2 * MIN);
        vm.prank(slasher);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Inconsistency, "x");
        assertEq(reg.stakeOf(PK_A), 2 * MIN - (2 * MIN * 2000) / 10000);
        assertTrue(reg.isActive(PK_A));
    }

    // ── Rewards ──────────────────────────────────────────────────────────────
    function test_creditReward_onlyMinter() public {
        _register(alice, PK_A, MIN);
        vm.deal(bob, 1 ether);
        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.NotMinter.selector);
        reg.creditReward{value: 1 ether}(PK_A, 1 ether);
    }

    function test_creditReward_mustBeFunded() public {
        _register(alice, PK_A, MIN);
        vm.deal(minter, 100 ether);
        vm.prank(minter);
        vm.expectRevert(ValidatorRegistry.BadValue.selector);
        reg.creditReward{value: 0}(PK_A, 100 ether); // credit without backing ETH → revert
    }

    function test_creditReward_vestsAndMetersAndBacked() public {
        _register(alice, PK_A, MIN);
        vm.deal(minter, 100 ether);
        uint256 balBefore = address(reg).balance;
        vm.prank(minter);
        reg.creditReward{value: 100 ether}(PK_A, 100 ether);
        (, , uint256 rewards, , , , , , ,) = reg.validatorInfo(PK_A);
        assertEq(rewards, 100 ether);
        assertEq(reg.emittedInEpoch(reg.currentEpoch()), 100 ether);
        assertEq(address(reg).balance, balBefore + 100 ether); // ETH-backed
    }

    function test_creditReward_emissionCap_reverts() public {
        _register(alice, PK_A, MIN);
        vm.deal(minter, 20_000 ether);
        vm.prank(minter);
        vm.expectRevert(ValidatorRegistry.EmissionCapped.selector);
        reg.creditReward{value: 10_001 ether}(PK_A, 10_001 ether); // > maxEpochEmission
    }

    // ── Governance (timelocked, bounded) ─────────────────────────────────────
    function test_governance_queueExecute_minStake() public {
        vm.prank(gov);
        reg.queueParam(keccak256("minStake"), 40_000 ether); // +25%, within 50% + bounds
        // before eta
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.Timelock.selector);
        reg.executeParam(keccak256("minStake"));
        vm.warp(block.timestamp + reg.GOV_TIMELOCK());
        vm.prank(gov);
        reg.executeParam(keccak256("minStake"));
        assertEq(reg.minStake(), 40_000 ether);
    }

    function test_governance_minStake_belowFloor_reverts() public {
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        reg.queueParam(keccak256("minStake"), 500 ether); // < FLOOR 1000
    }

    function test_governance_deltaTooLarge_reverts() public {
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        reg.queueParam(keccak256("minStake"), 100_000 ether); // > +50%
    }

    function test_governance_notGov_reverts() public {
        vm.prank(bob);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        reg.queueParam(keccak256("minStake"), 40_000 ether);
    }

    function test_governance_bootstrapFromZero() public {
        // blockSubsidy starts at 1 ether; set priorityFeeShareBps down then back tests non-zero.
        // Bootstrap-from-zero path: use maxEpochEmission after zeroing is not allowed, so test
        // a fresh registry with blockSubsidy 0.
        ValidatorRegistry r2 = new ValidatorRegistry(gov, slasher, minter, MIN, 0, 0, 10_000 ether);
        vm.prank(gov);
        r2.queueParam(keccak256("blockSubsidy"), 5 ether); // from 0 → allowed (bootstrap)
        vm.warp(block.timestamp + r2.GOV_TIMELOCK());
        vm.prank(gov);
        r2.executeParam(keccak256("blockSubsidy"));
        assertEq(r2.blockSubsidy(), 5 ether);
    }

    function test_governance_slasherRotation() public {
        address newSlasher = address(0x9999);
        vm.prank(gov);
        reg.queueSlasher(newSlasher);
        vm.warp(block.timestamp + reg.GOV_TIMELOCK());
        vm.prank(gov);
        reg.executeSlasher();
        assertEq(reg.slasher(), newSlasher);
    }

    // ── Active set view: canonical order + 1/3 cap ───────────────────────────
    function test_activeSet_sortedAndCapped() public {
        // 3 validators with skewed stake; effective stake capped at total/3.
        _register(alice, PK_A, 100_000 ether);
        _register(bob, PK_B, 100_000 ether);
        _register(carol, PK_C, 100_000 ether);
        (bytes32[] memory pks, uint256[] memory eff) = reg.activeSet();
        assertEq(pks.length, 3);
        // canonical sort by pubkey ascending
        assertTrue(pks[0] < pks[1] && pks[1] < pks[2]);
        // total = 300k, cap = 100k; each is exactly at cap → uncapped
        for (uint256 i = 0; i < 3; i++) assertEq(eff[i], 100_000 ether);
    }

    function test_activeSet_whaleCapped_fixpoint() public {
        _register(alice, PK_A, 900_000 ether);
        _register(bob, PK_B, 50_000 ether);
        _register(carol, PK_C, 50_000 ether);
        (bytes32[] memory pks, uint256[] memory eff) = reg.activeSet();
        // True 1/3 property: no effective stake exceeds floor(effectiveTotal/3) (+1 for integer
        // rounding of the clamp), and no effStake exceeds the validator's raw bond.
        uint256 effTotal;
        for (uint256 i = 0; i < eff.length; i++) effTotal += eff[i];
        uint256 cap = effTotal / 3;
        for (uint256 i = 0; i < pks.length; i++) {
            assertLe(eff[i], cap + 1);
            assertLe(eff[i], reg.stakeOf(pks[i]));
        }
        // the whale (900k) was ground down toward parity with the 50k stakers
        assertLt(eff[0] > eff[1] ? eff[0] - eff[1] : eff[1] - eff[0], 5_000 ether);
    }

    // ── Eviction (margin + churn) ────────────────────────────────────────────
    function _fillSet() internal {
        // Fill all MAX_ACTIVE_SET slots at exactly MIN stake, one distinct staker/pubkey each.
        uint256 max = reg.MAX_ACTIVE_SET();
        for (uint256 i = 0; i < max; i++) {
            address who = address(uint160(0x100000 + i));
            vm.deal(who, MIN + 1 ether);
            vm.prank(who);
            reg.registerValidator{value: MIN}(bytes32(uint256(0x1000 + i)), SIG);
        }
        assertEq(reg.activeCount(), max);
    }

    function test_eviction_noMargin_reverts() public {
        _fillSet();
        // newcomer at exactly MIN (incumbent min) — no 25% margin → reverts
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.SetFullNoMargin.selector);
        reg.registerValidator{value: MIN}(PK_A, SIG);
    }

    function test_eviction_withMargin_succeeds() public {
        _fillSet();
        uint256 required = MIN + (MIN * reg.EVICTION_MARGIN_BPS()) / 10000; // +25%
        vm.prank(alice);
        reg.registerValidator{value: required}(PK_A, SIG);
        assertTrue(reg.isActive(PK_A));
        // set stays bounded at MAX (one incumbent evicted)
        assertEq(reg.activeCount(), reg.MAX_ACTIVE_SET());
    }

    function test_eviction_churnCap_reverts() public {
        _fillSet();
        uint256 required = MIN + (MIN * reg.EVICTION_MARGIN_BPS()) / 10000;
        // CHURN_CAP evictions allowed this epoch
        uint256 cap = reg.CHURN_CAP();
        for (uint256 i = 0; i < cap; i++) {
            address who = address(uint160(0x200000 + i));
            vm.deal(who, required + 1 ether);
            vm.prank(who);
            reg.registerValidator{value: required}(bytes32(uint256(0x2000 + i)), SIG);
        }
        // the (cap+1)-th eviction in the same epoch → ChurnExceeded
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.ChurnExceeded.selector);
        reg.registerValidator{value: required}(PK_A, SIG);

        // next epoch resets the churn budget
        vm.roll(block.number + reg.EPOCH());
        vm.prank(alice);
        reg.registerValidator{value: required}(PK_A, SIG);
        assertTrue(reg.isActive(PK_A));
    }

    // ── Governance absolute ceilings (anti-hyperinflation) ───────────────────
    function test_governance_maxEpochEmission_ceiling_reverts() public {
        // start a registry whose maxEpochEmission is near the ceiling, then try to blow past it
        ValidatorRegistry r2 = new ValidatorRegistry(
            gov, slasher, minter, MIN, 1 ether, 5000, 900_000 ether
        );
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        r2.queueParam(keccak256("maxEpochEmission"), 2_000_000 ether); // > CEIL
    }

    // ── WS-5 reconcile: 100% priority-fee share is admissible (bound is <= 10000) ──
    function test_ctor_priorityFeeShare_100pct_admissible() public {
        // Exactly 10000 bps (100%) must construct — the owner routes the whole share.
        ValidatorRegistry r2 = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 10000, 10_000 ether);
        assertEq(r2.priorityFeeShareBps(), 10000, "100% share must be stored");
    }

    function test_ctor_priorityFeeShare_over100pct_reverts() public {
        // Above 100% is still nonsensical → OutOfBounds.
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 10001, 10_000 ether);
    }

    function test_governance_priorityFeeShare_to100pct_admissible() public {
        // Governance may raise the share up to (and including) 100% within the 50% delta bound.
        // start at 8000 so a single change to 10000 is within +50% (max +4000).
        ValidatorRegistry r2 = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 8000, 10_000 ether);
        vm.prank(gov);
        r2.queueParam(keccak256("priorityFeeShareBps"), 10000); // exactly 100% — must NOT revert
        vm.warp(block.timestamp + r2.GOV_TIMELOCK());
        vm.prank(gov);
        r2.executeParam(keccak256("priorityFeeShareBps"));
        assertEq(r2.priorityFeeShareBps(), 10000, "governance set to 100%");
    }

    function test_governance_priorityFeeShare_over100pct_reverts() public {
        ValidatorRegistry r2 = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 8000, 10_000 ether);
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        r2.queueParam(keccak256("priorityFeeShareBps"), 10001); // > 100% → OutOfBounds
    }

    function test_governance_bootstrapFromZero_stillBounded() public {
        // maxEpochEmission == 0 → bootstrap path skips the % delta, but the absolute CEIL still bites
        ValidatorRegistry r2 = new ValidatorRegistry(gov, slasher, minter, MIN, 0, 0, 0);
        vm.prank(gov);
        vm.expectRevert(ValidatorRegistry.OutOfBounds.selector);
        r2.queueParam(keccak256("maxEpochEmission"), 5_000_000 ether); // huge jump from 0 → blocked
    }

    // ── Grandfathering: a minStake raise doesn't strand a sitting validator ──
    function test_grandfathering_partialUnbondUsesAdmissionMin() public {
        _register(alice, PK_A, MIN + 1000 ether); // admissionMinStake = 32k
        // governance raises minStake to 40k
        vm.prank(gov);
        reg.queueParam(keccak256("minStake"), 40_000 ether);
        vm.warp(block.timestamp + reg.GOV_TIMELOCK());
        vm.prank(gov);
        reg.executeParam(keccak256("minStake"));
        assertEq(reg.minStake(), 40_000 ether);
        // alice can still partial-unbond down to her ADMISSION min (32k), not the new 40k
        vm.prank(alice);
        reg.initiateUnbond(PK_A, 1000 ether); // leaves 32k == admissionMinStake → allowed
        assertEq(reg.stakeOf(PK_A), MIN);
        assertTrue(reg.isActive(PK_A));
    }

    // ── ADR-5: matured-reward incremental claim ─────────────────────────────
    //
    // Before ADR-5, `withdraw` released rewards ONLY on a full exit after
    // EXIT_LOCK_EPOCHS, so a member could realise earnings only by ceasing to
    // validate. These pin the new behaviour AND the slashing invariant it must
    // not weaken.

    uint256 constant EPOCH_BLOCKS = 1000;

    function _rollEpochs(uint256 n) internal {
        vm.roll(block.number + n * EPOCH_BLOCKS);
    }

    function _credit(bytes32 pk, uint256 amount) internal {
        vm.deal(minter, amount);
        vm.prank(minter);
        reg.creditReward{value: amount}(pk, amount);
    }

    function test_adr5_rewards_not_claimable_inside_evidence_window() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether);

        (uint256 total, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 10 ether, "earned rewards must be visible immediately");
        assertEq(claimableNow, 0, "nothing matures inside the window");

        _rollEpochs(reg.REWARD_RING() - 1); // one epoch short
        (, claimableNow) = reg.rewardsOf(PK_A);
        assertEq(claimableNow, 0, "still inside the window");

        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.NothingToWithdraw.selector);
        reg.claimRewards(PK_A);
    }

    function test_adr5_claim_after_maturity_without_unbonding() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether);
        _rollEpochs(reg.REWARD_RING());

        (uint256 total, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 10 ether);
        assertEq(claimableNow, 10 ether, "must mature after REWARD_RING epochs");

        uint256 before = alice.balance;
        vm.prank(alice);
        reg.claimRewards(PK_A);
        assertEq(alice.balance - before, 10 ether, "staker receives the matured amount");

        // THE POINT OF ADR-5: still Active, still staked, never unbonded.
        assertTrue(reg.isActive(PK_A), "claiming must not remove the validator");
        assertEq(reg.stakeOf(PK_A), MIN, "claiming must not touch bonded stake");

        (total, claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 0);
        assertEq(claimableNow, 0, "no double claim");
    }

    function test_adr5_only_staker_can_claim() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 5 ether);
        _rollEpochs(reg.REWARD_RING());

        vm.prank(bob);
        vm.expectRevert(ValidatorRegistry.NotStaker.selector);
        reg.claimRewards(PK_A);
    }

    /// The invariant ADR-5 must not break: rewards inside the evidence window
    /// stay in the slashable base.
    function test_adr5_unmatured_rewards_remain_slashable() public {
        // Stake ABOVE minStake so a Latency slash does not push the bond under
        // `admissionMinStake` and trigger the demotion path — this test is about
        // the penalty BASE, not about demotion.
        uint256 stake = 40_000 ether;
        _register(alice, PK_A, stake);
        _credit(PK_A, 100 ether);

        (, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(claimableNow, 0, "precondition: rewards are unmatured");

        vm.prank(slasher);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Latency, bytes(""));

        // Latency = 5% of (bond + escrow + UNMATURED rewards). If rewards had
        // been excluded the penalty would be 2000 ether; because they are in the
        // base it is 2005. That 5-ether delta IS the invariant.
        uint256 penaltyWithRewards = ((stake + 100 ether) * 500) / 10000;
        uint256 penaltyWithout = (stake * 500) / 10000;
        assertEq(penaltyWithRewards, 2005 ether);
        assertEq(penaltyWithout, 2000 ether);
        assertEq(
            reg.stakeOf(PK_A),
            stake - penaltyWithRewards,
            "penalty must be computed over a base that includes unmatured rewards"
        );
        assertTrue(reg.isActive(PK_A), "still active: bond stayed above admission minStake");
    }

    /// The deliberate ADR-5 tradeoff, pinned so it is a decision and not a
    /// surprise: once rewards mature they LEAVE the slashable base, so a
    /// subsequent slasher-authorized tier draws against a smaller amount.
    /// Equivocation is unaffected because its evidence window is shorter than
    /// REWARD_RING.
    function test_adr5_matured_rewards_leave_the_slashable_base() public {
        uint256 stake = 40_000 ether;
        _register(alice, PK_A, stake);
        _credit(PK_A, 100 ether);
        _rollEpochs(reg.REWARD_RING()); // the 100 matures

        (, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(claimableNow, 100 ether, "precondition: rewards matured");

        vm.prank(slasher);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Latency, bytes(""));

        // Base is now bond only — 5% of 40,000 = 2,000, NOT 2,005.
        assertEq(
            reg.stakeOf(PK_A),
            stake - (stake * 500) / 10000,
            "matured rewards are outside the base"
        );
    }

    /// Regression: a slash draws down `vestedRewards` without touching the ring,
    /// so the ring can transiently exceed it. Without the clamp in
    /// `_sweepMatured` that underflows and bricks the validator.
    function test_adr5_slash_then_mature_does_not_underflow() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 100 ether);

        vm.prank(slasher);
        reg.slash(PK_A, ValidatorRegistry.SlashTier.Byzantine, bytes(""));

        // Maturity arrives with the ring still holding 100 ether but
        // vestedRewards at 0. Must not revert.
        _rollEpochs(reg.REWARD_RING() + 1);
        (uint256 total, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 0, "slashed rewards cannot resurrect via maturity");
        assertEq(claimableNow, 0);
    }

    /// Two epochs mapping to the same ring slot are always REWARD_RING apart,
    /// so a slot holding a different epoch is necessarily matured.
    function test_adr5_ring_slot_reuse_matures_previous_occupant() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 7 ether);

        _rollEpochs(reg.REWARD_RING()); // same slot, previous occupant matured
        _credit(PK_A, 3 ether);

        (uint256 total, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 10 ether, "both credits accounted");
        assertEq(claimableNow, 7 ether, "only the older credit matured");

        uint256 before = alice.balance;
        vm.prank(alice);
        reg.claimRewards(PK_A);
        assertEq(alice.balance - before, 7 ether);
    }

    /// The terminal full-exit path must still release EVERYTHING.
    function test_adr5_terminal_withdraw_releases_both_buckets() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether);
        _rollEpochs(reg.REWARD_RING()); // 10 matures
        _credit(PK_A, 4 ether);         // 4 still inside the window

        (uint256 total, uint256 claimableNow) = reg.rewardsOf(PK_A);
        assertEq(total, 14 ether);
        assertEq(claimableNow, 10 ether);

        vm.prank(alice);
        reg.initiateUnbond(PK_A, MIN);
        _rollEpochs(reg.EXIT_LOCK_EPOCHS() + 1);

        uint256 before = alice.balance;
        vm.prank(alice);
        reg.withdraw(PK_A);
        assertEq(alice.balance - before, MIN + 14 ether, "terminal payout includes both buckets");
    }

    function test_adr5_validatorInfo_exposes_total_and_claimable() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether);
        _rollEpochs(reg.REWARD_RING());
        _credit(PK_A, 4 ether);

        (, , uint256 rewards, , , , , , , uint256 claimableNow) = reg.validatorInfo(PK_A);
        assertEq(rewards, 14 ether, "validatorInfo.rewards is TOTAL unclaimed");
        assertEq(claimableNow, 10 ether, "matured portion exposed separately");
    }
}

/// A reporter contract that rejects ETH — proves a reverting bounty recipient cannot block
/// a proven equivocation slash (pull-payment decoupling).
contract RevertingReporter {
    ValidatorRegistry immutable reg;

    constructor(ValidatorRegistry r) { reg = r; }

    function report(bytes32 pubkey) external {
        reg.submitEquivocation(pubkey, 1, bytes32(uint256(1)), new bytes(64), bytes32(uint256(2)), new bytes(64));
    }

    function claim() external {
        reg.claimBounty();
    }

    receive() external payable { revert("no eth"); }
}
