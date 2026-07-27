// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Sortition} from "../src/quorum/Sortition.sol";

/// @title Sortition — invariant tests (QRM-S6.8)
///
/// SO-1..SO-3, plus the commit-reveal mechanics they rest on. The state machine
/// also carries a TLA+ spec at `specs/tla/contracts/Sortition.tla`; the two are
/// complements. The spec explores interleavings of open/commit/reveal/finalize/
/// void across the clock; these tests pin the arithmetic the spec abstracts
/// away — the sampling, the Merkle path, the exact block boundaries.
contract SortitionTest is Test {
    Sortition s;

    bytes32 constant DRAW = keccak256("panel-2026-q3");
    bytes32 constant POOL_ROOT = keccak256("pool-root");
    uint32 constant POOL = 12;
    uint32 constant K = 4;

    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    address constant CAROL = address(0xCA401);

    uint64 constant START = 1000;
    uint64 TARGET;

    function setUp() public {
        vm.roll(START);
        s = new Sortition();
        TARGET = START + s.MIN_DELTA();
    }

    function _open() internal {
        s.openDraw(DRAW, POOL_ROOT, POOL, K, TARGET);
    }

    /// Move to a block where finalization is allowed, and give the target block
    /// a hash — on a live chain the EVM supplies one for any block inside the
    /// horizon; `setBlockhash` is how a test supplies the same thing.
    function _reachFinalizeWindow(bytes32 anchor) internal {
        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, anchor);
    }

    /// The commitment is computed BEFORE the prank, deliberately. `vm.prank`
    /// applies to the next call, and an argument that is itself a call consumes
    /// it — so `s.commit(DRAW, s.commitmentFor(...))` would commit as the test
    /// contract rather than as `who`, silently.
    function _commit(address who, bytes32 r, bytes32 salt) internal {
        bytes32 c = s.commitmentFor(r, salt);
        vm.prank(who);
        s.commit(DRAW, c);
    }

    function _reveal(address who, bytes32 r, bytes32 salt) internal {
        vm.prank(who);
        s.reveal(DRAW, r, salt);
    }

    // ── SO-1: reproducibility ───────────────────────────────────────

    /// The committee is a pure function of the fixed seed. Anyone with the
    /// public data recomputes it and gets the same people — which is the whole
    /// claim, and the reason `selection` is a `view` rather than something
    /// stored at finalization.
    function test_SO1_theCommitteeIsRecomputableAndStable() public {
        _open();
        _commit(ALICE, keccak256("r-alice"), keccak256("salt-a"));
        _reachFinalizeWindow(keccak256("anchor"));
        _reveal(ALICE, keccak256("r-alice"), keccak256("salt-a"));
        s.finalize(DRAW);

        uint32[] memory first = s.selection(DRAW);
        uint32[] memory second = s.selection(DRAW);
        assertEq(first.length, K);
        for (uint256 i = 0; i < K; ++i) {
            assertEq(first[i], second[i], "the same draw must not answer twice");
        }

        // …and recomputing it off chain from the published seed agrees.
        bytes32 seed = s.drawOf(DRAW).seed;
        assertEq(first[0], _recomputeFirstPick(seed, POOL), "an outside verifier gets the same first pick");
    }

    /// An independent implementation of the first pick, written from the
    /// documented rule rather than by calling the contract — otherwise "anyone
    /// can recompute it" would be a claim tested against itself.
    function _recomputeFirstPick(bytes32 seed, uint32 poolSize) internal pure returns (uint32) {
        return uint32(uint256(keccak256(abi.encode(seed, uint32(0)))) % poolSize);
    }

    /// The committee is k distinct members of the pool, in range. A sampler that
    /// repeated a member would seat a panel of three people and call it four.
    function test_SO1_theCommitteeIsKDistinctMembersInRange() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor"));
        s.finalize(DRAW);

        uint32[] memory picks = s.selection(DRAW);
        assertEq(picks.length, K);
        for (uint256 i = 0; i < picks.length; ++i) {
            assertLt(picks[i], POOL, "a pick outside the pool is a member who does not exist");
            for (uint256 j = i + 1; j < picks.length; ++j) {
                assertTrue(picks[i] != picks[j], "the same member seated twice");
            }
        }
    }

    /// The degenerate case that breaks naive samplers: k == poolSize must
    /// produce every member exactly once, and the last draw is from a range of
    /// one. A rejection sampler would spin here; this walks the free slots.
    function test_SO1_kEqualsPoolSizeIsAFullPermutation() public {
        bytes32 drawId = keccak256("everyone");
        uint32 n = 6;
        s.openDraw(drawId, POOL_ROOT, n, n, TARGET);
        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, keccak256("anchor"));
        s.finalize(drawId);

        uint32[] memory picks = s.selection(drawId);
        assertEq(picks.length, n);
        bool[] memory seen = new bool[](n);
        for (uint256 i = 0; i < picks.length; ++i) {
            assertLt(picks[i], n);
            assertFalse(seen[picks[i]], "a permutation cannot repeat");
            seen[picks[i]] = true;
        }
    }

    /// A different seed gives a different committee — otherwise the entropy is
    /// decorative. Compared across two draws whose only difference is the
    /// anchor.
    function test_SO1_adifferentAnchorGivesADifferentCommittee() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor-one"));
        s.finalize(DRAW);
        uint32[] memory a = s.selection(DRAW);

        bytes32 other = keccak256("second-draw");
        vm.roll(START);
        s.openDraw(other, POOL_ROOT, POOL, K, TARGET);
        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, keccak256("anchor-two"));
        s.finalize(other);
        uint32[] memory b = s.selection(other);

        bool identical = true;
        for (uint256 i = 0; i < K; ++i) {
            if (a[i] != b[i]) identical = false;
        }
        assertFalse(identical, "the anchor must reach the committee");
    }

    /// Before the seed is fixed there is no committee to read. A `selection`
    /// that returned something for an open draw would be a preview of a result
    /// that has not been decided.
    function test_SO1_thereIsNoCommitteeBeforeTheSeedIsFixed() public {
        _open();
        vm.expectRevert(
            abi.encodeWithSelector(Sortition.NotFinal.selector, DRAW, Sortition.State.Open)
        );
        s.selection(DRAW);
    }

    // ── SO-2: one honest contributor makes it unbiasable ────────────

    /// Every revealed contribution reaches the seed. One contributor changing
    /// their value changes the committee, which is what "one honest contributor
    /// is enough" means operationally.
    function test_SO2_oneContributorsEntropyReachesTheSeed() public {
        _open();
        _commit(ALICE, keccak256("honest"), keccak256("salt"));
        _reachFinalizeWindow(keccak256("anchor"));
        _reveal(ALICE, keccak256("honest"), keccak256("salt"));
        s.finalize(DRAW);
        bytes32 withAlice = s.drawOf(DRAW).seed;

        // The same draw parameters and the same anchor, with a different
        // contribution.
        bytes32 other = keccak256("second");
        vm.roll(START);
        s.openDraw(other, POOL_ROOT, POOL, K, TARGET);
        bytes32 c = s.commitmentFor(keccak256("different"), keccak256("salt"));
        vm.prank(ALICE);
        s.commit(other, c);
        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, keccak256("anchor"));
        vm.prank(ALICE);
        s.reveal(other, keccak256("different"), keccak256("salt"));
        s.finalize(other);

        assertTrue(withAlice != s.drawOf(other).seed, "a contribution that cannot move the seed is theatre");
    }

    /// Commitments close AT the target block, not after it. A commitment made
    /// with the block hash in hand would be chosen rather than committed, which
    /// is precisely what the construction defends against.
    function test_SO2_theCommitWindowClosesAtTheTargetBlock() public {
        _open();
        vm.roll(TARGET - 1);
        _commit(ALICE, keccak256("in-time"), keccak256("salt"));

        bytes32 late = s.commitmentFor(keccak256("too-late"), keccak256("salt"));
        vm.roll(TARGET);
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Sortition.CommitWindowClosed.selector, TARGET));
        s.commit(DRAW, late);
    }

    /// A draw cannot target a block close enough for its opener to be about to
    /// propose it.
    function test_SO2_aTargetTooCloseToNowIsRefused() public {
        uint64 tooSoon = START + s.MIN_DELTA() - 1;
        vm.expectRevert(
            abi.encodeWithSelector(Sortition.TargetTooSoon.selector, tooSoon, START + s.MIN_DELTA())
        );
        s.openDraw(keccak256("rushed"), POOL_ROOT, POOL, K, tooSoon);
    }

    /// A reveal must open the commitment that was actually made. Without this
    /// the commit phase is decoration.
    function test_SO2_aRevealMustOpenTheCommitmentThatWasMade() public {
        _open();
        _commit(ALICE, keccak256("committed"), keccak256("salt"));
        _reachFinalizeWindow(keccak256("anchor"));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Sortition.BadReveal.selector, DRAW, ALICE));
        s.reveal(DRAW, keccak256("something-else"), keccak256("salt"));

        // The right salt matters too — the commitment binds both halves.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Sortition.BadReveal.selector, DRAW, ALICE));
        s.reveal(DRAW, keccak256("committed"), keccak256("wrong-salt"));

        _reveal(ALICE, keccak256("committed"), keccak256("salt"));
        assertTrue(s.revealedBy(DRAW, ALICE));
    }

    /// Reveals cannot happen before the target block: an early reveal would let
    /// the proposer see the contribution while still choosing its block.
    function test_SO2_revealsCannotPrecedeTheTargetBlock() public {
        _open();
        _commit(ALICE, keccak256("r"), keccak256("salt"));

        vm.roll(TARGET);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Sortition.RevealTooEarly.selector, TARGET));
        s.reveal(DRAW, keccak256("r"), keccak256("salt"));
    }

    /// **Bias is converted into denial of service.** A contributor who computes
    /// the outcome and dislikes it can withhold their reveal — and that kills
    /// the draw rather than steering it. A void draw is visible and re-runnable;
    /// a steered one looks exactly like a fair one.
    function test_SO2_aWithheldRevealKillsTheDrawRatherThanSteeringIt() public {
        _open();
        _commit(ALICE, keccak256("r-a"), keccak256("s-a"));
        _commit(BOB, keccak256("r-b"), keccak256("s-b"));
        _reachFinalizeWindow(keccak256("anchor"));
        _reveal(ALICE, keccak256("r-a"), keccak256("s-a"));

        vm.expectRevert(abi.encodeWithSelector(Sortition.UnrevealedCommitments.selector, uint32(2), uint32(1)));
        s.finalize(DRAW);

        // …and the record names who is missing, so the DoS has an author.
        assertTrue(s.revealedBy(DRAW, ALICE));
        assertFalse(s.revealedBy(DRAW, BOB));
        assertTrue(s.commitmentOf(DRAW, BOB) != bytes32(0), "bob committed and did not open it");
    }

    /// One commitment per address; one reveal per commitment. Neither is a
    /// second bite.
    function test_SO2_commitAndRevealAreEachOnce() public {
        _open();
        _commit(ALICE, keccak256("r"), keccak256("salt"));

        bytes32 second = s.commitmentFor(keccak256("r2"), keccak256("salt"));
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Sortition.AlreadyCommitted.selector, DRAW, ALICE));
        s.commit(DRAW, second);

        _reachFinalizeWindow(keccak256("anchor"));
        _reveal(ALICE, keccak256("r"), keccak256("salt"));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Sortition.AlreadyRevealed.selector, DRAW, ALICE));
        s.reveal(DRAW, keccak256("r"), keccak256("salt"));
    }

    /// Revealing without having committed contributes nothing — otherwise
    /// entropy could be added after the anchor is public, which is the same
    /// attack the commit window exists to close.
    function test_SO2_youCannotRevealWithoutHavingCommitted() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor"));

        vm.prank(CAROL);
        vm.expectRevert(abi.encodeWithSelector(Sortition.NothingCommitted.selector, DRAW, CAROL));
        s.reveal(DRAW, keccak256("r"), keccak256("salt"));
    }

    /// **The documented degraded state.** With nobody committing, the draw still
    /// completes — and reports that it had no entropy contributors, so the app
    /// can say out loud that this was a coin the proposer flipped.
    function test_SO2_aDrawWithNoContributorsCompletesAndSaysSo() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor"));
        s.finalize(DRAW);

        assertEq(uint8(s.stateOf(DRAW)), uint8(Sortition.State.Final));
        assertFalse(s.hasEntropyContributors(DRAW), "the degraded state must be legible");
        assertEq(s.drawOf(DRAW).commitCount, 0);
    }

    // ── SO-3: a stalled draw is void, not best-effort ───────────────

    /// Past the block-hash horizon the seed cannot be fixed. Not "should not" —
    /// the EVM has no hash to give, and the contract refuses rather than
    /// building a seed on a zero.
    function test_SO3_pastTheHorizonADrawCannotBeFinalized() public {
        _open();
        vm.roll(TARGET + s.BLOCKHASH_HORIZON() + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                Sortition.BeyondBlockhashHorizon.selector, TARGET, TARGET + s.BLOCKHASH_HORIZON()
            )
        );
        s.finalize(DRAW);
    }

    /// …and the only terminal state it can reach is `Void`. There is no path
    /// from a stalled draw to a committee.
    function test_SO3_aStalledDrawGoesVoidAndYieldsNoCommittee() public {
        _open();
        vm.roll(TARGET + s.BLOCKHASH_HORIZON() + 1);

        vm.expectEmit(true, false, false, true);
        emit Sortition.DrawVoided(DRAW, 0, 0);
        s.void(DRAW);

        assertEq(uint8(s.stateOf(DRAW)), uint8(Sortition.State.Void));
        vm.expectRevert(
            abi.encodeWithSelector(Sortition.NotFinal.selector, DRAW, Sortition.State.Void)
        );
        s.selection(DRAW);

        // And it cannot be resurrected.
        vm.expectRevert(
            abi.encodeWithSelector(Sortition.NotOpen.selector, DRAW, Sortition.State.Void)
        );
        s.finalize(DRAW);
    }

    /// Voiding is not a cancel button. While a draw can still be finalized,
    /// voiding it would let someone about to lose the draw call it off.
    function test_SO3_aDrawCannotBeVoidedWhileItIsStillFinalizable() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor"));

        vm.expectRevert(abi.encodeWithSelector(Sortition.StillFinalizable.selector, DRAW));
        s.void(DRAW);

        // The boundary: still finalizable at exactly the horizon.
        vm.roll(TARGET + s.BLOCKHASH_HORIZON());
        vm.expectRevert(abi.encodeWithSelector(Sortition.StillFinalizable.selector, DRAW));
        s.void(DRAW);
    }

    /// The seed cannot be fixed before the target has had time to reach BFT
    /// finality — a draw settled on a block that could still be reorged is a
    /// draw that can be re-rolled.
    function test_SO3_theSeedCannotBeFixedBeforeFinality() public {
        _open();
        vm.roll(TARGET + s.FINALITY_DELAY() - 1);
        vm.setBlockhash(TARGET, keccak256("anchor"));

        vm.expectRevert(
            abi.encodeWithSelector(Sortition.TooEarlyToFinalize.selector, TARGET + s.FINALITY_DELAY())
        );
        s.finalize(DRAW);

        // Exactly at the boundary it is allowed.
        vm.roll(TARGET + s.FINALITY_DELAY());
        s.finalize(DRAW);
        assertEq(uint8(s.stateOf(DRAW)), uint8(Sortition.State.Final));
    }

    /// An unreadable anchor is a refusal, not a default. The horizon check
    /// should make this unreachable on a live chain, but `blockhash` returning
    /// zero is how the EVM says "I cannot tell you", and a seed built on a zero
    /// is a draw the chain contributed nothing to.
    function test_SO3_aZeroAnchorIsRefusedRatherThanUsed() public {
        _open();
        vm.roll(TARGET + s.FINALITY_DELAY());
        vm.setBlockhash(TARGET, bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(Sortition.UnreadableAnchor.selector, TARGET));
        s.finalize(DRAW);
    }

    /// Finalizing is open to anyone: the draw belongs to whoever is waiting on
    /// it, not to whoever opened it. An opener who could stall it by declining
    /// to finalize would hold a veto over the result.
    function test_anyoneMayFinalize() public {
        _open();
        _reachFinalizeWindow(keccak256("anchor"));

        vm.prank(CAROL);
        s.finalize(DRAW);
        assertEq(uint8(s.stateOf(DRAW)), uint8(Sortition.State.Final));
    }

    // ── The pool stays off chain ────────────────────────────────────

    /// Only the root is committed, so a name is attached to a selected index by
    /// proof rather than by publishing the membership list (planset D6: hashes
    /// and CIDs only).
    function test_membershipIsProvedAgainstTheRootNotPublished() public {
        // A four-leaf tree, hashed the way the contract walks it: position
        // matters, so the same pair in the other order is a different node.
        bytes32 l0 = keccak256("member-0");
        bytes32 l1 = keccak256("member-1");
        bytes32 l2 = keccak256("member-2");
        bytes32 l3 = keccak256("member-3");
        bytes32 n01 = keccak256(abi.encode(l0, l1));
        bytes32 n23 = keccak256(abi.encode(l2, l3));
        bytes32 root = keccak256(abi.encode(n01, n23));

        bytes32 drawId = keccak256("proofs");
        s.openDraw(drawId, root, 4, 2, TARGET);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = l1;
        proof[1] = n23;
        assertTrue(s.verifyMember(drawId, 0, l0, proof), "member 0 is in the committed pool");

        // The same proof does not prove a different index…
        assertFalse(s.verifyMember(drawId, 1, l0, proof), "an index-shifted proof must not verify");
        // …nor a different leaf.
        assertFalse(s.verifyMember(drawId, 0, keccak256("impostor"), proof));
        // …and an index outside the pool is not a member at all.
        assertFalse(s.verifyMember(drawId, 4, l0, proof));

        // The right-hand side of the tree, to pin the path direction.
        bytes32[] memory proof3 = new bytes32[](2);
        proof3[0] = l2;
        proof3[1] = n01;
        assertTrue(s.verifyMember(drawId, 3, l3, proof3));
    }

    // ── Opening ─────────────────────────────────────────────────────

    function test_openingRefusesADrawThatCouldNeverMeanAnything() public {
        vm.expectRevert(Sortition.ZeroPoolRoot.selector);
        s.openDraw(keccak256("a"), bytes32(0), POOL, K, TARGET);

        vm.expectRevert(Sortition.EmptyPool.selector);
        s.openDraw(keccak256("b"), POOL_ROOT, 0, K, TARGET);

        vm.expectRevert(Sortition.ZeroCommittee.selector);
        s.openDraw(keccak256("c"), POOL_ROOT, POOL, 0, TARGET);

        // A committee larger than the pool cannot be sampled without
        // replacement, and seating someone twice is not a committee.
        vm.expectRevert(
            abi.encodeWithSelector(Sortition.CommitteeLargerThanPool.selector, POOL + 1, POOL)
        );
        s.openDraw(keccak256("d"), POOL_ROOT, POOL, POOL + 1, TARGET);
    }

    /// A draw id is used once. Reusing one would let a second draw overwrite the
    /// terms of a first that people had already committed entropy to.
    function test_aDrawIdIsUsedOnce() public {
        _open();
        vm.expectRevert(abi.encodeWithSelector(Sortition.DrawExists.selector, DRAW));
        s.openDraw(DRAW, POOL_ROOT, POOL, K, TARGET);
    }

    /// Asking about a draw that was never opened is an error, not an empty
    /// answer — a zeroed struct would read as a real draw with an empty pool.
    function test_anUnknownDrawIsAnErrorNotAnEmptyRecord() public {
        bytes32 ghost = keccak256("never opened");
        assertEq(uint8(s.stateOf(ghost)), uint8(Sortition.State.None));

        vm.expectRevert(abi.encodeWithSelector(Sortition.UnknownDraw.selector, ghost));
        s.drawOf(ghost);

        vm.expectRevert(abi.encodeWithSelector(Sortition.UnknownDraw.selector, ghost));
        s.commit(ghost, keccak256("c"));
    }

    /// The commitment derivation is exposed so a contributor computes it the
    /// same way the contract checks it, rather than reimplementing it.
    function test_commitmentDerivationIsPinned() public view {
        assertEq(
            s.commitmentFor(keccak256("r"), keccak256("salt")),
            keccak256(abi.encode(keccak256("r"), keccak256("salt")))
        );
    }
}
