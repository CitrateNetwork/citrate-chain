// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {VoteAllowance} from "../src/quorum/VoteAllowance.sol";

/// @title VoteAllowance — invariant tests (QRM-S6.6)
///
/// VA-1..VA-4. The state machine also carries a TLA+ spec at
/// `specs/tla/contracts/VoteAllowance.tla`, which explores interleavings these
/// tests can only sample — the two are complements, not duplicates: a test pins
/// behaviour at specific inputs, a spec explores the reachable state space.
contract VoteAllowanceTest is Test {
    VoteAllowance va;

    address constant PRINCIPAL = address(0xA11CE);
    address constant OTHER_PRINCIPAL = address(0xB0B);
    address constant CASTER = address(0xCA5);
    address constant STRANGER = address(0xBEEF);

    uint256 constant AGENT = 42;
    bytes32 constant SCOPE = keccak256("Citrate");
    bytes32 constant BUDGET_CLASS = keccak256("proposal.budget");
    bytes32 constant CHARTER_CLASS = keccak256("proposal.charter");
    bytes32 constant UNCOVERED = keccak256("proposal.merger");
    bytes32 constant PROPOSAL = keccak256("prop-1");
    bytes32 constant HIC_GRANT = keccak256("grant-1");

    uint256 constant CAP = 100;
    /// The instant `setUp` warps to. Tests that care about time use absolute
    /// offsets from this rather than reading `block.timestamp`, which solc
    /// caches within a call frame.
    uint64 constant START_SEC = 1_700_000_000;

    function setUp() public {
        va = new VoteAllowance();
        vm.warp(START_SEC);
    }

    function _classes() internal pure returns (bytes32[] memory c) {
        c = new bytes32[](2);
        c[0] = BUDGET_CLASS;
        c[1] = CHARTER_CLASS;
    }

    function _grant() internal returns (bytes32) {
        vm.prank(PRINCIPAL);
        return va.grant(AGENT, CASTER, SCOPE, _classes(), CAP, (START_SEC + 1 days) * 1000, HIC_GRANT);
    }

    function _cast(bytes32 id, bytes32 proposal, uint256 weight) internal {
        vm.prank(CASTER);
        va.castVote(id, proposal, BUDGET_CLASS, 1, weight);
    }

    // ── VA-1: spent <= weightCap ────────────────────────────────────

    /// Refused, not clamped. A clamped vote would be recorded as though the
    /// agent had voted the amount it asked for.
    function test_VA1_castingOverTheCapIsRefusedNotClamped() public {
        bytes32 id = _grant();
        _cast(id, PROPOSAL, 60);
        assertEq(va.remaining(id), 40);

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.OverAllowance.selector, id, uint256(41), uint256(40)));
        va.castVote(id, keccak256("prop-2"), BUDGET_CLASS, 1, 41);

        assertEq(va.allowanceOf(id).spent, 60, "a refused cast must not move the meter");

        // Exactly the remainder is fine — the boundary is inclusive.
        _cast(id, keccak256("prop-3"), 40);
        assertEq(va.remaining(id), 0);
    }

    /// The interesting case for VA-1 is not a single cast, it is a cast
    /// interleaved with a narrowing. `decrease` has a floor at `spent` because
    /// going below it would make VA-1 retroactively false and imply votes that
    /// were cast never were.
    function test_VA1_narrowingCannotGoBelowWhatIsAlreadySpent() public {
        bytes32 id = _grant();
        _cast(id, PROPOSAL, 70);

        vm.prank(PRINCIPAL);
        vm.expectRevert(
            abi.encodeWithSelector(VoteAllowance.CannotReduceBelowSpent.selector, id, uint256(69), uint256(70))
        );
        va.decrease(id, 69);

        // Down to exactly what is spent is allowed: it means "no more".
        vm.prank(PRINCIPAL);
        va.decrease(id, 70);
        assertEq(va.remaining(id), 0);
        assertEq(va.allowanceOf(id).spent, 70);
    }

    /// `decrease` is not in the planset's grant/increase/revoke list and was
    /// added deliberately: without it, the only way to narrow a franchise is
    /// revoke-and-regrant, which mints a new id and breaks the trace from an
    /// in-flight vote back to the delegation that permitted it.
    function test_wideningAndNarrowingAreBothPrincipalOnly() public {
        bytes32 id = _grant();

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotPrincipal.selector, id, STRANGER));
        va.increase(id, 10);

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotPrincipal.selector, id, CASTER));
        va.decrease(id, 10);

        vm.startPrank(PRINCIPAL);
        va.increase(id, 10);
        assertEq(va.allowanceOf(id).weightCap, CAP + 10);
        va.decrease(id, 5);
        assertEq(va.allowanceOf(id).weightCap, 5);
        vm.stopPrank();
    }

    // ── VA-2: a dead allowance can never be spent ───────────────────

    /// Immediate and unconditional — the "pull the plug" property. The honest
    /// answer to an executive is "the next block", not "once in-flight work
    /// drains".
    function test_VA2_revocationIsImmediateAndUnconditional() public {
        bytes32 id = _grant();
        assertTrue(va.isLive(id));
        assertTrue(va.covers(id, PROPOSAL, BUDGET_CLASS, 1));

        vm.prank(PRINCIPAL);
        va.revoke(id);

        assertFalse(va.isLive(id));
        assertFalse(va.covers(id, PROPOSAL, BUDGET_CLASS, 1));
        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.AllowanceInactive.selector, id));
        va.castVote(id, PROPOSAL, BUDGET_CLASS, 1, 1);
    }

    function test_VA2_expiryKillsAnAllowanceWithoutRevocation() public {
        bytes32 id = _grant();
        vm.warp(START_SEC + 1 days);
        assertFalse(va.isLive(id), "strictly greater, matching the Rust");

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.AllowanceInactive.selector, id));
        va.castVote(id, PROPOSAL, BUDGET_CLASS, 1, 1);
    }

    /// Only the principal. Not a tenant admin, not the caster — an allowance is
    /// one person's franchise, and someone else being able to end it is a
    /// different power than the one this contract models. (Contrast
    /// `CapabilityGrant.revoke`, where an admin pulling the plug on an agent's
    /// *work* is exactly right.)
    function test_VA2_onlyThePrincipalMayRevoke() public {
        bytes32 id = _grant();

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotPrincipal.selector, id, CASTER));
        va.revoke(id);

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotPrincipal.selector, id, STRANGER));
        va.revoke(id);

        vm.startPrank(PRINCIPAL);
        va.revoke(id);
        va.revoke(id); // idempotent
        vm.stopPrank();
        assertFalse(va.isLive(id));
    }

    // ── VA-3: every vote traces to exactly one principal ────────────

    /// The principal is in the cast event itself. A vote whose principal had to
    /// be reconstructed from elsewhere would not be traceable, it would be
    /// inferable.
    function test_VA3_everyCastNamesItsPrincipalAndAgent() public {
        bytes32 id = _grant();

        vm.expectEmit(true, true, true, true);
        emit VoteAllowance.AgentVoteCast(PROPOSAL, AGENT, PRINCIPAL, 1, 25, id, 25);
        _cast(id, PROPOSAL, 25);

        VoteAllowance.Allowance memory a = va.allowanceOf(id);
        assertEq(a.principal, PRINCIPAL);
        assertEq(a.agentSbtId, AGENT);
        assertEq(a.hicGrantId, HIC_GRANT, "and back to the envelope that let the agent act at all");
    }

    /// Only the nominated caster may spend. Agents are keyless, so something
    /// with a key transacts on their behalf — naming it means exactly one
    /// address can spend this franchise, and a vote cannot be attributed to a
    /// principal who did not authorise that path.
    function test_VA3_onlyTheNominatedCasterMaySpend() public {
        bytes32 id = _grant();

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotCaster.selector, id, STRANGER));
        va.castVote(id, PROPOSAL, BUDGET_CLASS, 1, 1);

        // Not even the principal, unless they nominated themselves.
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotCaster.selector, id, PRINCIPAL));
        va.castVote(id, PROPOSAL, BUDGET_CLASS, 1, 1);
    }

    /// One cast per (allowance, proposal). A second is either a duplicate or a
    /// contradiction, and neither should be resolved silently by whatever
    /// tallies. Changing a position means the principal voting themselves.
    function test_VA3_anAllowanceVotesOncePerProposal() public {
        bytes32 id = _grant();
        _cast(id, PROPOSAL, 10);

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.AlreadyCast.selector, id, PROPOSAL));
        va.castVote(id, PROPOSAL, BUDGET_CLASS, 0, 10);

        assertFalse(va.covers(id, PROPOSAL, BUDGET_CLASS, 10), "and covers says so before you try");
        assertTrue(va.covers(id, keccak256("another"), BUDGET_CLASS, 10), "a different proposal is untouched");
    }

    // ── VA-4: allowances never compound ─────────────────────────────

    /// Structural, not a check. The delegate is an `agentSbtId` — not an
    /// address — so a delegate has nothing to grant *from*, and `grant` always
    /// writes `principal = msg.sender`. There is no way to name someone else as
    /// the source of authority, so a delegation chain cannot form.
    ///
    /// The closest an adversary gets: the caster grants its own allowance. That
    /// works, and it is not sub-delegation — it delegates the CASTER's franchise,
    /// under the caster's own name, spending the caster's own weight. The
    /// original principal's franchise is untouched, which is exactly the
    /// property.
    function test_VA4_aCasterCanOnlyEverDelegateItsOwnFranchise() public {
        bytes32 id = _grant();

        vm.prank(CASTER);
        bytes32 theirs = va.grant(AGENT, CASTER, SCOPE, _classes(), 5, (START_SEC + 1 days) * 1000, bytes32(0));

        assertEq(va.allowanceOf(theirs).principal, CASTER, "the grant names its granter, always");
        assertTrue(theirs != id);
        assertEq(va.allowanceOf(id).weightCap, CAP, "the original franchise is untouched");
        assertEq(va.allowanceOf(id).principal, PRINCIPAL);

        // Spending the derived allowance does not touch the original's meter.
        vm.prank(CASTER);
        va.castVote(theirs, PROPOSAL, BUDGET_CLASS, 1, 5);
        assertEq(va.allowanceOf(id).spent, 0);
        assertEq(va.allowanceOf(theirs).spent, 5);
    }

    /// Allowances are separate meters even for the same principal and agent.
    function test_VA4_allowancesDoNotPool() public {
        bytes32 a = _grant();
        bytes32 b = _grant();
        assertTrue(a != b, "the grant nonce keeps ids apart");

        _cast(a, PROPOSAL, 100);
        assertEq(va.remaining(a), 0);
        assertEq(va.remaining(b), CAP, "an untouched franchise stays whole");
        assertEq(va.allowanceCount(PRINCIPAL), 2);
    }

    // ── Scope ───────────────────────────────────────────────────────

    function test_aClassOutsideTheGrantIsRefused() public {
        bytes32 id = _grant();

        vm.prank(CASTER);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.ClassNotCovered.selector, id, UNCOVERED));
        va.castVote(id, PROPOSAL, UNCOVERED, 1, 1);

        assertFalse(va.covers(id, PROPOSAL, UNCOVERED, 1));
        assertTrue(va.covers(id, PROPOSAL, CHARTER_CLASS, 1));
    }

    /// `covers` is the whole precondition of `castVote`, so a caller can ask
    /// before acting instead of learning from a revert — including about ids
    /// that do not exist, which is why it returns false rather than reverting.
    function test_coversMatchesWhatCastVoteWillActuallyDo() public {
        bytes32 ghost = keccak256("never granted");
        assertFalse(va.covers(ghost, PROPOSAL, BUDGET_CLASS, 1));
        assertFalse(va.isLive(ghost));
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.UnknownAllowance.selector, ghost));
        va.allowanceOf(ghost);

        bytes32 id = _grant();
        assertTrue(va.covers(id, PROPOSAL, BUDGET_CLASS, CAP));
        assertFalse(va.covers(id, PROPOSAL, BUDGET_CLASS, CAP + 1), "over the cap");
    }

    // ── Granting ────────────────────────────────────────────────────

    /// A zero-cap allowance can never be spent, and would read to anyone
    /// reviewing delegations like a franchise that exists.
    function test_grantRefusesAnAllowanceThatCouldNeverBeUsed() public {
        vm.startPrank(PRINCIPAL);

        vm.expectRevert(VoteAllowance.ZeroWeightCap.selector);
        va.grant(AGENT, CASTER, SCOPE, _classes(), 0, (START_SEC + 1 days) * 1000, bytes32(0));

        vm.expectRevert(VoteAllowance.NoProposalClasses.selector);
        va.grant(AGENT, CASTER, SCOPE, new bytes32[](0), CAP, (START_SEC + 1 days) * 1000, bytes32(0));

        uint64 past = START_SEC * 1000 - 1;
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.AlreadyExpired.selector, past, START_SEC * 1000));
        va.grant(AGENT, CASTER, SCOPE, _classes(), CAP, past, bytes32(0));

        vm.expectRevert(VoteAllowance.ZeroCaster.selector);
        va.grant(AGENT, address(0), SCOPE, _classes(), CAP, (START_SEC + 1 days) * 1000, bytes32(0));

        bytes32[] memory dupes = new bytes32[](2);
        dupes[0] = BUDGET_CLASS;
        dupes[1] = BUDGET_CLASS;
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.DuplicateProposalClass.selector, BUDGET_CLASS));
        va.grant(AGENT, CASTER, SCOPE, dupes, CAP, (START_SEC + 1 days) * 1000, bytes32(0));
        vm.stopPrank();
    }

    /// The cap is bounded by what `quorum-policy`'s `u64` can hold, for the same
    /// reason `CapabilityGrant` bounds its budget: a value that cannot
    /// round-trip into the implementation enforcing it in process is a
    /// divergence waiting to decide something.
    function test_capIsBoundedByWhatTheRustSideCanHold() public {
        uint256 tooBig = uint256(type(uint64).max) + 1;
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.WeightCapTooLarge.selector, tooBig));
        va.grant(AGENT, CASTER, SCOPE, _classes(), tooBig, (START_SEC + 1 days) * 1000, bytes32(0));

        // …and `increase` cannot climb past it either.
        bytes32 id = _grant();
        vm.prank(PRINCIPAL);
        vm.expectRevert(
            abi.encodeWithSelector(VoteAllowance.WeightCapTooLarge.selector, uint256(type(uint64).max) + CAP)
        );
        va.increase(id, type(uint64).max);
    }

    /// Two principals' allowances are wholly separate, including their ids.
    function test_principalsAreIsolatedFromEachOther() public {
        bytes32 mine = _grant();

        vm.prank(OTHER_PRINCIPAL);
        bytes32 theirs = va.grant(AGENT, CASTER, SCOPE, _classes(), CAP, (START_SEC + 1 days) * 1000, bytes32(0));

        assertTrue(mine != theirs);
        vm.prank(OTHER_PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(VoteAllowance.NotPrincipal.selector, mine, OTHER_PRINCIPAL));
        va.revoke(mine);

        assertEq(va.allowanceCount(PRINCIPAL), 1);
        assertEq(va.allowanceCount(OTHER_PRINCIPAL), 1);
    }
}
