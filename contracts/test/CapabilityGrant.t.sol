// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CapabilityGrant} from "../src/quorum/CapabilityGrant.sol";
import {ITenantHierarchy} from "../src/quorum/GovernanceProtocolFactory.sol";
import {TenantHierarchy} from "../src/rbac/TenantHierarchy.sol";

/// @title CapabilityGrant — invariant tests (QRM-S6.5)
///
/// CG-1..4, plus the rules that keep this contract and `quorum-policy`'s Rust
/// implementation from drifting. Run against the real `TenantHierarchy`.
contract CapabilityGrantTest is Test {
    CapabilityGrant grants;
    TenantHierarchy tenants;

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant CHILD = keccak256("Citrate/Wichita");

    address constant ADMIN = address(0xAD);
    address constant PRINCIPAL = address(0xA11CE);
    address constant CONSUMER = address(0xC0);
    address constant STRANGER = address(0xBEEF);

    bytes32 constant WRITE = keccak256("repo.write");
    bytes32 constant SPEND = keccak256("spend");
    bytes32 constant DELETE_ = keccak256("repo.delete");

    uint256 constant BUDGET = 1000;
    uint8 constant CUI = 2;
    /// The instant `setUp` warps to. Tests that care about time use absolute
    /// offsets from this rather than reading `block.timestamp`.
    uint64 constant START_SEC = 1_700_000_000;

    function setUp() public {
        tenants = new TenantHierarchy();
        address[] memory admins = new address[](1);
        admins[0] = ADMIN;
        tenants.initRoot(TENANT, "Citrate", keccak256("salt"), admins, 1, 3);
        vm.prank(ADMIN);
        tenants.createNode(TENANT, CHILD, "Wichita", 1, keccak256("s2"), admins, 1, 1);

        grants = new CapabilityGrant(ITenantHierarchy(address(tenants)));
        // Start well clear of the epoch so expiries are expressible in ms.
        vm.warp(START_SEC);
    }

    function _classes() internal pure returns (bytes32[] memory c) {
        c = new bytes32[](2);
        c[0] = WRITE;
        c[1] = SPEND;
    }

    function _nowMs() internal view returns (uint64) {
        return uint64(block.timestamp * 1000);
    }

    function _issue() internal returns (bytes32) {
        vm.prank(PRINCIPAL);
        return grants.issue(
            7,
            PRINCIPAL,
            CONSUMER,
            TENANT,
            _classes(),
            CapabilityGrant.Hic.Budgeted,
            CUI,
            BUDGET,
            _nowMs() + 1 days * 1000,
            keccak256("protocol")
        );
    }

    // ── CG-1: consumed <= budget ────────────────────────────────────

    /// The budget is a ceiling, not a suggestion. `consume` refuses and leaves
    /// state untouched rather than clamping — a partially-charged action would be
    /// a lie about what happened, and the caller would have no way to tell.
    function test_CG1_consumingOverBudgetRefusesAndChangesNothing() public {
        bytes32 id = _issue();

        vm.prank(CONSUMER);
        grants.consume(id, 900, keccak256("c1"));
        assertEq(grants.remaining(id), 100);

        vm.prank(CONSUMER);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.OverBudget.selector, id, uint256(101), uint256(100)));
        grants.consume(id, 101, keccak256("c2"));

        assertEq(grants.remaining(id), 100, "a refused charge must not move the meter");
        assertEq(grants.grantOf(id).consumed, 900);

        // Exactly the remainder is fine — the boundary is inclusive.
        vm.prank(CONSUMER);
        grants.consume(id, 100, keccak256("c3"));
        assertEq(grants.remaining(id), 0);
    }

    /// Only the nominated enforcement point may charge. Without this, any
    /// address could drain any agent's budget and "consumed" would stop meaning
    /// "work was done".
    function test_CG1_onlyTheNominatedConsumerMayCharge() public {
        bytes32 id = _issue();

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.NotConsumer.selector, id, STRANGER));
        grants.consume(id, 1, keccak256("x"));

        // Not even the principal, unless they nominated themselves.
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.NotConsumer.selector, id, PRINCIPAL));
        grants.consume(id, 1, keccak256("x"));
    }

    /// A refund exists for one case: charged, escalated to a human, human said
    /// no. Without it the envelope is quietly eaten by an approval that never
    /// happened. Saturating, matching the Rust.
    function test_refundReturnsUnitsAndCannotGoNegative() public {
        bytes32 id = _issue();
        vm.startPrank(CONSUMER);
        grants.consume(id, 300, keccak256("c"));
        grants.refund(id, 100, keccak256("r"));
        assertEq(grants.grantOf(id).consumed, 200);

        grants.refund(id, 10_000, keccak256("r2"));
        assertEq(grants.grantOf(id).consumed, 0, "saturating, never below zero");
        vm.stopPrank();
    }

    /// Refunds work on a revoked grant on purpose. Refusing would mean revoking
    /// permanently absorbs whatever was in flight — wrong in the one direction
    /// that disadvantages the agent's principal.
    function test_refundStillWorksAfterRevocation() public {
        bytes32 id = _issue();
        vm.prank(CONSUMER);
        grants.consume(id, 500, keccak256("c"));
        vm.prank(PRINCIPAL);
        grants.revoke(id);

        vm.prank(CONSUMER);
        grants.refund(id, 500, keccak256("r"));
        assertEq(grants.grantOf(id).consumed, 0);
        assertFalse(grants.isLive(id), "and it is still dead");
    }

    // ── CG-2: revoke is immediate ───────────────────────────────────

    /// Not "at next expiry", not "after in-flight work drains". Dead on the next
    /// call, regardless of an expiry that is still days away.
    function test_CG2_revocationIsImmediateAndOutranksExpiry() public {
        bytes32 id = _issue();
        assertTrue(grants.isLive(id));
        assertTrue(grants.covers(id, WRITE, 0, 1));

        vm.prank(PRINCIPAL);
        grants.revoke(id);

        assertFalse(grants.isLive(id));
        assertFalse(grants.covers(id, WRITE, 0, 1), "a revoked grant covers nothing");
        vm.prank(CONSUMER);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.GrantNotLive.selector, id));
        grants.consume(id, 1, keccak256("x"));
    }

    /// Idempotent: the second caller wanted the same end state, and making them
    /// handle an error teaches them to swallow errors.
    function test_CG2_revokingTwiceIsANoOp() public {
        bytes32 id = _issue();
        vm.startPrank(PRINCIPAL);
        grants.revoke(id);
        grants.revoke(id);
        vm.stopPrank();
        assertFalse(grants.isLive(id));
    }

    /// Pulling the plug must not require finding one specific person at 3am, so
    /// a tenant admin can revoke too — but a stranger cannot.
    function test_CG2_principalOrTenantAdminMayRevokeNobodyElse() public {
        bytes32 id = _issue();

        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.NotPrincipalOrTenantAdmin.selector, id, STRANGER));
        grants.revoke(id);

        vm.prank(ADMIN);
        grants.revoke(id);
        assertFalse(grants.isLive(id));
    }

    function test_expiryKillsAGrantWithoutRevocation() public {
        bytes32 id = _issue();
        vm.warp(block.timestamp + 1 days);
        assertFalse(grants.isLive(id), "expiry is strict: `>` matches the Rust exactly");
        assertFalse(grants.covers(id, WRITE, 0, 1));
    }

    // ── CG-3: what this contract owes the recording site ────────────

    /// CG-3 ("every recorded decision references a live grant or is flagged
    /// ungoverned") is enforced where decisions are recorded, not here. What
    /// this contract owes it is an unambiguous answer to "is there a live grant
    /// covering this?" — including for ids that do not exist, which a gate will
    /// ask about.
    function test_CG3_coversAnswersNoForAnythingItDoesNotCover() public {
        bytes32 id = _issue();
        assertTrue(grants.covers(id, WRITE, CUI, BUDGET), "the whole envelope");

        assertFalse(grants.covers(id, DELETE_, 0, 1), "action class outside the grant");
        assertFalse(grants.covers(id, WRITE, 3, 1), "above the classification ceiling");
        assertFalse(grants.covers(id, WRITE, 0, BUDGET + 1), "beyond the budget");
        assertFalse(grants.covers(keccak256("never issued"), WRITE, 0, 1), "an id that does not exist");
    }

    /// An unknown id is `false` from `covers`, but a REVERT from `grantOf` — a
    /// gate wants a boolean for ids that may not exist, and a reader must never
    /// mistake a zeroed struct for a real grant with no budget.
    function test_unknownGrantIsFalseToAskAboutAndAnErrorToRead() public {
        bytes32 ghost = keccak256("never issued");
        assertFalse(grants.isLive(ghost));
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.UnknownGrant.selector, ghost));
        grants.grantOf(ghost);
    }

    // ── CG-4: autonomy only moves up by an explicit principal act ───

    /// The direction that matters. An agent that could ask for more autonomy and
    /// get it has no envelope at all — so loosening is the principal alone, and
    /// a tenant admin (who may revoke outright) still cannot do it.
    function test_CG4_onlyThePrincipalMayIncreaseAutonomy() public {
        bytes32 id = _issue(); // Budgeted

        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(CapabilityGrant.AutonomyIncreaseIsPrincipalOnly.selector, id, ADMIN)
        );
        grants.setHic(id, CapabilityGrant.Hic.PostHoc);

        vm.prank(STRANGER);
        vm.expectRevert(
            abi.encodeWithSelector(CapabilityGrant.AutonomyIncreaseIsPrincipalOnly.selector, id, STRANGER)
        );
        grants.setHic(id, CapabilityGrant.Hic.PostHoc);

        vm.prank(PRINCIPAL);
        grants.setHic(id, CapabilityGrant.Hic.PostHoc);
        assertEq(uint8(grants.grantOf(id).hic), uint8(CapabilityGrant.Hic.PostHoc));
    }

    /// Tightening is always safe and sometimes urgent, so a tenant admin may do
    /// it — the asymmetry is the whole of CG-4.
    function test_CG4_tighteningIsOpenToTheTenantAdminToo() public {
        bytes32 id = _issue(); // Budgeted

        // A stranger cannot tighten either — "safe direction" is not "anyone".
        vm.prank(STRANGER);
        vm.expectRevert(
            abi.encodeWithSelector(CapabilityGrant.NotPrincipalOrTenantAdmin.selector, id, STRANGER)
        );
        grants.setHic(id, CapabilityGrant.Hic.ApproveEach);

        vm.prank(ADMIN);
        grants.setHic(id, CapabilityGrant.Hic.ApproveEach);
        assertEq(uint8(grants.grantOf(id).hic), uint8(CapabilityGrant.Hic.ApproveEach));

        // …and from there the admin cannot hand the autonomy back.
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(CapabilityGrant.AutonomyIncreaseIsPrincipalOnly.selector, id, ADMIN)
        );
        grants.setHic(id, CapabilityGrant.Hic.Budgeted);
    }

    /// Setting the level it already has is a no-op, not an error or an event —
    /// otherwise an idempotent reconciler would emit a stream of phantom changes.
    function test_CG4_settingTheSameLevelDoesNothing() public {
        bytes32 id = _issue();
        vm.prank(STRANGER);
        grants.setHic(id, CapabilityGrant.Hic.Budgeted);
        assertEq(uint8(grants.grantOf(id).hic), uint8(CapabilityGrant.Hic.Budgeted));
    }

    // ── Issuing ─────────────────────────────────────────────────────

    /// Anyone may grant to themselves; granting on someone else's behalf is a
    /// tenant-administration act. Both record `issuedBy` next to `principal`,
    /// because this contract cannot tell whether an address is a person and
    /// should record provenance rather than pretend to judge it.
    function test_issuingForAnotherRequiresTenantAdminAndIsRecordedAsSuch() public {
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.MayNotIssueForAnother.selector, TENANT, STRANGER));
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1000, bytes32(0)
        );

        // PBA-L2-056: a delegated grant must start at ApproveEach; the admin
        // cannot hand the principal's agent more autonomy than HIC-1.
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(
                CapabilityGrant.DelegatedGrantMustStartApproveEach.selector, ADMIN, uint8(CapabilityGrant.Hic.Budgeted)
            )
        );
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1 days * 1000, bytes32(0)
        );
        vm.prank(ADMIN);
        bytes32 delegated = grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.ApproveEach, CUI, BUDGET,
            _nowMs() + 1 days * 1000, bytes32(0)
        );
        assertEq(grants.grantOf(delegated).issuedBy, ADMIN);
        assertEq(grants.grantOf(delegated).principal, PRINCIPAL);

        bytes32 selfIssued = _issue();
        assertEq(grants.grantOf(selfIssued).issuedBy, PRINCIPAL, "self-issued is visible as such");
    }

    /// A grant may not authorize above the tenant's own ceiling — the ceiling a
    /// customer sets once for a whole part of their org must not be escapable by
    /// issuing a generous grant inside it.
    function test_aGrantCannotExceedTheTenantCeiling() public {
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.ClassificationAboveTenant.selector, uint8(2), uint8(1)));
        grants.issue(
            7, PRINCIPAL, CONSUMER, CHILD, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1 days * 1000, bytes32(0)
        );
    }

    /// An already-dead grant is not a grant. Issuing one would put a
    /// permanently-refusing envelope in the record that reads, to anyone
    /// scanning, like an authorization that exists.
    function test_issuingAnAlreadyExpiredGrantIsRefused() public {
        uint64 past = _nowMs() - 1;
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.AlreadyExpired.selector, past, _nowMs()));
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET, past, bytes32(0)
        );
    }

    function test_issuingRefusesAnIncoherentScope() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.startPrank(PRINCIPAL);

        vm.expectRevert(CapabilityGrant.NoActionClasses.selector);
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, empty, CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1000, bytes32(0)
        );

        bytes32[] memory dupes = new bytes32[](2);
        dupes[0] = WRITE;
        dupes[1] = WRITE;
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.DuplicateActionClass.selector, WRITE));
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, dupes, CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1000, bytes32(0)
        );

        vm.expectRevert(CapabilityGrant.ZeroConsumer.selector);
        grants.issue(
            7, PRINCIPAL, address(0), TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            _nowMs() + 1000, bytes32(0)
        );
        vm.stopPrank();
    }

    // ── Keeping the two implementations honest ──────────────────────

    /// The Rust budget is `u64`. A grant that cannot round-trip into the
    /// implementation that enforces it in process is not a grant, it is a future
    /// incident — so a larger one is refused at issue rather than discovered
    /// when the two sides disagree about what is left.
    function test_budgetIsCappedToWhatTheRustSideCanHold() public {
        uint256 tooBig = uint256(type(uint64).max) + 1;
        vm.prank(PRINCIPAL);
        vm.expectRevert(abi.encodeWithSelector(CapabilityGrant.BudgetTooLarge.selector, tooBig));
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, tooBig,
            _nowMs() + 1000, bytes32(0)
        );

        // Exactly u64::MAX is fine — the boundary is inclusive on the side that
        // still round-trips.
        vm.prank(PRINCIPAL);
        grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI,
            uint256(type(uint64).max), _nowMs() + 1 days * 1000, bytes32(0)
        );
    }

    /// Expiry is milliseconds, compared against `block.timestamp * 1000`,
    /// because the in-process implementation is epoch-ms. Storing seconds here
    /// would put a truncation between the two, and a grant that expired at
    /// slightly different instants on each side is the sort of divergence nobody
    /// notices until it decides something.
    function test_expiryIsMillisecondsAndStrictLikeTheRust() public {
        // Absolute times throughout. `block.timestamp` is deliberately never
        // read here: solc treats it as constant within a call frame and caches
        // it, so a test that computed its warps from it would compare a stale
        // value against a warped chain and be wrong in a way that reads correct.
        uint64 deadlineMs = (START_SEC + 2) * 1000;
        vm.prank(PRINCIPAL);
        bytes32 id = grants.issue(
            7, PRINCIPAL, CONSUMER, TENANT, _classes(), CapabilityGrant.Hic.Budgeted, CUI, BUDGET,
            deadlineMs, bytes32(0)
        );

        vm.warp(START_SEC + 1);
        assertTrue(grants.isLive(id), "one second in, one to go");

        // `expires_at_ms > now_ms` — at exactly the deadline the grant is dead.
        vm.warp(START_SEC + 2);
        assertFalse(grants.isLive(id), "strictly greater, matching the Rust");
    }

    /// Two grants for the same principal and agent are distinct envelopes, not
    /// one shared meter. Consuming from one must not touch the other.
    function test_grantsAreIndependentEnvelopes() public {
        bytes32 a = _issue();
        bytes32 b = _issue();
        assertTrue(a != b, "the issue nonce keeps ids apart");

        vm.prank(CONSUMER);
        grants.consume(a, 400, keccak256("c"));
        assertEq(grants.remaining(a), 600);
        assertEq(grants.remaining(b), BUDGET, "an untouched envelope stays whole");
        assertEq(grants.grantCount(PRINCIPAL), 2);
    }
}
