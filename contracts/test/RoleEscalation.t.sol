// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {RoleEscalation} from "../src/rbac/RoleEscalation.sol";

/// @title RoleEscalation.t — DPF-02-WP3 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/RoleEscalationGrant.tla`.
///      Coverage: every cited invariant + happy path + all reverts +
///      4 fuzz invariants. ≥40 tests per WP-3 acceptance.
contract RoleEscalationTest is Test {
    RoleEscalation internal re;

    bytes32 constant USER = keccak256("user-1");
    bytes32 constant USER2 = keccak256("user-2");
    bytes32 constant TENANT = keccak256("tenant-1");
    bytes32 constant TENANT2 = keccak256("tenant-2");
    bytes32 constant ROLE_ADMIN = keccak256("Admin");
    bytes32 constant ROLE_QA = keccak256("QA-L3");
    bytes32 constant CORR = keccak256("corr-1");

    address internal admin = address(0xA1);
    address internal stranger = address(0x5);

    function setUp() public {
        re = new RoleEscalation(admin);
        // FWA-C3-01: requestElevation is now gated on the authorized
        // elevation issuer (a role-admin) and requires the subject to
        // already hold a base role. The test harness calls elevation as
        // `address(this)`, so register it as a role-admin and seed base
        // roles for the principals these tests elevate. (The dedicated
        // C3-01 red test in RoleEscalationElevationPoC.t.sol asserts that
        // an UNregistered EOA still cannot elevate.)
        vm.prank(admin);
        re.setRoleAdmin(address(this), true);
        re.setBaseRole(USER, TENANT, ROLE_QA);
        re.setBaseRole(USER, TENANT2, ROLE_QA);
        re.setBaseRole(USER2, TENANT, ROLE_QA);
        re.setBaseRole(USER2, TENANT2, ROLE_QA);
    }

    // ── Constructor ─────────────────────────────────────────────────

    function test_constructor_setsInitialAdmin() public view {
        assertTrue(re.is_role_admin(admin));
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(bytes("RoleEscalation: zero admin"));
        new RoleEscalation(address(0));
    }

    // ── setRoleAdmin ────────────────────────────────────────────────

    function test_setRoleAdmin_addsByExistingAdmin() public {
        address newAdmin = address(0xA2);
        vm.prank(admin);
        re.setRoleAdmin(newAdmin, true);
        assertTrue(re.is_role_admin(newAdmin));
    }

    function test_setRoleAdmin_removes() public {
        address newAdmin = address(0xA2);
        vm.prank(admin);
        re.setRoleAdmin(newAdmin, true);
        vm.prank(admin);
        re.setRoleAdmin(newAdmin, false);
        assertFalse(re.is_role_admin(newAdmin));
    }

    function test_setRoleAdmin_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(RoleEscalation.NotRoleAdmin.selector, stranger)
        );
        re.setRoleAdmin(stranger, true);
    }

    function test_setRoleAdmin_emitsEvent() public {
        address newAdmin = address(0xA2);
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit RoleEscalation.RoleAdminSet(newAdmin, true);
        re.setRoleAdmin(newAdmin, true);
    }

    // ── setBaseRole ─────────────────────────────────────────────────

    function test_setBaseRole_admin() public {
        vm.prank(admin);
        re.setBaseRole(USER, TENANT, ROLE_QA);
        assertEq(re.base_role(USER, TENANT), ROLE_QA);
    }

    function test_setBaseRole_emitsEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit RoleEscalation.BaseRoleSet(USER, TENANT, ROLE_QA, admin);
        re.setBaseRole(USER, TENANT, ROLE_QA);
    }

    function test_setBaseRole_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(RoleEscalation.NotRoleAdmin.selector, stranger)
        );
        re.setBaseRole(USER, TENANT, ROLE_QA);
    }

    // ── requestElevation happy path ─────────────────────────────────

    function test_requestElevation_happyPath() public {
        _request(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba-proof", "kba");
        assertTrue(re.isActiveNow(USER, TENANT));
        RoleEscalation.RoleGrant memory g = re.latestGrant(USER, TENANT);
        assertEq(g.role, ROLE_ADMIN);
        assertEq(g.corr_id, CORR);
        assertTrue(g.active);
    }

    function test_requestElevation_emitsEntered() public {
        bytes memory proof = "kba-proof";
        uint64 t = uint64(block.timestamp);
        vm.expectEmit(true, true, true, true);
        emit RoleEscalation.Entered(
            USER, TENANT, ROLE_ADMIN, t + 3600, CORR, "kba"
        );
        re.requestElevation(USER, TENANT, ROLE_ADMIN, 0, CORR, proof, "kba");
    }

    function test_requestElevation_usesDefaultDuration() public {
        uint64 t = uint64(block.timestamp);
        _request(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "kba");
        assertEq(re.latestGrant(USER, TENANT).expires_at, t + 3600);
    }

    function test_requestElevation_customDuration() public {
        uint64 t = uint64(block.timestamp);
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        assertEq(re.latestGrant(USER, TENANT).expires_at, t + 1800);
    }

    function test_requestElevation_storesProofHash() public {
        bytes memory proof = "specific-kba-bytes";
        bytes32 expected = keccak256(proof);
        re.requestElevation(USER, TENANT, ROLE_ADMIN, 0, CORR, proof, "kba");
        assertEq(re.latestGrant(USER, TENANT).reauth_proof_hash, expected);
    }

    function test_requestElevation_independentTenants() public {
        _request(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "kba");
        _request(USER, TENANT2, ROLE_QA, 0, CORR, "kba", "kba");
        assertTrue(re.isActiveNow(USER, TENANT));
        assertTrue(re.isActiveNow(USER, TENANT2));
    }

    function test_requestElevation_independentUsers() public {
        _request(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "kba");
        _request(USER2, TENANT, ROLE_QA, 0, CORR, "kba", "kba");
        assertTrue(re.isActiveNow(USER, TENANT));
        assertTrue(re.isActiveNow(USER2, TENANT));
    }

    // ── requestElevation invariants ─────────────────────────────────

    function test_requestElevation_revertsOnEmptyProof() public {
        vm.expectRevert(RoleEscalation.EmptyReauthProof.selector);
        re.requestElevation(USER, TENANT, ROLE_ADMIN, 0, CORR, "", "kba");
    }

    function test_requestElevation_revertsOnEmptyKind() public {
        vm.expectRevert(RoleEscalation.EmptyReauthProofKind.selector);
        re.requestElevation(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "");
    }

    function test_requestElevation_revertsOnExceedingMax() public {
        uint32 tooLong = 9 hours;
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.ExceedsMaxDuration.selector, tooLong, 8 hours
            )
        );
        re.requestElevation(USER, TENANT, ROLE_ADMIN, tooLong, CORR, "kba", "kba");
    }

    /// @dev Cites `NoDoubleActiveGrant`. Re-elevating while an active
    ///      grant survives must revert.
    function test_NoDoubleActiveGrant_invariant() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.AlreadyElevated.selector, USER, TENANT
            )
        );
        re.requestElevation(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "kba");
    }

    /// @dev Cites `EnteredImpliesReauthProof`. Already covered by
    ///      empty-proof revert test; this one asserts the stored
    ///      grant carries a non-empty kind.
    function test_EnteredImpliesReauthProof_storedKindNonEmpty() public {
        _request(USER, TENANT, ROLE_ADMIN, 0, CORR, "kba", "biometric");
        assertEq(re.latestGrant(USER, TENANT).reauth_proof_kind, "biometric");
    }

    /// @dev Cites `ActiveExpiresAfterGranted`. expires_at > granted_at.
    function test_ActiveExpiresAfterGranted_invariant() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        RoleEscalation.RoleGrant memory g = re.latestGrant(USER, TENANT);
        assertGt(g.expires_at, g.granted_at);
    }

    /// @dev Cites `ActiveImpliesNotExpired`. isActiveNow returns false
    ///      after the window passes.
    function test_ActiveImpliesNotExpired_invariant() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        vm.warp(block.timestamp + 1801);
        assertFalse(re.isActiveNow(USER, TENANT));
    }

    // ── stepDown ────────────────────────────────────────────────────

    function test_stepDown_voluntary() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        re.stepDown(USER, TENANT, CORR);
        assertFalse(re.isActiveNow(USER, TENANT));
        assertFalse(re.latestGrant(USER, TENANT).active);
    }

    function test_stepDown_emitsExitedVoluntary() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        vm.expectEmit(true, true, true, true);
        emit RoleEscalation.Exited(USER, TENANT, ROLE_ADMIN, CORR, "voluntary");
        re.stepDown(USER, TENANT, CORR);
    }

    function test_stepDown_revertsOnNoGrant() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.NoActiveGrant.selector, USER, TENANT
            )
        );
        re.stepDown(USER, TENANT, CORR);
    }

    function test_stepDown_revertsAfterExpiry() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        vm.warp(block.timestamp + 1801);
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.NoActiveGrant.selector, USER, TENANT
            )
        );
        re.stepDown(USER, TENANT, CORR);
    }

    function test_stepDown_allowsReElevationAfter() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        re.stepDown(USER, TENANT, CORR);
        _request(USER, TENANT, ROLE_QA, 3600, CORR, "kba", "kba");
        assertTrue(re.isActiveNow(USER, TENANT));
        assertEq(re.latestGrant(USER, TENANT).role, ROLE_QA);
    }

    // ── revoke ──────────────────────────────────────────────────────

    function test_revoke_admin() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        vm.prank(admin);
        re.revoke(USER, TENANT, keccak256("foreign-national"), CORR);
        assertFalse(re.isActiveNow(USER, TENANT));
    }

    function test_revoke_revertsForStranger() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(RoleEscalation.NotRoleAdmin.selector, stranger)
        );
        re.revoke(USER, TENANT, keccak256("any"), CORR);
    }

    function test_revoke_revertsOnNoGrant() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.NoActiveGrant.selector, USER, TENANT
            )
        );
        re.revoke(USER, TENANT, keccak256("any"), CORR);
    }

    // ── tickExpire ──────────────────────────────────────────────────

    function test_tickExpire_expiresPastWindow() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        vm.warp(block.timestamp + 1801);

        bytes32[] memory users = new bytes32[](1);
        users[0] = USER;
        bytes32[] memory tenants = new bytes32[](1);
        tenants[0] = TENANT;
        re.tickExpire(users, tenants);
        assertFalse(re.latestGrant(USER, TENANT).active);
    }

    function test_tickExpire_emitsExpiredReason() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        vm.warp(block.timestamp + 1801);

        bytes32[] memory users = new bytes32[](1);
        users[0] = USER;
        bytes32[] memory tenants = new bytes32[](1);
        tenants[0] = TENANT;
        vm.expectEmit(true, true, true, true);
        emit RoleEscalation.Exited(USER, TENANT, ROLE_ADMIN, CORR, "expired");
        re.tickExpire(users, tenants);
    }

    function test_tickExpire_noopWhenStillActive() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        bytes32[] memory users = new bytes32[](1);
        users[0] = USER;
        bytes32[] memory tenants = new bytes32[](1);
        tenants[0] = TENANT;
        re.tickExpire(users, tenants);
        assertTrue(re.latestGrant(USER, TENANT).active);
    }

    function test_tickExpire_noopWhenNoGrants() public {
        bytes32[] memory users = new bytes32[](1);
        users[0] = USER;
        bytes32[] memory tenants = new bytes32[](1);
        tenants[0] = TENANT;
        re.tickExpire(users, tenants);
        assertEq(re.grantCount(USER, TENANT), 0);
    }

    function test_tickExpire_revertsOnArityMismatch() public {
        bytes32[] memory users = new bytes32[](2);
        bytes32[] memory tenants = new bytes32[](1);
        vm.expectRevert(bytes("RoleEscalation: arity mismatch"));
        re.tickExpire(users, tenants);
    }

    function test_tickExpire_batchedMultipleUsers() public {
        _request(USER, TENANT, ROLE_ADMIN, 1800, CORR, "kba", "kba");
        _request(USER2, TENANT, ROLE_QA, 1800, CORR, "kba", "kba");
        vm.warp(block.timestamp + 1801);

        bytes32[] memory users = new bytes32[](2);
        users[0] = USER;
        users[1] = USER2;
        bytes32[] memory tenants = new bytes32[](2);
        tenants[0] = TENANT;
        tenants[1] = TENANT;
        re.tickExpire(users, tenants);
        assertFalse(re.isActiveNow(USER, TENANT));
        assertFalse(re.isActiveNow(USER2, TENANT));
    }

    // ── Read views ──────────────────────────────────────────────────

    function test_grantCount_increments() public {
        assertEq(re.grantCount(USER, TENANT), 0);
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        assertEq(re.grantCount(USER, TENANT), 1);
        re.stepDown(USER, TENANT, CORR);
        _request(USER, TENANT, ROLE_QA, 3600, CORR, "kba", "kba");
        assertEq(re.grantCount(USER, TENANT), 2);
    }

    function test_grantAt_indexed() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        re.stepDown(USER, TENANT, CORR);
        _request(USER, TENANT, ROLE_QA, 3600, CORR, "kba", "kba");
        assertEq(re.grantAt(USER, TENANT, 0).role, ROLE_ADMIN);
        assertEq(re.grantAt(USER, TENANT, 1).role, ROLE_QA);
    }

    function test_latestGrant_revertsOnNoHistory() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                RoleEscalation.NoActiveGrant.selector, USER, TENANT
            )
        );
        re.latestGrant(USER, TENANT);
    }

    function test_isActiveNow_falseWhenNoHistory() public view {
        assertFalse(re.isActiveNow(USER, TENANT));
    }

    function test_isActiveNow_falseAfterStepDown() public {
        _request(USER, TENANT, ROLE_ADMIN, 3600, CORR, "kba", "kba");
        re.stepDown(USER, TENANT, CORR);
        assertFalse(re.isActiveNow(USER, TENANT));
    }

    // ── Fuzz invariants ─────────────────────────────────────────────

    /// @dev Fuzz `NoDoubleActiveGrant`: two consecutive elevation
    ///      requests on the same (user, tenant) within the same
    ///      window — second always reverts.
    function testFuzz_NoDoubleActiveGrant(uint32 dur) public {
        dur = uint32(bound(dur, 1, 8 hours));
        re.requestElevation(USER, TENANT, ROLE_ADMIN, dur, CORR, "kba", "kba");
        vm.expectRevert();
        re.requestElevation(USER, TENANT, ROLE_ADMIN, dur, CORR, "kba", "kba");
    }

    /// @dev Fuzz `ActiveExpiresAfterGranted`.
    function testFuzz_ActiveExpiresAfterGranted(uint32 dur) public {
        dur = uint32(bound(dur, 1, 8 hours));
        re.requestElevation(USER, TENANT, ROLE_ADMIN, dur, CORR, "kba", "kba");
        RoleEscalation.RoleGrant memory g = re.latestGrant(USER, TENANT);
        assertGt(g.expires_at, g.granted_at);
        assertEq(g.expires_at - g.granted_at, dur);
    }

    /// @dev Fuzz `ActiveImpliesNotExpired`. After warping past the
    ///      window, isActiveNow returns false.
    function testFuzz_ActiveImpliesNotExpired(uint32 dur, uint32 advance) public {
        dur = uint32(bound(dur, 1, 8 hours));
        advance = uint32(bound(advance, dur + 1, dur + 365 days));
        re.requestElevation(USER, TENANT, ROLE_ADMIN, dur, CORR, "kba", "kba");
        vm.warp(block.timestamp + advance);
        assertFalse(re.isActiveNow(USER, TENANT));
    }

    /// @dev Fuzz idempotent tickExpire: calling it on a grant whose
    ///      window has not passed leaves it active.
    function testFuzz_TickExpireIdempotent(uint32 dur, uint32 advance) public {
        dur = uint32(bound(dur, 100, 8 hours));
        advance = uint32(bound(advance, 0, dur - 1));
        re.requestElevation(USER, TENANT, ROLE_ADMIN, dur, CORR, "kba", "kba");
        vm.warp(block.timestamp + advance);

        bytes32[] memory users = new bytes32[](1);
        users[0] = USER;
        bytes32[] memory tenants = new bytes32[](1);
        tenants[0] = TENANT;
        re.tickExpire(users, tenants);
        assertTrue(re.isActiveNow(USER, TENANT));
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _request(
        bytes32 user,
        bytes32 tenant,
        bytes32 role,
        uint32  dur,
        bytes32 corr,
        bytes memory proof,
        string memory kind
    ) internal {
        re.requestElevation(user, tenant, role, dur, corr, proof, kind);
    }
}
