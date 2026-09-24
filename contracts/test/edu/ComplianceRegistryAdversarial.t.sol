// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";

/// @notice Adversarial / penetration tests for ComplianceRegistry. Each
///         test models a specific attack vector and verifies the contract
///         refuses or behaves correctly under malicious inputs.
///
///         Attack categories:
///           1. Authority spoofing — non-admins trying to sign / revoke
///           2. Cross-school spillover — School A's admin acting on School B
///           3. Replay & stale-data attacks — re-using old envelopes / records
///           4. State-mutation race — interleaving sign / expire / revoke
///           5. Self-erasure — institutional admin trying to revoke own record
///           6. Tree-revocation interaction — signing post-tree-revocation
///           7. Re-entrancy attempts via the `tree` external call boundary
///           8. Governance hand-off interference
contract ComplianceRegistryAdversarialTest is Test {
    InstitutionTreeV1 internal tree;
    ComplianceRegistry internal reg;

    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);
    address internal schoolA_Admin = address(0x5C0AAA);
    address internal schoolB_Admin = address(0x5C0BBB);
    address internal attacker = address(0xBADBADBAD);

    bytes32 internal constant CMO_HASH = keccak256("ADV-CMO");
    bytes32 internal constant DIST_HASH = keccak256("ADV-DIST");
    bytes32 internal constant SCH_A = keccak256("ADV-SCH-A");
    bytes32 internal constant SCH_B = keccak256("ADV-SCH-B");
    bytes32 internal constant ENV_A = keccak256("env-a");
    bytes32 internal constant ENV_B = keccak256("env-b");
    bytes32 internal constant REASON = keccak256("audit-reason");

    uint64 internal constant T0 = 1_700_000_000;
    uint8 internal constant STATE_CA = 0;

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
        reg = new ComplianceRegistry(governance, address(tree));

        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DIST_HASH, districtAdmin, STATE_CA);
        vm.startPrank(districtAdmin);
        tree.registerSchool(DIST_HASH, SCH_A, schoolA_Admin, STATE_CA);
        tree.registerSchool(DIST_HASH, SCH_B, schoolB_Admin, STATE_CA);
        vm.stopPrank();

        vm.warp(T0);
    }

    // ──────────────────────────────────────────────────────────────
    // 1. Authority spoofing — non-admin / non-governance attacks
    // ──────────────────────────────────────────────────────────────

    /// @notice An attacker with no role attempts to sign a gate for any school.
    function test_attack_strangerCannotSign() public {
        vm.prank(attacker);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
    }

    /// @notice An attacker spoofing as the parent CMO/district admin
    ///         attempts to sign at the school level. The contract must
    ///         require the *school's* admin (more granular authority).
    function test_attack_cmoAdminCannotSignSchoolGate() public {
        vm.prank(cmoAdmin);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
    }

    function test_attack_districtAdminCannotSignSchoolGate() public {
        vm.prank(districtAdmin);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
    }

    /// @notice An attacker attempts to revoke a gate (governance-only).
    function test_attack_strangerCannotRevoke() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        vm.prank(attacker);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_A, 0, REASON);
    }

    /// @notice An attacker attempts to take over governance via the two-step
    ///         transfer without being the pending governor.
    function test_attack_strangerCannotAcceptGovernance() public {
        vm.prank(attacker);
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        reg.acceptGovernance();

        // Even if a transfer is in flight, only the named pending can accept
        vm.prank(governance);
        reg.transferGovernance(address(0xCAFE));

        vm.prank(attacker);
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        reg.acceptGovernance();
    }

    // ──────────────────────────────────────────────────────────────
    // 2. Cross-school spillover — School A's admin acting on School B
    // ──────────────────────────────────────────────────────────────

    function test_attack_schoolACannotSignForSchoolB() public {
        vm.prank(schoolA_Admin);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCH_B, 0, ENV_A, T0 + 30 days);
    }

    /// @notice Even after School A's admin signs A's gate, they cannot
    ///         influence School B's matrix in any way.
    function test_attack_schoolASigningDoesNotTouchSchoolB() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);

        // School B's record for the same gate must remain Untouched
        ComplianceRegistry.Record memory rB = reg.getRecord(SCH_B, 0);
        assertEq(uint8(rB.status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(rB.envelopeIdHash, bytes32(0));
        assertEq(rB.signer, address(0));
    }

    // ──────────────────────────────────────────────────────────────
    // 3. Replay & stale-data attacks
    // ──────────────────────────────────────────────────────────────

    /// @notice After a gate is revoked, the prior envelope hash should NOT
    ///         remain "active" in any read. isCompliant must return false
    ///         even if the envelope itself is still valid off-chain.
    function test_attack_revokedRecord_isNotCompliant() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        vm.prank(governance);
        reg.revokeGate(SCH_A, 0, REASON);

        assertFalse(reg.isCompliant(SCH_A, 0));

        // Even though the raw record retains the envelope hash for
        // forensic purposes, the effective status is Revoked.
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_A, 0);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Revoked));
    }

    /// @notice An attacker tries to "replay" an envelope that was previously
    ///         signed and expired. The contract MUST allow re-signing with
    ///         the same envelope hash (not unique-constrained), but the
    ///         signer must be the school admin and the timestamps must be fresh.
    ///         This isn't an attack per se, but verifies the contract
    ///         doesn't accidentally bind envelopes to first-signing only.
    function test_envelopeHashIsNotUniqueConstrained() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        vm.warp(T0 + 30 days + 1);
        reg.expireGate(SCH_A, 0);

        // Same envelope hash, new signing — should work (the off-chain envelope
        // re-issuance might re-use the hash if it's deterministic from school+gate)
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 60 days + 2);
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_A, 0);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, ENV_A);
    }

    /// @notice An attacker who somehow learns the school admin's signing
    ///         key can only do what the school admin can do — which is
    ///         sign (not revoke). The attacker cannot escalate.
    function test_attack_keyCompromise_doesNotEscalate() public {
        // Simulate key compromise: attacker now controls schoolA_Admin
        vm.startPrank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        // Compromised admin tries to escalate to revocation — blocked
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_A, 0, REASON);
        // Compromised admin tries to revoke their own School B too — blocked
        // (they're not B's admin even if they were A's)
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_B, 0, REASON);
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────────────────────
    // 4. State-mutation race — interleaving sign / expire / revoke
    // ──────────────────────────────────────────────────────────────

    /// @notice Race scenario: governance revokes WHILE keeper expire is racing.
    ///         Foundry tests are sequential so we model both orderings:
    ///         (a) expire-then-revoke (already covered by canRevokeExpired)
    ///         (b) revoke-then-expire — must refuse expire on Revoked.
    function test_attack_race_revokeFirstThenExpireFails() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        vm.prank(governance);
        reg.revokeGate(SCH_A, 0, REASON);
        vm.warp(T0 + 30 days + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotExpire.selector, ComplianceRegistry.Status.Revoked
            )
        );
        reg.expireGate(SCH_A, 0);
    }

    /// @notice Race scenario: school admin tries to re-sign WHILE the keeper
    ///         hasn't yet swept an expired record. Re-signing while still
    ///         in `Signed` (even if past expiresAt) must refuse — the
    ///         keeper sweep is required first.
    function test_attack_race_resignBeforeKeeperSweepFails() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        // Walk past expiry but DON'T call expireGate
        vm.warp(T0 + 30 days + 1);
        vm.prank(schoolA_Admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.CannotRecordSigned.selector, ComplianceRegistry.Status.Signed
            )
        );
        reg.recordSigned(SCH_A, 0, ENV_B, T0 + 60 days + 2);

        // Note: isCompliant returns false here because of the time-bound
        // check, so downstream readers correctly see "not compliant" even
        // before the sweep. The sweep is just for cleanup.
        assertFalse(reg.isCompliant(SCH_A, 0));
    }

    // ──────────────────────────────────────────────────────────────
    // 5. Self-erasure — admin trying to revoke own record
    // ──────────────────────────────────────────────────────────────

    /// @notice The audit-resilience property: a school under audit cannot
    ///         self-revoke its own non-compliance to "look clean". Only
    ///         governance can revoke.
    function test_attack_schoolCannotSelfRevoke() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
        vm.prank(schoolA_Admin);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_A, 0, REASON);
    }

    // ──────────────────────────────────────────────────────────────
    // 6. Tree-revocation interaction
    // ──────────────────────────────────────────────────────────────

    /// @notice After a school is revoked at the tree level, its admin
    ///         cannot continue signing new gates — preserves the tree's
    ///         revocation authority.
    function test_attack_treeRevokedSchoolCannotSign() public {
        vm.prank(governance);
        tree.revokeInstitution(SCH_A);
        vm.prank(schoolA_Admin);
        vm.expectRevert(
            abi.encodeWithSelector(ComplianceRegistry.SchoolRevoked.selector, SCH_A)
        );
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);
    }

    /// @notice Pre-existing signed records are preserved through a tree
    ///         revocation (forensic visibility), but `isCompliant` returns
    ///         false. This is the right behavior: auditors need to see
    ///         what was true; gating decisions need to refuse.
    function test_treeRevocation_preservesRecordsButGatesFalseCompliance() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);

        vm.prank(governance);
        tree.revokeInstitution(SCH_A);

        // Record still in storage
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_A, 0);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, ENV_A);

        // But isCompliant returns false because school is revoked
        assertFalse(reg.isCompliant(SCH_A, 0));
    }

    // ──────────────────────────────────────────────────────────────
    // 7. Re-entrancy attempts via the tree boundary
    // ──────────────────────────────────────────────────────────────

    /// @notice The contract makes external view calls to `tree` (getNode).
    ///         Solidity-level re-entrancy is impossible because no state-
    ///         mutating calls cross the boundary, but we explicitly verify
    ///         that the tree dependency cannot be replaced post-deploy
    ///         (immutable property).
    function test_treeIsImmutable() public view {
        // Constructor sets `tree` via `IInstitutionTreeV1(_tree)` into an
        // immutable field. There's no setter. Verifying this by reading
        // the tree address — must equal the deployed tree.
        assertEq(address(reg.tree()), address(tree));
    }

    // ──────────────────────────────────────────────────────────────
    // 8. Governance hand-off interference
    // ──────────────────────────────────────────────────────────────

    /// @notice After governance is transferred, the OLD governance can no
    ///         longer revoke. This is a hand-off correctness property.
    function test_oldGovernanceLosesRevocationPower() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 30 days);

        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        reg.transferGovernance(newGov);
        vm.prank(newGov);
        reg.acceptGovernance();

        // Old governance now powerless
        vm.prank(governance);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_A, 0, REASON);

        // New governance can revoke
        vm.prank(newGov);
        reg.revokeGate(SCH_A, 0, REASON);
        assertEq(
            uint8(reg.getRecord(SCH_A, 0).status), uint8(ComplianceRegistry.Status.Revoked)
        );
    }

    /// @notice A pending-governance handoff that's cancelled correctly
    ///         locks out the would-be new governor.
    function test_cancelledTransferLocksOutPendingGov() public {
        address pending = address(0xC0FFEE);
        vm.prank(governance);
        reg.transferGovernance(pending);
        vm.prank(governance);
        reg.cancelGovernanceTransfer();

        vm.prank(pending);
        vm.expectRevert(ComplianceRegistry.InvalidGovernanceTransfer.selector);
        reg.acceptGovernance();
    }

    // ──────────────────────────────────────────────────────────────
    // 9. Boundary attacks on numeric inputs
    // ──────────────────────────────────────────────────────────────

    /// @notice An attacker tries the absolute-max uint64 expiry (uint64.max)
    ///         to overflow the validity-window check. Math is safe because
    ///         we check `expiresAt - nowTs > MAX_VALIDITY_WINDOW`.
    function test_attack_maxUint64Expiry_revertsCleanly() public {
        vm.prank(schoolA_Admin);
        vm.expectRevert(ComplianceRegistry.ValidityWindowTooLong.selector);
        reg.recordSigned(SCH_A, 0, ENV_A, type(uint64).max);
    }

    /// @notice An attacker tries expiresAt = nowTs + MAX_VALIDITY_WINDOW + 1
    ///         which is the smallest illegal value. Must revert.
    function test_attack_oneSecondTooLong_reverts() public {
        uint64 expiresAt = T0 + uint64(reg.MAX_VALIDITY_WINDOW()) + 1;
        vm.prank(schoolA_Admin);
        vm.expectRevert(ComplianceRegistry.ValidityWindowTooLong.selector);
        reg.recordSigned(SCH_A, 0, ENV_A, expiresAt);
    }

    /// @notice The smallest legal expiry: nowTs + 1.
    function test_minimalLegalExpiry_oneSecondAhead() public {
        vm.prank(schoolA_Admin);
        reg.recordSigned(SCH_A, 0, ENV_A, T0 + 1);
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_A, 0);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.expiresAt, T0 + 1);
    }
}
