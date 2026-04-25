// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../src/TEEAttestationRegistry.sol";

/// @title RmD3Test — RM-D3 SOL-03 + SOL-05 acceptance suite
/// @notice
///   SOL-03 (HIGH) — `strictCryptographicMode` defaults to TRUE.
///                   Pre-fix the bool zero left fresh deployments
///                   silently in V1 governance-trusted mode.
///   SOL-05 (HIGH) — JWT replay protection (sig hash one-time-use)
///                   AND two-step MAA RSA key install with timelock.
///                   Pre-fix the same JWT could be replayed by any
///                   address indefinitely, and a one-block governance
///                   compromise could install a malicious RSA key.
contract RmD3Test is Test {
    TEEAttestationRegistry internal registry;
    address internal governance = address(this);
    address internal worker1 = address(0xCAFE1);
    address internal worker2 = address(0xCAFE2);

    bytes32 internal constant MAA_KID_HASH = keccak256("azure-prod-kid-2026q2");
    bytes32 internal constant NRAS_KEY = keccak256("nras-prod");
    bytes32 internal constant MODEL_HASH = keccak256("model-v1");

    bytes constant SIGNED_JWT = bytes("hello citrate compute marketplace tee attestation 2026");

    bytes constant MAA_RSA_MODULUS =
        hex"9D49E0BB044BFF32E79B2FB2EC3E7784849FF6B9494D7DF48D246ADBE2002ACF"
        hex"2775FDB92C12E388FD09920E25317461B6ADC861995684F8825BBCB5FABC51B5"
        hex"3CFD60CEFA721298AB520E8A6E2AC783EE5F6EB5B6B4081D0EFB25FC64ECD585"
        hex"72BF6CC8521142B422EA386083F3FDE5E3B66F73D54271E7A880644F594C96CB"
        hex"B97A53CB964639A514F1BB9144EF9665179FB9A609DA929A64BDE6464E208B7E"
        hex"A5091B7B7B5F728A2BBADD57F88A7B73CD681233D5BB6DBFBB260B712243CD2B"
        hex"E12AFDE7ABF592AF59C5E3554193BA752123D44132C5AD4E740470805A7A1886"
        hex"BE3C93B4BD8A23911045AE3F29886C85CAAFBBD4A8EF741EE705918E55617EB5";
    bytes constant MAA_RSA_EXPONENT = hex"010001";
    bytes constant MAA_RSA_SIGNATURE =
        hex"4f81da0511e699ed58d94d87170e4eda473d69623061c74e87b697748dce9cd0"
        hex"6b1dd487bd7f39e9130529b48c3b219e2fedd6a06115c4a21c1773beb5d55705"
        hex"d1d426705cce43bc1610362bb785cb12e8ccce011ba5bb57682653ee01c9b7ce"
        hex"347ccaed9358f91d0b2ffd9204a2aa1f02e67b7d87e1b082cfced433fbe23c8c"
        hex"fbfe807ef329d7ecfa76a533f548b9d098e5068e65576e1c73e2c549bc848e22"
        hex"a05a2a5e18b0d61b13c43fe8175a5e91416ec5fe2a8940bfc7dabc837a279103"
        hex"a99c0b9e3d3371688ab8c6447bb1e4d3b59812bea3ca1fb9d1333988d6022dbb"
        hex"336d9bf07c54e5e3ff930b21d902e5bb0225bff19672c5f08a8bceae8f6c2e5d";

    function setUp() public {
        registry = new TEEAttestationRegistry(governance);
        registry.setNrasSigner(NRAS_KEY, true);
        // Install MAA RSA key via the new two-step path.
        registry.proposeMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);
        vm.roll(block.number + uint256(registry.RSA_KEY_TIMELOCK_BLOCKS()) + 1);
        registry.finalizeMaaRsaKey(MAA_KID_HASH);
    }

    // ── SOL-03: strict mode is the default ──────────────────────────

    function test_sol03_strict_mode_default_true() public {
        // Fresh deployment without any toggle.
        TEEAttestationRegistry fresh = new TEEAttestationRegistry(governance);
        assertTrue(
            fresh.strictCryptographicMode(),
            "SOL-03: strict mode must default to TRUE"
        );

        // V1 path is closed by default.
        fresh.setMaaSigner(keccak256("any"), true);
        fresh.setNrasSigner(NRAS_KEY, true);
        vm.prank(worker1);
        vm.expectRevert("TEERegistry: strict mode active, use submitAttestationStrict");
        fresh.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            keccak256("any"),
            NRAS_KEY
        );
    }

    // ── SOL-05: JWT replay protection ───────────────────────────────

    function test_sol05_jwt_signature_cannot_be_replayed_by_same_worker() public {
        // First submission succeeds.
        vm.prank(worker1);
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );

        // Second submission of the same signature MUST revert.
        vm.prank(worker1);
        vm.expectRevert("TEERegistry: jwt replay");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_sol05_jwt_signature_cannot_be_replayed_by_other_worker() public {
        // worker1 submits first.
        vm.prank(worker1);
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );

        // worker2 tries to replay the same JWT — must revert.
        vm.prank(worker2);
        vm.expectRevert("TEERegistry: jwt replay");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_sol05_used_signatures_are_publicly_visible() public {
        bytes32 sigHash = keccak256(MAA_RSA_SIGNATURE);
        assertFalse(registry.usedJwtSignatures(sigHash), "not yet used");

        vm.prank(worker1);
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );

        assertTrue(registry.usedJwtSignatures(sigHash), "now consumed");
    }

    // ── SOL-05: two-step RSA key install ────────────────────────────

    function test_sol05_proposed_key_not_active_before_timelock() public {
        bytes32 newKid = keccak256("rotation-2026q3");

        registry.proposeMaaRsaKey(newKid, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);

        // Before timelock elapses: pending exists, real key absent.
        (, , , uint64 etaBlock, bool exists) = registry.getPendingMaaRsaKey(newKid);
        assertTrue(exists, "proposal staged");
        assertGt(uint256(etaBlock), block.number, "eta in future");

        (, , bool active) = registry.getMaaRsaKey(newKid);
        assertFalse(active, "real key not installed yet");

        // Finalize too early reverts.
        vm.expectRevert("TEERegistry: timelock not elapsed");
        registry.finalizeMaaRsaKey(newKid);
    }

    function test_sol05_proposal_can_be_finalized_after_timelock() public {
        bytes32 newKid = keccak256("rotation-2026q3");
        registry.proposeMaaRsaKey(newKid, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);

        vm.roll(block.number + uint256(registry.RSA_KEY_TIMELOCK_BLOCKS()) + 1);

        // Permissionless finalize — anyone can push it.
        vm.prank(worker1);
        registry.finalizeMaaRsaKey(newKid);

        (, , bool active) = registry.getMaaRsaKey(newKid);
        assertTrue(active, "key installed and active");

        // Pending entry cleared.
        (, , , , bool exists) = registry.getPendingMaaRsaKey(newKid);
        assertFalse(exists, "pending cleared");
    }

    function test_sol05_proposal_can_be_cancelled_before_finalization() public {
        bytes32 newKid = keccak256("rotation-2026q3");
        registry.proposeMaaRsaKey(newKid, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);

        registry.cancelMaaRsaKeyProposal(newKid);

        (, , , , bool exists) = registry.getPendingMaaRsaKey(newKid);
        assertFalse(exists, "proposal cancelled");

        // Even after timelock, finalize must revert (no pending entry).
        vm.roll(block.number + uint256(registry.RSA_KEY_TIMELOCK_BLOCKS()) + 1);
        vm.expectRevert("TEERegistry: no pending proposal");
        registry.finalizeMaaRsaKey(newKid);
    }

    function test_sol05_propose_only_governance() public {
        bytes32 newKid = keccak256("rotation-2026q3");
        vm.prank(worker1);
        vm.expectRevert("TEERegistry: not governance");
        registry.proposeMaaRsaKey(newKid, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);
    }

    function test_sol05_cancel_only_governance() public {
        bytes32 newKid = keccak256("rotation-2026q3");
        registry.proposeMaaRsaKey(newKid, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);

        vm.prank(worker1);
        vm.expectRevert("TEERegistry: not governance");
        registry.cancelMaaRsaKeyProposal(newKid);
    }

    function test_sol05_emergency_deactivation_remains_single_step() public {
        // The MAA_KID_HASH key is already installed and active.
        // Deactivation MUST be a single-step call so a compromised
        // key can be killed instantly.
        registry.setMaaRsaKeyActive(MAA_KID_HASH, false);

        (, , bool active) = registry.getMaaRsaKey(MAA_KID_HASH);
        assertFalse(active, "instantly deactivated");

        // Subsequent strict submission with this kid must fail.
        vm.prank(worker1);
        vm.expectRevert("TEERegistry: unknown or inactive MAA kid");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }
}
