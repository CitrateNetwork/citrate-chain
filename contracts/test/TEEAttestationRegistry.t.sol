// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../src/TEEAttestationRegistry.sol";

/// @title TEEAttestationRegistryTest — CM-08 WP-08.1 acceptance
/// @notice Verifies the PipelineParallelTEE.tla invariants at
///         contract level: NotAttested → Attested → Expired; Slashed
///         is absorbing.
contract TEEAttestationRegistryTest is Test {
    TEEAttestationRegistry internal registry;

    address internal governance = address(this);
    address internal worker = address(0xCAFE);
    address internal reporter = address(0xB0B);

    bytes32 internal constant MAA_KEY = keccak256("maa-prod");
    bytes32 internal constant NRAS_KEY = keccak256("nras-prod");
    bytes32 internal constant MODEL_HASH = keccak256("model-v1");

    function setUp() public {
        registry = new TEEAttestationRegistry(governance);
        registry.setMaaSigner(MAA_KEY, true);
        registry.setNrasSigner(NRAS_KEY, true);
        vm.deal(reporter, 10 ether);
    }

    function _attest(address who) internal {
        vm.prank(who);
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_submit_transitions_not_attested_to_attested() public {
        assertFalse(registry.isAttested(worker, block.number));
        _attest(worker);
        assertTrue(registry.isAttested(worker, block.number));
    }

    function test_untrusted_signer_reverts() public {
        bytes32 bogusMaa = keccak256("attacker-maa");
        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted MAA signer");
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            bogusMaa,
            NRAS_KEY
        );
    }

    function test_attestation_expires_after_lifetime() public {
        _attest(worker);
        assertTrue(registry.isAttested(worker, block.number));

        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 1);
        assertFalse(registry.isAttested(worker, block.number));
    }

    function test_reattest_extends_expiry() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        uint256 originalExpiry = block.number + lifetime;

        // Advance halfway through the lifetime, then re-attest.
        vm.roll(block.number + lifetime / 2);
        uint256 reattestBlock = block.number;
        _attest(worker);

        // Roll past the ORIGINAL expiry — still attested because
        // fresh expiry = reattestBlock + lifetime > originalExpiry.
        vm.roll(originalExpiry + 100);
        assertTrue(registry.isAttested(worker, block.number),
            "still attested past original expiry thanks to re-attest");

        // Roll past the NEW expiry — now fully expired.
        vm.roll(reattestBlock + lifetime + 1);
        assertFalse(registry.isAttested(worker, block.number));
    }

    function test_slashed_cannot_reattest() public {
        _attest(worker);

        // Force the worker into Slashed via governance path.
        // (In production this goes through reportExpiredServe +
        // finalizeReport; here we simulate the end-state by going
        // through the full flow.)
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 10);

        vm.prank(reporter);
        uint256 reportId = registry.reportExpiredServe{value: 1 ether}(
            worker,
            uint64(block.number - 5), // expired 5 blocks ago
            uint64(block.number - 1)  // served after that
        );

        // Governance upholds, target slashed.
        registry.finalizeReport(reportId, true, 10 ether);

        // Now slashed — re-attest MUST fail.
        vm.prank(worker);
        vm.expectRevert("TEERegistry: slashed cannot re-attest");
        registry.submitAttestation(
            keccak256("vm2"),
            keccak256("gpu2"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_governance_signer_rotation() public {
        bytes32 newMaa = keccak256("maa-rotated");
        registry.setMaaSigner(newMaa, true);
        assertTrue(registry.trustedMaaSigners(newMaa));

        registry.setMaaSigner(MAA_KEY, false);
        assertFalse(registry.trustedMaaSigners(MAA_KEY));

        // Old key no longer works.
        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted MAA signer");
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_self_report_rejected() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 5);

        vm.deal(worker, 10 ether);
        vm.prank(worker);
        vm.expectRevert("TEERegistry: no self-report");
        registry.reportExpiredServe{value: 1 ether}(
            worker,
            uint64(block.number - 3),
            uint64(block.number - 1)
        );
    }

    function test_wrong_bond_rejected() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 5);

        vm.prank(reporter);
        vm.expectRevert("TEERegistry: wrong bond");
        registry.reportExpiredServe{value: 0.5 ether}(
            worker,
            uint64(block.number - 3),
            uint64(block.number - 1)
        );
    }

    // ── Strict mode (V2: cryptographic submission) ──────────────────

    // Real RSA-2048 public key + signature, generated with OpenSSL
    // 3.0. The "signed payload" simulates what the JWT
    // `header.payload` portion looks like — for testing we use the
    // same plaintext as `RS256.t.sol` so we know the signature is
    // valid against the modulus/exponent below.
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

    bytes32 constant MAA_KID_HASH = keccak256("azure-prod-kid-2026q2");

    function _registerMaaKey() internal {
        registry.setMaaRsaKey(
            MAA_KID_HASH,
            MAA_RSA_MODULUS,
            MAA_RSA_EXPONENT,
            true
        );
    }

    function test_strict_submit_accepts_valid_jwt_signature() public {
        _registerMaaKey();
        registry.setStrictCryptographicMode(true);

        vm.prank(worker);
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm-from-jwt"),
            keccak256("gpu-from-nras"),
            MODEL_HASH,
            NRAS_KEY
        );

        assertTrue(registry.isAttested(worker, block.number));
        TEEAttestationRegistry.AttestationRecord memory rec = registry.getAttestation(worker);
        assertEq(rec.modelHash, MODEL_HASH);
        assertEq(rec.vmMeasurement, keccak256("vm-from-jwt"));
    }

    function test_strict_submit_rejects_tampered_jwt() public {
        _registerMaaKey();
        registry.setStrictCryptographicMode(true);

        bytes memory tampered = bytes("hello citrate compute marketplace tee attestation 2027"); // changed year

        vm.prank(worker);
        vm.expectRevert("TEERegistry: invalid MAA JWT signature");
        registry.submitAttestationStrict(
            tampered,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm-from-jwt"),
            keccak256("gpu-from-nras"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_strict_submit_rejects_unknown_kid() public {
        _registerMaaKey();
        registry.setStrictCryptographicMode(true);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: unknown or inactive MAA kid");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            keccak256("rotated-kid-not-yet-registered"),
            keccak256("vm-from-jwt"),
            keccak256("gpu-from-nras"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_strict_submit_rejects_inactive_kid() public {
        _registerMaaKey();
        registry.setMaaRsaKeyActive(MAA_KID_HASH, false);
        registry.setStrictCryptographicMode(true);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: unknown or inactive MAA kid");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm-from-jwt"),
            keccak256("gpu-from-nras"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_strict_submit_rejects_untrusted_nras() public {
        _registerMaaKey();
        registry.setStrictCryptographicMode(true);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted NRAS signer");
        registry.submitAttestationStrict(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            keccak256("vm-from-jwt"),
            keccak256("gpu-from-nras"),
            MODEL_HASH,
            keccak256("attacker-nras")
        );
    }

    function test_strict_mode_disables_v1_path() public {
        registry.setStrictCryptographicMode(true);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: strict mode active, use submitAttestationStrict");
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_v1_path_works_when_strict_off() public {
        // Strict mode defaults OFF, so V1 should still work.
        assertFalse(registry.strictCryptographicMode());
        _attest(worker);
        assertTrue(registry.isAttested(worker, block.number));
    }

    function test_strict_toggle_emits_event() public {
        vm.expectEmit(true, true, true, true);
        emit TEEAttestationRegistry.StrictCryptographicModeChanged(true);
        registry.setStrictCryptographicMode(true);

        vm.expectEmit(true, true, true, true);
        emit TEEAttestationRegistry.StrictCryptographicModeChanged(false);
        registry.setStrictCryptographicMode(false);
    }

    function test_set_maa_rsa_key_emits_event() public {
        vm.expectEmit(true, true, true, true);
        emit TEEAttestationRegistry.MaaRsaKeyUpdated(MAA_KID_HASH, true);
        registry.setMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);

        // Round-trip via getter.
        (bytes memory n, bytes memory e, bool active) = registry.getMaaRsaKey(MAA_KID_HASH);
        assertEq(keccak256(n), keccak256(MAA_RSA_MODULUS));
        assertEq(keccak256(e), keccak256(MAA_RSA_EXPONENT));
        assertTrue(active);
    }

    function test_set_maa_rsa_key_rejects_empty_inputs() public {
        bytes memory empty;
        vm.expectRevert("TEERegistry: empty modulus");
        registry.setMaaRsaKey(MAA_KID_HASH, empty, MAA_RSA_EXPONENT, true);
        vm.expectRevert("TEERegistry: empty exponent");
        registry.setMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, empty, true);
    }

    function test_strict_mode_toggle_only_governance() public {
        vm.prank(worker);
        vm.expectRevert("TEERegistry: not governance");
        registry.setStrictCryptographicMode(true);
    }

    function test_set_maa_rsa_key_only_governance() public {
        vm.prank(worker);
        vm.expectRevert("TEERegistry: not governance");
        registry.setMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);
    }
}
