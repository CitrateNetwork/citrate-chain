// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../src/TEEAttestationRegistry.sol";

/// @title RmD3BoundTest — RM-D3 WP-D3.4 (audit SOL-05) acceptance
/// @notice End-to-end coverage for `submitAttestationStrictBound`,
///         which uses JWTParser to bind the on-chain `vmMeasurement`
///         to actual JWT payload content.
///
/// @dev Fixtures generated with OpenSSL 3.0:
///        openssl genrsa -out jwt.pem 2048
///        HEADER='{"alg":"RS256","typ":"JWT","kid":"test-kid"}'
///        PAYLOAD='{"iss":"sharedeus2.eus2.attest.azure.net","x-ms-vm-measurement":"0xdeadbeefcafe","iat":1745520000}'
///        SIGNED=$(printf %s "$HEADER" | base64 -w0 | tr -d '=' | tr '/+' '_-').$(printf %s "$PAYLOAD" | base64 -w0 | tr -d '=' | tr '/+' '_-')
///        echo -n "$SIGNED" | openssl dgst -sha256 -sign jwt.pem | xxd -p
contract RmD3BoundTest is Test {
    TEEAttestationRegistry internal registry;
    address internal governance = address(this);
    address internal worker = address(0xCAFE);

    bytes32 internal constant MAA_KID_HASH = keccak256("test-kid");
    bytes32 internal constant NRAS_KEY = keccak256("nras-prod");
    bytes32 internal constant MODEL_HASH = keccak256("model-v1");

    // The base64url(header).base64url(payload) bytes that were
    // RS256-signed. CHAIN-B-C019 (audit 2026-09-02): the payload now embeds a
    // `"holder":"0x…cafe"` claim naming `worker` (address(0xCAFE)); the
    // strict-bound path requires the JWT to name its submitter. Fixture
    // regenerated with a fresh RSA-2048 key (see the openssl recipe in the
    // header) so the signature covers the holder claim.
    //   PAYLOAD='{"iss":"sharedeus2.eus2.attest.azure.net",
    //     "x-ms-vm-measurement":"0xdeadbeefcafe",
    //     "holder":"0x000000000000000000000000000000000000cafe",
    //     "iat":1745520000}'
    bytes constant SIGNED_JWT = bytes(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0."
        "eyJpc3MiOiJzaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsIngtbXMtdm0tbWVhc3VyZW1lbnQiOiIweGRlYWRiZWVmY2FmZSIsImhvbGRlciI6IjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwY2FmZSIsImlhdCI6MTc0NTUyMDAwMH0"
    );

    bytes constant MAA_RSA_MODULUS =
        hex"8968a575e3c2896fdf42b735207c0bc76867a80f1b5848a9f29e91c5074c79b3"
        hex"14542429a91fdb004a7176ef2cbfcf9c93255afb9d6c2bd5b549ae386c49b1e4"
        hex"719069adffe155a6a876ed696f856c7a6448ab7779dbb9705c5c05ed93f04d73"
        hex"dd9d8fc227b35b7682150124e57e6a66ebafcf9d90780fb0a7cb92248c5c0c8e"
        hex"77815f3acd82f20f8e55fb99c43e2d008f1097f409cd916a891189cb976cbade"
        hex"39dddaf5491eac484a4c9a6066ff18dd40754fb346e7289b4d7182ec7e9b2f83"
        hex"1a7045c903dfd85e02bbc064c0005ba0a7bd18f5a476bb3a27d8dbe5eda6f2aa"
        hex"e3af31c6b0e8dd1f4eff4d5a7497335125818898150ad7e50fc890cc0a405929";
    bytes constant MAA_RSA_EXPONENT = hex"010001";

    bytes constant MAA_RSA_SIGNATURE =
        hex"239f979fd70d784ca8a32dd63bcc1d6ce9a06532d0f15c24155e544be7f84644"
        hex"d6fcc420252f52814f9701c068981b6d05c240479182adb4468f3761626f7f4f"
        hex"60b3eed7cc32775fc5180ee19bf03c2171dfd3f25be85ee5de36446d722668cf"
        hex"15217a0d843ab4b2924a28e3c76adf9526cd3513014ea411fbd568bb23268bee"
        hex"b281c06f09d47f4230ebc18fc344ad14894c3e3717f048f824cc282338514599"
        hex"4582ce27ff11f609a2aaa1bae73e16adde69798d553a2a8eafe0efcb57b9c4a8"
        hex"f145493685e879d8c402dedca81186dfcec2a9f1a885ea41451fb4a88a65b96a"
        hex"57cc68dedbeac606ad991624fb91aaec068c0e7277d170a04505732a23a2c197";

    /// The exact JSON pair as it appears in the JWT payload.
    bytes constant VM_MEASUREMENT_CLAIM = bytes('"x-ms-vm-measurement":"0xdeadbeefcafe"');

    function setUp() public {
        registry = new TEEAttestationRegistry(governance);
        registry.setNrasSigner(NRAS_KEY, true);
        // Two-step install of the test RSA key.
        registry.proposeMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);
        vm.roll(block.number + uint256(registry.RSA_KEY_TIMELOCK_BLOCKS()) + 1);
        registry.finalizeMaaRsaKey(MAA_KID_HASH);
    }

    // ── Happy path ──────────────────────────────────────────────────

    /// A JWT that genuinely contains the asserted measurement claim
    /// is accepted, and the on-chain `vmMeasurement` is the keccak
    /// of the claim bytes — not whatever the caller pretends.
    function test_sol05_bound_submission_accepts_real_jwt_with_real_claim() public {
        vm.prank(worker);
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );

        TEEAttestationRegistry.AttestationRecord memory rec =
            registry.getAttestation(worker);
        assertEq(
            rec.vmMeasurement,
            keccak256(VM_MEASUREMENT_CLAIM),
            "SOL-05: vmMeasurement bound to claim hash"
        );
        assertTrue(registry.isAttested(worker, block.number));
    }

    // ── Substitution attack: the core SOL-05 case ──────────────────

    /// A worker holds a valid MAA JWT for measurement A. They try
    /// to claim measurement B on-chain by passing fake claim bytes.
    /// Pre-RM-D3 a `submitAttestationStrict` variant (since removed
    /// in RM-J3) would have accepted this; the bound variant rejects
    /// because the fake claim isn't in the JWT.
    function test_sol05_bound_rejects_fabricated_measurement_claim() public {
        bytes memory fakeClaim = bytes('"x-ms-vm-measurement":"0xfake_value_attacker_wants"');

        vm.prank(worker);
        vm.expectRevert("TEERegistry: vm claim not in jwt");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            fakeClaim,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    // ── CHAIN-B-C019: the JWT must name its submitter ───────────────

    /// RED (pre-fix): the strict-bound path wrote `attestations[msg.sender]`
    /// from any valid MAA JWT without checking it named the caller, so an
    /// attacker who observed the JWT in the mempool could resubmit it from
    /// their OWN address, seize the Attested record, and — via the one-time
    /// `usedJwtSignatures` guard — permanently lock the genuine worker out.
    /// GREEN: the JWT's `"holder"` claim must equal the caller's address, so
    /// an attacker's resubmission is rejected and the worker keeps its record.
    function test_C019_jwt_must_name_the_submitter() public {
        address attacker = address(0xBEEF);
        vm.prank(attacker);
        vm.expectRevert("TEERegistry: jwt not bound to caller");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
        // The attacker did NOT consume the JWT (revert rolled it back), so the
        // real worker can still attest.
        vm.prank(worker);
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
        assertTrue(registry.isAttested(worker, block.number));
        assertFalse(registry.isAttested(attacker, block.number));
    }

    // ── Replay protection still applies ─────────────────────────────

    function test_sol05_bound_jwt_replay_rejected() public {
        vm.prank(worker);
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );

        vm.prank(worker);
        vm.expectRevert("TEERegistry: jwt replay");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    // ── Other guards still applied ──────────────────────────────────

    function test_sol05_bound_rejects_invalid_signature() public {
        // Tamper one byte of the signed payload — RS256 verify fails.
        bytes memory tamperedJwt = bytes(SIGNED_JWT);
        tamperedJwt[0] = bytes1(uint8(tamperedJwt[0]) ^ 0x01);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: invalid MAA JWT signature");
        registry.submitAttestationStrictBound(
            tamperedJwt,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_sol05_bound_rejects_empty_claim() public {
        bytes memory empty;
        vm.prank(worker);
        vm.expectRevert("TEERegistry: empty vm claim");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            empty,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    function test_sol05_bound_rejects_unknown_kid() public {
        vm.prank(worker);
        vm.expectRevert("TEERegistry: unknown or inactive MAA kid");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            keccak256("not-installed"),
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    /// RM-J3 — coverage moved here from `TEEAttestationRegistry.t.sol`
    /// when `submitAttestationStrict` was removed. An RSA key that's
    /// been emergency-deactivated (e.g., compromised) is rejected
    /// through the same `key.active` branch as an unknown kid; this
    /// test asserts the deactivation flow specifically.
    function test_sol05_bound_rejects_inactive_kid() public {
        // Emergency deactivation remains a single-step governance
        // call so a compromised key can be killed instantly.
        registry.setMaaRsaKeyActive(MAA_KID_HASH, false);

        vm.prank(worker);
        vm.expectRevert("TEERegistry: unknown or inactive MAA kid");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            NRAS_KEY
        );
    }

    /// RM-J3 — coverage moved here from `TEEAttestationRegistry.t.sol`.
    /// NRAS signer hashes are governance-curated; a hash not on the
    /// trusted list is rejected before any signature work is done.
    function test_sol05_bound_rejects_untrusted_nras() public {
        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted NRAS signer");
        registry.submitAttestationStrictBound(
            SIGNED_JWT,
            MAA_RSA_SIGNATURE,
            MAA_KID_HASH,
            VM_MEASUREMENT_CLAIM,
            keccak256("gpu"),
            MODEL_HASH,
            keccak256("attacker-nras")
        );
    }
}
