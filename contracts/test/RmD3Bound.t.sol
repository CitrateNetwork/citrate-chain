// SPDX-License-Identifier: MIT
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
    // RS256-signed.
    bytes constant SIGNED_JWT = bytes(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0."
        "eyJpc3MiOiJzaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsIngtbXMtdm0tbWVhc3VyZW1lbnQiOiIweGRlYWRiZWVmY2FmZSIsImlhdCI6MTc0NTUyMDAwMH0"
    );

    bytes constant MAA_RSA_MODULUS =
        hex"CCD36A5718C9CE85E0538385FDEDF541F95E2E7630CC6C4CA93CF24A6EA266CD"
        hex"E68721ACC53E2203899F79F3FC55903A723D124962648DAE179C2B6A7C81BC7E"
        hex"96A7DA9232AD0B0FB87414918F14254D2E9060AE95243CE62260E5F9281F8A3F"
        hex"F662404DF8A6A2B33CCB60B0C96B6DFF5F7E3A41D4AC02C9C61717EEB352A955"
        hex"809018ED60D357859F197DF79B556C7ADC8175CA431A243AD0B72F30E8C178BA"
        hex"15D8F4D94A1C6AB8D3F82B0E46B64615256CF999644946D7C185DDB6A617B5E9"
        hex"AE578ED0365BA32907B714EDBFF1CF218D0A9FE9AAA8AE9F1895CAC599EF82D8"
        hex"BF5E97FCAFDB6D68EC82B1E3921C17BD1342BF9E8D0D00C4295F112799031457";
    bytes constant MAA_RSA_EXPONENT = hex"010001";

    bytes constant MAA_RSA_SIGNATURE =
        hex"31214f289d954465d72c80f19255aa613e13818b609262a926a9279f598a6b9c"
        hex"95a0027010176407bc23aec13b9176740dc271acac2bbae6008fbd8d2edfe44b"
        hex"4d694cfe0c40bb939a054cb071de7e42e54ed5fd3bc02e08df3e4805498841c0"
        hex"078b421b8afeeb9906201cf9e45c012eb474d71a0f335752d5e87122803165f3"
        hex"c19b4fb01448c62643a7bf98559dbb3f8aaca4094f2e787f0a67aeeb5cf02208"
        hex"3f622e2c647b0d6695c363912f973db29f08d9e7c9f3b9a082148574d6c9e360"
        hex"f8433bef023dd627dc392cb33fd822c67b01340e029af63aa6ebceba6b2e487c"
        hex"f6c39ea01ff0793e718e707c176e3edf08fbd514c7f52f3eff4027796584e7b1";

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
    /// Pre-fix `submitAttestationStrict` accepted this. Post-fix
    /// `submitAttestationStrictBound` rejects: the fake claim isn't
    /// in the JWT.
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
}
