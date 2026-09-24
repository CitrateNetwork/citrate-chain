// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {RS256} from "../src/lib/RS256.sol";

/// @notice Thin harness so `vm.expectRevert` sees the library
/// requires at a lower call depth than the test runner.
contract RS256Harness {
    function verify(
        bytes memory message,
        bytes memory signature,
        bytes memory modulus,
        bytes memory exponent
    ) external view returns (bool) {
        return RS256.verify(message, signature, modulus, exponent);
    }
}

/// @title RS256Test — RSASSA-PKCS1-v1_5 + SHA-256 verification
/// @notice Test vectors generated via OpenSSL 3.0 with a fresh
///         RSA-2048 keypair (e=65537). Asserts verify accepts the
///         legitimate signature and rejects each of the standard
///         tampering attacks: bit-flipped sig, bit-flipped message,
///         wrong modulus, malformed PKCS#1 padding.
contract RS256Test is Test {
    // Test vector — see _msg() below for the cleartext.

    bytes constant TEST_MODULUS =
        hex"9D49E0BB044BFF32E79B2FB2EC3E7784849FF6B9494D7DF48D246ADBE2002ACF"
        hex"2775FDB92C12E388FD09920E25317461B6ADC861995684F8825BBCB5FABC51B5"
        hex"3CFD60CEFA721298AB520E8A6E2AC783EE5F6EB5B6B4081D0EFB25FC64ECD585"
        hex"72BF6CC8521142B422EA386083F3FDE5E3B66F73D54271E7A880644F594C96CB"
        hex"B97A53CB964639A514F1BB9144EF9665179FB9A609DA929A64BDE6464E208B7E"
        hex"A5091B7B7B5F728A2BBADD57F88A7B73CD681233D5BB6DBFBB260B712243CD2B"
        hex"E12AFDE7ABF592AF59C5E3554193BA752123D44132C5AD4E740470805A7A1886"
        hex"BE3C93B4BD8A23911045AE3F29886C85CAAFBBD4A8EF741EE705918E55617EB5";

    bytes constant TEST_EXPONENT = hex"010001";

    bytes constant TEST_SIGNATURE =
        hex"4f81da0511e699ed58d94d87170e4eda473d69623061c74e87b697748dce9cd0"
        hex"6b1dd487bd7f39e9130529b48c3b219e2fedd6a06115c4a21c1773beb5d55705"
        hex"d1d426705cce43bc1610362bb785cb12e8ccce011ba5bb57682653ee01c9b7ce"
        hex"347ccaed9358f91d0b2ffd9204a2aa1f02e67b7d87e1b082cfced433fbe23c8c"
        hex"fbfe807ef329d7ecfa76a533f548b9d098e5068e65576e1c73e2c549bc848e22"
        hex"a05a2a5e18b0d61b13c43fe8175a5e91416ec5fe2a8940bfc7dabc837a279103"
        hex"a99c0b9e3d3371688ab8c6447bb1e4d3b59812bea3ca1fb9d1333988d6022dbb"
        hex"336d9bf07c54e5e3ff930b21d902e5bb0225bff19672c5f08a8bceae8f6c2e5d";

    function _msg() internal pure returns (bytes memory) {
        return bytes("hello citrate compute marketplace tee attestation 2026");
    }

    // ── Positive ────────────────────────────────────────────────────

    function test_verify_accepts_legitimate_signature() public view {
        bool ok = RS256.verify(_msg(), TEST_SIGNATURE, TEST_MODULUS, TEST_EXPONENT);
        assertTrue(ok, "legitimate RSA-2048 signature must verify");
    }

    function test_verify_digest_path_matches_message_path() public view {
        bytes32 digest = sha256(_msg());
        bool okDigest = RS256.verifyDigest(
            digest,
            TEST_SIGNATURE,
            TEST_MODULUS,
            TEST_EXPONENT
        );
        assertTrue(okDigest, "verifyDigest path must accept the same signature");
    }

    // ── Negative: tampering ─────────────────────────────────────────

    function test_verify_rejects_bit_flipped_signature() public view {
        bytes memory tampered = TEST_SIGNATURE;
        tampered[0] ^= 0x01;
        bool ok = RS256.verify(_msg(), tampered, TEST_MODULUS, TEST_EXPONENT);
        assertFalse(ok, "single-bit flip in signature must reject");
    }

    function test_verify_rejects_bit_flipped_message() public view {
        bytes memory msgTampered = _msg();
        msgTampered[0] ^= 0x01;
        bool ok = RS256.verify(msgTampered, TEST_SIGNATURE, TEST_MODULUS, TEST_EXPONENT);
        assertFalse(ok, "tampered message must reject");
    }

    function test_verify_rejects_wrong_modulus() public view {
        // Flip a bit in the modulus — the resulting EM won't have
        // valid PKCS#1 padding, so _emCheck returns false.
        bytes memory wrongMod = TEST_MODULUS;
        wrongMod[100] ^= 0x55;
        bool ok = RS256.verify(_msg(), TEST_SIGNATURE, wrongMod, TEST_EXPONENT);
        assertFalse(ok, "wrong modulus must reject");
    }

    function test_verify_rejects_wrong_exponent() public view {
        // Use a 3-byte exponent that's almost-but-not-quite e=65537.
        bytes memory wrongExp = hex"010002";
        bool ok = RS256.verify(_msg(), TEST_SIGNATURE, TEST_MODULUS, wrongExp);
        assertFalse(ok, "wrong exponent must reject");
    }

    // ── Input validation ────────────────────────────────────────────

    function test_verify_reverts_on_sig_modulus_length_mismatch() public {
        RS256Harness h = new RS256Harness();
        bytes memory shortSig = hex"deadbeef"; // 4 bytes vs 256-byte modulus
        vm.expectRevert("RS256: sig/mod len mismatch");
        h.verify(_msg(), shortSig, TEST_MODULUS, TEST_EXPONENT);
    }

    function test_verify_reverts_on_empty_signature() public {
        RS256Harness h = new RS256Harness();
        bytes memory empty;
        vm.expectRevert("RS256: empty sig");
        h.verify(_msg(), empty, TEST_MODULUS, TEST_EXPONENT);
    }

    function test_verify_reverts_on_empty_modulus() public {
        RS256Harness h = new RS256Harness();
        bytes memory empty;
        vm.expectRevert("RS256: empty modulus");
        h.verify(_msg(), TEST_SIGNATURE, empty, TEST_EXPONENT);
    }

    function test_verify_reverts_on_empty_exponent() public {
        RS256Harness h = new RS256Harness();
        bytes memory empty;
        vm.expectRevert("RS256: empty exponent");
        h.verify(_msg(), TEST_SIGNATURE, TEST_MODULUS, empty);
    }

    // ── Gas snapshot ────────────────────────────────────────────────

    function test_gas_snapshot_verify_2048_e65537() public {
        uint256 g0 = gasleft();
        bool ok = RS256.verify(_msg(), TEST_SIGNATURE, TEST_MODULUS, TEST_EXPONENT);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        // Document the per-verify gas; this is informational only,
        // not a regression gate. RSA-2048 with e=65537 typically
        // sits around 60-100k gas including modexp.
        emit log_named_uint("RS256.verify(2048) gas", used);
    }
}
