// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title RS256 — RSA-PKCS#1 v1.5 + SHA-256 signature verification
/// @notice Pure-Solidity RSASSA-PKCS1-v1_5 verify per RFC 8017,
///         using the EVM `modexp` precompile (0x05) for the
///         `sig^e mod N` operation. Designed to verify Azure
///         Microsoft Attestation (MAA) JWTs in
///         `TEEAttestationRegistry.submitAttestationStrictBound`.
///
/// @dev Gas cost per verify (RSA-2048): ~70-100k including modexp
///      (depends on exponent size; e=65537 is standard and cheap).
///      Tested against fixtures generated with Node.js `crypto`
///      and OpenSSL.
library RS256 {
    /// @notice DigestInfo prefix for SHA-256 per RFC 8017 § 9.2.
    /// Encoded as a fixed 19-byte ASN.1 SEQUENCE:
    ///   30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    /// followed by the 32-byte SHA-256 digest.
    bytes19 internal constant SHA256_DIGEST_INFO_PREFIX =
        0x3031300d060960864801650304020105000420;

    /// @notice Verify an RSASSA-PKCS1-v1_5 signature with SHA-256.
    /// @param message The original message (will be SHA-256'd here)
    /// @param signature The raw signature bytes (length == |modulus|)
    /// @param modulus  RSA modulus N (big-endian bytes)
    /// @param exponent RSA public exponent e (big-endian bytes)
    /// @return True iff signature verifies under (modulus, exponent).
    ///
    /// Reverts on malformed inputs (zero-length signature/modulus).
    /// Returns false on cryptographic mismatch (does NOT revert) so
    /// callers can distinguish "bad input" from "valid input, wrong
    /// signature".
    function verify(
        bytes memory message,
        bytes memory signature,
        bytes memory modulus,
        bytes memory exponent
    ) internal view returns (bool) {
        require(signature.length > 0, "RS256: empty sig");
        require(modulus.length > 0, "RS256: empty modulus");
        require(exponent.length > 0, "RS256: empty exponent");
        require(signature.length == modulus.length, "RS256: sig/mod len mismatch");

        // EM = sig^e mod N
        bytes memory em = _modexp(signature, exponent, modulus);
        if (em.length != modulus.length) {
            return false;
        }

        return _emCheck(em, sha256(message));
    }

    /// @notice Verify an already-hashed message. Useful when the
    /// caller has already computed SHA-256 (e.g. JWT header.payload
    /// hashed once, used both for verify and for storing as
    /// `vmMeasurement`).
    function verifyDigest(
        bytes32 digest,
        bytes memory signature,
        bytes memory modulus,
        bytes memory exponent
    ) internal view returns (bool) {
        require(signature.length > 0, "RS256: empty sig");
        require(modulus.length > 0, "RS256: empty modulus");
        require(exponent.length > 0, "RS256: empty exponent");
        require(signature.length == modulus.length, "RS256: sig/mod len mismatch");

        bytes memory em = _modexp(signature, exponent, modulus);
        if (em.length != modulus.length) {
            return false;
        }
        return _emCheck(em, digest);
    }

    // ── Internal: PKCS#1 v1.5 EM check ──────────────────────────────

    /// @dev EM = 0x00 || 0x01 || PS || 0x00 || T
    /// where T = DigestInfo || hash, length 51 bytes for SHA-256
    /// and PS is at least 8 bytes of 0xFF padding. EM has total
    /// length k = |modulus|.
    function _emCheck(bytes memory em, bytes32 hash) private pure returns (bool) {
        // Minimum length: 0x00 0x01 [8x 0xFF] 0x00 [51-byte T] = 62 bytes
        if (em.length < 62) return false;

        // First two bytes MUST be 0x00 0x01.
        if (em[0] != 0x00 || em[1] != 0x01) return false;

        // PS: 0xFF bytes from index 2 until we hit a 0x00 separator.
        // PS length must be >= 8.
        uint256 i = 2;
        uint256 emLen = em.length;
        while (i < emLen && em[i] == 0xFF) {
            unchecked {
                ++i;
            }
        }
        if (i - 2 < 8) return false; // PS too short
        if (i >= emLen || em[i] != 0x00) return false; // no 0x00 separator
        unchecked {
            ++i;
        }

        // Remaining bytes (T) must equal SHA256_DIGEST_INFO_PREFIX || hash.
        // T length is exactly 19 + 32 = 51.
        if (emLen - i != 51) return false;

        // Compare 19-byte DigestInfo prefix.
        bytes19 prefix = SHA256_DIGEST_INFO_PREFIX;
        for (uint256 j = 0; j < 19; ++j) {
            if (em[i + j] != prefix[j]) return false;
        }

        // Compare 32-byte hash.
        for (uint256 j = 0; j < 32; ++j) {
            if (em[i + 19 + j] != hash[j]) return false;
        }

        return true;
    }

    // ── Internal: modexp precompile wrapper ─────────────────────────

    /// @dev Calls the modexp precompile at address 0x05.
    /// Input layout: lenB(32) | lenE(32) | lenM(32) | B | E | M
    /// Output: M-length bytes containing (B^E mod M).
    function _modexp(
        bytes memory base,
        bytes memory exp,
        bytes memory mod_
    ) private view returns (bytes memory result) {
        uint256 baseLen = base.length;
        uint256 expLen = exp.length;
        uint256 modLen = mod_.length;
        result = new bytes(modLen);

        // Build the precompile input. We need a contiguous buffer:
        //   [32 bytes baseLen][32 bytes expLen][32 bytes modLen][base][exp][mod]
        bytes memory input = new bytes(96 + baseLen + expLen + modLen);

        assembly ("memory-safe") {
            // Write the three length headers (big-endian uint256).
            mstore(add(input, 32), baseLen)
            mstore(add(input, 64), expLen)
            mstore(add(input, 96), modLen)
        }

        // Copy base, exp, mod_ into input. Use a simple loop —
        // bytes-copy via mcopy / mstore in assembly would be faster
        // but the loop is simpler to audit and gas isn't critical
        // here (modexp itself dominates).
        uint256 dst;
        assembly ("memory-safe") {
            dst := add(input, 128)
        }
        _memcpy(dst, base);
        dst += baseLen;
        _memcpy(dst, exp);
        dst += expLen;
        _memcpy(dst, mod_);

        bool ok;
        assembly ("memory-safe") {
            // staticcall(gas, address, input, inSize, output, outSize)
            ok := staticcall(
                gas(),
                0x05,
                add(input, 32),
                mload(input),
                add(result, 32),
                modLen
            )
        }
        require(ok, "RS256: modexp failed");
    }

    /// @dev Copy `src.length` bytes from src's data area to memory
    /// position `dst`. Caller is responsible for ensuring `dst` has
    /// at least src.length bytes of allocated space.
    ///
    /// RM-B1 / WP-D3.4 (audit SOL-04): pre-fix this function used a
    /// manual word-by-word copy with a tail-byte mask. The mask
    /// branch was *currently* correct but fragile — it relied on
    /// masking-out OOB reads from `mload(srcPtr+i)` past the source's
    /// data, where `bytes memory` is padded but not zero-filled. A
    /// future contributor flipping the mask direction would silently
    /// corrupt the modulus and either DoS all signatures or, worse,
    /// accept different keys. Post-fix uses Cancun's `mcopy` opcode,
    /// which is the canonical EVM memory-copy primitive and correct
    /// by construction for any length.
    function _memcpy(uint256 dst, bytes memory src) private pure {
        uint256 len = src.length;
        assembly ("memory-safe") {
            // src points at the length word; data starts at src+32.
            mcopy(dst, add(src, 32), len)
        }
    }
}
