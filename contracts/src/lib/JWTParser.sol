// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title JWTParser — minimal on-chain JWT payload binding
/// @notice Pure-Solidity helpers for binding a strict-mode TEE
///         attestation to the actual content of an MAA JWT, not
///         just its signature.
///
///         Pre-RM-D3: `submitAttestationStrict` verified the RS256
///         signature but trusted the caller's `vmMeasurement` claim
///         — a worker holding ANY valid MAA JWT could substitute
///         a different on-chain measurement and the contract would
///         accept it. This library closes that gap by letting the
///         contract require that a specific claim string appears
///         inside the signed JWT payload.
///
///         RM-B1 / WP-D3.4 (audit SOL-05).
///
/// @dev Scope is deliberately minimal. We do NOT implement a full
///      JSON parser — instead we offer:
///        1. `extractPayload`: split `header.payload` at the `.`
///           and base64url-decode the payload to raw JSON bytes.
///        2. `containsClaim`: byte-level substring containment.
///
///      The caller-supplied claim bytes must be the EXACT bytes
///      as they appear in the JSON payload, including the field
///      name, the colon, and the surrounding quotes — e.g.
///      `"x-ms-runtime-vm-measurement":"0xabcd..."`. This is
///      sufficient for Azure MAA JWTs whose schema has no
///      attacker-controlled free-text fields that could embed
///      forged claim substrings (per ADR-010 §"MAA schema").
library JWTParser {
    /// @notice Split a signed JWT (`header.payload` form, no
    /// signature) at the dot separator and base64url-decode the
    /// payload portion. Returns the raw JSON bytes.
    /// @param signedJwt The bytes that were RS256-signed: the
    ///        concatenation of `base64url(header)`, `.`, and
    ///        `base64url(payload)` per RFC 7515.
    function extractPayload(bytes memory signedJwt)
        internal
        pure
        returns (bytes memory)
    {
        // Find the `.` separator. There must be exactly one in
        // a well-formed signed JWT (header.payload).
        uint256 dotIndex = 0;
        bool found = false;
        for (uint256 i = 0; i < signedJwt.length; i++) {
            if (signedJwt[i] == 0x2e /* '.' */) {
                require(!found, "JWTParser: malformed jwt: multiple dots");
                dotIndex = i;
                found = true;
            }
        }
        require(found, "JWTParser: malformed jwt: no dot separator");
        require(dotIndex + 1 < signedJwt.length, "JWTParser: empty payload");

        // Slice out the base64url(payload) bytes.
        uint256 payloadLen = signedJwt.length - dotIndex - 1;
        bytes memory b64Payload = new bytes(payloadLen);
        for (uint256 i = 0; i < payloadLen; i++) {
            b64Payload[i] = signedJwt[dotIndex + 1 + i];
        }
        return base64UrlDecode(b64Payload);
    }

    /// @notice Decode RFC 4648 §5 base64url (no padding) into raw
    /// bytes. Accepts the URL-safe alphabet `A-Z a-z 0-9 - _`.
    /// Reverts on any other character.
    function base64UrlDecode(bytes memory input)
        internal
        pure
        returns (bytes memory)
    {
        uint256 inLen = input.length;
        if (inLen == 0) return new bytes(0);

        // Compute output length: every 4 input chars → 3 output bytes.
        // For unpadded base64url:
        //   inLen % 4 == 2 → tailExtra = 1
        //   inLen % 4 == 3 → tailExtra = 2
        //   inLen % 4 == 0 → tailExtra = 0
        //   inLen % 4 == 1 → invalid (no single-char tail)
        uint256 tail = inLen % 4;
        require(tail != 1, "JWTParser: invalid base64url length");

        uint256 outLen = (inLen / 4) * 3;
        if (tail == 2) outLen += 1;
        else if (tail == 3) outLen += 2;

        bytes memory out = new bytes(outLen);
        uint256 j = 0;

        for (uint256 i = 0; i < inLen; i += 4) {
            uint256 chunk = inLen - i;
            // Decode each present char.
            uint8 a = _b64Char(uint8(input[i]));
            uint8 b = _b64Char(uint8(input[i + 1]));
            // First output byte uses 6 bits from a + top 2 of b.
            out[j++] = bytes1((a << 2) | (b >> 4));
            if (chunk >= 3) {
                uint8 c = _b64Char(uint8(input[i + 2]));
                out[j++] = bytes1(((b & 0x0F) << 4) | (c >> 2));
                if (chunk >= 4) {
                    uint8 d = _b64Char(uint8(input[i + 3]));
                    out[j++] = bytes1(((c & 0x03) << 6) | d);
                }
            }
        }

        return out;
    }

    /// @notice Map a single base64url character to its 6-bit value.
    function _b64Char(uint8 c) private pure returns (uint8) {
        if (c >= 0x41 && c <= 0x5A) return c - 0x41;        // 'A'-'Z' → 0-25
        if (c >= 0x61 && c <= 0x7A) return c - 0x61 + 26;   // 'a'-'z' → 26-51
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52;   // '0'-'9' → 52-61
        if (c == 0x2D) return 62;                           // '-'      → 62
        if (c == 0x5F) return 63;                           // '_'      → 63
        revert("JWTParser: invalid base64url char");
    }

    /// @notice Returns true iff `needle` appears as a contiguous
    /// substring of `haystack`.
    /// @dev O(n*m) naive search. Adequate for JWT payloads which are
    ///      a few hundred bytes; not suitable for large inputs.
    function containsClaim(bytes memory haystack, bytes memory needle)
        internal
        pure
        returns (bool)
    {
        uint256 nLen = needle.length;
        uint256 hLen = haystack.length;
        if (nLen == 0) return true;
        if (nLen > hLen) return false;

        for (uint256 i = 0; i <= hLen - nLen; i++) {
            bool match_ = true;
            for (uint256 j = 0; j < nLen; j++) {
                if (haystack[i + j] != needle[j]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) return true;
        }
        return false;
    }
}
