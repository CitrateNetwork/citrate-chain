// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {JWTParser} from "../src/lib/JWTParser.sol";

/// @title JWTParserTest — RM-D3 WP-D3.4 (audit SOL-05) acceptance
/// @notice Unit tests for the on-chain JWT payload binding helpers.
contract JWTParserTest is Test {
    // ── base64UrlDecode round-trips ─────────────────────────────────

    /// "Hello world!" → "SGVsbG8gd29ybGQh" (no padding)
    function test_b64_basic_round_trip_no_padding() public pure {
        bytes memory enc = bytes("SGVsbG8gd29ybGQh");
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        // ASCII bytes
        bytes memory expected = bytes("Hello world!");
        assertEq(keccak256(dec), keccak256(expected));
    }

    /// "Hello" → "SGVsbG8" (5 bytes → 7 chars unpadded, tail = 3)
    function test_b64_tail_three_chars() public pure {
        bytes memory enc = bytes("SGVsbG8");
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        bytes memory expected = bytes("Hello");
        assertEq(keccak256(dec), keccak256(expected));
    }

    /// "Hi" → "SGk" (2 bytes → 3 chars, tail = 3 — wait, 2 bytes = 16 bits = ceil(16/6) = 3 chars; that's tail=3)
    function test_b64_tail_three_two_bytes() public pure {
        bytes memory enc = bytes("SGk");
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        bytes memory expected = bytes("Hi");
        assertEq(keccak256(dec), keccak256(expected));
    }

    /// "H" → "SA" (1 byte → 2 chars, tail = 2)
    function test_b64_tail_two_one_byte() public pure {
        bytes memory enc = bytes("SA");
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        bytes memory expected = bytes("H");
        assertEq(keccak256(dec), keccak256(expected));
    }

    /// URL-safe alphabet uses '-' and '_' instead of '+' and '/'.
    /// 0xFB 0xFF 0xFE → in standard base64: "+//+", in url-safe: "-__-"
    function test_b64_url_safe_alphabet() public pure {
        bytes memory enc = bytes("-__-");
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        assertEq(dec.length, 3);
        assertEq(uint8(dec[0]), 0xFB);
        assertEq(uint8(dec[1]), 0xFF);
        assertEq(uint8(dec[2]), 0xFE);
    }

    function test_b64_rejects_invalid_char() public {
        // 8 chars (length valid), one is '+' which belongs to the
        // STANDARD base64 alphabet but NOT base64url (which uses '-').
        bytes memory enc = bytes("SGVs+G8h");
        vm.expectRevert("JWTParser: invalid base64url char");
        this.b64DecodeExternal(enc);
    }

    function test_b64_rejects_invalid_tail_length() public {
        // 5 chars → tail = 1, which is invalid for unpadded base64url
        bytes memory enc = bytes("SGVsb");
        vm.expectRevert("JWTParser: invalid base64url length");
        this.b64DecodeExternal(enc);
    }

    function test_b64_empty_input_returns_empty() public pure {
        bytes memory enc = new bytes(0);
        bytes memory dec = JWTParser.base64UrlDecode(enc);
        assertEq(dec.length, 0);
    }

    // External wrapper so vm.expectRevert can catch library reverts.
    function b64DecodeExternal(bytes memory input) external pure returns (bytes memory) {
        return JWTParser.base64UrlDecode(input);
    }

    function extractPayloadExternal(bytes memory input) external pure returns (bytes memory) {
        return JWTParser.extractPayload(input);
    }

    // ── extractPayload ──────────────────────────────────────────────

    /// header = `{"typ":"JWT"}` → b64url `eyJ0eXAiOiJKV1QifQ`
    /// payload = `{"x":1}` → b64url `eyJ4IjoxfQ`
    function test_extract_payload_round_trip() public pure {
        bytes memory signed = bytes("eyJ0eXAiOiJKV1QifQ.eyJ4IjoxfQ");
        bytes memory decoded = JWTParser.extractPayload(signed);
        assertEq(keccak256(decoded), keccak256(bytes('{"x":1}')));
    }

    function test_extract_payload_rejects_no_dot() public {
        bytes memory bad = bytes("eyJ0eXAiOiJKV1QifQ");
        vm.expectRevert("JWTParser: malformed jwt: no dot separator");
        this.extractPayloadExternal(bad);
    }

    function test_extract_payload_rejects_multiple_dots() public {
        bytes memory bad = bytes("a.b.c");
        vm.expectRevert("JWTParser: malformed jwt: multiple dots");
        this.extractPayloadExternal(bad);
    }

    function test_extract_payload_rejects_empty_payload() public {
        bytes memory bad = bytes("eyJ0eXAiOiJKV1QifQ.");
        vm.expectRevert("JWTParser: empty payload");
        this.extractPayloadExternal(bad);
    }

    // ── containsClaim ───────────────────────────────────────────────

    function test_contains_claim_finds_substring() public pure {
        bytes memory hay = bytes('{"a":1,"x-ms-vm":"0xabc","b":2}');
        bytes memory needle = bytes('"x-ms-vm":"0xabc"');
        assertTrue(JWTParser.containsClaim(hay, needle));
    }

    function test_contains_claim_returns_false_when_absent() public pure {
        bytes memory hay = bytes('{"a":1,"y":2}');
        bytes memory needle = bytes('"x-ms-vm":"0xabc"');
        assertFalse(JWTParser.containsClaim(hay, needle));
    }

    function test_contains_claim_empty_needle_is_present() public pure {
        bytes memory hay = bytes("anything");
        bytes memory needle = new bytes(0);
        assertTrue(JWTParser.containsClaim(hay, needle));
    }

    function test_contains_claim_empty_haystack_rejects_nonempty_needle() public pure {
        bytes memory hay = new bytes(0);
        bytes memory needle = bytes("x");
        assertFalse(JWTParser.containsClaim(hay, needle));
    }

    function test_contains_claim_finds_at_start_and_end() public pure {
        bytes memory hay = bytes("ABCDEFGH");
        assertTrue(JWTParser.containsClaim(hay, bytes("ABC")), "start match");
        assertTrue(JWTParser.containsClaim(hay, bytes("FGH")), "end match");
        assertTrue(JWTParser.containsClaim(hay, bytes("ABCDEFGH")), "full match");
    }

    function test_contains_claim_partial_overlap_is_not_match() public pure {
        bytes memory hay = bytes("ABCDABCE");
        // "ABCE" appears once at the end — the prefix "ABCD" doesn't satisfy.
        assertTrue(JWTParser.containsClaim(hay, bytes("ABCE")));
        // "ABCF" doesn't appear at all.
        assertFalse(JWTParser.containsClaim(hay, bytes("ABCF")));
    }
}
