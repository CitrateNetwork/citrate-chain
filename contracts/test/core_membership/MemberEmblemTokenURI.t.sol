// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import "../../src/core_membership/CitrateMemberSBT.sol";
import "../../src/core_membership/MemberEmblem.sol";

/// WS-2 golden-vector test: proves the on-chain emblem (MemberEmblem, embedded
/// in tokenURI) is a byte-for-byte port of citrate-core's `sbtArt.ts`.
///
/// GROUND TRUTH: `GOLDEN_SVG` below is emitted by running the ACTUAL pure
/// functions of `citrate-core/src/identity/sbtArt.ts` in node
/// (`scratchpad/golden.mjs`) for the seed `ADDR_A` — which is one of
/// sbtArt.ts's OWN determinism-test addresses
/// (`0x9858effd232b4033e47d90003d41ec34ecaeda94`). If the on-chain algorithm
/// ever drifts from sbtArt.ts (seed derivation, RNG, thresholds, palette,
/// cell order, or SVG layout) the keccak of the rendered SVG stops matching
/// this literal and the test fails — so in-app emblem == explorer emblem is
/// enforced in CI.
contract MemberEmblemTokenURITest is Test {
    CitrateMemberSBT internal sbt;

    // sbtArt.ts test vector (ADDR_A). The member wallet (token owner) is the seed.
    address internal constant ADDR_A = 0x9858EfFD232B4033E47d90003D41EC34EcaEda94;

    bytes32 internal constant SUB = keccak256("auth.citrate.ai|sub|golden");
    uint64 internal constant TERM_START = 1_700_000_000;
    uint64 internal constant TERM_END = 1_800_000_000;

    // Palette index 4 (amber) for ADDR_A — from sbtArt.ts (golden.mjs output).
    uint256 internal constant GOLDEN_PALETTE = 4;

    // Byte-exact SVG that sbtArt.ts `sbtArtSvg(ADDR_A, 320)` produces.
    string internal constant GOLDEN_SVG =
        '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="320" viewBox="0 0 5 5" shape-rendering="geometricPrecision" role="img"><rect width="5" height="5" fill="#1a140e"/><rect x="0" y="1" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="4" y="1" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="0" y="2" width="1" height="1" rx="0.14" fill="#b07b00"/><rect x="4" y="2" width="1" height="1" rx="0.14" fill="#b07b00"/><rect x="1" y="0" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="3" y="0" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="1" y="1" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="3" y="1" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="1" y="3" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="3" y="3" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="1" y="4" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="3" y="4" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="2" y="0" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="2" y="1" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="2" y="2" width="1" height="1" rx="0.14" fill="#e0a83f"/><rect x="2" y="4" width="1" height="1" rx="0.14" fill="#e0a83f"/></svg>';

    function setUp() public {
        sbt = new CitrateMemberSBT(address(this));
    }

    /// The core parity assertion: the on-chain SVG for ADDR_A is byte-identical
    /// to sbtArt.ts's output, and the palette index matches.
    function testEmblem_matchesSbtArtGoldenVector() public pure {
        (string memory svg, uint256 palIdx) = MemberEmblem.render(ADDR_A);
        assertEq(palIdx, GOLDEN_PALETTE, "palette index drift vs sbtArt.ts");
        assertEq(
            keccak256(bytes(svg)),
            keccak256(bytes(GOLDEN_SVG)),
            "on-chain SVG drifted from sbtArt.ts golden vector"
        );
    }

    /// hashSeed parity: FNV-1a of the lowercase wallet-address string.
    /// sbtArt.ts hashSeed("0x9858...eda94") == 3479862797 (golden.mjs).
    function testEmblem_hashSeedMatchesReference() public pure {
        uint32 h = MemberEmblem.hashSeed(Strings.toHexString(ADDR_A));
        assertEq(uint256(h), 3479862797, "FNV-1a seed hash drift");
    }

    /// The full tokenURI is a valid, non-empty data:json embedding the golden
    /// emblem as a base64 SVG data-URI (Rule 1: real on-chain image, no
    /// placeholder). Reconstructs the expected document from the INDEPENDENT
    /// golden SVG literal, so a drift in the embedded art fails here too.
    function testTokenURI_isGoldenDataJson() public {
        uint256 id = sbt.mintMember(ADDR_A, SUB, TERM_START, TERM_END);

        string memory uri = sbt.tokenURI(id);
        assertGt(bytes(uri).length, 0, "tokenURI must be non-empty");
        assertTrue(_startsWith(uri, "data:application/json;base64,"), "not a data:json URI");

        string memory expJson = string(
            abi.encodePacked(
                '{"name":"Citrate MemberSBT #0","description":"Soulbound Citrate membership token. The emblem is generated deterministically on-chain from the member wallet address (no IPFS, no external image) and matches the in-app identity mark.","image":"data:image/svg+xml;base64,',
                Base64.encode(bytes(GOLDEN_SVG)),
                '","attributes":[',
                '{"trait_type":"Wallet","value":"',
                Strings.toHexString(ADDR_A),
                '"},{"trait_type":"Sub Hash","value":"',
                Strings.toHexString(uint256(SUB), 32),
                '"},{"trait_type":"Term Start","display_type":"date","value":',
                Strings.toString(uint256(TERM_START)),
                '},{"trait_type":"Term End","display_type":"date","value":',
                Strings.toString(uint256(TERM_END)),
                '},{"trait_type":"Palette","value":"4"}',
                "]}"
            )
        );
        string memory expected = string(
            abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(expJson)))
        );
        assertEq(uri, expected, "tokenURI drifted from golden data:json");
    }

    /// No empty/placeholder URI path: tokenURI reverts for unminted tokens.
    function testTokenURI_revertsForUnminted() public {
        vm.expectRevert();
        sbt.tokenURI(123);
    }

    /// tokenURI reverts for burned (revoked) tokens — never a placeholder.
    function testTokenURI_revertsAfterRevoke() public {
        uint256 id = sbt.mintMember(ADDR_A, SUB, TERM_START, TERM_END);
        sbt.revoke(id);
        vm.expectRevert();
        sbt.tokenURI(id);
    }

    function _startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory sb = bytes(s);
        bytes memory pb = bytes(prefix);
        if (sb.length < pb.length) return false;
        for (uint256 i = 0; i < pb.length; i++) {
            if (sb[i] != pb[i]) return false;
        }
        return true;
    }
}
