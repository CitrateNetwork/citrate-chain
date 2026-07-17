// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/utils/Strings.sol";

/// @title MemberEmblem — on-chain deterministic membership emblem (WS-2)
///
/// EXACT on-chain port of citrate-core's canonical art algorithm
/// (`citrate-core/src/identity/sbtArt.ts`). The emblem is a deterministic,
/// identicon-style geometric mark seeded purely from the member's wallet
/// address, so the emblem an explorer renders from `tokenURI()` is
/// byte-for-byte identical (same seed, same shapes, same palette, same layout)
/// to the one citrate-core renders in-app from `sbtArtSpec(walletAddr)`.
///
/// Seed parity: the app seeds from the wallet-address STRING
/// (`SbtArt seed={walletAddr}`), and `hashSeed` lowercases it. On-chain we
/// seed from `Strings.toHexString(wallet)` — the lowercase, 0x-prefixed,
/// 40-hex-digit form — which is exactly that same string. No IPFS, no external
/// image, no placeholder (Rule 1): the image is generated wholly on-chain.
///
/// Float-free port of the JS RNG comparisons: sbtArt.ts compares
/// `rng() < c` where `rng()` returns `u / 2^32` for a uint32 `u`. Because
/// `u / 2^32` is an EXACT IEEE-754 double (division by a power of two) and `c`
/// is a compile-time double, `rng() < c` is exactly `u < ceil(c * 2^32)`. The
/// two thresholds below are `ceil(0.55 * 2^32)` and `ceil(0.62 * 2^32)`; a
/// harness (`golden.mjs`) verified they reproduce every boolean decision of the
/// reference RNG with zero mismatches.
library MemberEmblem {
    using Strings for uint256;

    /// Board is GRID×GRID; only the left HALF columns are generated and
    /// mirrored to the right (matches sbtArt.ts GRID=5, HALF=ceil(5/2)=3).
    uint256 internal constant GRID = 5;
    uint256 internal constant HALF = 3;

    /// Pixel square of the emblem `<svg>` (cosmetic; the art lives in the
    /// 0 0 5 5 viewBox and is size-independent, so parity with the app — which
    /// varies `size` at render time — holds regardless of this value).
    uint256 internal constant SIZE = 320;

    /// FNV-1a 32-bit parameters (sbtArt.ts hashSeed).
    uint32 internal constant FNV_OFFSET = 0x811c9dc5;
    uint32 internal constant FNV_PRIME = 0x01000193;

    /// rng() < 0.55  <=>  u < ceil(0.55 * 2^32) = 2362232013.
    uint32 internal constant THRESH_055 = 2362232013;
    /// rng() < 0.62  <=>  u < ceil(0.62 * 2^32) = 2662879724.
    uint32 internal constant THRESH_062 = 2662879724;

    /// FNV-1a 32-bit hash of the (already-lowercase) seed bytes. Matches
    /// sbtArt.ts `hashSeed` (charCodeAt == byte for the ASCII hex address).
    function hashSeed(string memory seed) internal pure returns (uint32 h) {
        bytes memory b = bytes(seed);
        h = FNV_OFFSET;
        unchecked {
            for (uint256 i = 0; i < b.length; i++) {
                h ^= uint32(uint8(b[i]));
                h = h * FNV_PRIME; // uint32 wraps mod 2^32 (== Math.imul >>> 0)
            }
        }
    }

    /// One step of the mulberry32 PRNG. Returns the advanced state and the
    /// uint32 `u` (sbtArt.ts returns `u / 2^32`; we keep `u` for exact
    /// integer-threshold comparisons). All ops are uint32 and wrap mod 2^32,
    /// matching JS `| 0` / `Math.imul` / `>>>` semantics bit-for-bit.
    function _next(uint32 a) private pure returns (uint32 newA, uint32 u) {
        unchecked {
            a = a + 0x6d2b79f5;
            uint32 t = (a ^ (a >> 15)) * (1 | a);
            t = ((t + ((t ^ (t >> 7)) * (61 | t)))) ^ t;
            u = t ^ (t >> 14);
            newA = a;
        }
    }

    /// The 8 curated palettes (bg, a, b), verbatim from sbtArt.ts PALETTES.
    function _palette(uint256 i)
        private
        pure
        returns (string memory bg, string memory a, string memory b)
    {
        if (i == 0) return ("#0e1a13", "#8ecc09", "#4f8a05");
        if (i == 1) return ("#0e1a13", "#5a8205", "#b9c6bd");
        if (i == 2) return ("#101c22", "#8ecc09", "#3f8fb0");
        if (i == 3) return ("#0f1622", "#6fb0e0", "#1b4965");
        if (i == 4) return ("#1a140e", "#e0a83f", "#b07b00");
        if (i == 5) return ("#141021", "#a98fe0", "#6f5ab0");
        if (i == 6) return ("#0e1a13", "#8ecc09", "#e0a83f");
        return ("#111", "#b9c6bd", "#5a8205"); // i == 7
    }

    /// The palette index a seed selects (`Math.floor(rng()*8) % 8` == u >> 29).
    function paletteIndex(address wallet) internal pure returns (uint256) {
        (, uint32 u) = _next(hashSeed(Strings.toHexString(wallet)));
        return uint256(u >> 29);
    }

    /// Render the deterministic SVG for a wallet address, byte-identical to
    /// sbtArt.ts `sbtArtSvg(walletAddr, SIZE)`. Also returns the palette index
    /// (for tokenURI attributes) so callers need not recompute.
    function render(address wallet)
        internal
        pure
        returns (string memory svg, uint256 palIdx)
    {
        uint32 a = hashSeed(Strings.toHexString(wallet));
        uint32 u;

        // Call 1: palette selection.
        (a, u) = _next(a);
        palIdx = uint256(u >> 29);
        (string memory bg, string memory pa, string memory pb) = _palette(palIdx);

        // Body: left HALF columns, mirrored to the right (sbtArt.ts order:
        // for each filled (c,r) push (c,r) then the mirror column).
        bytes memory rects;
        for (uint256 c = 0; c < HALF; c++) {
            for (uint256 r = 0; r < GRID; r++) {
                (a, u) = _next(a);
                if (u < THRESH_055) {
                    (a, u) = _next(a);
                    string memory color = u < THRESH_062 ? pa : pb;
                    rects = abi.encodePacked(rects, _rect(c, r, color));
                    uint256 mc = GRID - 1 - c;
                    if (mc != c) {
                        rects = abi.encodePacked(rects, _rect(mc, r, color));
                    }
                }
            }
        }

        svg = string(
            abi.encodePacked(
                '<svg xmlns="http://www.w3.org/2000/svg" width="',
                SIZE.toString(),
                '" height="',
                SIZE.toString(),
                '" viewBox="0 0 ',
                GRID.toString(),
                " ",
                GRID.toString(),
                '" shape-rendering="geometricPrecision" role="img"><rect width="',
                GRID.toString(),
                '" height="',
                GRID.toString(),
                '" fill="',
                bg,
                '"/>',
                rects,
                "</svg>"
            )
        );
    }

    /// One `<rect>` cell, matching sbtArt.ts exactly (rx=0.14, 1×1 unit cell).
    function _rect(uint256 c, uint256 r, string memory color)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            '<rect x="',
            c.toString(),
            '" y="',
            r.toString(),
            '" width="1" height="1" rx="0.14" fill="',
            color,
            '"/>'
        );
    }
}
