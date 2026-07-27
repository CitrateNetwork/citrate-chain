// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title QuorumIdentity — the one way an address becomes a subject key
/// @notice citrate-quorum QRM-S6.
///
/// `ClassificationRegistry`, `RoleEscalation`, `MultiSigEnvelope` and
/// `ContradictionLedger` all key people by `bytes32`, never by address. Turning
/// an address into that key is the same computation every time, and it is the
/// highest-consequence line in any contract that does it:
///
/// **If a contract derives this differently from citrate-quorum, nothing
/// reverts.** It reads a different subject's record, finds nothing, and gets
/// whatever the source's default is — `Public` clearance, no elevation, no open
/// contradiction. Every one of those defaults is permissive. A fail-open wearing
/// a default's clothing.
///
/// So there is exactly one implementation, here, and every quorum contract calls
/// it rather than carrying its own copy. It reproduces
/// `citrate-quorum/src-tauri/src/chain.rs::clearance_subject`: `keccak256` of the
/// **lowercase, `0x`-prefixed hex string** — not of the 20 address bytes.
///
/// Pinned by `ClassificationGate.t.sol::test_subjectKeyMatchesQuorumsDerivation`
/// against a literal that citrate-quorum's
/// `chain::tests::clearance_subject_matches_the_on_chain_vector` also asserts.
/// Two repositories, one number.
library QuorumIdentity {
    /// The subject key for an address.
    function subjectKey(address who) internal pure returns (bytes32) {
        bytes16 digits = "0123456789abcdef";
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        uint160 v = uint160(who);
        for (uint256 i = 0; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            s[2 + i * 2] = digits[b >> 4];
            s[3 + i * 2] = digits[b & 0x0f];
        }
        return keccak256(s);
    }
}
