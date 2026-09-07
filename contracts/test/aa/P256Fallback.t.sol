// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {P256} from "../../src/aa/lib/webauthn/P256.sol";

/// Exposes the internal P256 helpers so a test can call them.
contract P256Harness {
    function verifyAllowMalleability(bytes32 h, uint256 r, uint256 s, uint256 x, uint256 y)
        external
        view
        returns (bool)
    {
        return P256.verifySignatureAllowMalleability(h, r, s, x, y);
    }

    function verify(bytes32 h, uint256 r, uint256 s, uint256 x, uint256 y) external view returns (bool) {
        return P256.verifySignature(h, r, s, x, y);
    }

    function verifierAddr() external pure returns (address) {
        return P256.VERIFIER;
    }
}

/// CHAIN-B-C031 (audit 2026-09-02): the P-256 verifier is a hardcoded external
/// address with no deployment in this repo, and the call site did
/// `assert(success); abi.decode(ret, (uint256))`. A `staticcall` to a codeless
/// address returns `success == true` with EMPTY returndata, so the decode
/// reverted — freezing every wallet whose root validator is the passkey
/// validator, inside the EntryPoint validation phase. The fix fails CLOSED
/// (returns false) instead of reverting.
contract P256FallbackTest is Test {
    P256Harness internal h;

    function setUp() public {
        h = new P256Harness();
    }

    /// RED (pre-fix): with the verifier absent this reverted (empty-returndata
    /// decode). GREEN: it returns false without reverting.
    function test_C031_absent_verifier_fails_closed() public {
        // Precondition: the verifier address is codeless in this environment
        // (the whole point of the finding — it is not deployed).
        assertEq(h.verifierAddr().code.length, 0, "precondition: verifier absent");

        bool ok = h.verifyAllowMalleability(bytes32(uint256(1)), 1, 1, 1, 1);
        assertFalse(ok, "absent verifier must fail closed, not revert");

        // The malleability-checked wrapper must also fail closed (low-s input).
        bool ok2 = h.verify(bytes32(uint256(1)), 1, 1, 1, 1);
        assertFalse(ok2, "verifySignature must also fail closed");
    }

    /// GREEN: when a verifier IS present and returns 1, it still succeeds — the
    /// fallback only prevents the freeze, it does not break the happy path.
    function test_C031_present_verifier_returning_one_succeeds() public {
        // Etch a stub at the verifier address that returns abi.encode(1).
        vm.etch(h.verifierAddr(), type(AlwaysOneVerifier).runtimeCode);
        bool ok = h.verifyAllowMalleability(bytes32(uint256(1)), 1, 1, 1, 1);
        assertTrue(ok, "a present verifier returning 1 must succeed");
    }

    /// GREEN: a present verifier returning malformed (short) data still fails
    /// closed rather than reverting.
    function test_C031_present_verifier_short_return_fails_closed() public {
        vm.etch(h.verifierAddr(), type(ShortReturnVerifier).runtimeCode);
        bool ok = h.verifyAllowMalleability(bytes32(uint256(1)), 1, 1, 1, 1);
        assertFalse(ok, "short returndata must fail closed");
    }
}

contract AlwaysOneVerifier {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

contract ShortReturnVerifier {
    fallback(bytes calldata) external returns (bytes memory) {
        return hex"01"; // 1 byte, not 32
    }
}
