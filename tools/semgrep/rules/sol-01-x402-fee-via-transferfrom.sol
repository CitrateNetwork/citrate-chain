// SOL-01 / RFI-01 — fixture for tools/semgrep/rules/sol-01-x402-fee-via-transferfrom.yaml
//
// Run via:
//   semgrep --config sol-01-x402-fee-via-transferfrom.yaml \
//           sol-01-x402-fee-via-transferfrom.sol
//
// Both `ruleid:` markers must produce findings; both `ok:` markers
// must not. The path-include filter in the rule normally limits
// matching to `contracts/src/X402Facilitator.sol` and the typehash
// rules to `contracts/src/**/*.sol`. For this fixture we run the
// rules with `--config` directly so the include filter is bypassed.
//
// This file is NOT compiled. It is fixture data only.

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transferWithFeeAuthorization(
        address from, address to, address treasury, uint256 value, uint256 fee,
        uint256 validAfter, uint256 validBefore, bytes32 nonce,
        uint8 v, bytes32 r, bytes32 s
    ) external;
}

contract Bad {
    IToken public token;
    address public treasury;

    // ============================================================
    // POSITIVES — these patterns must be flagged
    // ============================================================

    /// SOL-01: pre-fix shape — fee-leg via `transferFrom` to treasury.
    function settle_bad(address from, uint256 fee) external {
        // ruleid: sol-01-x402-fee-via-transferfrom
        token.transferFrom(from, treasury, fee);
    }

    /// RFI-01: typehash for fee-bearing auth omits BOTH treasury and fee.
    // ruleid: rfi-01-fee-auth-typehash-missing-treasury-or-fee
    bytes32 public constant TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH_BAD =
        keccak256("TransferWithFeeAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /// RFI-01: typehash binds treasury but NOT fee.
    // ruleid: rfi-01-fee-auth-typehash-missing-fee
    bytes32 public constant FEE_AUTHORIZATION_TYPEHASH_NO_FEE =
        keccak256("FeeAuthorization(address from,address to,uint256 value,address treasury,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
}

contract Good {
    IToken public token;
    address public treasury;

    // ============================================================
    // NEGATIVES — these patterns must NOT be flagged
    // ============================================================

    /// SOL-01 closure: fee-leg consumed via single signed authorization.
    /// No `transferFrom` call to treasury.
    // ok: sol-01-x402-fee-via-transferfrom
    function settle_good(
        address from, address to, uint256 value, uint256 fee,
        uint256 validAfter, uint256 validBefore, bytes32 nonce,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        token.transferWithFeeAuthorization(
            from, to, treasury, value, fee, validAfter, validBefore, nonce, v, r, s
        );
    }

    /// RFI-01 closure: typehash binds BOTH treasury AND fee.
    // ok: rfi-01-fee-auth-typehash-missing-treasury-or-fee
    // ok: rfi-01-fee-auth-typehash-missing-fee
    bytes32 public constant TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithFeeAuthorization(address from,address to,uint256 value,address treasury,uint256 fee,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /// Legacy authorization (no fee) — out of scope of the RFI-01 rule
    /// because its typehash NAME doesn't contain `FEE_AUTH`. This is
    /// the existing legacy `transferWithAuthorization` typehash.
    // ok: rfi-01-fee-auth-typehash-missing-treasury-or-fee
    // ok: rfi-01-fee-auth-typehash-missing-fee
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
}
