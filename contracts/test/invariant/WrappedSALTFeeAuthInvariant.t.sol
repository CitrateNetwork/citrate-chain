// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// RFI-01 / WP-H1.1 — Front-run fee redirect must be blocked.
//
// Finding: `.audit/2026-04-25-reaudit/06_FINDINGS_SOLIDITY_CONTRACTS.md#rfi-01`
//
// The SOL-01 closure introduced `transferWithFeeAuthorization` whose
// signed digest covered only `(from, to, value, validAfter, validBefore,
// nonce)` — `treasury` and `fee` were caller-supplied parameters NOT
// bound to the EIP-712 typehash. A mempool watcher could intercept any
// in-flight x402 authorization, call `transferWithFeeAuthorization`
// directly with `treasury = attacker, fee = value`, and redirect the
// entire payment.
//
// This file asserts that:
//   (a) `test_rfi01_front_run_fee_redirect_blocked` — a signature minted
//       under the legacy `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` cannot
//       be replayed against `transferWithFeeAuthorization`. The call
//       MUST revert with `InvalidFeeAuthorization()`.
//   (b) `Invariant_FrontRunFeeRedirectFails` — fuzz-driven: for any
//       attacker-chosen `(treasury, fee)` not present in the signed
//       digest, the call reverts and balances do not change.

import "forge-std/Test.sol";
import "../../src/WrappedSALT.sol";

contract WrappedSALTFeeAuthInvariant is Test {
    WrappedSALT public wSALT;

    address public alice;
    uint256 public alicePk;
    address public bob;
    address public attacker;
    address public legitimateTreasury;

    // Legacy typehash — what the buggy implementation accepts.
    bytes32 internal constant LEGACY_TRANSFER_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    // Post-fix typehash — what the corrected implementation requires.
    bytes32 internal constant FEE_AUTH_TYPEHASH =
        keccak256("TransferWithFeeAuthorization(address from,address to,uint256 value,address treasury,uint256 fee,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    uint256 internal constant ALICE_BALANCE = 100 ether;

    function setUp() public {
        wSALT = new WrappedSALT();
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");
        legitimateTreasury = makeAddr("legitimateTreasury");

        vm.deal(alice, 1000 ether);
        vm.prank(alice);
        wSALT.deposit{value: ALICE_BALANCE}();
    }

    // ============================================================
    // Unit RED test — primary attack vector
    // ============================================================

    /// @notice Alice signs a digest the OLD typehash would have accepted
    ///         (simulating a wallet still on the buggy schema, OR an
    ///         in-flight authorization minted before the fix). The
    ///         attacker tries to replay it through
    ///         `transferWithFeeAuthorization` with attacker-controlled
    ///         `(treasury, fee)`. Post-fix, the call MUST revert.
    function test_rfi01_front_run_fee_redirect_blocked() public {
        uint256 value = 10 ether;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("rfi01-front-run-nonce");

        // Alice signs under the LEGACY typehash. This is the exact
        // shape that the pre-fix buggy code accepted for the fee path.
        (uint8 v, bytes32 r, bytes32 s) = _signLegacyTransferAuth(
            alicePk,
            alice,
            bob,
            value,
            validAfter,
            validBefore,
            nonce
        );

        uint256 aliceBalBefore = wSALT.balanceOf(alice);
        uint256 bobBalBefore = wSALT.balanceOf(bob);
        uint256 attackerBalBefore = wSALT.balanceOf(attacker);

        // Attacker front-runs with treasury = attacker, fee = value.
        // Post-fix this MUST revert because the signed digest does not
        // include `(treasury, fee)`. We use the bare `expectRevert()` so
        // the test compiles against pre-fix code; the assertion is that
        // SOMETHING reverts. The pre-fix code does NOT revert (it
        // happily steals funds), so the test fails RED. Post-fix the
        // contract reverts with `InvalidFeeAuthorization()`.
        vm.prank(attacker);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        wSALT.transferWithFeeAuthorization(
            alice,
            bob,
            attacker,        // attacker-chosen treasury
            value,
            value,           // attacker-chosen fee = value (steals all)
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        // No balance change — attack failed.
        assertEq(wSALT.balanceOf(alice), aliceBalBefore, "alice balance changed");
        assertEq(wSALT.balanceOf(bob), bobBalBefore, "bob balance changed");
        assertEq(wSALT.balanceOf(attacker), attackerBalBefore, "attacker stole");
        // The nonce must NOT have been consumed — alice can still spend it.
        assertFalse(wSALT.authorizationState(alice, nonce), "nonce was consumed");
    }

    /// @notice The post-fix happy path: alice signs under the NEW
    ///         typehash that binds `(treasury, fee)`; the call succeeds
    ///         and the split is performed honestly.
    function test_rfi01_post_fix_happy_path_succeeds() public {
        uint256 value = 10 ether;
        uint256 fee = 1 ether;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("rfi01-happy-path-nonce");

        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk,
            alice,
            bob,
            value,
            legitimateTreasury,
            fee,
            validAfter,
            validBefore,
            nonce
        );

        uint256 aliceBalBefore = wSALT.balanceOf(alice);

        wSALT.transferWithFeeAuthorization(
            alice,
            bob,
            legitimateTreasury,
            value,
            fee,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        assertEq(wSALT.balanceOf(alice), aliceBalBefore - value, "alice debit");
        assertEq(wSALT.balanceOf(bob), value - fee, "bob credit (net)");
        assertEq(wSALT.balanceOf(legitimateTreasury), fee, "treasury credit");
        assertTrue(wSALT.authorizationState(alice, nonce), "nonce not consumed");
    }

    /// @notice If alice signs under the NEW typehash binding a specific
    ///         treasury/fee, an attacker substituting a DIFFERENT
    ///         treasury or fee at submission time MUST fail.
    function test_rfi01_substituted_treasury_fails() public {
        uint256 value = 10 ether;
        uint256 fee = 1 ether;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("rfi01-substituted-treasury");

        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk,
            alice,
            bob,
            value,
            legitimateTreasury,
            fee,
            validAfter,
            validBefore,
            nonce
        );

        // Attacker submits with a different treasury.
        vm.prank(attacker);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        wSALT.transferWithFeeAuthorization(
            alice,
            bob,
            attacker, // SUBSTITUTED
            value,
            fee,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_rfi01_substituted_fee_fails() public {
        uint256 value = 10 ether;
        uint256 fee = 1 ether;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("rfi01-substituted-fee");

        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk,
            alice,
            bob,
            value,
            legitimateTreasury,
            fee,
            validAfter,
            validBefore,
            nonce
        );

        // Attacker bumps fee.
        vm.prank(attacker);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        wSALT.transferWithFeeAuthorization(
            alice,
            bob,
            legitimateTreasury,
            value,
            value, // SUBSTITUTED — drain everything to treasury
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    // ============================================================
    // Property: any (treasury, fee) outside the signed digest MUST fail
    // ============================================================

    /// @notice Fuzz: alice signs (legitimateTreasury, fee_signed); for
    ///         any (treasury_call, fee_call) != (legitimateTreasury,
    ///         fee_signed), the call MUST revert. Bound `value` and
    ///         `fee_signed` to alice's balance to keep the test crisp.
    function testFuzz_FrontRunFeeRedirectFails(
        address treasury_call,
        uint256 fee_call,
        uint256 value,
        uint256 fee_signed
    ) public {
        // Bound to legal range.
        value = bound(value, 1, ALICE_BALANCE);
        fee_signed = bound(fee_signed, 0, value);
        fee_call = bound(fee_call, 0, value);
        vm.assume(treasury_call != address(0));
        vm.assume(treasury_call != legitimateTreasury || fee_call != fee_signed);

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256(abi.encode("rfi01-fuzz", treasury_call, fee_call, value, fee_signed));

        // Alice signs binding (legitimateTreasury, fee_signed).
        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk,
            alice,
            bob,
            value,
            legitimateTreasury,
            fee_signed,
            validAfter,
            validBefore,
            nonce
        );

        uint256 aliceBalBefore = wSALT.balanceOf(alice);
        uint256 bobBalBefore = wSALT.balanceOf(bob);
        uint256 legitBalBefore = wSALT.balanceOf(legitimateTreasury);
        uint256 callTreasuryBalBefore = wSALT.balanceOf(treasury_call);

        // Caller substitutes (treasury_call, fee_call) — at least one
        // differs from the signed pair. The call MUST revert.
        vm.prank(attacker);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        wSALT.transferWithFeeAuthorization(
            alice,
            bob,
            treasury_call,
            value,
            fee_call,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        // No balance change at all.
        assertEq(wSALT.balanceOf(alice), aliceBalBefore, "alice");
        assertEq(wSALT.balanceOf(bob), bobBalBefore, "bob");
        assertEq(wSALT.balanceOf(legitimateTreasury), legitBalBefore, "legit treasury");
        assertEq(wSALT.balanceOf(treasury_call), callTreasuryBalBefore, "call treasury");
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _signLegacyTransferAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            LEGACY_TRANSFER_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }

    function _signFeeAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        address treasury,
        uint256 fee,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            FEE_AUTH_TYPEHASH,
            from, to, value, treasury, fee, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }
}
