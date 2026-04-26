// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WrappedSALT.sol";
import "../src/X402Facilitator.sol";

contract X402FacilitatorTest is Test {
    WrappedSALT public wSALT;
    X402Facilitator public facilitator;

    address public admin;
    uint256 public adminPk;
    address public alice;
    uint256 public alicePk;
    address public bob;
    address public treasury;

    uint256 constant FEE_BPS = 50; // 0.5%

    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /// RFI-01 / WP-H1.1: distinct typehash binding (treasury, fee) into
    /// the signed digest. The facilitator now requires this typehash —
    /// the legacy one is rejected by `transferWithFeeAuthorization`.
    bytes32 constant FEE_AUTH_TYPEHASH =
        keccak256("TransferWithFeeAuthorization(address from,address to,uint256 value,address treasury,uint256 fee,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    function setUp() public {
        (admin, adminPk) = makeAddrAndKey("admin");
        (alice, alicePk) = makeAddrAndKey("alice");
        bob = makeAddr("bob");
        treasury = makeAddr("treasury");

        vm.deal(alice, 100 ether);

        wSALT = new WrappedSALT();

        vm.prank(admin);
        facilitator = new X402Facilitator(address(wSALT), treasury, FEE_BPS);

        // Alice deposits.
        // RM-B1 / WP-D2.1 (audit SOL-01): note that we do NOT
        // pre-approve the facilitator here. The post-fix
        // settlement consumes a single EIP-3009 authorization for
        // the gross value and splits internally — no allowance
        // required. Pre-fix tests called `wSALT.approve(...)` to
        // grant the facilitator unbounded fee-leg access; that's
        // exactly the UX regression the audit flagged.
        vm.startPrank(alice);
        wSALT.deposit{value: 50 ether}();
        vm.stopPrank();
    }

    // ============================================================
    // settlePayment Tests
    // ============================================================

    function test_settlePayment_valid() public {
        uint256 value = 10 ether;
        uint256 fee = (value * FEE_BPS) / 10000; // 0.05 ether
        uint256 netValue = value - fee;

        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("settle-1");

        // RFI-01 / WP-H1.1: alice signs the FEE-AUTH typehash binding
        // (treasury, fee) — the only shape the post-fix wSALT accepts.
        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk, alice, bob, value, treasury, fee, validAfter, validBefore, nonce
        );

        vm.prank(admin);
        facilitator.settlePayment(alice, bob, value, validAfter, validBefore, nonce, v, r, s);

        assertEq(wSALT.balanceOf(bob), netValue);
        assertEq(wSALT.balanceOf(treasury), fee);
    }

    function test_settlePayment_zero_value_reverts() public {
        bytes32 nonce = keccak256("settle-zero");
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 0, 0, block.timestamp + 1 hours, nonce
        );

        vm.prank(admin);
        vm.expectRevert("X402: zero value");
        facilitator.settlePayment(alice, bob, 0, 0, block.timestamp + 1 hours, nonce, v, r, s);
    }

    function test_settlePayment_non_facilitator_reverts() public {
        bytes32 nonce = keccak256("settle-unauth");
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce
        );

        vm.prank(bob); // bob is not a facilitator
        vm.expectRevert("AccessControl: account missing role");
        facilitator.settlePayment(alice, bob, 1 ether, 0, block.timestamp + 1 hours, nonce, v, r, s);
    }

    // ============================================================
    // batchSettle Tests
    // ============================================================

    function test_batchSettle() public {
        X402Facilitator.PaymentAuthorization[] memory payments = new X402Facilitator.PaymentAuthorization[](2);

        // Payment 1 — RFI-01: alice signs FEE-AUTH typehash binding
        // (treasury, fee).
        {
            uint256 value1 = 2 ether;
            uint256 fee1 = (value1 * FEE_BPS) / 10000;
            bytes32 nonce1 = keccak256("batch-1");
            (uint8 v1, bytes32 r1, bytes32 s1) = _signFeeAuth(
                alicePk, alice, bob, value1, treasury, fee1, 0, block.timestamp + 1 hours, nonce1
            );
            payments[0] = X402Facilitator.PaymentAuthorization({
                from: alice, to: bob, value: value1,
                validAfter: 0, validBefore: block.timestamp + 1 hours,
                nonce: nonce1, v: v1, r: r1, s: s1
            });
        }

        // Payment 2
        {
            uint256 value2 = 3 ether;
            uint256 fee2 = (value2 * FEE_BPS) / 10000;
            bytes32 nonce2 = keccak256("batch-2");
            (uint8 v2, bytes32 r2, bytes32 s2) = _signFeeAuth(
                alicePk, alice, bob, value2, treasury, fee2, 0, block.timestamp + 1 hours, nonce2
            );
            payments[1] = X402Facilitator.PaymentAuthorization({
                from: alice, to: bob, value: value2,
                validAfter: 0, validBefore: block.timestamp + 1 hours,
                nonce: nonce2, v: v2, r: r2, s: s2
            });
        }

        vm.prank(admin);
        facilitator.batchSettle(payments);

        // Bob got net values, treasury got fees
        uint256 totalNet = (2 ether - (2 ether * FEE_BPS) / 10000) + (3 ether - (3 ether * FEE_BPS) / 10000);
        uint256 totalFees = (2 ether * FEE_BPS) / 10000 + (3 ether * FEE_BPS) / 10000;
        assertEq(wSALT.balanceOf(bob), totalNet);
        assertEq(wSALT.balanceOf(treasury), totalFees);
    }

    // ============================================================
    // Fee Configuration Tests
    // ============================================================

    function test_setFacilitatorFee_admin() public {
        vm.prank(admin);
        facilitator.setFacilitatorFee(100); // 1%

        assertEq(facilitator.feeBps(), 100);
    }

    function test_setFacilitatorFee_exceeds_max_reverts() public {
        vm.prank(admin);
        vm.expectRevert("X402: fee exceeds 10%");
        facilitator.setFacilitatorFee(1001);
    }

    function test_setFacilitatorFee_non_admin_reverts() public {
        vm.prank(bob);
        vm.expectRevert("AccessControl: account missing role");
        facilitator.setFacilitatorFee(100);
    }

    // ============================================================
    // Treasury Tests
    // ============================================================

    function test_setTreasury() public {
        address newTreasury = makeAddr("newTreasury");
        vm.prank(admin);
        facilitator.setTreasury(newTreasury);

        assertEq(facilitator.treasury(), newTreasury);
    }

    function test_setTreasury_zero_reverts() public {
        vm.prank(admin);
        vm.expectRevert("X402: zero treasury address");
        facilitator.setTreasury(address(0));
    }

    // ============================================================
    // RM-B1 / WP-D2.1 (audit SOL-01): no pre-approval needed
    // ============================================================

    /// SOL-01.1: Alice has NOT pre-approved the facilitator. With
    /// the post-fix `transferWithFeeAuthorization`, settlement
    /// must succeed anyway because the fee leg is settled as part
    /// of the same signed authorization. Pre-fix this would have
    /// reverted with "wSALT: insufficient allowance" on the
    /// `transferFrom(from, treasury, fee)` call.
    function test_sol01_settlement_works_without_preapproval() public {
        // No `wSALT.approve(...)` call in the test setup — so any
        // path that depends on `transferFrom` allowance will fail.
        uint256 value = 4 ether;
        uint256 fee = (value * FEE_BPS) / 10000;
        bytes32 nonce = keccak256("sol01-no-approve");
        // RFI-01 / WP-H1.1: signed under FEE-AUTH typehash.
        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk, alice, bob, value, treasury, fee, 0, block.timestamp + 1 hours, nonce
        );

        vm.prank(admin);
        facilitator.settlePayment(
            alice, bob, value, 0, block.timestamp + 1 hours, nonce, v, r, s
        );

        assertEq(wSALT.balanceOf(bob), value - fee);
        assertEq(wSALT.balanceOf(treasury), fee);
        // Sanity check: alice did NOT grant any allowance.
        assertEq(wSALT.allowance(alice, address(facilitator)), 0);
    }

    /// SOL-01.2 / RFI-01: a signature minted under the legacy
    /// `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` (signed over `netValue`,
    /// no treasury/fee bound) must NOT be accepted by the post-fix
    /// `transferWithFeeAuthorization`. Post-fix the rejection is
    /// `InvalidFeeAuthorization()` (the structural marker that the
    /// new typehash is in force) instead of the legacy
    /// `wSALT: invalid signature` string.
    function test_sol01_legacy_netvalue_signature_rejected() public {
        uint256 value = 4 ether;
        uint256 fee = (value * FEE_BPS) / 10000;
        uint256 netValue = value - fee;
        bytes32 nonce = keccak256("sol01-legacy");

        // Sign over netValue under the legacy typehash (pre-fix shape).
        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(
            alicePk, alice, bob, netValue, 0, block.timestamp + 1 hours, nonce
        );

        // Submit gross `value` with the legacy-typehash signature —
        // must reject under the new typehash.
        vm.prank(admin);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        facilitator.settlePayment(
            alice, bob, value, 0, block.timestamp + 1 hours, nonce, v, r, s
        );
    }

    // ============================================================
    // RM-B1 / WP-D2.2 (audit SOL-02): chainId-rebuilt domain separator
    // ============================================================

    /// SOL-02.1: at the deploy chainId, DOMAIN_SEPARATOR() returns
    /// the cached value.
    function test_sol02_domain_separator_cached_at_deploy_chainid() public view {
        bytes32 ds = wSALT.DOMAIN_SEPARATOR();
        // Deploy chainId is whatever foundry uses (default 31337);
        // the cached value should match a fresh recomputation at
        // the same chainId.
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        bytes32 expected = keccak256(abi.encode(
            typeHash,
            keccak256(bytes(wSALT.name())),
            keccak256(bytes("1")),
            block.chainid,
            address(wSALT)
        ));
        assertEq(ds, expected, "SOL-02: DOMAIN_SEPARATOR matches expected");
    }

    /// SOL-02.2: under a `vm.chainId` change, DOMAIN_SEPARATOR()
    /// rebuilds — the new value differs from the cached one.
    /// This is the load-bearing behaviour that closes cross-fork
    /// replay.
    function test_sol02_domain_separator_rebuilds_on_chainid_change() public {
        bytes32 originalDs = wSALT.DOMAIN_SEPARATOR();

        // Simulate a fork: change the chainId.
        vm.chainId(99_999);
        bytes32 newDs = wSALT.DOMAIN_SEPARATOR();
        assertTrue(
            originalDs != newDs,
            "SOL-02: DOMAIN_SEPARATOR must rebuild on chainId change"
        );

        // Restore to the original chainId; cached value resumes.
        vm.chainId(31337);
        bytes32 restoredDs = wSALT.DOMAIN_SEPARATOR();
        assertEq(restoredDs, originalDs, "SOL-02: cached DS resumes when chainId restored");
    }

    /// SOL-02.3: a signature minted under chainId A is REJECTED
    /// when verified under chainId B. Cross-fork replay closed.
    /// RFI-01 / WP-H1.1: post-fix the rejection comes through the
    /// `transferWithFeeAuthorization` path, so the revert is
    /// `InvalidFeeAuthorization()`.
    function test_sol02_cross_chainid_signature_replay_rejected() public {
        uint256 value = 1 ether;
        uint256 fee = (value * FEE_BPS) / 10000;
        bytes32 nonce = keccak256("sol02-cross-chain");

        // Sign at the original chainId — under the FEE-AUTH typehash,
        // since that's the path the facilitator takes.
        (uint8 v, bytes32 r, bytes32 s) = _signFeeAuth(
            alicePk, alice, bob, value, treasury, fee, 0, block.timestamp + 1 hours, nonce
        );

        // Switch chainId; the signature should now fail to verify
        // because DOMAIN_SEPARATOR rebuilds.
        vm.chainId(99_999);
        vm.prank(admin);
        vm.expectRevert(WrappedSALT.InvalidFeeAuthorization.selector);
        facilitator.settlePayment(
            alice, bob, value, 0, block.timestamp + 1 hours, nonce, v, r, s
        );
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _signTransferAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }

    /// RFI-01 / WP-H1.1: helper for the fee-authorization typehash.
    /// Signs over `(from, to, value, treasury_, fee, validAfter,
    /// validBefore, nonce)` — the post-fix shape required by
    /// `transferWithFeeAuthorization`.
    function _signFeeAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        address treasury_,
        uint256 fee,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(
            FEE_AUTH_TYPEHASH,
            from, to, value, treasury_, fee, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", wSALT.DOMAIN_SEPARATOR(), structHash
        ));
        (v, r, s) = vm.sign(signerPk, digest);
    }
}
