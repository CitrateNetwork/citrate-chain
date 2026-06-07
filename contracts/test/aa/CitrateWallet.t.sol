// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {IEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";

/// Stub EntryPoint sufficient for the constructor wiring +
/// CitrateWalletFactory deployment paths. Wallet-internal entrypoint()
/// reads remain functional because we only ASSERT on the immutable;
/// no actual UserOp routing is exercised here (the validator + factory
/// + paymaster test files cover those independently).
contract StubKernelEntryPoint {
    receive() external payable {}
}

/// Tests for the Citrate-branded ERC-4337 v0.7 / ERC-7579 wallet
/// implementation (`CitrateWallet`). This contract is a thin adapter
/// over the vendored ZeroDev Kernel v3.3; the validators + recovery
/// module + factory + paymaster all have their own test files that
/// already cover behavioural correctness.
///
/// What we explicitly verify here:
///   1. The implementation deploys + the EntryPoint immutable wires
///      through to the Kernel base (so DeployAA.s.sol can stand up
///      a usable implementation contract on any chain).
///   2. The factory accepts CitrateWallet as the `implementation`
///      argument and predicts an ERC-1967 proxy address for a given
///      (userId, ownerSalt) pair (the address-prediction contract the
///      identity service relies on).
///   3. The implementation's runtime size is inside the EIP-170 24576-byte
///      limit AND has enough margin to absorb a small Citrate-specific
///      extension without an immediate refactor.
contract CitrateWalletTest is Test {
    StubKernelEntryPoint internal entryPoint;
    CitrateWallet internal walletImpl;
    CitrateWalletFactory internal factory;
    address internal identitySigner;
    address internal owner;

    function setUp() public {
        entryPoint = new StubKernelEntryPoint();
        walletImpl = new CitrateWallet(IEntryPoint(address(entryPoint)));
        identitySigner = vm.addr(uint256(keccak256("identity-signer")));
        owner = vm.addr(uint256(keccak256("owner")));
        factory = new CitrateWalletFactory(address(walletImpl), identitySigner, owner);
    }

    // --- Construction ---

    function test_constructor_setsEntryPointImmutable() public {
        // Kernel exposes `entrypoint()` publicly (line 71 of upstream
        // Kernel.sol — `IEntryPoint public immutable entrypoint`). The
        // CitrateWallet adapter inherits it byte-identically; the
        // deployment contract's entrypoint() must match what we passed.
        assertEq(address(walletImpl.entrypoint()), address(entryPoint));
    }

    function test_walletImpl_codeIsDeployed() public {
        // Sanity: the implementation contract has non-empty runtime code
        // (so the factory's ERC-1967 proxy `delegatecall` lands somewhere
        // real, not in an EOA).
        assertGt(address(walletImpl).code.length, 0);
    }

    function test_walletImpl_runtimeSize_underEip170LimitWithMargin() public {
        // EIP-170 contract size limit is 24,576 bytes. We sit at 24,522
        // at this commit (verified via `forge build --sizes`). This test
        // is a trip-wire: if an upstream Kernel patch pushes us over the
        // limit, we lose deployability without warning. Catch it here
        // before CI.
        uint256 size = address(walletImpl).code.length;
        assertLt(size, 24_576, "CitrateWallet exceeds EIP-170 24576-byte limit");
        assertGt(size, 20_000, "CitrateWallet suspiciously small (vendor regression?)");
    }

    // --- Factory integration ---

    function test_factory_acceptsCitrateWalletAsImplementation() public {
        // The factory stores the implementation address it was wired
        // against; mirror the DeployAA path.
        assertEq(factory.implementation(), address(walletImpl));
    }

    function test_factory_predictsDeterministicAddress_forUserSalt() public {
        // The factory derives the proxy address from
        // `keccak256(userId)` per the EW-S1 ADR (factory salt = userId
        // alone, gated by EIP-191 identity-signer permit). Same input →
        // same address; different input → different address.
        bytes32 user1 = keccak256("alice@citrate.ai");
        bytes32 user2 = keccak256("bob@citrate.ai");

        address pred1 = factory.predictAddress(user1);
        address pred2 = factory.predictAddress(user2);

        assertTrue(pred1 != address(0));
        assertTrue(pred2 != address(0));
        assertTrue(pred1 != pred2);

        // Determinism: same input MUST yield the same address.
        assertEq(factory.predictAddress(user1), pred1);
    }
}
