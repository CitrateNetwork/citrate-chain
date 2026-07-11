// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// E-8 — paymaster registrar gap (first-op sponsorship).
///
/// Reproduces the counterfactual CREATE2 onboarding flow the way
/// EntryPoint v0.7 actually sequences it (`_validatePrepayment`,
/// lib/account-abstraction/contracts/core/EntryPoint.sol):
///
///   1. `_validateAccountPrepayment` → `_createSenderIfNeeded` runs the
///      UserOp's initCode, i.e. `CitrateWalletFactory.deployFor(...)`
///      (EntryPoint.sol L480).
///   2. Only then does `_validatePaymasterPrepayment` call
///      `CitratePaymaster.validatePaymasterUserOp` (EntryPoint.sol
///      L661-666).
///
/// The 40204 ceremony (script/aa/DeployAA.s.sol) wires the paymaster
/// with `registrar = factory`. But the factory never calls
/// `registerWallet`, so a wallet's FIRST sponsored UserOp — the one
/// whose initCode deploys it — reaches step 2 unregistered and the
/// paymaster reverts `NotARegisteredCitrateWallet`. Onboarding degrades
/// to "you pay gas", which the first-op category exists to prevent.
///
/// These tests assert the DELIVERABLE (first-op sponsorship succeeds at
/// step 2 with no out-of-band registration transaction). They are RED
/// against the current contracts — that is the E-8 WP-1 reproduction.

/// Minimal initializable wallet implementation (stand-in for the Kernel
/// v3.3 CitrateWallet adapter, which is irrelevant to registrar logic).
contract E8MockWalletImpl {
    uint256 public initCalls;

    function init(bytes calldata) external payable {
        initCalls += 1;
    }
}

/// Minimal EntryPoint stub — reports IEntryPoint support so
/// BasePaymaster's constructor accepts it, and lets the test masquerade
/// as the entry point when invoking paymaster hooks.
contract E8StubEntryPoint {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IEntryPoint).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    receive() external payable {}

    function depositTo(address) external payable {}
}

contract E8FirstOpRegistrarTest is Test {
    using MessageHashUtils for bytes32;

    uint8 internal constant CAT_FIRST_OP = 2;

    CitrateWalletFactory internal factory;
    CitratePaymaster internal pm;
    E8MockWalletImpl internal impl;
    E8StubEntryPoint internal entryPoint;

    uint256 internal constant SIGNER_PK = 0x59E7;
    address internal signer;
    address internal ownerAddr = address(0xA11CE);

    bytes32 internal constant USER = keccak256("e8-first-op-user");

    uint256 internal constant DAILY = 100_000;
    uint256 internal constant RECOVERY = 200_000;
    uint256 internal constant FIRST_OP = 300_000;

    function setUp() public {
        signer = vm.addr(SIGNER_PK);
        impl = new E8MockWalletImpl();
        entryPoint = new E8StubEntryPoint();

        // Wire exactly as script/aa/DeployAA.s.sol does on 40204:
        // factory first, then paymaster with registrar = factory.
        factory = new CitrateWalletFactory(address(impl), signer, ownerAddr);
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)), ownerAddr, address(factory), DAILY, RECOVERY, FIRST_OP
        );
    }

    /// The whole E-8 deliverable in one test: a counterfactual CREATE2
    /// wallet's first sponsored UserOp must pass paymaster validation
    /// with no registration transaction between deploy and validate —
    /// because in a single `handleOps` there is nowhere to put one.
    function test_E8_counterfactualFirstOp_sponsorshipSucceedsAfterFactoryDeploy() public {
        address predicted = factory.predictAddress(USER);
        assertEq(predicted.code.length, 0, "wallet must start counterfactual");

        // Step 1 — EntryPoint._createSenderIfNeeded executes initCode:
        // the permit-gated factory deploy.
        address account = _deployViaPermit(USER);
        assertEq(account, predicted, "CREATE2 address mismatch");

        // Step 2 — EntryPoint._validatePaymasterPrepayment, same UserOp.
        // No other transaction has run. This must sponsor the first op.
        PackedUserOperation memory op = _firstOpUserOp(account);
        vm.prank(address(entryPoint));
        (bytes memory ctx,) = pm.validatePaymasterUserOp(op, bytes32(0), 250_000);

        (address ctxAccount, uint8 ctxCategory) = abi.decode(ctx, (address, uint8));
        assertEq(ctxAccount, account, "context account");
        assertEq(ctxCategory, CAT_FIRST_OP, "context category");
    }

    /// The mechanism behind the deliverable: a factory deploy must leave
    /// the wallet registered with the paymaster (the factory IS the
    /// registrar per the 40204 ceremony — nobody else can register it).
    function test_E8_deployFor_registersWalletWithPaymaster() public {
        address account = _deployViaPermit(USER);
        assertTrue(pm.isRegistered(account), "deployFor must register the wallet it deploys");
    }

    // --- Helpers ---

    function _deployViaPermit(bytes32 userId) internal returns (address) {
        bytes memory initData = abi.encodeCall(E8MockWalletImpl.init, (bytes("e8")));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(userId, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest.toEthSignedMessageHash());
        return factory.deployFor(userId, address(0xDEAD), initData, expiresAt, abi.encodePacked(r, s, v));
    }

    /// paymasterAndData: 52-byte ERC-4337 v0.7 prefix then the 1-byte
    /// category tag (0x02 = first-op).
    function _firstOpUserOp(address sender) internal view returns (PackedUserOperation memory op) {
        op.sender = sender;
        bytes memory pmd = new bytes(53);
        for (uint256 i = 0; i < 20; i++) {
            pmd[i] = bytes20(address(pm))[i];
        }
        pmd[52] = bytes1(CAT_FIRST_OP);
        op.paymasterAndData = pmd;
    }
}
