// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
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
        // factory first, then paymaster with registrar = factory, then
        // (E-8 fix) the owner wires the registry direction
        // factory → paymaster so deploys register atomically.
        factory = new CitrateWalletFactory(address(impl), signer, ownerAddr);
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)), ownerAddr, address(factory), DAILY, RECOVERY, FIRST_OP
        );
        vm.prank(ownerAddr);
        factory.setPaymaster(address(pm));
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

/// E-8 end-to-end against the REAL EntryPoint v0.7 + real Kernel wallet:
/// one `handleOps` whose UserOp carries initCode (counterfactual CREATE2
/// deploy through `deployFor`) and a first-op-tagged paymaster. This
/// pins the load-bearing ordering claim from
/// ADR-2026-07-11-e8-atomic-factory-registration in-tree: sender
/// creation runs before paymaster validation, so atomic registration
/// inside `deployFor` makes the wallet's FIRST sponsored op eligible.
///
/// NB: `gasFees` are zero here. The paymaster compares the
/// EntryPoint-reported `maxCost` (WEI = gas x maxFeePerGas) against
/// `firstOpCap`, which the ADR-2026-06-05 policy and deploy script
/// document in GAS UNITS (300k). At any nonzero fee a full
/// counterfactual deploy's maxCost exceeds the cap — a pre-existing
/// units mismatch flagged to Lane C in the E-8 PR, out of scope here.
contract E8RealEntryPointE2ETest is Test {
    using MessageHashUtils for bytes32;

    uint8 internal constant CAT_FIRST_OP = 2;

    EntryPoint internal entryPoint;
    CitrateWallet internal walletImpl;
    CitrateECDSAValidator internal ecdsaValidator;
    CitrateWalletFactory internal factory;
    CitratePaymaster internal pm;

    uint256 internal constant IDENTITY_PK = 0x59E7;
    uint256 internal constant OWNER_PK = 0xB0B0;
    address internal walletOwner;
    address internal opsOwner = address(0xA11CE);
    address payable internal beneficiary = payable(address(0xFEE));

    bytes32 internal constant USER_ID = keccak256("e8-e2e-user");

    function setUp() public {
        entryPoint = new EntryPoint();
        walletImpl = new CitrateWallet(IKernelEntryPoint(address(entryPoint)));
        ecdsaValidator = new CitrateECDSAValidator();
        walletOwner = vm.addr(OWNER_PK);

        // The full 40204 ceremony, including the E-8 wiring step.
        factory = new CitrateWalletFactory(address(walletImpl), vm.addr(IDENTITY_PK), opsOwner);
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)), opsOwner, address(factory), 100_000, 200_000, 300_000
        );
        vm.prank(opsOwner);
        factory.setPaymaster(address(pm));

        // Sponsor treasury: the paymaster's EntryPoint deposit.
        vm.deal(address(this), 100 ether);
        pm.deposit{value: 10 ether}();
    }

    function test_E8_realEntryPoint_counterfactualFirstOp_endToEnd() public {
        address predicted = factory.predictAddress(USER_ID);
        assertEq(predicted.code.length, 0, "wallet must start counterfactual");
        assertFalse(pm.isRegistered(predicted), "must start unregistered");

        // initCode: factory ++ deployFor(permit) — ECDSA root validator
        // owned by walletOwner (source tag 1 = gui-native).
        bytes memory initData = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            bytes21(abi.encodePacked(bytes1(0x01), address(ecdsaValidator))),
            address(0),
            abi.encodePacked(walletOwner, uint8(1)),
            bytes(""),
            new bytes[](0)
        );
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 permit = factory.permitDigest(USER_ID, initData, expiresAt);
        (uint8 pv, bytes32 pr, bytes32 ps) = vm.sign(IDENTITY_PK, permit.toEthSignedMessageHash());
        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeCall(
                CitrateWalletFactory.deployFor,
                (USER_ID, address(ecdsaValidator), initData, expiresAt, abi.encodePacked(pr, ps, pv))
            )
        );

        // First action: a no-op single-call execute (value 0). What
        // matters is that the op EXECUTES sponsored, not what it does.
        bytes memory callData = abi.encodeWithSignature(
            "execute(bytes32,bytes)", bytes32(0), abi.encodePacked(address(0xD00D), uint256(0), bytes(""))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: predicted,
            nonce: entryPoint.getNonce(predicted, 0), // key 0 → Kernel root validator
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(0), // see contract doc — units-mismatch note
            paymasterAndData: abi.encodePacked(
                address(pm), uint128(500_000), uint128(200_000), bytes1(CAT_FIRST_OP)
            ),
            signature: ""
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, entryPoint.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        // Deployed at the predicted address, registered atomically, and
        // the first-op budget was consumed — all in ONE handleOps with
        // zero out-of-band transactions.
        assertGt(predicted.code.length, 0, "wallet deployed via initCode");
        assertTrue(pm.isRegistered(predicted), "registered atomically by deployFor");
        assertTrue(pm.hasUsedFirstOp(predicted), "first-op category consumed via postOp");
    }
}
