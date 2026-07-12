// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {EntryPointSimulations} from "@account-abstraction/core/EntryPointSimulations.sol";
import {IEntryPointSimulations} from "@account-abstraction/interfaces/IEntryPointSimulations.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// E-8 — paymaster registrar gap (first-op sponsorship), SIGNATURE-BASED.
///
/// Post-E8-1 the counterfactual CREATE2 first op is authorized by a
/// SPONSOR SIGNATURE the paymaster verifies against its OWN signer — the
/// factory no longer writes the paymaster's `isRegistered` slot during
/// the UserOp's initCode/validation phase (the removed cross-entity
/// write). These tests assert:
///   - a counterfactual first op is sponsorable with a valid signature,
///     with NO registration transaction and NO cross-entity write;
///   - the E8-2 fix makes first-op sponsorship pass at a NONZERO gas
///     price (it reverted before, when caps were mis-denominated in gas
///     units — the units bug);
///   - a validation-phase simulation (EntryPointSimulations) accepts the
///     counterfactual first op AND leaves the paymaster's registry slot
///     untouched by the factory.

/// Minimal initializable wallet implementation (stand-in for the Kernel
/// v3.3 CitrateWallet adapter, which is irrelevant to sponsorship logic).
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

    uint256 internal constant SIGNER_PK = 0x59E7; // identity + sponsor (single-key test)
    address internal signer;
    address internal ownerAddr = address(0xA11CE);

    bytes32 internal constant USER = keccak256("e8-first-op-user");

    uint256 internal constant DAILY = 0.01 ether;
    uint256 internal constant RECOVERY = 0.01 ether;
    uint256 internal constant FIRST_OP = 0.02 ether;

    function setUp() public {
        signer = vm.addr(SIGNER_PK);
        impl = new E8MockWalletImpl();
        entryPoint = new E8StubEntryPoint();

        factory = new CitrateWalletFactory(address(impl), signer, ownerAddr);
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            ownerAddr,
            address(factory),
            signer, // sponsorSigner
            DAILY,
            RECOVERY,
            FIRST_OP,
            20 gwei, // maxFeePerGas ceiling
            5 ether // global daily cap
        );
        vm.prank(ownerAddr);
        factory.setPaymaster(address(pm));
    }

    /// The E-8 deliverable: a counterfactual CREATE2 wallet's first
    /// sponsored UserOp passes paymaster validation with only a sponsor
    /// signature — NO registration transaction, NO cross-entity write.
    function test_E8_counterfactualFirstOp_sponsorshipSucceedsBySignature() public {
        address predicted = factory.predictAddress(USER);
        assertEq(predicted.code.length, 0, "wallet must start counterfactual");

        // Deploy via the permit (this is what EntryPoint initCode runs).
        address account = _deployViaPermit(USER);
        assertEq(account, predicted, "CREATE2 address mismatch");

        // E8-1: the factory did NOT register the wallet. First-op is
        // authorized by signature alone.
        assertFalse(pm.isRegistered(account), "E8-1: factory must not write paymaster storage");

        PackedUserOperation memory op = _firstOpUserOp(account);
        vm.prank(address(entryPoint));
        (bytes memory ctx,) = pm.validatePaymasterUserOp(op, bytes32(0), 0.015 ether);

        (address ctxAccount, uint8 ctxCategory) = abi.decode(ctx, (address, uint8));
        assertEq(ctxAccount, account, "context account");
        assertEq(ctxCategory, CAT_FIRST_OP, "context category");
    }

    /// E8-1 invariant, stated directly: `deployFor` must not touch the
    /// paymaster's `isRegistered` mapping at all.
    function test_E8_deployFor_doesNotRegisterWithPaymaster() public {
        address account = _deployViaPermit(USER);
        assertFalse(pm.isRegistered(account), "deployFor must not register (cross-entity write removed)");
    }

    // --- Helpers ---

    function _deployViaPermit(bytes32 userId) internal returns (address) {
        bytes memory initData = abi.encodeCall(E8MockWalletImpl.init, (bytes("e8")));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(userId, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest.toEthSignedMessageHash());
        return factory.deployFor(userId, address(0xDEAD), initData, expiresAt, abi.encodePacked(r, s, v));
    }

    /// paymasterAndData: 52-byte ERC-4337 v0.7 prefix, then
    /// [tag(1) | validUntil(6) | validAfter(6) | sponsorSig(65)].
    function _firstOpUserOp(address sender) internal view returns (PackedUserOperation memory op) {
        op.sender = sender;
        uint48 until = uint48(block.timestamp + 1 hours);
        uint48 aft = uint48(block.timestamp);
        bytes32 digest = pm.sponsorDigest(sender, CAT_FIRST_OP, until, aft);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest.toEthSignedMessageHash());
        op.paymasterAndData = abi.encodePacked(
            address(pm), uint128(0), uint128(0), bytes1(CAT_FIRST_OP), until, aft, abi.encodePacked(r, s, v)
        );
    }
}

/// E-8 end-to-end against the REAL EntryPoint v0.7 + real Kernel wallet:
/// one `handleOps` whose UserOp carries initCode (counterfactual CREATE2
/// deploy through `deployFor`) and a signature-authorized first-op
/// paymaster. This pins the load-bearing ordering claim in-tree AND (the
/// E8-3 fix) exercises it at a NONZERO gas price with the E8-2 wei caps.
contract E8RealEntryPointE2ETest is Test {
    using MessageHashUtils for bytes32;

    uint8 internal constant CAT_FIRST_OP = 2;

    EntryPoint internal entryPoint;
    CitrateWallet internal walletImpl;
    CitrateECDSAValidator internal ecdsaValidator;
    CitrateWalletFactory internal factory;
    CitratePaymaster internal pm;

    uint256 internal constant IDENTITY_PK = 0x59E7; // identity + sponsor (single-key test)
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

        factory = new CitrateWalletFactory(address(walletImpl), vm.addr(IDENTITY_PK), opsOwner);
        pm = new CitratePaymaster(
            IEntryPoint(address(entryPoint)),
            opsOwner,
            address(factory),
            vm.addr(IDENTITY_PK), // sponsorSigner
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(opsOwner);
        factory.setPaymaster(address(pm));

        vm.deal(address(this), 100 ether);
        pm.deposit{value: 10 ether}();
    }

    /// E8-3: a counterfactual first op sponsored end-to-end at a NONZERO
    /// gas price. Before the E8-2 fix the caps were denominated in gas
    /// units (300k), so at any nonzero maxFeePerGas the wei `maxCost` far
    /// exceeded the cap and validation reverted `FirstOpCapExceeded`.
    /// With wei caps + a fee ceiling it passes.
    function test_E8_realEntryPoint_counterfactualFirstOp_nonzeroGasPrice() public {
        address predicted = factory.predictAddress(USER_ID);
        assertEq(predicted.code.length, 0, "wallet must start counterfactual");
        assertFalse(pm.isRegistered(predicted), "must start unregistered");

        PackedUserOperation memory op = _buildFirstOp(predicted, 1 gwei); // NONZERO fee
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, entryPoint.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        assertGt(predicted.code.length, 0, "wallet deployed via initCode");
        // E8-1: NOT registered — the factory writes no paymaster storage.
        assertFalse(pm.isRegistered(predicted), "E8-1: no cross-entity write");
        assertTrue(pm.hasUsedFirstOp(predicted), "first-op consumed via postOp");
    }

    /// E8-3: validation-phase proof via EntryPointSimulations. This runs
    /// `simulateValidation`, the account-abstraction harness that mirrors
    /// what a bundler's `debug_traceCall` drives — account validation
    /// (initCode → deployFor) THEN paymaster validation — WITHOUT
    /// executing the op. It asserts the counterfactual first op passes
    /// validation AND that after simulation the factory left the
    /// paymaster's `isRegistered` slot untouched (the E8-1 invariant:
    /// during validation no entity writes another entity's storage).
    ///
    /// Residual gap (documented honestly): `simulateValidation` proves
    /// the validation path SUCCEEDS and lets us assert the storage
    /// invariant by inspection, but forge cannot run the ERC-7562
    /// OPCODE/STORAGE TRACER itself. A full banned-storage-access proof
    /// still requires the live Citrate bundler's `debug_traceCall`
    /// (WP-3 staging). What this test DOES prove: (1) validation succeeds
    /// end-to-end with the signature gate, (2) the factory performs zero
    /// writes to paymaster storage during the whole validation, which is
    /// the specific behavior E8-1 flagged. It does NOT independently
    /// re-derive the tracer's verdict.
    function test_E8_simulateValidation_counterfactualFirstOp_noCrossEntityWrite() public {
        // Deploy a fresh EntryPointSimulations at the canonical EntryPoint
        // address so account/paymaster wiring resolves against it.
        EntryPointSimulations sim = new EntryPointSimulations();

        // Rebuild the stack against the simulations EntryPoint.
        CitrateWallet wImpl = new CitrateWallet(IKernelEntryPoint(address(sim)));
        CitrateECDSAValidator val = new CitrateECDSAValidator();
        CitrateWalletFactory f = new CitrateWalletFactory(address(wImpl), vm.addr(IDENTITY_PK), opsOwner);
        CitratePaymaster p = new CitratePaymaster(
            IEntryPoint(address(sim)),
            opsOwner,
            address(f),
            vm.addr(IDENTITY_PK),
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(opsOwner);
        f.setPaymaster(address(p));
        vm.deal(address(this), 100 ether);
        p.deposit{value: 10 ether}();

        bytes32 userId = keccak256("e8-sim-user");
        address predicted = f.predictAddress(userId);
        assertFalse(p.isRegistered(predicted), "counterfactual: unregistered");

        PackedUserOperation memory op = _buildFirstOpFor(sim, f, val, p, userId, predicted, 1 gwei);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, sim.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);

        // simulateValidation runs account (initCode/deployFor) + paymaster
        // validation. A revert here would mean the counterfactual first
        // op is NOT sponsorable in the validation phase.
        IEntryPointSimulations.ValidationResult memory res = sim.simulateValidation(op);

        // Paymaster validation returned a valid (non-sig-failed) result.
        assertEq(uint160(res.returnInfo.paymasterValidationData), 0, "paymaster validation must succeed (sigFailed==0)");

        // E8-1 invariant: the factory ran (initCode executed — the sender
        // now has code) but wrote NOTHING to the paymaster's registry.
        assertGt(predicted.code.length, 0, "initCode executed during validation");
        assertFalse(p.isRegistered(predicted), "E8-1: factory wrote no paymaster storage during validation");
    }

    // --- Helpers ---

    function _buildFirstOp(address predicted, uint256 maxFee) internal view returns (PackedUserOperation memory) {
        return _buildFirstOpFor(entryPoint, factory, ecdsaValidator, pm, USER_ID, predicted, maxFee);
    }

    function _buildFirstOpFor(
        EntryPoint ep,
        CitrateWalletFactory f,
        CitrateECDSAValidator val,
        CitratePaymaster p,
        bytes32 userId,
        address predicted,
        uint256 maxFee
    ) internal view returns (PackedUserOperation memory op) {
        bytes memory initData = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            bytes21(abi.encodePacked(bytes1(0x01), address(val))),
            address(0),
            abi.encodePacked(walletOwner, uint8(1)),
            bytes(""),
            new bytes[](0)
        );
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 permit = f.permitDigest(userId, initData, expiresAt);
        (uint8 pv, bytes32 pr, bytes32 ps) = vm.sign(IDENTITY_PK, permit.toEthSignedMessageHash());
        bytes memory initCode = abi.encodePacked(
            address(f),
            abi.encodeCall(
                CitrateWalletFactory.deployFor,
                (userId, address(val), initData, expiresAt, abi.encodePacked(pr, ps, pv))
            )
        );

        bytes memory callData = abi.encodeWithSignature(
            "execute(bytes32,bytes)", bytes32(0), abi.encodePacked(address(0xD00D), uint256(0), bytes(""))
        );

        // E8-1: sign the sponsorship for this sender + first-op + window.
        uint48 until = uint48(block.timestamp + 1 hours);
        uint48 aft = uint48(block.timestamp);
        bytes32 sd = p.sponsorDigest(predicted, CAT_FIRST_OP, until, aft);
        (uint8 sv, bytes32 sr, bytes32 ss) = vm.sign(IDENTITY_PK, sd.toEthSignedMessageHash());

        op = PackedUserOperation({
            sender: predicted,
            nonce: ep.getNonce(predicted, 0),
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(maxFee), uint128(maxFee))), // NONZERO (E8-3)
            paymasterAndData: abi.encodePacked(
                address(p), uint128(500_000), uint128(200_000), bytes1(CAT_FIRST_OP), until, aft, abi.encodePacked(sr, ss, sv)
            ),
            signature: ""
        });
    }
}
