// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitrateECDSAValidator} from "../../src/aa/validators/CitrateECDSAValidator.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {StubEntryPoint} from "./CitratePaymaster.t.sol";
import {IEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
import {IEntryPoint as IAaEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {KERNEL_WRAPPER_TYPE_HASH, ERC1271_MAGICVALUE, ERC1271_INVALID} from "@kernel/types/Constants.sol";

/// Stub EntryPoint — 1271 verification never touches the EntryPoint, so
/// the constructor wiring is all the Kernel base needs here.
contract StubKernelEntryPoint {
    receive() external payable {}
}

/// ERC-5267 surface Solady's EIP712 (and therefore Kernel) exposes — we
/// read the LIVE domain from the proxy instead of hardcoding name/version.
interface IERC5267 {
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}

interface IKernel1271 {
    function isValidSignature(bytes32 hash, bytes calldata data) external view returns (bytes4);
}

/// IDP-S1.5 / WP-C4 — the FULL Kernel-proxy EIP-1271 path
/// (`CitrateWallet.isValidSignature` → ValidationManager →
/// `CitrateECDSAValidator.isValidSignatureWithSender`), which is how a
/// Citrate smart wallet signs in via SIWE at auth.citrate.ai.
///
/// The load-bearing nuance these tests pin (validator-level tests can't
/// see it): Kernel does NOT hand the raw hash to the validator. It
/// 1. strips a 1-byte ValidationId prefix off the signature
///    (`0x00` = root validator; `0x01 ++ validator` = explicit), and
/// 2. EIP-712-wraps the hash with its own domain
///    (`Kernel(bytes32 hash)` struct, verifyingContract = the PROXY)
///    before calling the validator.
/// So a smart-wallet SIWE client MUST sign the wrapped digest and MUST
/// prefix the mode byte — a signature over the raw SIWE digest is
/// rejected. citrate-identity's `verifySiweLogin` 1271 path calls
/// `isValidSignature(hash, sig)` with whatever blob the client supplies,
/// so the client-side signer (citrate-sdk-js, TD-EW-D follow-up) owns
/// this encoding.
contract KernelEip1271Test is Test {
    using MessageHashUtils for bytes32;

    uint256 internal constant IDENTITY_PK = 0x59E7;
    uint256 internal constant OWNER_PK = 0xB0B0;
    uint256 internal constant STRANGER_PK = 0xBAD;

    CitrateWallet internal walletImpl;
    CitrateWalletFactory internal factory;
    CitrateECDSAValidator internal validator;
    address internal walletOwner;
    IKernel1271 internal wallet;

    bytes32 internal constant USER_ID = keccak256("eip1271-user");

    function setUp() public {
        StubKernelEntryPoint ep = new StubKernelEntryPoint();
        walletImpl = new CitrateWallet(IEntryPoint(address(ep)));
        validator = new CitrateECDSAValidator();
        walletOwner = vm.addr(OWNER_PK);
        factory = new CitrateWalletFactory(address(walletImpl), vm.addr(IDENTITY_PK), address(0xA11CE));

        // E-8: deployFor fails closed until the paymaster registry is
        // wired (registrar = factory, as in script/aa/DeployAA.s.sol).
        CitratePaymaster pm = new CitratePaymaster(
            IAaEntryPoint(address(new StubEntryPoint())),
            address(0xA11CE),
            address(factory),
            vm.addr(IDENTITY_PK), // sponsorSigner (unused in this suite)
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(address(0xA11CE));
        factory.setPaymaster(address(pm));

        // initialize(bytes21 rootValidator, address hook, bytes validatorData,
        //            bytes hookData, bytes[] initConfig) — ECDSA root validator
        // owned by walletOwner, source tag 1 (gui-native).
        bytes21 vId = bytes21(abi.encodePacked(bytes1(0x01), address(validator)));
        bytes memory initData = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            vId,
            address(0),
            abi.encodePacked(walletOwner, uint8(1)),
            bytes(""),
            new bytes[](0)
        );
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(USER_ID, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(IDENTITY_PK, digest.toEthSignedMessageHash());
        address account =
            factory.deployFor(USER_ID, address(validator), initData, expiresAt, abi.encodePacked(r, s, v));
        wallet = IKernel1271(account);
    }

    /// Kernel's `_toWrappedHash`: EIP-712 digest of `Kernel(bytes32 hash)`
    /// under the PROXY's live domain (read via ERC-5267 so a Kernel
    /// name/version bump cannot silently stale this test).
    function _wrappedDigest(bytes32 hash) internal view returns (bytes32) {
        (, string memory name, string memory version,,,,) = IERC5267(address(wallet)).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(wallet)
            )
        );
        bytes32 structHash = keccak256(abi.encode(KERNEL_WRAPPER_TYPE_HASH, hash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // --- The happy path a smart-wallet SIWE login takes ---

    function test_isValidSignature_rootPrefix_overWrappedDigest() public {
        bytes32 siweDigest = keccak256("EIP-4361 message digest stand-in");
        bytes memory sig = _sign(OWNER_PK, _wrappedDigest(siweDigest));
        // 0x00 mode byte = route to the root validator.
        bytes4 result = wallet.isValidSignature(siweDigest, abi.encodePacked(bytes1(0x00), sig));
        assertEq(result, ERC1271_MAGICVALUE, "root-prefixed signature over the wrapped digest must verify");
    }

    function test_isValidSignature_explicitValidatorPrefix() public {
        bytes32 siweDigest = keccak256("explicit validator route");
        bytes memory sig = _sign(OWNER_PK, _wrappedDigest(siweDigest));
        // 0x01 ++ validator address routes to that validator explicitly
        // (here: the same ECDSA validator that is root).
        bytes memory blob = abi.encodePacked(bytes1(0x01), address(validator), sig);
        assertEq(wallet.isValidSignature(siweDigest, blob), ERC1271_MAGICVALUE);
    }

    // --- The nuance: signing the RAW hash is NOT enough ---

    function test_isValidSignature_rejectsSignatureOverRawHash() public {
        bytes32 siweDigest = keccak256("client signed the unwrapped digest");
        // A naive client signs the SIWE digest directly (what an EOA
        // would do). Kernel wraps before the validator recovers, so the
        // recovered address cannot match the owner.
        bytes memory sig = _sign(OWNER_PK, siweDigest);
        bytes4 result = wallet.isValidSignature(siweDigest, abi.encodePacked(bytes1(0x00), sig));
        assertEq(result, ERC1271_INVALID, "raw-hash signature must NOT verify through the Kernel proxy");
    }

    function test_isValidSignature_rejectsEthPrefixedRawHash() public {
        bytes32 siweDigest = keccak256("personal_sign over the unwrapped digest");
        bytes memory sig = _sign(OWNER_PK, siweDigest.toEthSignedMessageHash());
        bytes4 result = wallet.isValidSignature(siweDigest, abi.encodePacked(bytes1(0x00), sig));
        assertEq(result, ERC1271_INVALID, "personal_sign over the raw hash must NOT verify either");
    }

    // --- Wrong signer / malformed routing ---

    function test_isValidSignature_rejectsWrongSigner() public {
        bytes32 siweDigest = keccak256("stranger danger");
        bytes memory sig = _sign(STRANGER_PK, _wrappedDigest(siweDigest));
        bytes4 result = wallet.isValidSignature(siweDigest, abi.encodePacked(bytes1(0x00), sig));
        assertEq(result, ERC1271_INVALID);
    }

    function test_isValidSignature_rejectsUnknownValidatorRoute() public {
        bytes32 siweDigest = keccak256("route to a validator that is not installed");
        bytes memory sig = _sign(OWNER_PK, _wrappedDigest(siweDigest));
        bytes memory blob = abi.encodePacked(bytes1(0x01), address(0xDEAD), sig);
        // Routing to a never-installed validator reverts InvalidValidator.
        vm.expectRevert();
        wallet.isValidSignature(siweDigest, blob);
    }
}
