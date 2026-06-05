// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";

import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// A minimal initializable target so we can test that:
///   - the factory deploys a clone at the expected deterministic address
///   - the init data is called exactly once (idempotency)
///   - the proxy delegates calls to this implementation
contract MockImplementation {
    address public lastInitializer;
    bytes public lastInitArgs;
    uint256 public initCalls;

    /// Special init that reverts when called with a magic marker byte
    /// sequence. We use this to test the factory's InitializeFailed
    /// path — delegating through a proxy means we can't flip a flag on
    /// the implementation contract itself (the proxy delegatecall reads
    /// the proxy's storage, not the impl's), so we encode the
    /// fail-trigger in the init args themselves.
    function init(bytes calldata args) external payable {
        if (args.length >= 4 && bytes4(args[:4]) == bytes4(0xDEADC0DE)) revert("init refused");
        lastInitializer = msg.sender;
        lastInitArgs = args;
        initCalls += 1;
    }
}

contract CitrateWalletFactoryTest is Test {
    using MessageHashUtils for bytes32;

    CitrateWalletFactory internal factory;
    MockImplementation internal impl;

    uint256 internal constant SIGNER_PK = 0x59E7;
    address internal signer;
    address internal ownerAddr = address(0xA11CE);

    bytes32 internal constant USER_A = keccak256("user-a");
    bytes32 internal constant USER_B = keccak256("user-b");

    function setUp() public {
        impl = new MockImplementation();
        signer = vm.addr(SIGNER_PK);
        factory = new CitrateWalletFactory(address(impl), signer, ownerAddr);
    }

    // --- Constructor ---

    function test_constructor_rejectsZeroImpl() public {
        vm.expectRevert(CitrateWalletFactory.ZeroAddress.selector);
        new CitrateWalletFactory(address(0), signer, ownerAddr);
    }

    function test_constructor_rejectsZeroSigner() public {
        vm.expectRevert(CitrateWalletFactory.ZeroAddress.selector);
        new CitrateWalletFactory(address(impl), address(0), ownerAddr);
    }

    function test_constructor_rejectsZeroOwner() public {
        vm.expectRevert(CitrateWalletFactory.ZeroAddress.selector);
        new CitrateWalletFactory(address(impl), signer, address(0));
    }

    function test_constructor_rejectsImplWithNoCode() public {
        address fake = address(0xFAEC);
        vm.expectRevert(CitrateWalletFactory.ImplementationNotDeployed.selector);
        new CitrateWalletFactory(fake, signer, ownerAddr);
    }

    // --- Address determinism ---

    function test_predictAddress_isStablePerUserId() public {
        address a1 = factory.predictAddress(USER_A);
        address a2 = factory.predictAddress(USER_A);
        assertEq(a1, a2, "same userId, same address");

        address b = factory.predictAddress(USER_B);
        assertTrue(a1 != b, "different userIds, different addresses");
    }

    function test_predictAddress_matchesActualDeploy() public {
        address predicted = factory.predictAddress(USER_A);
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("hello"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);

        address deployed = factory.deployFor{value: 0}(USER_A, address(0xDEAD), initData, expiresAt, sig);
        assertEq(deployed, predicted);
    }

    // --- Permit gating ---

    function test_deployFor_rejectsExpiredPermit() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("x"));
        uint256 expiresAt = block.timestamp - 1; // already expired
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);

        vm.expectRevert(CitrateWalletFactory.PermitExpired.selector);
        factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
    }

    function test_deployFor_rejectsSignatureFromWrongKey() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("x"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _signWith(0xBADBAD, factory.permitDigest(USER_A, initData, expiresAt));

        vm.expectRevert(CitrateWalletFactory.InvalidSigner.selector);
        factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
    }

    function test_deployFor_rejectsTamperedInitData() public {
        bytes memory signedInitData = abi.encodeCall(MockImplementation.init, ("signed"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, signedInitData, expiresAt);

        bytes memory tamperedInitData = abi.encodeCall(MockImplementation.init, ("tampered"));
        vm.expectRevert(CitrateWalletFactory.InvalidSigner.selector);
        factory.deployFor(USER_A, address(0xDEAD), tamperedInitData, expiresAt, sig);
    }

    function test_deployFor_rejectsCrossUserIdReplay() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("init"));
        uint256 expiresAt = block.timestamp + 1 hours;

        // Sign for USER_A; try to use the signature for USER_B.
        bytes memory sigForA = _permitSig(USER_A, initData, expiresAt);
        vm.expectRevert(CitrateWalletFactory.InvalidSigner.selector);
        factory.deployFor(USER_B, address(0xDEAD), initData, expiresAt, sigForA);
    }

    function test_deployFor_rejectsCrossChainReplay() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("x"));
        uint256 expiresAt = block.timestamp + 1 hours;

        // Sign for chain N; try to redeem on chain N+1.
        bytes32 digestOnOtherChain = keccak256(
            abi.encode(
                address(factory),
                uint256(999),
                USER_A,
                keccak256(initData),
                expiresAt
            )
        );
        bytes memory sig = _signWith(SIGNER_PK, digestOnOtherChain);

        vm.expectRevert(CitrateWalletFactory.InvalidSigner.selector);
        factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
    }

    function test_deployFor_initFailureReverts() public {
        // The mock's init reverts when its `bytes` arg starts with the
        // magic 0xDEADC0DE marker. Trigger that path here.
        bytes memory failingArg = hex"DEADC0DE";
        bytes memory initData = abi.encodeCall(MockImplementation.init, (failingArg));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);

        vm.expectRevert(CitrateWalletFactory.InitializeFailed.selector);
        factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
    }

    // --- Idempotency ---

    function test_deployFor_isIdempotent() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("once"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);

        address first = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
        address second = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
        assertEq(first, second, "redeploy returns same address");

        // Init must have been called exactly once via the proxy's
        // delegatecall to the impl; check directly on the proxy slot —
        // because the proxy delegatecalls to impl, the slot read here is
        // ON THE PROXY'S storage at the same layout as MockImplementation.
        MockImplementation viaProxy = MockImplementation(first);
        assertEq(viaProxy.initCalls(), 1, "init called once total");
    }

    function test_deployFor_returnsExistingAddressOnRepeat() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("once"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);

        address deployed = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
        assertEq(factory.predictAddress(USER_A), deployed);

        // Second call: even with a different (still valid) permit — should
        // return the same address (no second init).
        bytes memory differentInit = abi.encodeCall(MockImplementation.init, ("different"));
        bytes memory sig2 = _permitSig(USER_A, differentInit, expiresAt);
        address again = factory.deployFor(USER_A, address(0xDEAD), differentInit, expiresAt, sig2);
        assertEq(again, deployed);

        MockImplementation viaProxy = MockImplementation(deployed);
        assertEq(viaProxy.initCalls(), 1, "init still only once total");
        // lastInitArgs stores the inner `bytes` argument to init, not the
        // outer selector+encoding — i.e. the literal "once" string bytes.
        assertEq(viaProxy.lastInitArgs(), bytes("once"));
    }

    // --- Admin ---

    function test_setIdentitySigner_onlyOwner() public {
        address newSigner = vm.addr(0xFEED);
        vm.expectRevert(CitrateWalletFactory.NotOwner.selector);
        factory.setIdentitySigner(newSigner);

        vm.prank(ownerAddr);
        factory.setIdentitySigner(newSigner);
        assertEq(factory.identitySigner(), newSigner);
    }

    function test_setIdentitySigner_rejectsZero() public {
        vm.prank(ownerAddr);
        vm.expectRevert(CitrateWalletFactory.ZeroAddress.selector);
        factory.setIdentitySigner(address(0));
    }

    function test_transferOwnership() public {
        address newOwner = address(0xC0FFEE);
        vm.expectRevert(CitrateWalletFactory.NotOwner.selector);
        factory.transferOwnership(newOwner);

        vm.prank(ownerAddr);
        factory.transferOwnership(newOwner);
        assertEq(factory.owner(), newOwner);
    }

    function test_rotatedSignerAuthorizesNewDeploys() public {
        uint256 newSignerPk = 0xFEEDFACE;
        address newSigner = vm.addr(newSignerPk);

        vm.prank(ownerAddr);
        factory.setIdentitySigner(newSigner);

        bytes memory initData = abi.encodeCall(MockImplementation.init, ("post-rotation"));
        uint256 expiresAt = block.timestamp + 1 hours;
        // Old signer signature no longer authorizes.
        bytes memory oldSig = _permitSig(USER_A, initData, expiresAt);
        vm.expectRevert(CitrateWalletFactory.InvalidSigner.selector);
        factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, oldSig);

        // New signer signature does.
        bytes memory newSig = _signWith(newSignerPk, factory.permitDigest(USER_A, initData, expiresAt));
        address deployed = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, newSig);
        assertEq(deployed, factory.predictAddress(USER_A));
    }

    // --- Helpers ---

    function _permitSig(bytes32 userId, bytes memory initData, uint256 expiresAt)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encode(address(factory), block.chainid, userId, keccak256(initData), expiresAt)
        );
        return _signWith(SIGNER_PK, digest);
    }

    function _signWith(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethDigest = digest.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethDigest);
        return abi.encodePacked(r, s, v);
    }
}
