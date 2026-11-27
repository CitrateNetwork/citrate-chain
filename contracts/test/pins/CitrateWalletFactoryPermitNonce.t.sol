// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {MockImplementation} from "../aa/CitrateWalletFactory.t.sol";
import {StubEntryPoint} from "../aa/CitratePaymaster.t.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// The permit nonce is what makes a deploy permit single-use for the issuer:
/// the SDK reads `deployNonce(userId)` to build the next permit, and
/// `permitDigest` must move once a permit has been consumed. `deployFor`
/// itself short-circuits for an existing account before it checks a
/// signature, so these properties are only visible through the two views.
contract CitrateWalletFactoryPermitNonceTest is Test {
    using MessageHashUtils for bytes32;

    CitrateWalletFactory internal factory;
    uint256 internal constant SIGNER_PK = 0x59E7;
    address internal ownerAddr = address(0xA11CE);
    bytes32 internal constant USER_A = keccak256("user-a");
    bytes32 internal constant USER_B = keccak256("user-b");

    function setUp() public {
        MockImplementation impl = new MockImplementation();
        address signer = vm.addr(SIGNER_PK);
        factory = new CitrateWalletFactory(address(impl), signer, ownerAddr);
        StubEntryPoint ep = new StubEntryPoint();
        CitratePaymaster pm = new CitratePaymaster(
            IEntryPoint(address(ep)),
            ownerAddr,
            address(factory),
            signer,
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(ownerAddr);
        factory.setPaymaster(address(pm));
    }

    function _permitSig(bytes32 userId, bytes memory initData, uint256 expiresAt) internal view returns (bytes memory) {
        bytes32 ethDigest = factory.permitDigest(userId, initData, expiresAt).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, ethDigest);
        return abi.encodePacked(r, s, v);
    }

    function _deploy(bytes32 userId, bytes memory initData, uint256 expiresAt) internal returns (address) {
        bytes memory sig = _permitSig(userId, initData, expiresAt);
        return factory.deployFor(userId, address(0xDEAD), initData, expiresAt, sig);
    }

    function test_initializingDeployConsumesThePermitNonce() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("n"));
        uint256 expiresAt = block.timestamp + 1 hours;
        assertEq(factory.deployNonce(USER_A), 0);
        _deploy(USER_A, initData, expiresAt);
        assertEq(factory.deployNonce(USER_A), 1, "the initializing deploy consumes the nonce");
        assertEq(factory.deployNonce(USER_B), 0, "other users' nonces are untouched");
    }

    function test_consumedPermitDigestNoLongerMatches() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("n"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 before = factory.permitDigest(USER_A, initData, expiresAt);
        _deploy(USER_A, initData, expiresAt);
        bytes32 afterDeploy = factory.permitDigest(USER_A, initData, expiresAt);
        assertTrue(before != afterDeploy, "a consumed permit's digest must not be reissuable");
    }

    function test_idempotentRedeployDoesNotAdvanceTheNonce() public {
        bytes memory initData = abi.encodeCall(MockImplementation.init, ("n"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes memory sig = _permitSig(USER_A, initData, expiresAt);
        address a = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
        address b = factory.deployFor(USER_A, address(0xDEAD), initData, expiresAt, sig);
        assertEq(a, b);
        assertEq(factory.deployNonce(USER_A), 1, "short-circuit path consumes nothing");
        assertEq(MockImplementation(a).initCalls(), 1, "init ran exactly once");
    }
}
