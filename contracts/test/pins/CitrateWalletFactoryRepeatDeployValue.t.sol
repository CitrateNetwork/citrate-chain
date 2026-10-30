// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {StubEntryPoint} from "../aa/CitratePaymaster.t.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// Wallet implementation that can receive plain value transfers.
contract PayableWalletImpl {
    uint256 public initCalls;

    function init(bytes calldata) external payable {
        initCalls += 1;
    }

    receive() external payable {}
}

/// `deployFor` is payable and idempotent. When the account already exists the
/// call is a no-op, and any value sent with it goes to that account instead of
/// staying in the factory (which has no way to pay it out).
contract CitrateWalletFactoryRepeatDeployValueTest is Test {
    using MessageHashUtils for bytes32;

    CitrateWalletFactory internal factory;
    uint256 internal constant SIGNER_PK = 0x59E7;
    address internal signer;
    address internal constant OWNER = address(0xA11CE);
    bytes32 internal constant USER = keccak256("repeat-deploy-user");
    address internal constant FUNDER = address(0xF0);

    function setUp() public {
        PayableWalletImpl impl = new PayableWalletImpl();
        signer = vm.addr(SIGNER_PK);
        factory = new CitrateWalletFactory(address(impl), signer, OWNER);
        StubEntryPoint ep = new StubEntryPoint();
        CitratePaymaster pm = new CitratePaymaster(
            IEntryPoint(address(ep)),
            OWNER,
            address(factory),
            signer,
            0.01 ether,
            0.01 ether,
            0.02 ether,
            20 gwei,
            5 ether
        );
        vm.prank(OWNER);
        factory.setPaymaster(address(pm));
        vm.deal(FUNDER, 10 ether);
    }

    function _deploy(uint256 value) internal returns (address) {
        bytes memory initData = abi.encodeCall(PayableWalletImpl.init, ("x"));
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 digest = factory.permitDigest(USER, initData, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest.toEthSignedMessageHash());
        vm.prank(FUNDER);
        return factory.deployFor{value: value}(USER, address(0xDEAD), initData, expiresAt, abi.encodePacked(r, s, v));
    }

    function test_valueOnRepeatDeployIsForwardedToTheExistingAccount() public {
        address account = _deploy(0);
        uint256 before = account.balance;

        address again = _deploy(1 ether);
        assertEq(again, account, "idempotent: same account");
        assertEq(account.balance - before, 1 ether, "value reaches the existing account");
        assertEq(address(factory).balance, 0, "nothing is trapped in the factory");
        assertEq(PayableWalletImpl(payable(account)).initCalls(), 1, "no second init");
    }

    function test_repeatDeployWithoutValueMovesNothing() public {
        address account = _deploy(0);
        uint256 before = account.balance;
        _deploy(0);
        assertEq(account.balance, before);
        assertEq(address(factory).balance, 0);
    }
}
