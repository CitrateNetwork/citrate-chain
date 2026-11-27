// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {MockFoldVerifier} from "../IPFSIncentivesV3.t.sol";

/// @notice The honest-pinner compensation pool is funded by the real
///         wrong-root slash path and can be paid out by the admin, and only by
///         the admin. Pins the full lifecycle: accrue -> withdraw -> empty.
contract IPFSIncentivesCompensationPoolTest is Test {
    event CompensationPoolWithdrawn(address indexed to, uint256 amount);

    IPFSIncentivesV3 internal inc;
    KYCRegistry internal kyc;
    MockFoldVerifier internal fold;

    address internal admin = address(this);
    address internal challenger = address(0xC44A);
    address internal modelOwner = address(0x310D);
    address internal distributor = address(0xD157);
    address internal stranger = address(0x5743);

    uint256 internal constant MIN_MODEL_BOND = 5 ether;
    uint256 internal constant MODEL_CHALLENGER_BPS = 5000;

    bytes32 internal cid = keccak256("ipfs://model");
    bytes internal constant PROOF_REAL = hex"C0FFEE01";
    bytes32 internal constant REAL_COMMD = keccak256("real-commD");
    bytes32 internal constant REAL_DATACOMMIT = keccak256("real-dataCommit");

    function setUp() public {
        kyc = new KYCRegistry(address(0), address(this));
        fold = new MockFoldVerifier();
        inc = new IPFSIncentivesV3(
            kyc,
            10 ether, // pin bond
            4 ether, // reward
            4, // rounds
            0, // max missed
            5000, // challenger bps
            2, // quorum
            10, // response window
            32, // challenge n
            1 ether, // challenger bond
            32, // reveal delay
            MIN_MODEL_BOND,
            100, // model challenge window
            MODEL_CHALLENGER_BPS,
            address(fold),
            address(this)
        );
        vm.deal(modelOwner, 100 ether);
        vm.deal(challenger, 100 ether);
    }

    /// Register a model with a wrong commD and slash it through challengeWrongCommD.
    function _accrueViaSlash() internal returns (uint256 pool) {
        fold.setProof(keccak256(PROOF_REAL), REAL_COMMD, REAL_DATACOMMIT);
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(
            cid, keccak256("WRONG_commD"), keccak256("data"), REAL_DATACOMMIT, "ipfs://x"
        );
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, PROOF_REAL, 1, 0, new uint256[](0));
        pool = MIN_MODEL_BOND - (MIN_MODEL_BOND * MODEL_CHALLENGER_BPS) / 10000;
        assertEq(inc.honestPinnerCompensationPool(), pool, "slash accrues the remainder to the pool");
    }

    function test_compensationPool_adminWithdrawsAccruedSlash() public {
        uint256 pool = _accrueViaSlash();
        uint256 contractBefore = address(inc).balance;
        uint256 before = distributor.balance;

        vm.expectEmit(true, false, false, true, address(inc));
        emit CompensationPoolWithdrawn(distributor, pool);
        inc.withdrawCompensationPool(distributor);

        assertEq(distributor.balance - before, pool, "recipient receives the whole pool");
        assertEq(contractBefore - address(inc).balance, pool, "funds leave the contract");
        assertEq(inc.honestPinnerCompensationPool(), 0, "pool is zeroed");

        vm.expectRevert("Empty pool");
        inc.withdrawCompensationPool(distributor);
    }

    function test_compensationPool_nonAdminCannotWithdraw() public {
        _accrueViaSlash();
        vm.prank(stranger);
        vm.expectRevert("AccessControl: account missing role");
        inc.withdrawCompensationPool(stranger);
        assertGt(inc.honestPinnerCompensationPool(), 0, "pool untouched");
    }

    function test_compensationPool_rejectsZeroRecipient() public {
        _accrueViaSlash();
        vm.expectRevert("Zero recipient");
        inc.withdrawCompensationPool(address(0));
    }

    function test_compensationPool_emptyPoolReverts() public {
        assertEq(inc.honestPinnerCompensationPool(), 0);
        vm.expectRevert("Empty pool");
        inc.withdrawCompensationPool(distributor);
    }
}
