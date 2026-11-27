// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {MockVerifier, MockFoldVerifier} from "../IPFSIncentivesV3.t.sol";

/// A slot budget is a reward liability, so the first seal into a slot must
/// draw it from SALT governance actually deposited with `fund()`. A seal into
/// an unfunded (or under-funded) contract must not create a budget out of
/// thin air that later reward claims would pay from pinner bonds.
contract IPFSIncentivesV3SlotBackingTest is Test {
    IPFSIncentivesV3 internal inc;
    KYCRegistry internal kyc;
    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;
    address internal constant PINNER = address(0xB0B);
    address internal constant MODEL_OWNER = address(0x310D);
    bytes32 internal constant CID = keccak256("ipfs://legit-model");

    function setUp() public {
        kyc = new KYCRegistry(address(0), address(this));
        MockFoldVerifier fold = new MockFoldVerifier();
        inc = new IPFSIncentivesV3(
            kyc,
            10 ether,
            4 ether,
            4,
            1,
            5000,
            2,
            10,
            32,
            1 ether,
            32,
            55 ether,
            302400,
            5000,
            address(fold),
            address(this)
        );
        vm.etch(VERIFY, type(MockVerifier).runtimeCode);
        (bool ok,) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", uint256(1)));
        require(ok);
        vm.deal(address(this), 1_000 ether);
        vm.deal(MODEL_OWNER, 100 ether);
        vm.deal(PINNER, 100 ether);
        kyc.setVerified(PINNER);
        vm.prank(MODEL_OWNER);
        inc.registerModel{value: 55 ether}(CID, bytes32("commD"), bytes32("h"), bytes32("dc"), "ipfs://x");
        vm.prank(PINNER);
        inc.registerPinner();
    }

    function _seal() internal {
        vm.prank(PINNER);
        inc.sealCommit{value: 10 ether}(
            CID, 0, bytes32("rid"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00"
        );
    }

    function test_sealIntoUnfundedContractReverts() public {
        vm.prank(PINNER);
        vm.expectRevert(bytes("Insufficient slot funding"));
        inc.sealCommit{value: 10 ether}(
            CID, 0, bytes32("rid"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00"
        );
        assertEq(inc.totalSlotBudgetFunded(), 0, "no budget created without backing");
    }

    function test_sealBelowTheSeedLeavesFundingUntouched() public {
        inc.fund{value: 1 ether}();
        vm.prank(PINNER);
        vm.expectRevert(bytes("Insufficient slot funding"));
        inc.sealCommit{value: 10 ether}(
            CID, 0, bytes32("rid"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00"
        );
        assertEq(inc.unallocatedSlotFunding(), 1 ether);
        assertEq(inc.totalSlotBudgetFunded(), 0);
    }

    function test_fundedSealDrawsExactlyTheSeed() public {
        inc.fund{value: 100 ether}();
        _seal();
        uint256 seeded = inc.totalSlotBudgetFunded();
        assertGt(seeded, 0);
        assertEq(inc.unallocatedSlotFunding() + seeded, 100 ether, "budget is carved out of deposited funding");
    }
}
