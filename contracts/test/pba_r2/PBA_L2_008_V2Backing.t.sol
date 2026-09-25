// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV2} from "../../src/IPFSIncentivesV2.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {Handler, InvVerifier} from "../IPFSIncentivesV2Invariant.t.sol";

contract MockVerifier0108 {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

/// PBA-L2-008 regression (pre-bounty audit 2026-09-24): the lane PoC
/// `test_F2_03_v2_unbackedBudget_paysRewardFromOtherBonds`, inverted.
contract PBA_L2_008_V2BackingTest is Test {
    KYCRegistry kyc;
    IPFSIncentivesV2 inc;
    address honest = makeAddr("honest");
    address attacker = makeAddr("attacker");
    bytes32 cidH = keccak256("honest-model");
    bytes32 cidA = keccak256("attacker-own-data");

    function setUp() public {
        vm.etch(address(0x0108), type(MockVerifier0108).runtimeCode);
        kyc = new KYCRegistry(address(0), address(this));
        // Live 40204 params: BOND 10, REWARD 4, QUORUM 2, ROUNDS 4.
        inc = new IPFSIncentivesV2(kyc, 10 ether, 4 ether, 4, 1, 5000, 2, 10, 32, address(this));
        kyc.setVerified(honest);
        kyc.setVerified(attacker);
        vm.deal(honest, 10 ether);
        vm.deal(attacker, 10 ether);
        vm.prank(honest);
        inc.registerPinner();
        vm.prank(attacker);
        inc.registerPinner();
    }

    /// The PoC, unfunded: opening a slot no longer mints a phantom budget.
    function test_L2_008_unfundedSlot_cannotOpen() public {
        vm.prank(honest);
        vm.expectRevert("Insufficient slot funding");
        inc.sealCommit{value: 10 ether}(cidH, 0, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), hex"01");
    }

    /// The PoC's end state can no longer be reached: after the attacker vests,
    /// claims and takes its bond back, the honest pinner's bond is intact,
    /// because the reward came from `fund()` backing, not from the bond pool.
    function test_L2_008_rewardNeverComesFromOtherBonds() public {
        vm.deal(address(this), 16 ether);
        inc.fund{value: 16 ether}(); // exactly two slots of QUORUM*REWARD = 8
        vm.prank(honest);
        inc.sealCommit{value: 10 ether}(cidH, 0, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), hex"01");
        vm.prank(attacker);
        inc.sealCommit{value: 10 ether}(cidA, 0, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), hex"01");

        for (uint256 r = 0; r < 4; r++) {
            vm.prank(attacker);
            inc.challenge(cidA, 0);
            (,,,,,,, uint256 nonce) = inc.getPin(attacker, cidA, 0);
            vm.prank(attacker);
            inc.submitPoSt(cidA, 0, bytes32(uint256(2)), bytes32(uint256(3)), nonce, hex"01");
        }
        vm.startPrank(attacker);
        inc.claim(cidA, 0);
        inc.returnBond(cidA, 0);
        vm.stopPrank();
        assertEq(attacker.balance, 14 ether, "attacker: bond back + 4 SALT reward (from backing)");
        // Honest bond (10) + the honest slot's untouched budget (8) + the rest
        // of the attacker slot's budget (4) remain fully backed.
        assertEq(address(inc).balance, 22 ether);
        (, , , , uint256 bondHeld, , , ) = inc.getPin(honest, cidH, 0);
        assertLe(bondHeld, address(inc).balance, "honest bond is backed");
    }

    /// A third fresh slot with no backing left is refused.
    function test_L2_008_backingIsConsumedPerSlot() public {
        vm.deal(address(this), 8 ether);
        inc.fund{value: 8 ether}();
        vm.prank(honest);
        inc.sealCommit{value: 10 ether}(cidH, 0, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), hex"01");
        vm.prank(attacker);
        vm.expectRevert("Insufficient slot funding");
        inc.sealCommit{value: 10 ether}(cidA, 0, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), hex"01");
    }
}

/// Tripwire (PBA-L2-008): with NO `fund()` in setUp, the contract balance must
/// always cover every liability — live bonds, owed rewards, slot budgets,
/// unallocated backing and challenger credit — whatever the fuzzer does.
contract PBA_L2_008_V2SolvencyInvariant is Test {
    IPFSIncentivesV2 internal inc;
    KYCRegistry internal kyc;
    Handler internal handler;
    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    function setUp() public {
        vm.etch(VERIFY, type(InvVerifier).runtimeCode);
        kyc = new KYCRegistry(address(0), address(this));
        inc = new IPFSIncentivesV2(kyc, 10 ether, 4 ether, 4, 1, 5000, 2, 5, 16, address(this));
        // Deliberately NO inc.fund(): budgets must never appear from nothing.
        kyc.setVerified(address(0xA1));
        kyc.setVerified(address(0xA2));
        handler = new Handler(inc, kyc);
        targetContract(address(handler));
    }

    function invariant_Solvent() public view {
        // `unallocatedSlotFunding` is read low-level so this tripwire also
        // compiles (and fails) against the pre-fix contract, which has none.
        (bool ok, bytes memory ret) = address(inc).staticcall(abi.encodeWithSignature("unallocatedSlotFunding()"));
        uint256 liabilities = ok && ret.length == 32 ? abi.decode(ret, (uint256)) : 0;
        for (uint256 j; j < 2; j++) {
            bytes32 cid = handler.cids(j);
            (, uint256 budget, ) = inc.getSlot(cid, 0);
            liabilities += budget;
            for (uint256 i; i < 2; i++) {
                address p = handler.pinners(i);
                (, , , , uint256 bondHeld, , , ) = inc.getPin(p, cid, 0);
                liabilities += bondHeld + inc.owedOf(p, cid, 0);
            }
        }
        liabilities += inc.challengerCredit(address(handler)) + inc.challengerCredit(address(this));
        assertGe(address(inc).balance, liabilities);
    }

    /// Non-vacuity: unfunded, a seal must fail, so no reward can ever be paid.
    function test_L2_008_unfundedHandlerSealFails() public {
        handler.seal(0, 0);
        assertEq(handler.sealedCount(), 0);
        assertEq(inc.paidTotal(), 0);
    }
}
