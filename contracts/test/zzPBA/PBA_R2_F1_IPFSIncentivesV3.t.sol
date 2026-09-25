// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {MockVerifier, MockFoldVerifier} from "../IPFSIncentivesV3.t.sol";

/// PBA-R2 CONTRACTS-A: evidence/F1/PBA_F1_IPFSIncentivesV3.t.sol turned into
/// regression tests with INVERTED assertions (live 40204 constants).
contract PBA_R2_F1_IPFSIncentivesV3 is Test {
    IPFSIncentivesV3 inc;
    KYCRegistry kyc;
    MockFoldVerifier fold;
    address constant VERIFY = 0x0000000000000000000000000000000000000108;

    address attacker = address(0xA77);
    address attacker2 = address(0xA78);
    address honest = address(0xB0B);
    address modelOwner = address(0x310D);
    bytes32 cid = keccak256("ipfs://legit-model");

    function setUp() public {
        kyc = new KYCRegistry(address(0), address(this));
        fold = new MockFoldVerifier();
        inc = new IPFSIncentivesV3(
            kyc, 10 ether, 4 ether, 4, 1, 5000, 2, 10, 32, 1 ether, 32, 55 ether, 302400, 5000, address(fold), address(this)
        );
        vm.etch(VERIFY, type(MockVerifier).runtimeCode);
        (bool ok,) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", uint256(1)));
        require(ok);
        vm.deal(address(this), 10_000 ether);
        vm.deal(modelOwner, 100 ether);
        vm.deal(attacker, 100 ether);
        vm.deal(honest, 100 ether);
        kyc.setVerified(attacker);
        kyc.setVerified(honest);
        vm.prank(modelOwner);
        inc.registerModel{value: 55 ether}(cid, bytes32("commD"), bytes32("h"), bytes32("dc"), "ipfs://x");
    }

    function _seal(address who, bytes32 rid, uint256 sector) internal {
        vm.prank(who);
        inc.sealCommit{value: 10 ether}(cid, sector, rid, 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00");
    }

    /// PBA-L2-006 (F1-01 inverted): an outsider can no longer move slot
    /// funding into phantom slots — a commit on a slot with no live pin reverts.
    function test_L2_006_commit_cannot_strand_slot_funding() public {
        inc.fund{value: 800 ether}();
        address outsider = address(0xDEAD01);
        vm.startPrank(outsider);
        for (uint256 sector = 1_000_000; sector < 1_000_010; sector++) {
            vm.expectRevert(bytes("No live pin in slot"));
            inc.commitChallenge(cid, sector);
        }
        vm.stopPrank();
        assertEq(inc.unallocatedSlotFunding(), 800 ether, "funding untouched");
        assertEq(inc.totalSlotBudgetFunded(), 0);

        vm.prank(honest);
        inc.registerPinner();
        _seal(honest, bytes32("rid"), 0); // a real pinner can still seal
        vm.prank(outsider);
        inc.commitChallenge(cid, 0); // and a commit on a LIVE slot works
        assertEq(inc.unallocatedSlotFunding(), 792 ether, "only the bonded seal drew funding");
    }

    /// PBA-L2-006 (R2 verifier follow-up): a bonded pinner can no longer pull
    /// slot funding into arbitrary far sectors; sectors are bounded.
    function test_L2_006_seal_sector_bounded() public {
        inc.fund{value: 40 ether}();
        vm.prank(honest);
        inc.registerPinner();
        vm.prank(honest);
        vm.expectRevert(bytes("Sector out of range"));
        inc.sealCommit{value: 10 ether}(cid, 1_000_000, bytes32("rid"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00");
        uint256 maxS = inc.MAX_SECTORS();
        vm.prank(honest);
        vm.expectRevert(bytes("Sector out of range"));
        inc.sealCommit{value: 10 ether}(cid, maxS, bytes32("rid"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00");
        _seal(honest, bytes32("rid"), maxS - 1); // last valid sector
        assertEq(inc.unallocatedSlotFunding(), 32 ether);
    }

    /// PBA-L2-006 tripwire (fuzz): `commitChallenge` never changes
    /// `unallocatedSlotFunding`, for any sector and any caller.
    function testFuzz_L2_006_commit_never_allocates(uint256 sector, address caller) public {
        vm.assume(caller != address(0));
        inc.fund{value: 80 ether}();
        uint256 before = inc.unallocatedSlotFunding();
        vm.prank(caller);
        try inc.commitChallenge(cid, sector) {} catch {}
        assertEq(inc.unallocatedSlotFunding(), before);
    }

    // ── helpers for F1-02 ──
    function _commit() internal returns (uint256 cb) {
        inc.commitChallenge(cid, 0);
        (,,, cb,,) = inc.getSlot(cid, 0);
        vm.roll(cb + 32);
    }

    function _answer(address who) internal returns (bool) {
        (,,,, uint256 nonce,) = inc.getSlot(cid, 0);
        vm.prank(who);
        try inc.submitPoSt(cid, 0, bytes32("R"), bytes32("C"), nonce, hex"00") {
            return true;
        } catch {
            return false;
        }
    }

    function _closeWindow() internal {
        (,,, uint256 cb,,) = inc.getSlot(cid, 0);
        vm.roll(cb + 32 + 10 + 1);
    }

    /// PBA-L2-007 (F1-02 inverted): the starvation cycle can no longer put an
    /// honest pinner into a slot whose budget cannot pay it, so its bond is
    /// never exposed. The honest seal is refused up front (no bond taken).
    function test_L2_007_budget_starvation_cannot_slash_honest_pinner() public {
        inc.fund{value: 8 ether}();
        vm.prank(attacker);
        inc.registerPinner();
        vm.prank(honest);
        inc.registerPinner();

        _seal(attacker, bytes32("ridA"), 0);
        for (uint256 i = 0; i < 3; i++) {
            _commit();
            assertTrue(_answer(attacker));
            _closeWindow();
        }
        vm.prank(attacker);
        inc.claim(cid, 0);
        _commit();
        _closeWindow();
        vm.prank(attacker2);
        inc.slash(attacker, cid, 0);
        _commit();
        _closeWindow();
        vm.prank(attacker2);
        inc.slash(attacker, cid, 0);

        vm.prank(attacker);
        inc.clearSlashed(cid, 0);
        _seal(attacker, bytes32("ridA"), 0);

        uint256 honestBal = honest.balance;
        vm.prank(honest);
        vm.expectRevert(bytes("Insufficient slot budget"));
        inc.sealCommit{value: 10 ether}(cid, 0, bytes32("ridH"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00");
        assertEq(honest.balance, honestBal, "honest bond never at risk");
    }

    /// PBA-L2-007 tripwire: with two live pins every answered round vests
    /// (the reservation covers both), and an answering pin is never Slashed.
    function test_L2_007_answering_pins_always_vest_and_never_slash() public {
        inc.fund{value: 8 ether}();
        vm.prank(attacker);
        inc.registerPinner();
        vm.prank(honest);
        inc.registerPinner();
        _seal(attacker, bytes32("ridA"), 0);
        _seal(honest, bytes32("ridH"), 0);
        for (uint256 i = 0; i < 4; i++) {
            _commit();
            assertTrue(_answer(attacker));
            assertTrue(_answer(honest), "valid proof always accepted");
            _closeWindow();
            // Answered (or Done after the last round): never slashable.
            vm.expectRevert();
            inc.slash(honest, cid, 0);
        }
        (IPFSIncentivesV3.Status st, uint64 round,,,,) = inc.getPin(honest, cid, 0);
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Done));
        assertEq(round, 4);
        (, uint256 budget,,,,) = inc.getSlot(cid, 0);
        assertEq(budget, 0, "exactly 2 x REWARD vested from 2 x REWARD");
    }

    /// PBA-L2-007 boundary: a seal is admitted only if the UNRESERVED budget
    /// covers a full reward (free budget of REWARD - PER_ROUND is not enough).
    function test_L2_007_reservation_boundary() public {
        inc.fund{value: 8 ether}();
        vm.prank(attacker);
        inc.registerPinner();
        vm.prank(honest);
        inc.registerPinner();
        _seal(attacker, bytes32("ridA"), 0);
        _commit();
        assertTrue(_answer(attacker)); // budget 7, reserved 3
        _closeWindow();
        vm.prank(attacker);
        inc.claim(cid, 0);
        _commit();
        _closeWindow();
        vm.prank(attacker2);
        inc.slash(attacker, cid, 0);
        _commit();
        _closeWindow();
        vm.prank(attacker2);
        inc.slash(attacker, cid, 0); // slashed: reservation released, budget 7
        assertEq(inc.slotReserved(cid, 0), 0);
        vm.prank(attacker);
        inc.clearSlashed(cid, 0);
        _seal(attacker, bytes32("ridA"), 0); // reserved 4, free 3
        vm.prank(honest);
        vm.expectRevert(bytes("Insufficient slot budget"));
        inc.sealCommit{value: 10 ether}(cid, 0, bytes32("ridH"), 1, bytes32("commD"), bytes32("R"), bytes32("C"), hex"00");
    }

    /// CON-04 (closed with PBA-L2-007): one commit window vests at most one round.
    function test_CON04_one_window_vests_one_round() public {
        inc.fund{value: 8 ether}();
        vm.prank(honest);
        inc.registerPinner();
        _seal(honest, bytes32("ridH"), 0);
        _commit();
        assertTrue(_answer(honest));
        assertFalse(_answer(honest), "second answer to the same commit refused");
        (, uint64 round,,,,) = inc.getPin(honest, cid, 0);
        assertEq(round, 1);
    }

    receive() external payable {}
}
