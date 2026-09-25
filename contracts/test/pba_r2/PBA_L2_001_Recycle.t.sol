// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TreasuryGovernor} from "../../src/TreasuryGovernor.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";
import {StablecoinTreasury} from "../../src/StablecoinTreasury.sol";

/// PBA-L2-001 regression (pre-bounty audit 2026-09-24): the lane PoC
/// `test_F2_01_recycledBalance_passesQuorum_andExecutesCall`, inverted.
///
/// The escrow entry points (`lockVotes`/`unlockVotes`) are reached through
/// low-level calls so this file compiles against the pre-fix governor too;
/// that is what lets the revert check re-run it on the vulnerable code.
contract PBA_L2_001_TreasuryGovernorTest is Test {
    TreasuryGovernor gov;

    function setUp() public {
        vm.roll(10);
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        StablecoinTreasury treasury = new StablecoinTreasury(address(this));
        gov = new TreasuryGovernor(address(pool), address(treasury), address(0xDEAD), 1e27);
        vm.deal(address(gov), 500 ether);
    }

    function _lock(address who, uint256 amount) internal {
        vm.prank(who);
        (bool ok,) = address(gov).call{value: amount}(abi.encodeWithSignature("lockVotes()"));
        ok; // pre-fix: no such function (reverts, SALT stays with `who`)
    }

    function _unlockAll(address who) internal {
        (bool ok, bytes memory ret) = address(gov).staticcall(abi.encodeWithSignature("lockedBalance(address)", who));
        if (!ok || ret.length != 32) return;
        uint256 bal = abi.decode(ret, (uint256));
        if (bal == 0) return;
        vm.prank(who);
        (ok,) = address(gov).call(abi.encodeWithSignature("unlockVotes(uint256)", bal));
        require(ok, "unlock");
    }

    /// The lane PoC: a 1 % holder recycles one stack through 11 addresses.
    /// After the fix only the snapshot escrow counts, so the hops add nothing,
    /// the proposal fails quorum, and the governor's SALT stays put.
    function test_L2_001_recycledStack_cannotForgeQuorum() public {
        address a0 = makeAddr("attacker0");
        uint256 stack = 10_000_000 ether; // 1 % of 1e27
        vm.deal(a0, stack);
        _lock(a0, stack);
        vm.roll(vm.getBlockNumber() + 1);

        vm.prank(a0);
        uint256 id = gov.proposeCall("t", "d", a0, 500 ether, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);

        address cur = a0;
        for (uint256 i = 0; i < 11; i++) {
            vm.prank(cur);
            try gov.castVote(id, TreasuryGovernor.VoteType.For) {} catch {}
            address nxt = makeAddr(string(abi.encodePacked("hop", vm.toString(i))));
            _unlockAll(cur);
            uint256 bal = cur.balance;
            vm.prank(cur);
            (bool ok,) = payable(nxt).call{value: bal}("");
            require(ok);
            _lock(nxt, bal);
            cur = nxt;
        }
        (, , , , , , , , , uint256 forVotes, , , ,) = gov.getProposal(id);
        assertLt(forVotes, gov.quorumThreshold(), "recycled 1% stack must not reach the 10% quorum");
        assertLe(forVotes, stack, "counted votes never exceed the attacker's snapshot escrow");

        vm.roll(vm.getBlockNumber() + gov.VOTING_PERIOD() + 1);
        assertEq(uint256(gov.state(id)), uint256(TreasuryGovernor.ProposalState.Failed));
        vm.expectRevert("TreasuryGovernor: not succeeded");
        gov.queue(id);
        assertGe(address(gov).balance, 500 ether, "governor funds untouched");
    }

}
