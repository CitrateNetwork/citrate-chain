// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TreasuryGovernor} from "../../src/TreasuryGovernor.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";
import {StablecoinTreasury} from "../../src/StablecoinTreasury.sol";

/// PBA-L2-001: escrow/snapshot behaviour of the fixed TreasuryGovernor, plus
/// the vote-sum invariant tripwire.
contract PBA_L2_001_EscrowTest is Test {
    TreasuryGovernor gov;

    function setUp() public {
        vm.roll(10);
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        StablecoinTreasury treasury = new StablecoinTreasury(address(this));
        gov = new TreasuryGovernor(address(pool), address(treasury), address(0xDEAD), 1e27);
        vm.deal(address(gov), 500 ether);
    }

    /// Live balance (no escrow) carries no weight at all.
    function test_L2_001_liveBalanceIsNotVotingPower() public {
        address whale = makeAddr("whale");
        vm.deal(whale, 900_000_000 ether);
        address locker = makeAddr("locker");
        vm.deal(locker, 20_000 ether);
        vm.prank(locker);
        gov.lockVotes{value: 20_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(locker);
        uint256 id = gov.proposeCall("t", "d", locker, 1 ether, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(whale);
        vm.expectRevert("TreasuryGovernor: no voting power");
        gov.castVote(id, TreasuryGovernor.VoteType.For);
    }

    /// SALT locked in the proposal's own block is not in its snapshot.
    function test_L2_001_lockAfterSnapshotDoesNotCount() public {
        address p = makeAddr("proposer");
        vm.deal(p, 20_000 ether);
        vm.prank(p);
        gov.lockVotes{value: 20_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(p);
        uint256 id = gov.proposeCall("t", "d", p, 1 ether, hex"00000000");

        address late = makeAddr("late");
        vm.deal(late, 200_000_000 ether);
        vm.prank(late);
        gov.lockVotes{value: 200_000_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(late);
        vm.expectRevert("TreasuryGovernor: no voting power");
        gov.castVote(id, TreasuryGovernor.VoteType.For);
    }

    /// Same-block lock cannot create a proposal (threshold read at block-1).
    function test_L2_001_flashLockCannotPropose() public {
        address p = makeAddr("flash");
        vm.deal(p, 20_000 ether);
        vm.startPrank(p);
        gov.lockVotes{value: 20_000 ether}();
        vm.expectRevert("TreasuryGovernor: below proposal threshold");
        gov.proposeCall("t", "d", p, 1 ether, hex"00000000");
        vm.stopPrank();
    }

    /// Escrowed SALT is a liability: a passed Call proposal cannot spend it.
    function test_L2_001_callCannotSpendEscrow() public {
        address v = makeAddr("bigVoter");
        vm.deal(v, 200_000_000 ether);
        vm.prank(v);
        gov.lockVotes{value: 200_000_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        // Spend 500 surplus + 1 wei of escrow.
        vm.prank(v);
        uint256 id = gov.proposeCall("t", "d", v, 500 ether + 1, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(v);
        gov.castVote(id, TreasuryGovernor.VoteType.For);
        vm.roll(vm.getBlockNumber() + gov.VOTING_PERIOD() + 1);
        gov.queue(id);
        vm.roll(vm.getBlockNumber() + gov.EXECUTION_DELAY());
        vm.expectRevert("TreasuryGovernor: call would spend escrowed votes");
        gov.execute(id);
    }

    /// Votes cast keep their snapshot weight after unlock; unlock pays back.
    function test_L2_001_unlockReturnsEscrowAndKeepsCastWeight() public {
        address v = makeAddr("v");
        vm.deal(v, 150_000_000 ether);
        vm.prank(v);
        gov.lockVotes{value: 150_000_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(v);
        uint256 id = gov.proposeCall("t", "d", v, 1 ether, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(v);
        gov.castVote(id, TreasuryGovernor.VoteType.For);
        vm.prank(v);
        gov.unlockVotes(150_000_000 ether);
        assertEq(v.balance, 150_000_000 ether);
        assertEq(gov.totalLocked(), 0);
        (, , , , , , , , , uint256 forVotes, , , ,) = gov.getProposal(id);
        assertEq(forVotes, 150_000_000 ether);
        assertEq(gov.getPastVotes(v, gov.proposalSnapshot(id)), 150_000_000 ether);
        assertEq(gov.getVotingPower(v), 0);
    }
}

/// Tripwire (PBA-L2-001): a handler that locks, unlocks, moves SALT between
/// actors and votes mid-vote can never push the counted votes above the
/// escrow that existed at the snapshot.
contract GovVoteHandler is Test {
    TreasuryGovernor public gov;
    uint256 public id;
    address[] public actors;

    constructor(TreasuryGovernor g, uint256 id_, address[] memory a) {
        gov = g;
        id = id_;
        actors = a;
    }

    function _actor(uint256 s) internal view returns (address) {
        return actors[s % actors.length];
    }

    function lock(uint256 s, uint256 amt) external {
        address a = _actor(s);
        amt = bound(amt, 0, a.balance);
        if (amt == 0) return;
        vm.prank(a);
        gov.lockVotes{value: amt}();
    }

    function unlock(uint256 s, uint256 amt) external {
        address a = _actor(s);
        uint256 bal = gov.lockedBalance(a);
        if (bal == 0) return;
        amt = bound(amt, 1, bal);
        vm.prank(a);
        gov.unlockVotes(amt);
    }

    function move(uint256 s1, uint256 s2, uint256 amt) external {
        address a = _actor(s1);
        address b = _actor(s2);
        amt = bound(amt, 0, a.balance);
        vm.prank(a);
        (bool ok,) = payable(b).call{value: amt}("");
        require(ok);
    }

    function vote(uint256 s, uint8 support) external {
        address a = _actor(s);
        if (gov.hasVoted(id, a)) return;
        if (gov.getPastVotes(a, gov.proposalSnapshot(id)) == 0) return;
        vm.prank(a);
        gov.castVote(id, TreasuryGovernor.VoteType(support % 3));
    }
}

contract PBA_L2_001_VoteInvariant is Test {
    TreasuryGovernor gov;
    GovVoteHandler handler;
    uint256 id;

    function setUp() public {
        vm.roll(10);
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        StablecoinTreasury treasury = new StablecoinTreasury(address(this));
        gov = new TreasuryGovernor(address(pool), address(treasury), address(0xDEAD), 1e27);
        address[] memory a = new address[](5);
        for (uint256 i = 0; i < a.length; i++) {
            a[i] = address(uint160(0xA0000 + i));
            vm.deal(a[i], 50_000_000 ether);
        }
        vm.prank(a[0]);
        gov.lockVotes{value: 30_000_000 ether}();
        vm.prank(a[1]);
        gov.lockVotes{value: 10_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(a[0]);
        id = gov.proposeCall("t", "d", a[0], 1 ether, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);
        handler = new GovVoteHandler(gov, id, a);
        targetContract(address(handler));
    }

    function invariant_countedVotesNeverExceedSnapshotEscrow() public view {
        (, , , , , , , , , uint256 f, uint256 ag, uint256 ab, ,) = gov.getProposal(id);
        assertLe(f + ag + ab, gov.getPastTotalLocked(gov.proposalSnapshot(id)));
    }
}

/// Verifier-contributed hardening (PBA-L2-001): an unlock BEFORE the snapshot
/// must zero that account's snapshot weight (kills the mutant where
/// unlockVotes skips the per-account checkpoint), and the guardian can never
/// be the CREATE2 factory.
contract PBA_L2_001_VerifierHardening is Test {
    TreasuryGovernor gov;
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function setUp() public {
        vm.roll(10);
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        StablecoinTreasury treasury = new StablecoinTreasury(address(this));
        gov = new TreasuryGovernor(address(pool), address(treasury), address(0xDEAD), 1e27);
    }

    function test_V_001_unlockBeforeSnapshotZeroesWeight() public {
        address atk = makeAddr("atk");
        address hon = makeAddr("hon");
        vm.deal(atk, 50_000 ether);
        vm.deal(hon, 50_000 ether);
        vm.prank(atk);
        gov.lockVotes{value: 50_000 ether}();
        vm.prank(hon);
        gov.lockVotes{value: 50_000 ether}();
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(atk);
        gov.unlockVotes(50_000 ether);
        vm.roll(vm.getBlockNumber() + 1);
        assertEq(gov.getPastVotes(atk, vm.getBlockNumber() - 1), 0);
        vm.prank(hon);
        uint256 id = gov.proposeCall("t", "d", hon, 1 ether, hex"00000000");
        vm.roll(vm.getBlockNumber() + 1);
        vm.prank(atk);
        vm.expectRevert("TreasuryGovernor: no voting power");
        gov.castVote(id, TreasuryGovernor.VoteType.Against);
        vm.prank(hon);
        gov.castVote(id, TreasuryGovernor.VoteType.For);
    }

    function test_L2_001_guardianCannotBeFactory() public {
        LiquidStakingPool pool = new LiquidStakingPool(address(this));
        StablecoinTreasury treasury = new StablecoinTreasury(address(this));
        vm.expectRevert("TreasuryGovernor: factory guardian");
        new TreasuryGovernor(address(pool), address(treasury), FACTORY, 1e27);
    }

    function test_L2_001_guardianCannotBeTransferredToFactory() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("TreasuryGovernor: factory guardian");
        gov.transferGuardian(FACTORY);
        assertEq(gov.guardian(), address(0xDEAD));
    }
}
