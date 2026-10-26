// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TreasuryGovernor} from "../../src/TreasuryGovernor.sol";
import {StablecoinTreasury} from "../../src/StablecoinTreasury.sol";
import {MockERC20Gov} from "../TreasuryGovernor.t.sol";
import {SaltSupply} from "../../src/lib/SaltSupply.sol";

contract CallTarget {
    uint256 public hits;
    function hit() external { hits++; }
}

/// LiquidStakingPool is not part of block 0: TreasuryGovernor is deployed
/// with no pool (address(0)) and runs its whole lifecycle without ever
/// calling it.
contract GovernorWithoutStakingPoolTest is Test {
    TreasuryGovernor governor;
    StablecoinTreasury treasury;
    MockERC20Gov usdc;
    CallTarget target;
    address guardian = makeAddr("guardian");
    address voter = makeAddr("voter");
    uint256 constant QUORUM = SaltSupply.TOTAL_SUPPLY / 10;
    uint256 h;

    function setUp() public {
        treasury = new StablecoinTreasury(address(this));
        usdc = new MockERC20Gov("USD Coin", "USDC", 6);
        treasury.addStablecoin(address(usdc));
        target = new CallTarget();
        // A reverting constructor leaves `governor` unset, so each test fails
        // on its first assertion rather than in setUp.
        bytes memory init = abi.encodePacked(
            type(TreasuryGovernor).creationCode,
            abi.encode(address(0), address(treasury), guardian, SaltSupply.TOTAL_SUPPLY)
        );
        address g;
        assembly {
            g := create(0, add(init, 0x20), mload(init))
        }
        governor = TreasuryGovernor(payable(g));
        h = block.number;
    }

    function _deployed() internal view {
        assertTrue(address(governor) != address(0), "governor deploys with the liquid-staking path disabled");
    }

    function test_deploysWithNoStakingPool() public view {
        _deployed();
        assertEq(address(governor.stakingPool()), address(0));
    }

    /// Lock -> propose a call -> vote -> queue -> execute -> unlock, and
    /// never a call to address(0).
    function test_fullLifecycle_neverCallsAddressZero() public {
        _deployed();
        vm.expectCall(address(0), bytes(""), 0);
        vm.deal(voter, QUORUM);
        vm.prank(voter);
        governor.lockVotes{value: QUORUM}();
        vm.roll(++h);
        vm.prank(voter);
        uint256 id = governor.proposeCall("t", "d", address(target), 0, abi.encodeCall(CallTarget.hit, ()));
        vm.roll(++h);
        vm.prank(voter);
        governor.castVote(id, TreasuryGovernor.VoteType.For);
        h += governor.VOTING_PERIOD() + 1;
        vm.roll(h);
        governor.queue(id);
        h += governor.EXECUTION_DELAY();
        vm.roll(h);
        governor.execute(id);
        assertEq(target.hits(), 1, "the call proposal executed");
        vm.prank(voter);
        governor.unlockVotes(QUORUM);
        assertEq(voter.balance, QUORUM, "votes unlocked");
    }

    function test_parameterAndEmergencyPaths_neverCallAddressZero() public {
        _deployed();
        vm.expectCall(address(0), bytes(""), 0);
        vm.deal(voter, QUORUM);
        vm.prank(voter);
        governor.lockVotes{value: QUORUM}();
        vm.roll(++h);
        vm.startPrank(voter);
        uint256 a = governor.proposeParameterChange("p", "d", keccak256("k"), 1);
        uint256 b = governor.proposeEmergency("e", "d");
        vm.stopPrank();
        vm.roll(++h);
        vm.prank(voter);
        governor.castVote(a, TreasuryGovernor.VoteType.For);
        vm.prank(guardian);
        governor.cancel(b);
        assertEq(uint256(governor.state(b)), uint256(TreasuryGovernor.ProposalState.Canceled));
    }
}
