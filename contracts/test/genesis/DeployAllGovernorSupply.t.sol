// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {TreasuryGovernor} from "../../src/TreasuryGovernor.sol";

/// TreasuryGovernor as deployed by DeployAll must count quorum against the
/// canonical SALT supply: 1,000,000,000,000 SALT, 18 decimals, the value of
/// `TOTAL_SUPPLY` in core/economics/src/lib.rs (the genesis cap). SALT is the
/// native coin, so there is no token contract to read a totalSupply from; the
/// canonical constant is the only supply basis.
contract DeployAllGovernorSupplyTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    uint256 constant CANON_SUPPLY = 1_000_000_000_000 ether;
    uint256 constant CANON_QUORUM = CANON_SUPPLY / 10; // QUORUM_BPS = 1_000

    address multisig = makeAddr("multisig");
    TreasuryGovernor governor;

    function setUp() public {
        DeployAll a = new DeployAll();
        DeployAll.Deployed memory d = a.deployWith(SENDER, multisig, multisig);
        governor = TreasuryGovernor(payable(d.governor));
    }

    function test_governorSupplyBasis_isCanonicalSupply() public view {
        assertEq(governor.totalSaltSupply(), CANON_SUPPLY, "governor supply basis = 1T SALT canon");
    }

    function test_governorQuorum_isTenPercentOfCanon() public view {
        assertEq(governor.quorumThreshold(), CANON_QUORUM, "quorum = 100B SALT");
    }

    /// Lock `amount`, propose, vote For with all of it, and return the state
    /// once voting has closed.
    function _runVote(uint256 amount) internal returns (TreasuryGovernor.ProposalState) {
        // Track the height locally: under via-IR, `block.number` reads after
        // vm.roll can be folded to the pre-roll value.
        uint256 h = block.number;
        address voter = makeAddr("voter");
        vm.deal(voter, amount);
        vm.prank(voter);
        governor.lockVotes{value: amount}();
        vm.roll(++h);

        vm.prank(voter);
        uint256 id = governor.proposeParameterChange("p", "d", keccak256("k"), 1);
        vm.roll(++h);

        vm.prank(voter);
        governor.castVote(id, TreasuryGovernor.VoteType.For);
        vm.roll(h + governor.VOTING_PERIOD() + 1);
        return governor.state(id);
    }

    /// 100M SALT was the whole quorum under the old 1B basis; against the
    /// canon it is a tenth of a percent of supply and must not carry a vote.
    function test_quorum_oldBasisQuorumNoLongerPasses() public {
        assertEq(uint256(_runVote(100_000_000 ether)), uint256(TreasuryGovernor.ProposalState.Failed));
    }

    function test_quorum_oneWeiBelowFails() public {
        assertEq(uint256(_runVote(CANON_QUORUM - 1)), uint256(TreasuryGovernor.ProposalState.Failed));
    }

    function test_quorum_exactlyAtPasses() public {
        assertEq(uint256(_runVote(CANON_QUORUM)), uint256(TreasuryGovernor.ProposalState.Succeeded));
    }
}
