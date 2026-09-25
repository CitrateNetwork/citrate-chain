// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TreasuryGovernor} from "../src/TreasuryGovernor.sol";
import {LiquidStakingPool} from "../src/LiquidStakingPool.sol";
import {StablecoinTreasury} from "../src/StablecoinTreasury.sol";

/// @dev Minimal ERC-20 mock for stablecoin interactions
contract MockERC20Gov {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "MockERC20: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "MockERC20: insufficient balance");
        require(allowance[from][msg.sender] >= amount, "MockERC20: insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TreasuryGovernorTest is Test {
    TreasuryGovernor public governor;
    LiquidStakingPool public stakingPool;
    StablecoinTreasury public treasury;
    MockERC20Gov public usdc;

    address public guardianAddr;
    address public proposer;
    address public voter1;
    address public voter2;
    address public voter3;
    address public outsider;
    address public recipient1;
    address public recipient2;

    uint256 public constant TOTAL_SUPPLY = 1_000_000_000 ether; // 1B SALT
    uint256 public constant PROPOSAL_THRESHOLD = 10_000 ether;

    function setUp() public {
        guardianAddr = address(0x6AAD);
        proposer = address(0xF001);
        voter1 = address(0xA001);
        voter2 = address(0xA002);
        voter3 = address(0xA003);
        outsider = address(0xBAD1);
        recipient1 = address(0xB001);
        recipient2 = address(0xB002);

        // Deploy LiquidStakingPool (governance = this test contract)
        stakingPool = new LiquidStakingPool(address(this));

        // Deploy StablecoinTreasury (governance = this test contract)
        treasury = new StablecoinTreasury(address(this));

        // Deploy mock USDC and set up treasury
        usdc = new MockERC20Gov("USD Coin", "USDC", 6);
        treasury.addStablecoin(address(usdc));

        // Deploy TreasuryGovernor
        governor = new TreasuryGovernor(
            address(stakingPool),
            address(treasury),
            guardianAddr,
            TOTAL_SUPPLY
        );

        // Fund treasury via deposit() so stablecoinBalances is tracked correctly
        address depositor = address(0xDE90);
        usdc.mint(depositor, 1_000_000e6);
        vm.startPrank(depositor);
        usdc.approve(address(treasury), 1_000_000e6);
        treasury.deposit(address(usdc), 1_000_000e6);
        vm.stopPrank();

        // Transfer treasury governance to the governor contract
        // so it can call treasury.distribute(). Post Governable
        // migration (audit SOL-21), this is a two-step process:
        // current governance proposes, then the governor pulls.
        treasury.transferGovernance(address(governor));
        governor.acceptGovernanceOf(address(treasury));

        // Fund accounts with SALT and ESCROW it as voting power. PBA-L2-001:
        // voting power is the escrow at the proposal snapshot (block - 1), not
        // the live balance, so every voter locks here and one block passes
        // before any proposal is created.
        vm.deal(proposer, 50_000 ether);
        vm.deal(voter1, 200_000_000 ether + 1_000 ether); // 200M SALT — large voter (+ gas/staking float)
        vm.deal(voter2, 150_000_000 ether); // 150M SALT
        vm.deal(voter3, 100_000_000 ether); // 100M SALT
        vm.deal(outsider, 1 ether);
        _lock(proposer, 50_000 ether);
        _lock(voter1, 200_000_000 ether);
        _lock(voter2, 150_000_000 ether);
        _lock(voter3, 100_000_000 ether);
        _lock(outsider, 1 ether);
        vm.roll(block.number + 1);
    }

    function _lock(address who, uint256 amount) internal {
        vm.prank(who);
        governor.lockVotes{value: amount}();
    }

    // ============================================================
    // Helper: Create and pass a TreasurySpend proposal
    // ============================================================

    function _createSpendProposal() internal returns (uint256 proposalId) {
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 60_000e6;
        amounts[1] = 40_000e6;

        vm.prank(proposer);
        proposalId = governor.proposeTreasurySpend(
            "Fund community grants",
            "Distribute $100K to community contributors",
            address(usdc),
            recipients,
            amounts
        );
    }

    function _voteAndPass(uint256 proposalId) internal {
        // Advance to voting start
        vm.roll(block.number + 2);

        // Large voters vote For
        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
        vm.prank(voter2);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    // ============================================================
    // Test 1: Deploy with correct initial state
    // ============================================================

    function test_deploy_correct_state() public view {
        assertEq(governor.guardian(), guardianAddr);
        assertEq(governor.totalSaltSupply(), TOTAL_SUPPLY);
        assertEq(governor.nextProposalId(), 1);
        assertEq(address(governor.stakingPool()), address(stakingPool));
        assertEq(address(governor.treasury()), address(treasury));
    }

    function test_deploy_zero_staking_pool_reverts() public {
        vm.expectRevert("TreasuryGovernor: zero staking pool");
        new TreasuryGovernor(address(0), address(treasury), guardianAddr, TOTAL_SUPPLY);
    }

    function test_deploy_zero_treasury_reverts() public {
        vm.expectRevert("TreasuryGovernor: zero treasury");
        new TreasuryGovernor(address(stakingPool), address(0), guardianAddr, TOTAL_SUPPLY);
    }

    function test_deploy_zero_guardian_reverts() public {
        vm.expectRevert("TreasuryGovernor: zero guardian");
        new TreasuryGovernor(address(stakingPool), address(treasury), address(0), TOTAL_SUPPLY);
    }

    function test_deploy_zero_supply_reverts() public {
        vm.expectRevert("TreasuryGovernor: zero supply");
        new TreasuryGovernor(address(stakingPool), address(treasury), guardianAddr, 0);
    }

    // ============================================================
    // Test 2: Proposal creation
    // ============================================================

    function test_create_treasury_spend_proposal() public {
        uint256 proposalId = _createSpendProposal();
        assertEq(proposalId, 1);
        assertEq(governor.nextProposalId(), 2);

        (uint256 id, address p, , , , , , , , , , , , ) = governor.getProposal(proposalId);
        assertEq(id, 1);
        assertEq(p, proposer);
    }

    function test_create_parameter_change_proposal() public {
        bytes32 key = keccak256("voting_period");

        vm.prank(proposer);
        uint256 proposalId = governor.proposeParameterChange(
            "Extend voting period",
            "Change voting period to 100800 blocks",
            key,
            100_800
        );
        assertEq(proposalId, 1);
    }

    function test_create_oracle_update_proposal() public {
        vm.prank(proposer);
        uint256 proposalId = governor.proposeOracleUpdate(
            "Update price oracle",
            "Point to new oracle v2",
            address(0x1234),
            address(0x5678)
        );
        assertEq(proposalId, 1);
    }

    function test_proposal_below_threshold_reverts() public {
        // outsider has only 1 SALT — below 10,000 threshold
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100e6;

        vm.prank(outsider);
        vm.expectRevert("TreasuryGovernor: below proposal threshold");
        governor.proposeTreasurySpend("Test", "Test", address(usdc), recipients, amounts);
    }

    function test_proposal_empty_title_reverts() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100e6;

        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: empty title");
        governor.proposeTreasurySpend("", "Desc", address(usdc), recipients, amounts);
    }

    function test_proposal_empty_recipients_reverts() public {
        address[] memory recipients = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: empty recipients");
        governor.proposeTreasurySpend("Title", "Desc", address(usdc), recipients, amounts);
    }

    function test_proposal_length_mismatch_reverts() public {
        address[] memory recipients = new address[](2);
        recipients[0] = recipient1;
        recipients[1] = recipient2;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100e6;

        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: length mismatch");
        governor.proposeTreasurySpend("Title", "Desc", address(usdc), recipients, amounts);
    }

    // ============================================================
    // Test 3: Voting
    // ============================================================

    function test_cast_vote_for() public {
        uint256 proposalId = _createSpendProposal();

        // Advance to voting period
        vm.roll(block.number + 2);

        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);

        (,,,,,,,,, uint256 forVotes, , , , ) = governor.getProposal(proposalId);
        assertGt(forVotes, 0);
        assertTrue(governor.hasVoted(proposalId, voter1));
    }

    function test_cast_vote_against() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.Against);

        (,,,,,,,,,, uint256 againstVotes, , , ) = governor.getProposal(proposalId);
        assertGt(againstVotes, 0);
    }

    function test_cast_vote_abstain() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.Abstain);

        (,,,,,,,,,,, uint256 abstainVotes, , ) = governor.getProposal(proposalId);
        assertGt(abstainVotes, 0);
    }

    function test_double_vote_reverts() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);

        vm.prank(voter1);
        vm.expectRevert("TreasuryGovernor: already voted");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.Against);
    }

    function test_vote_before_start_reverts() public {
        uint256 proposalId = _createSpendProposal();
        // Do NOT advance — voting hasn't started

        vm.prank(voter1);
        vm.expectRevert("TreasuryGovernor: voting not started");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    function test_vote_after_end_reverts() public {
        uint256 proposalId = _createSpendProposal();
        // Advance past voting period
        vm.roll(block.number + 50_500);

        vm.prank(voter1);
        vm.expectRevert("TreasuryGovernor: voting ended");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    function test_vote_no_power_reverts() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        // Create an account with exactly 0 balance
        address noPower = address(0xDEAD);
        vm.prank(noPower);
        vm.expectRevert("TreasuryGovernor: no voting power");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    // ============================================================
    // Test 4: Proposal states
    // ============================================================

    function test_state_pending() public {
        uint256 proposalId = _createSpendProposal();
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Pending));
    }

    function test_state_active() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Active));
    }

    function test_state_failed_no_quorum() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        // Only outsider votes (1 SALT) — nowhere near 10% quorum
        vm.deal(outsider, 100 ether);
        vm.prank(outsider);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);

        // Advance past voting period
        vm.roll(block.number + 50_500);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Failed));
    }

    function test_state_failed_insufficient_approval() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        // voter1 votes Against (200M SALT), voter2 votes For (150M SALT)
        // For < 60% of total
        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.Against);
        vm.prank(voter2);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);

        vm.roll(block.number + 50_500);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Failed));
    }

    function test_state_succeeded() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);

        // Advance past voting period
        vm.roll(block.number + 50_500);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Succeeded));
    }

    // ============================================================
    // Test 5: Queue and timelock
    // ============================================================

    function test_queue_succeeded_proposal() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);
        vm.roll(block.number + 50_500);

        governor.queue(proposalId);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Queued));
    }

    function test_queue_non_succeeded_reverts() public {
        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        vm.expectRevert("TreasuryGovernor: not succeeded");
        governor.queue(proposalId);
    }

    // ============================================================
    // Test 6: Execution
    // ============================================================

    function test_execute_treasury_spend() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);
        vm.roll(block.number + 50_500);

        governor.queue(proposalId);

        // Advance past execution delay
        vm.roll(block.number + 7_200 + 1);

        uint256 r1Before = usdc.balanceOf(recipient1);
        uint256 r2Before = usdc.balanceOf(recipient2);

        governor.execute(proposalId);

        assertEq(usdc.balanceOf(recipient1) - r1Before, 60_000e6);
        assertEq(usdc.balanceOf(recipient2) - r2Before, 40_000e6);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Executed));
    }

    // ── CHAIN-B-C030: governed-target functions stay reachable ─────

    /// RED (pre-fix): `execute` had exactly one on-chain effect —
    /// `treasury.distribute`. Once treasury governance was handed to the
    /// governor (the documented deployment flow, done in setUp), every OTHER
    /// governance function on the treasury — `addStablecoin`,
    /// `emergencyWithdraw`, `removeStablecoin` — became permanently
    /// unreachable: no proposal type could call them, and no other caller
    /// satisfies `onlyGovernance`. GREEN: a generic `Call` proposal routes any
    /// such call through vote + timelock.
    function test_C030_governed_function_reachable_via_call_proposal() public {
        MockERC20Gov newToken = new MockERC20Gov("Second Coin", "SEC", 6);
        assertFalse(treasury.acceptedStablecoins(address(newToken)));

        // The governed function is unreachable by any direct caller: treasury
        // governance is the governor, so no EOA can call it.
        vm.prank(outsider);
        vm.expectRevert();
        treasury.addStablecoin(address(newToken));

        // A Call proposal reaches it through governance.
        bytes memory cd = abi.encodeWithSignature("addStablecoin(address)", address(newToken));
        vm.prank(proposer);
        uint256 id = governor.proposeCall(
            "Add SEC as accepted stablecoin", "governed-target call", address(treasury), 0, cd
        );
        _voteAndPass(id);
        vm.roll(block.number + 50_500);
        governor.queue(id);
        vm.roll(block.number + 7_200 + 1);
        governor.execute(id);

        assertTrue(treasury.acceptedStablecoins(address(newToken)), "governed call must take effect");
        assertEq(uint8(governor.state(id)), uint8(TreasuryGovernor.ProposalState.Executed));
    }

    /// A failing governed call bubbles up and does not mark the proposal
    /// executed-with-silent-success.
    function test_C030_failing_call_reverts_execute() public {
        // addStablecoin(address(0)) reverts inside the treasury.
        bytes memory cd = abi.encodeWithSignature("addStablecoin(address)", address(0));
        vm.prank(proposer);
        uint256 id = governor.proposeCall("Bad add", "desc", address(treasury), 0, cd);
        _voteAndPass(id);
        vm.roll(block.number + 50_500);
        governor.queue(id);
        vm.roll(block.number + 7_200 + 1);
        vm.expectRevert();
        governor.execute(id);
    }

    function test_execute_before_timelock_reverts() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);
        vm.roll(block.number + 50_500);

        governor.queue(proposalId);
        // Do NOT advance past execution delay

        vm.expectRevert("TreasuryGovernor: timelock not elapsed");
        governor.execute(proposalId);
    }

    function test_execute_after_grace_period_reverts() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);
        vm.roll(block.number + 50_500);

        governor.queue(proposalId);

        // Advance past execution delay + grace period
        vm.roll(block.number + 7_200 + 50_400 + 1);

        vm.expectRevert("TreasuryGovernor: execution expired");
        governor.execute(proposalId);
    }

    // ============================================================
    // Test 7: Cancellation
    // ============================================================

    function test_cancel_by_proposer() public {
        uint256 proposalId = _createSpendProposal();

        vm.prank(proposer);
        governor.cancel(proposalId);

        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Canceled));
    }

    function test_cancel_by_guardian() public {
        uint256 proposalId = _createSpendProposal();

        vm.prank(guardianAddr);
        governor.cancel(proposalId);

        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Canceled));
    }

    function test_cancel_by_outsider_reverts() public {
        uint256 proposalId = _createSpendProposal();

        vm.prank(outsider);
        vm.expectRevert("TreasuryGovernor: not authorized");
        governor.cancel(proposalId);
    }

    function test_cancel_already_executed_reverts() public {
        uint256 proposalId = _createSpendProposal();
        _voteAndPass(proposalId);
        vm.roll(block.number + 50_500);
        governor.queue(proposalId);
        vm.roll(block.number + 7_200 + 1);
        governor.execute(proposalId);

        vm.prank(guardianAddr);
        vm.expectRevert("TreasuryGovernor: already executed");
        governor.cancel(proposalId);
    }

    function test_cancel_already_canceled_reverts() public {
        uint256 proposalId = _createSpendProposal();

        vm.prank(proposer);
        governor.cancel(proposalId);

        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: already canceled");
        governor.cancel(proposalId);
    }

    // ============================================================
    // Test 8: Voting power with staking
    // ============================================================

    /// PBA-L2-001: stSALT is NOT voting power any more. LiquidStakingPool
    /// shares are not checkpointed and move freely mid-vote, which is the same
    /// recycling defect as a live balance. Only escrow in the governor counts.
    function test_voting_power_excludes_unsnapshotted_staking() public {
        // voter1 stakes 100 ether (from its unlocked float) into LiquidStakingPool
        vm.prank(voter1);
        stakingPool.deposit{value: 100 ether}();

        // Voting power is exactly the 200M escrow; the 100 stSALT adds nothing.
        uint256 power = governor.getVotingPower(voter1);
        assertEq(power, 200_000_000 ether);
    }

    function test_voting_power_pure_salt() public {
        uint256 power = governor.getVotingPower(voter1);
        assertEq(power, 200_000_000 ether);
    }

    function test_voting_power_zero_balance() public {
        address nobody = address(0x999);
        uint256 power = governor.getVotingPower(nobody);
        assertEq(power, 0);
    }

    // ============================================================
    // Test 9: Guardian management
    // ============================================================

    function test_transfer_guardian() public {
        vm.prank(guardianAddr);
        governor.transferGuardian(voter1);
        assertEq(governor.guardian(), voter1);
    }

    function test_transfer_guardian_zero_reverts() public {
        vm.prank(guardianAddr);
        vm.expectRevert("TreasuryGovernor: zero guardian");
        governor.transferGuardian(address(0));
    }

    function test_transfer_guardian_non_guardian_reverts() public {
        vm.prank(outsider);
        vm.expectRevert("TreasuryGovernor: not guardian");
        governor.transferGuardian(outsider);
    }

    // ============================================================
    // Test 10: Emergency proposal
    // ============================================================

    function test_emergency_proposal_requires_3x_threshold() public {
        // outsider has only 1 SALT — below 30,000 emergency threshold
        vm.deal(outsider, 20_000 ether);
        vm.prank(outsider);
        vm.expectRevert("TreasuryGovernor: below emergency threshold");
        governor.proposeEmergency("Emergency", "Critical fix");
    }

    function test_emergency_proposal_success() public {
        // proposer has 50,000 SALT — above 30,000 emergency threshold
        vm.prank(proposer);
        uint256 proposalId = governor.proposeEmergency("Emergency halt", "Critical vulnerability");
        assertEq(proposalId, 1);

        (,,TreasuryGovernor.ProposalType pType,,,,,,,,,,, ) = governor.getProposal(proposalId);
        assertEq(uint8(pType), uint8(TreasuryGovernor.ProposalType.Emergency));
    }

    // ============================================================
    // Test 11: Quorum threshold view
    // ============================================================

    function test_quorum_threshold() public view {
        // 10% of 1B SALT = 100M SALT
        assertEq(governor.quorumThreshold(), TOTAL_SUPPLY / 10);
    }

    function test_C013_countedVotingPower_cannotExceedDeclaredSupply() public {
        address first = address(0xC0131);
        address second = address(0xC0132);
        address third = address(0xC0133);
        vm.deal(first, 600_000_000 ether);
        vm.deal(second, 400_000_000 ether);
        vm.deal(third, 1 ether);
        // PBA-L2-001: weight is snapshot escrow, so lock BEFORE the proposal.
        _lock(first, 600_000_000 ether);
        _lock(second, 400_000_000 ether);
        _lock(third, 1 ether);
        vm.roll(block.number + 1);

        uint256 proposalId = _createSpendProposal();
        vm.roll(block.number + 2);

        vm.prank(first);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
        vm.prank(second);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);

        vm.prank(third);
        vm.expectRevert("TreasuryGovernor: voting power exceeds supply");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    // ============================================================
    // Test 12: Get spend details
    // ============================================================

    function test_get_spend_details() public {
        uint256 proposalId = _createSpendProposal();
        (address stablecoin, address[] memory recipients, uint256[] memory amounts) =
            governor.getSpendDetails(proposalId);

        assertEq(stablecoin, address(usdc));
        assertEq(recipients.length, 2);
        assertEq(recipients[0], recipient1);
        assertEq(recipients[1], recipient2);
        assertEq(amounts[0], 60_000e6);
        assertEq(amounts[1], 40_000e6);
    }

    // ============================================================
    // Test 13: Invalid proposal ID queries
    // ============================================================

    function test_get_proposal_invalid_id_reverts() public {
        vm.expectRevert("TreasuryGovernor: invalid proposal");
        governor.getProposal(0);
    }

    function test_state_invalid_id_reverts() public {
        vm.expectRevert("TreasuryGovernor: invalid proposal");
        governor.state(999);
    }

    function test_vote_invalid_id_reverts() public {
        vm.prank(voter1);
        vm.expectRevert("TreasuryGovernor: invalid proposal");
        governor.castVote(0, TreasuryGovernor.VoteType.For);
    }

    // ============================================================
    // Test 14: Full lifecycle end-to-end
    // ============================================================

    function test_full_lifecycle() public {
        // 1. Create proposal
        uint256 proposalId = _createSpendProposal();
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Pending));

        // 2. Advance to voting
        vm.roll(block.number + 2);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Active));

        // 3. Vote
        vm.prank(voter1);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
        vm.prank(voter2);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
        vm.prank(voter3);
        governor.castVote(proposalId, TreasuryGovernor.VoteType.Abstain);

        // 4. Advance past voting
        vm.roll(block.number + 50_500);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Succeeded));

        // 5. Queue
        governor.queue(proposalId);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Queued));

        // 6. Advance past timelock
        vm.roll(block.number + 7_200 + 1);

        // 7. Execute
        governor.execute(proposalId);
        assertEq(uint8(governor.state(proposalId)), uint8(TreasuryGovernor.ProposalState.Executed));

        // 8. Verify funds transferred
        assertEq(usdc.balanceOf(recipient1), 60_000e6);
        assertEq(usdc.balanceOf(recipient2), 40_000e6);
    }

    // ============================================================
    // Test 15: Vote on canceled proposal reverts
    // ============================================================

    function test_vote_on_canceled_proposal_reverts() public {
        uint256 proposalId = _createSpendProposal();

        vm.prank(proposer);
        governor.cancel(proposalId);

        vm.roll(block.number + 2);

        vm.prank(voter1);
        vm.expectRevert("TreasuryGovernor: proposal canceled");
        governor.castVote(proposalId, TreasuryGovernor.VoteType.For);
    }

    // ============================================================
    // Test 16: Multiple proposals
    // ============================================================

    function test_multiple_proposals() public {
        uint256 p1 = _createSpendProposal();

        bytes32 key = keccak256("reward_rate");
        vm.prank(proposer);
        uint256 p2 = governor.proposeParameterChange("Change reward", "Adjust rate", key, 5);

        assertEq(p1, 1);
        assertEq(p2, 2);
        assertEq(governor.nextProposalId(), 3);
    }

    // ============================================================
    // Test 17: Oracle update proposal details
    // ============================================================

    function test_oracle_update_zero_target_reverts() public {
        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: zero target");
        governor.proposeOracleUpdate("Update", "Desc", address(0), address(0x1234));
    }

    function test_oracle_update_zero_oracle_reverts() public {
        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: zero oracle");
        governor.proposeOracleUpdate("Update", "Desc", address(0x1234), address(0));
    }

    // ============================================================
    // Test 18: Zero stablecoin in spend proposal reverts
    // ============================================================

    function test_spend_zero_stablecoin_reverts() public {
        address[] memory recipients = new address[](1);
        recipients[0] = recipient1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100e6;

        vm.prank(proposer);
        vm.expectRevert("TreasuryGovernor: zero stablecoin");
        governor.proposeTreasurySpend("Title", "Desc", address(0), recipients, amounts);
    }
}
