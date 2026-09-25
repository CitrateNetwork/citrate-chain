// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {GovernanceSink} from "../interfaces/IGovernanceSink.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract LiquidStakingPool is ERC4626, GovernanceSink, Ownable {
    uint256 public constant MAX_CONTRIBUTORS = 1024;
    mapping(address => uint256) private _contributors;
    mapping(address => bool) public slashedSALT;

    event MaxContributorsUpdated(uint256 newMax);
    event SlashedFundsWithdrawn(address indexed slasher, uint256 amount);

    constructor() ERC4626("Citrate Liquidity Staking", "cLST") {}

    modifier onlyGovernance() {
        require(msg.sender == governance(), "Governance: Not authorized");
        _;
    }

    function setMaxContributors(uint256 newMax) external onlyGovernance {
        require(newMax > 0, "MAX_CONTRIBUTORS: Must be positive");
        MAX_CONTRIBUTORS = newMax;
        emit MaxContributorsUpdated(newMax);
    }

    function withdrawSlashed(uint256 amount) external onlyGovernance {
        require(slashedSALT[msg.sender] >= amount, "GovernanceSink: Insufficient slashed funds");
        slashedSALT[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit SlashedFundsWithdrawn(msg.sender, amount);
    }

    function _beforeDeposit(address, uint256) internal override {
        require(_contributors[msg.sender] < MAX_CONTRIBUTORS, "ContributionAccounting: Max contributors reached");
        _contributors[msg.sender]++;
    }

    function _afterWithdraw(address, uint256, uint256) internal override {
        _contributors[msg.sender]--;
    }

    function reportSlashed(address slasher, uint256 amount) external onlyGovernance {
        slashedSALT[slasher] += amount;
    }
}