// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract VoteAllowance is Ownable {
    uint256 public perPrincipalCap = 1000;

    mapping(address => uint256) public principalVotes;

    modifier enforceCap(address principal) {
        require(principalVotes[principal] < perPrincipalCap, "VoteAllowance: Per-principal cap exceeded");
        _;
    }

    function setPerPrincipalCap(uint256 newCap) external onlyOwner {
        perPrincipalCap = newCap;
    }
}