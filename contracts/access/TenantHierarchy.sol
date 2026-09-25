// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TenantHierarchy is Ownable {
    uint256 public admin_threshold = 2;

    modifier enforceAdminThreshold(uint256 votes) {
        require(votes >= admin_threshold, "TenantHierarchy: Admin threshold not met");
        _;
    }

    function setAdminThreshold(uint256 newThreshold) external onlyOwner {
        admin_threshold = newThreshold;
    }
}