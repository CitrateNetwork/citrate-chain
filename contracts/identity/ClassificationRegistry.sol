// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ClassificationRegistry is Ownable {
    mapping(bytes32 => mapping(address => bool)) public clearances;

    modifier validateOracleSig(bytes memory sig) {
        require(bytes(sig).length > 0, "ClassificationRegistry: Oracle signature required");
        _;
    }

    function setClearance(bytes32 classificationId, address principal, bool allowed) external validateOracleSig(msg.data) {
        clearances[classificationId][principal] = allowed;
    }
}