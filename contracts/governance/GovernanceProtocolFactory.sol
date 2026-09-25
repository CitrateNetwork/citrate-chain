// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract GovernanceProtocolFactory is Ownable {
    mapping(bytes32 => address) public specHashToProtocol;

    modifier validateSpecHash(bytes32 specHash) {
        require(specHashToProtocol[specHash] == address(0), "GovernanceProtocolFactory: SpecHash already registered");
        _;
    }

    function registerProtocol(bytes32 specHash, address protocol) external onlyOwner validateSpecHash(specHash) {
        specHashToProtocol[specHash] = protocol;
    }
}