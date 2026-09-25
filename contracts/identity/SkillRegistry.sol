// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract SkillRegistry is Ownable {
    struct Skill {
        bytes32 id;
        string name;
    }

    mapping(bytes32 => Skill) public skills;

    function registerSkill(string memory name) external onlyOwner returns (bytes32) {
        bytes32 id = keccak256(abi.encodePacked(msg.sender, name));
        require(skills[id].id == bytes32(0), "SkillRegistry: ID collision");
        skills[id] = Skill({id: id, name: name});
        return id;
    }
}