// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Counter} from "./Counter.sol";

contract Greeter {
    string public greeting;
    uint256 public immutable seed;

    constructor(uint256 seed_, string memory greeting_) {
        seed = seed_;
        greeting = greeting_;
    }
}
