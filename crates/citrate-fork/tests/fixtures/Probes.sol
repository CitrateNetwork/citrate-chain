// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

/// Calls one Citrate precompile from its constructor and records what came back,
/// plus the chain id and the GASPRICE opcode the dry run executed under.
contract PrecompileProbe {
    bool public ok;
    bytes public out;
    uint256 public seenGasPrice;
    uint256 public seenChainId;

    constructor(address precompile, bytes memory input) {
        (ok, out) = precompile.staticcall(input);
        seenGasPrice = tx.gasprice;
        seenChainId = block.chainid;
    }
}

/// Holds SALT sent at deploy and pays it out from contract code (a contract-initiated
/// value transfer, the case the chain's value-transfer activation is about).
contract Payout {
    constructor() payable {}

    function pay(address payable to) external {
        (bool sent, ) = to.call{value: address(this).balance}("");
        require(sent, "pay failed");
    }

    function balanceOf(address who) external view returns (uint256) {
        return who.balance;
    }
}
