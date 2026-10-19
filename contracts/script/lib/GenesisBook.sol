// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title GenesisBook: book-shaped output for the C4 genesis ceremony scripts
/// @notice Each genesis script writes its addresses to the path in an env var (never to
///         `addresses/40204.json`, the live book), in the same shape as the book:
///           {"chainId":…, "deployer":"0x…", "contracts":{"Name":"0x…",…}, "aaStack":{}, "params":{…}}
///         so `CheckDeployedAdmins` gates it directly (ADDRESS_BOOK=<file>) or alongside the
///         main book (EXTRA_ADDRESS_BOOKS=<file>,…). The path must sit under a directory
///         foundry.toml grants write access to (`./genesis`).
abstract contract GenesisBook is Script {
    /// @param params a JSON object body (without braces) of ceremony parameters, or "".
    function _bookJson(address deployer, string[] memory names, address[] memory addrs, string memory params)
        internal
        view
        returns (string memory json)
    {
        require(names.length == addrs.length, "GenesisBook: names/addresses length mismatch");
        string memory body = "";
        for (uint256 i = 0; i < names.length; i++) {
            body = string.concat(body, i == 0 ? "" : ",", '"', names[i], '":"', vm.toString(addrs[i]), '"');
        }
        json = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"deployer":"',
            vm.toString(deployer),
            '","contracts":{',
            body,
            '},"aaStack":{},"params":{',
            params,
            "}}"
        );
    }

    /// @notice Write `json` to the path in env `key`. Fails closed when `key` is unset.
    function _writeBook(string memory key, string memory json) internal {
        string memory path = vm.envString(key);
        require(bytes(path).length != 0, string.concat(key, " must name an output path"));
        vm.writeFile(path, json);
        console.log(string.concat("wrote ", key, ":"), path);
    }
}
