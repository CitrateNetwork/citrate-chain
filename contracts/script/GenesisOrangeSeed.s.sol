// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OrangeSeedV0} from "../src/genesis/OrangeSeedV0.sol";

/// @title GenesisOrangeSeed: block-0 allocation for the OrangeSeed predeploy
/// @notice Produces the exact runtime code and storage of the OrangeSeed proxy and its V0
///         implementation, for the genesis builder to place in the block-0 allocation. No
///         transaction is sent and nothing is signed.
///
///         How: each contract's creation code runs AT its predeploy address (etch the init
///         code, call it, etch the returned runtime), so every constructor-time value is
///         the one the predeploy needs: UUPS's immutable `__self` is the implementation's
///         own predeploy address (without that, every upgrade would revert), and the proxy
///         constructor runs `initialize` in the same frame that sets the implementation.
///         The chain is set to block 0 at the genesis timestamp first, so the planting
///         record is block 0 and that timestamp. `vm.record` captures every slot written;
///         the final values are read back with `vm.load`.
///
///         Run (writes book-shaped JSON under ./genesis, which is gitignored):
///           ORANGESEED_GOVERNANCE=<GovernanceTimelock from the governance ceremony book> \
///           ORANGESEED_PLANTER=<Citrate Inc. treasury or governance address> \  (default: governance)
///           GENESIS_TIMESTAMP=<block-0 timestamp, unix seconds> \
///           GENESIS_ORANGESEED_OUT=genesis/orangeseed.json \
///             forge script script/GenesisOrangeSeed.s.sol
///         Optional: ORANGESEED_PROXY / ORANGESEED_IMPLEMENTATION override the addresses.
///
///         Output: {"alloc":{"<addr>":{"balance":"0x0","nonce":"0x1","code":"0x…",
///                  "storage":{"<slot>":"<value>",…}},…},"params":{…}}
///         `nonce` 1 follows EIP-161 for contract accounts; `balance` is always 0 (the seed
///         holds no value).
contract GenesisOrangeSeed is Script {
    /// "C17A7E 5EED": the reserved predeploy address of the OrangeSeed proxy.
    address public constant DEFAULT_PROXY = 0x000000000000000000000000000000c17A7e5EeD;
    /// The V0 implementation ("5EE0": seed, version 0).
    address public constant DEFAULT_IMPLEMENTATION = 0x000000000000000000000000000000c17A7E5Ee0;

    struct SeedAccount {
        address addr;
        bytes code;
        bytes32[] slots;
        bytes32[] values;
    }

    struct Alloc {
        SeedAccount proxy;
        SeedAccount implementation;
    }

    function run() external {
        address governance = vm.envAddress("ORANGESEED_GOVERNANCE");
        address planter = _envAddressOr("ORANGESEED_PLANTER", governance);
        uint256 genesisTimestamp = vm.envUint("GENESIS_TIMESTAMP");
        address proxy = _envAddressOr("ORANGESEED_PROXY", DEFAULT_PROXY);
        address impl = _envAddressOr("ORANGESEED_IMPLEMENTATION", DEFAULT_IMPLEMENTATION);

        Alloc memory a = build(proxy, impl, governance, planter, genesisTimestamp);
        string memory json = toJson(a, governance, planter, genesisTimestamp);

        string memory path = vm.envString("GENESIS_ORANGESEED_OUT");
        require(bytes(path).length != 0, "GENESIS_ORANGESEED_OUT must name an output path");
        vm.writeFile(path, json);
        console.log("wrote GENESIS_ORANGESEED_OUT:", path);
        console.log("OrangeSeed proxy         :", proxy);
        console.log("OrangeSeedV0 implementation:", impl);
    }

    /// @notice The block-0 accounts for OrangeSeed. Pure function of its inputs (and the
    ///         compiled bytecode): two calls with the same inputs return identical results.
    function build(address proxy, address impl, address governance, address planter, uint256 genesisTimestamp)
        public
        returns (Alloc memory a)
    {
        require(governance != address(0), "OrangeSeed: governance is the zero address");
        require(planter != address(0), "OrangeSeed: planter is the zero address");
        require(proxy != impl, "OrangeSeed: proxy and implementation share an address");
        require(proxy.code.length == 0 && impl.code.length == 0, "OrangeSeed: predeploy address already has code");

        uint256 savedBlock = block.number;
        uint256 savedTimestamp = block.timestamp;
        vm.roll(0);
        vm.warp(genesisTimestamp);

        vm.record();
        _constructAt(impl, type(OrangeSeedV0).creationCode);
        _constructAt(
            proxy,
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(impl, abi.encodeCall(OrangeSeedV0.initialize, (governance, planter)))
            )
        );
        a.implementation = _account(impl);
        a.proxy = _account(proxy);

        vm.roll(savedBlock);
        vm.warp(savedTimestamp);
    }

    function toJson(Alloc memory a, address governance, address planter, uint256 genesisTimestamp)
        public
        returns (string memory)
    {
        string memory alloc = "orangeseed.alloc";
        vm.serializeString(alloc, vm.toString(a.implementation.addr), _accountJson("orangeseed.impl", a.implementation));
        string memory allocJson =
            vm.serializeString(alloc, vm.toString(a.proxy.addr), _accountJson("orangeseed.proxy", a.proxy));

        string memory params = "orangeseed.params";
        vm.serializeAddress(params, "proxy", a.proxy.addr);
        vm.serializeAddress(params, "implementation", a.implementation.addr);
        vm.serializeAddress(params, "governance", governance);
        vm.serializeAddress(params, "planter", planter);
        vm.serializeUint(params, "plantedAtBlock", 0);
        vm.serializeUint(params, "genesisTimestamp", genesisTimestamp);
        vm.serializeBytes32(params, "proxyCodehash", keccak256(a.proxy.code));
        string memory paramsJson =
            vm.serializeBytes32(params, "implementationCodehash", keccak256(a.implementation.code));

        string memory root = "orangeseed";
        vm.serializeString(root, "alloc", allocJson);
        return vm.serializeString(root, "params", paramsJson);
    }

    /// Run `initCode` as if deployed at `where`, then leave its runtime code there.
    function _constructAt(address where, bytes memory initCode) private {
        vm.etch(where, initCode);
        (bool ok, bytes memory runtime) = where.call("");
        require(ok, "OrangeSeed: constructor reverted");
        vm.etch(where, runtime);
    }

    function _account(address addr) private returns (SeedAccount memory acct) {
        (, bytes32[] memory writes) = vm.accesses(addr);
        bytes32[] memory unique = new bytes32[](writes.length);
        uint256 n;
        for (uint256 i = 0; i < writes.length; i++) {
            bool seen;
            for (uint256 j = 0; j < n; j++) {
                if (unique[j] == writes[i]) {
                    seen = true;
                    break;
                }
            }
            // A slot written back to zero is the default; it does not belong in the alloc.
            if (!seen && vm.load(addr, writes[i]) != bytes32(0)) unique[n++] = writes[i];
        }
        acct.addr = addr;
        acct.code = addr.code;
        _sort(unique, n);
        acct.slots = new bytes32[](n);
        acct.values = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            acct.slots[i] = unique[i];
            acct.values[i] = vm.load(addr, unique[i]);
        }
    }

    /// Ascending slot order, so the output does not depend on write order.
    function _sort(bytes32[] memory xs, uint256 n) private pure {
        for (uint256 i = 1; i < n; i++) {
            bytes32 x = xs[i];
            uint256 j = i;
            while (j > 0 && xs[j - 1] > x) {
                xs[j] = xs[j - 1];
                j--;
            }
            xs[j] = x;
        }
    }

    function _accountJson(string memory key, SeedAccount memory acct) private returns (string memory) {
        string memory storageKey = string.concat(key, ".storage");
        string memory storageJson = "{}";
        for (uint256 i = 0; i < acct.slots.length; i++) {
            storageJson = vm.serializeBytes32(storageKey, vm.toString(acct.slots[i]), acct.values[i]);
        }
        vm.serializeString(key, "balance", "0x0");
        vm.serializeString(key, "nonce", "0x1");
        vm.serializeBytes(key, "code", acct.code);
        return vm.serializeString(key, "storage", storageJson);
    }

    function _envAddressOr(string memory key, address fallbackValue) private view returns (address) {
        try vm.envAddress(key) returns (address v) {
            return v;
        } catch {
            return fallbackValue;
        }
    }
}
