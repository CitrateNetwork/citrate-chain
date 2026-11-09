// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {OrangeSeedV0} from "../../src/genesis/OrangeSeedV0.sol";
import {GenesisOrangeSeed} from "../../script/GenesisOrangeSeed.s.sol";

/// @notice Shared fixture: OrangeSeed exactly as the block-0 allocation leaves it. The
///         builder runs, its two accounts are wiped, and only the artifacts it returned
///         (code + storage) are put back, so every test exercises what the genesis builder
///         consumes and nothing else.
abstract contract OrangeSeedBase is Test {
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant INITIALIZABLE_SLOT = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    uint256 internal constant GENESIS_TS = 1_793_059_200; // 2026-10-26T00:00:00Z (any fixed value)

    address internal governance = makeAddr("governanceTimelock");
    address internal planter = makeAddr("citrateTreasury");
    address internal deployer = makeAddr("deployer");

    GenesisOrangeSeed internal builder;
    GenesisOrangeSeed.Alloc internal alloc;
    address internal proxyAddr;
    address internal implAddr;
    OrangeSeedV0 internal seed;

    function setUp() public virtual {
        builder = new GenesisOrangeSeed();
        proxyAddr = builder.DEFAULT_PROXY();
        implAddr = builder.DEFAULT_IMPLEMENTATION();
        vm.roll(1234);
        vm.warp(GENESIS_TS + 999_999);
        GenesisOrangeSeed.Alloc memory a = builder.build(proxyAddr, implAddr, governance, planter, GENESIS_TS);
        _copyAlloc(a);
        _wipe(a.proxy);
        _wipe(a.implementation);
        _apply(a.proxy);
        _apply(a.implementation);
        seed = OrangeSeedV0(proxyAddr);
    }

    function seedBase() internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256("citrate.storage.OrangeSeed")) - 1)) & ~bytes32(uint256(0xff));
    }

    function _wipe(GenesisOrangeSeed.SeedAccount memory acct) internal {
        vm.etch(acct.addr, "");
        for (uint256 i = 0; i < acct.slots.length; i++) {
            vm.store(acct.addr, acct.slots[i], bytes32(0));
        }
        assertEq(acct.addr.code.length, 0, "wipe left code");
    }

    function _apply(GenesisOrangeSeed.SeedAccount memory acct) internal {
        vm.etch(acct.addr, acct.code);
        for (uint256 i = 0; i < acct.slots.length; i++) {
            vm.store(acct.addr, acct.slots[i], acct.values[i]);
        }
    }

    function _copyAlloc(GenesisOrangeSeed.Alloc memory a) private {
        alloc.proxy.addr = a.proxy.addr;
        alloc.proxy.code = a.proxy.code;
        alloc.implementation.addr = a.implementation.addr;
        alloc.implementation.code = a.implementation.code;
        delete alloc.proxy.slots;
        delete alloc.proxy.values;
        delete alloc.implementation.slots;
        delete alloc.implementation.values;
        for (uint256 i = 0; i < a.proxy.slots.length; i++) {
            alloc.proxy.slots.push(a.proxy.slots[i]);
            alloc.proxy.values.push(a.proxy.values[i]);
        }
        for (uint256 i = 0; i < a.implementation.slots.length; i++) {
            alloc.implementation.slots.push(a.implementation.slots[i]);
            alloc.implementation.values.push(a.implementation.values[i]);
        }
    }
}
