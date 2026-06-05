// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../ScriptEnv.sol";

import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title FundPaymaster
 * @notice Top up the CitratePaymaster's EntryPoint deposit so it can keep
 *         sponsoring UserOps. Reads the paymaster address + the desired
 *         delta from env so the operator can re-run with different
 *         amounts without recompiling.
 *
 * Env:
 *   CITRATE_AA_PAYMASTER     — paymaster contract address
 *   CITRATE_AA_FUND_AMOUNT   — wei to deposit (defaults to 1 ether)
 *
 * Usage (treasury operator wallet):
 *   CITRATE_AA_PAYMASTER=0x... \
 *   CITRATE_AA_FUND_AMOUNT=10000000000000000000 \
 *   forge script script/aa/FundPaymaster.s.sol \
 *     --rpc-url https://rpc.citrate.ai \
 *     --account ceremony-deployer \
 *     --broadcast
 */
contract FundPaymaster is Script, ScriptEnv {
    function run() external {
        address paymasterAddr = envAddressOr("CITRATE_AA_PAYMASTER", address(0));
        uint256 amount = envUintOr("CITRATE_AA_FUND_AMOUNT", 1 ether);

        require(paymasterAddr != address(0), "set CITRATE_AA_PAYMASTER");
        require(amount > 0, "fund amount must be > 0");

        CitratePaymaster paymaster = CitratePaymaster(payable(paymasterAddr));
        IEntryPoint entryPoint = paymaster.entryPoint();
        uint256 before = entryPoint.balanceOf(paymasterAddr);

        vm.startBroadcast();
        paymaster.deposit{value: amount}();
        vm.stopBroadcast();

        uint256 afterBal = entryPoint.balanceOf(paymasterAddr);
        console2.log("Paymaster:", paymasterAddr);
        console2.log("EntryPoint:", address(entryPoint));
        console2.log("Deposit before:", before);
        console2.log("Deposit after:", afterBal);
        console2.log("Delta:", afterBal - before);
    }
}
