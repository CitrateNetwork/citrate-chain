// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./lib/AdminChecks.sol";
import {P256} from "../src/aa/lib/webauthn/P256.sol";

/// @title CheckDeployedAdmins — read-only post-deploy gate (PBA-L2-002, PBA-L2-011)
/// @notice Reads every address in the canonical address book and fails if any
///         deployed contract names the CREATE2 factory (0x4e59…956C) as its
///         governance / pending governance / owner / provider / DEFAULT_ADMIN,
///         or has no code. Also fails if the P-256 verifier the passkey
///         validator hard-codes has no code (PBA-L2-011).
///
///         READ-ONLY: never broadcasts. Run after every ceremony step:
///           forge script script/CheckDeployedAdmins.s.sol --rpc-url https://rpc.citrate.ai
///         Env: ADDRESS_BOOK (default addresses/40204.json).
///
///         Expected result on the 2026-09-24 deployment: FAIL (21 contracts),
///         which is the finding. It must pass after the PBA-L2-002 redeploy.
contract CheckDeployedAdmins is Script, AdminChecks {
    uint256 public failures;

    function run() external {
        string memory path = vm.envOr("ADDRESS_BOOK", string("addresses/40204.json"));
        string memory json = vm.readFile(path);
        _sweep(json, ".contracts");
        _sweep(json, ".aaStack");
        if (P256.VERIFIER.code.length == 0) {
            console.log("FAIL P256 verifier: no code at", P256.VERIFIER);
            failures++;
        }
        console.log("admin-slot failures:", failures);
        require(failures == 0, "CheckDeployedAdmins: orphaned admin slots or missing code (see log)");
    }

    function _sweep(string memory json, string memory section) internal {
        string[] memory names = vm.parseJsonKeys(json, section);
        for (uint256 i = 0; i < names.length; i++) {
            address target = vm.parseJsonAddress(json, string.concat(section, ".", names[i]));
            string memory problem = _factoryAdminProblem(target);
            if (bytes(problem).length != 0) {
                console.log(string.concat("FAIL ", names[i], ": ", problem), target);
                failures++;
            }
        }
    }
}
