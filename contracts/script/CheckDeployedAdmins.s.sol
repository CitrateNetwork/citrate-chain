// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./lib/AdminChecks.sol";
import {P256} from "../src/aa/lib/webauthn/P256.sol";

/// @title CheckDeployedAdmins — read-only post-deploy gate (PBA-L2-002, PBA-L2-011)
/// @notice Reads every address in the canonical address book and classifies it:
///
///   FACTORY-ADMIN  governance / pendingGovernance / owner / provider /
///                  DEFAULT_ADMIN_ROLE is the CREATE2 factory (0x4e59…956C).
///                  This is the PBA-L2-002 defect. GATE: must be 0.
///   VERIFIER       the P-256 verifier the passkey validator hard-codes has no
///                  code (PBA-L2-011). GATE: must be present.
///   NO-CODE        address-book entry with no code (not yet deployed on this
///                  chain, or a stale pin). REPORTED, not gated: the book lists
///                  planned contracts (DPF/quorum/coop) ahead of their deploy.
///                  Set REQUIRE_ALL_CODE=true to gate on it too.
///
///         READ-ONLY: never broadcasts. Run after every ceremony step:
///           forge script script/CheckDeployedAdmins.s.sol --rpc-url https://rpc.citrate.ai
///         Env: ADDRESS_BOOK (default addresses/40204.json), REQUIRE_ALL_CODE.
///
///         Expected on the 2026-09-24 deployment (a fork of 40204): 22
///         FACTORY-ADMIN (21 admin slots + X402Paywall.provider), VERIFIER
///         missing, ~20 NO-CODE -> FAIL. After the PBA-L2-002 redeploy and
///         DeployP256Verifier: 0 FACTORY-ADMIN, VERIFIER present -> PASS
///         (NO-CODE entries still listed for the owner to reconcile).
contract CheckDeployedAdmins is Script, AdminChecks {
    uint256 public factoryAdmin;
    uint256 public noCode;
    bool public verifierMissing;

    function run() external {
        string memory path = vm.envOr("ADDRESS_BOOK", string("addresses/40204.json"));
        check(vm.readFile(path), vm.envOr("REQUIRE_ALL_CODE", false));
    }

    /// @notice The gate over an address-book JSON document (sections
    ///         `.contracts` and `.aaStack`). Reverts on failure.
    function check(string memory json, bool requireAllCode) public {
        _sweep(json, ".contracts");
        _sweep(json, ".aaStack");
        verifierMissing = P256.VERIFIER.code.length == 0;
        if (verifierMissing) console.log("VERIFIER missing: no code at", P256.VERIFIER);
        console.log("FACTORY-ADMIN failures:", factoryAdmin);
        console.log("NO-CODE entries (reported):", noCode);
        console.log("VERIFIER present:", !verifierMissing);
        require(factoryAdmin == 0, "CheckDeployedAdmins: CREATE2 factory holds an admin slot (see log)");
        require(!verifierMissing, "CheckDeployedAdmins: P-256 verifier not provisioned");
        if (requireAllCode) require(noCode == 0, "CheckDeployedAdmins: address-book entries without code");
    }

    function _sweep(string memory json, string memory section) internal {
        string[] memory names = vm.parseJsonKeys(json, section);
        for (uint256 i = 0; i < names.length; i++) {
            address target = vm.parseJsonAddress(json, string.concat(section, ".", names[i]));
            if (target.code.length == 0) {
                console.log(string.concat("NO-CODE ", names[i]), target);
                noCode++;
                continue;
            }
            string memory problem = _factoryAdminProblem(target);
            if (bytes(problem).length != 0) {
                console.log(string.concat("FACTORY-ADMIN ", names[i], ": ", problem), target);
                factoryAdmin++;
            }
        }
    }
}
