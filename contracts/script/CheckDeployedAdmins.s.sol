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
///         The post-redeploy run (against the regenerated book) always uses
///         REQUIRE_ALL_CODE=true, so a NO-CODE entry fails it:
///           REQUIRE_ALL_CODE=true forge script script/CheckDeployedAdmins.s.sol --rpc-url https://rpc.citrate.ai
///         Env: ADDRESS_BOOK (default addresses/40204.json), REQUIRE_ALL_CODE,
///         EXTRA_ADDRESS_BOOKS (optional, comma-separated genesis ceremony outputs).
///
///         DEPLOYER-ADMIN also covers the C4 genesis seats (AdminChecks
///         `_governingSeatProblem`): the deployer must not hold a TimelockController
///         PROPOSER / EXECUTOR / CANCELLER role or an m-of-n owner seat (`isOwner`).
///
///         TIMELOCK-HOLDERS (chain#320 P1): every book entry that answers `getMinDelay()` is
///         treated as an OZ TimelockController and its COMPLETE role-holder sets are
///         established (AdminChecks `_timelockHolderProblem`: rebuilt from the timelock's
///         RoleGranted / RoleRevoked logs, re-read with hasRole). An entry `<P>Timelock` must
///         have a `<P>Multisig` beside it in the same section; the timelock must be its own SOLE
///         admin and that multisig its SOLE proposer, executor and canceller. No paired
///         multisig, no node, or an incomplete history fails it. GATE: must be 0.
///
///         Expected on the 2026-09-24 deployment (a fork of 40204): 22
///         FACTORY-ADMIN (21 admin slots + X402Paywall.provider), VERIFIER
///         missing, ~20 NO-CODE -> FAIL. After the PBA-L2-002 redeploy and
///         DeployP256Verifier, run with REQUIRE_ALL_CODE=true: 0 FACTORY-ADMIN,
///         VERIFIER present, 0 NO-CODE -> PASS (reconcile the book first).
contract CheckDeployedAdmins is Script, AdminChecks {
    uint256 public factoryAdmin;
    uint256 public deployerAdmin;
    uint256 public noCode;
    uint256 public timelockHolders;
    bool public verifierMissing;

    function run() external {
        string memory path = vm.envOr("ADDRESS_BOOK", string("addresses/40204.json"));
        string[] memory extraPaths = vm.envOr("EXTRA_ADDRESS_BOOKS", ",", new string[](0));
        string[] memory extras = new string[](extraPaths.length);
        for (uint256 i = 0; i < extraPaths.length; i++) {
            extras[i] = vm.readFile(extraPaths[i]);
        }
        checkAll(vm.readFile(path), extras, vm.envOr("REQUIRE_ALL_CODE", false));
    }

    /// @notice The gate over an address-book JSON document (sections
    ///         `.contracts` and `.aaStack`). Reverts on failure.
    function check(string memory json, bool requireAllCode) public {
        checkAll(json, new string[](0), requireAllCode);
    }

    /// @notice `check` plus the `.contracts` of each extra book: the C4 genesis ceremony
    ///         outputs (DeployGenesisGovernance / DeployTeamVesting / DeployDormantLedgers
    ///         write book-shaped JSON) before they are folded into the canonical book.
    ///         Env: EXTRA_ADDRESS_BOOKS=path1,path2. Each extra must name the same
    ///         `.deployer` as the main book, so the DEPLOYER-ADMIN class covers them too.
    function checkAll(string memory json, string[] memory extras, bool requireAllCode) public {
        address deployer = vm.parseJsonAddress(json, ".deployer");
        _sweep(json, ".contracts", deployer);
        _sweep(json, ".aaStack", deployer);
        for (uint256 i = 0; i < extras.length; i++) {
            require(
                vm.parseJsonAddress(extras[i], ".deployer") == deployer,
                "CheckDeployedAdmins: extra address book names a different deployer"
            );
            _sweep(extras[i], ".contracts", deployer);
        }
        verifierMissing = P256.VERIFIER.code.length == 0;
        if (verifierMissing) console.log("VERIFIER missing: no code at", P256.VERIFIER);
        console.log("FACTORY-ADMIN failures:", factoryAdmin);
        console.log("DEPLOYER-ADMIN failures:", deployerAdmin);
        console.log("NO-CODE entries (reported):", noCode);
        console.log("VERIFIER present:", !verifierMissing);
        console.log("TIMELOCK-HOLDERS failures:", timelockHolders);
        require(factoryAdmin == 0, "CheckDeployedAdmins: CREATE2 factory holds an admin slot (see log)");
        require(deployerAdmin == 0, "CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)");
        require(!verifierMissing, "CheckDeployedAdmins: P-256 verifier not provisioned");
        require(
            timelockHolders == 0, "CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"
        );
        if (requireAllCode) require(noCode == 0, "CheckDeployedAdmins: address-book entries without code");
    }

    function _sweep(string memory json, string memory section, address deployer) internal {
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
            string memory dproblem = _deployerAdminProblem(target, deployer);
            if (bytes(dproblem).length != 0) {
                console.log(string.concat("DEPLOYER-ADMIN ", names[i], ": ", dproblem), target);
                deployerAdmin++;
            }
            string memory hproblem = _timelockEntryProblem(json, section, names[i], target);
            if (bytes(hproblem).length != 0) {
                console.log(string.concat("TIMELOCK-HOLDERS ", names[i], ": ", hproblem), target);
                timelockHolders++;
            }
        }
    }

    /// @notice Empty unless `target` is a timelock (answers `getMinDelay()`) whose complete
    ///         holder sets are not exactly {itself} as admin and its paired `<P>Multisig` as
    ///         proposer / executor / canceller.
    function _timelockEntryProblem(string memory json, string memory section, string memory name, address target)
        internal
        returns (string memory)
    {
        (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSignature("getMinDelay()"));
        if (!ok || ret.length != 32) return "";
        bytes memory n = bytes(name);
        bytes memory suffix = bytes("Timelock");
        if (n.length < suffix.length || keccak256(_slice(n, n.length - suffix.length, n.length)) != keccak256(suffix)) {
            return "a timelock entry must be named <P>Timelock with a <P>Multisig beside it";
        }
        string memory key = string.concat(section, ".", string(_slice(n, 0, n.length - suffix.length)), "Multisig");
        if (!vm.keyExistsJson(json, key)) return "no paired <P>Multisig entry in the same section";
        return _timelockHolderProblem(target, vm.parseJsonAddress(json, key), new address[](0));
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; i++) {
            out[i - from] = b[i];
        }
    }
}
