// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./lib/AdminChecks.sol";
import "./lib/GenesisProfile.sol";
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
///         admin and that multisig its SOLE proposer, executor and canceller. The one permitted
///         extra canceller is a GOVERNANCE timelock's GuardianCanceller, and only when a book in
///         this run lists it beside that GovernanceTimelock and it verifies on chain
///         (GenesisProfile `_bookGuardianCanceller`: its CREATE2 address for (GovernanceTimelock,
///         GuardianTimelock), this build's runtime code, its wiring, and the GuardianTimelock's
///         own sole holders). No paired multisig, no node, or an incomplete history fails it.
///         The paired multisig must also be authenticated: the MultisigProposer
///         DeployGenesisGovernance deploys for that timelock and its reported owners / threshold
///         / proposalTtl, at its CREATE2 address under the salt "Genesis.<P>Multisig"
///         (AdminChecks `_multisigProposerProblem`). GATE: must be 0.
///
///         GENESIS-FLOOR (chain 40204, as reported by the node; GenesisProfile): every book's
///         C4 genesis councils are re-checked ON CHAIN against the genesis floors, from the
///         deployed contracts, not from the book's params: GovernanceTimelock minDelay >= 48 h,
///         GovernanceMultisig >= 3-of-5 (majority), GuardianMultisig >= 2-of-3 (majority),
///         each multisig fronting its timelock with the fixed 14-day proposal TTL, and the
///         GuardianCanceller wired to them as GOVERNANCE's guardian CANCELLER. Every listed
///         GovernanceTimelock must have such a verified GuardianCanceller, listed by some book in
///         the run and holding CANCELLER on it now (the guardian veto is required). A book that
///         records `params.genesisProfile = false` or `params.overrideUsed = true` fails too.
///         The node's eth_chainId must equal the simulated chain id (any mismatch reverts),
///         and without a node the 40204 gate fails closed. GATE: must be 0.
///
///         Expected on the 2026-09-24 deployment (a fork of 40204): 22
///         FACTORY-ADMIN (21 admin slots + X402Paywall.provider), VERIFIER
///         missing, ~20 NO-CODE -> FAIL. After the PBA-L2-002 redeploy and
///         DeployP256Verifier, run with REQUIRE_ALL_CODE=true: 0 FACTORY-ADMIN,
///         VERIFIER present, 0 NO-CODE -> PASS (reconcile the book first).
contract CheckDeployedAdmins is GenesisProfile {
    uint256 public factoryAdmin;
    uint256 public deployerAdmin;
    uint256 public noCode;
    uint256 public timelockHolders;
    uint256 public genesisFloor;
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
        // The node decides whether the genesis floors apply; a simulated id that differs reverts.
        bool genesis = _resolveChainProfile(false).genesis;
        address deployer = vm.parseJsonAddress(json, ".deployer");
        // The GuardianCanceller each GOVERNANCE timelock may carry as its one extra canceller,
        // from the book(s) that list it, verified on chain before any timelock is swept.
        delete cancellerTimelocks;
        delete cancellerOf;
        _registerGuardianCanceller(json);
        for (uint256 i = 0; i < extras.length; i++) {
            _registerGuardianCanceller(extras[i]);
        }
        _sweep(json, ".contracts", deployer);
        _sweep(json, ".aaStack", deployer);
        if (genesis) _genesisFloorSweep(json);
        for (uint256 i = 0; i < extras.length; i++) {
            require(
                vm.parseJsonAddress(extras[i], ".deployer") == deployer,
                "CheckDeployedAdmins: extra address book names a different deployer"
            );
            _sweep(extras[i], ".contracts", deployer);
            if (genesis) _genesisFloorSweep(extras[i]);
        }
        if (genesis) {
            _guardianVetoSweep(json);
            for (uint256 i = 0; i < extras.length; i++) {
                _guardianVetoSweep(extras[i]);
            }
        }
        verifierMissing = P256.VERIFIER.code.length == 0;
        if (verifierMissing) console.log("VERIFIER missing: no code at", P256.VERIFIER);
        console.log("FACTORY-ADMIN failures:", factoryAdmin);
        console.log("DEPLOYER-ADMIN failures:", deployerAdmin);
        console.log("NO-CODE entries (reported):", noCode);
        console.log("VERIFIER present:", !verifierMissing);
        console.log("TIMELOCK-HOLDERS failures:", timelockHolders);
        console.log("GENESIS-FLOOR failures:", genesisFloor);
        require(factoryAdmin == 0, "CheckDeployedAdmins: CREATE2 factory holds an admin slot (see log)");
        require(deployerAdmin == 0, "CheckDeployedAdmins: deployer EOA holds governance/owner/DEFAULT_ADMIN (see log)");
        require(!verifierMissing, "CheckDeployedAdmins: P-256 verifier not provisioned");
        require(genesisFloor == 0, "CheckDeployedAdmins: genesis governance floor not met (see log)");
        require(
            timelockHolders == 0, "CheckDeployedAdmins: a timelock's role holders are not exactly its council (see log)"
        );
        if (requireAllCode) require(noCode == 0, "CheckDeployedAdmins: address-book entries without code");
    }

    /// @notice GENESIS-FLOOR over one book: the councils it lists, read from chain.
    function _genesisFloorSweep(string memory json) internal {
        if (vm.keyExistsJson(json, ".params.genesisProfile") && !vm.parseJsonBool(json, ".params.genesisProfile")) {
            _floorFail("book was generated off the genesis profile");
        }
        if (vm.keyExistsJson(json, ".params.overrideUsed") && vm.parseJsonBool(json, ".params.overrideUsed")) {
            _floorFail("book records a safety override");
        }
        (bool hasGovTl, address govTl) = _entry(json, "GovernanceTimelock");
        (bool hasGovMs, address govMs) = _entry(json, "GovernanceMultisig");
        (bool hasGrdTl, address grdTl) = _entry(json, "GuardianTimelock");
        (bool hasGrdMs, address grdMs) = _entry(json, "GuardianMultisig");
        (bool hasCanceller, address canceller) = _entry(json, "GuardianCanceller");
        if (hasGovTl || hasGovMs) {
            if (!(hasGovTl && hasGovMs)) {
                _floorFail("GovernanceTimelock and GovernanceMultisig must be listed together");
            } else {
                _floorCheck(_councilFloorProblem("GOVERNANCE", govTl, govMs, true));
            }
        }
        if (hasGrdTl || hasGrdMs) {
            if (!(hasGrdTl && hasGrdMs)) _floorFail("GuardianTimelock and GuardianMultisig must be listed together");
            else _floorCheck(_councilFloorProblem("GUARDIAN", grdTl, grdMs, false));
        }
        if (hasGovTl && hasGrdTl) {
            (bool okGov, uint256 govDelay) = _readUint(govTl, abi.encodeWithSignature("getMinDelay()"));
            (bool okGrd, uint256 grdDelay) = _readUint(grdTl, abi.encodeWithSignature("getMinDelay()"));
            if (!okGov || !okGrd || grdDelay >= govDelay) {
                _floorFail("GuardianTimelock minDelay is not shorter than GovernanceTimelock minDelay");
            }
        }
        if (hasCanceller) {
            if (!(hasGovTl && hasGrdTl)) _floorFail("GuardianCanceller listed without both timelocks");
            else _floorCheck(_cancellerProblem(canceller, govTl, grdTl));
        }
    }

    /// @notice GENESIS-FLOOR: the guardian veto is required on the genesis profile. Every
    ///         GovernanceTimelock a book lists must have a GuardianCanceller that some book in
    ///         this run lists beside it and that verified on chain (`_registerGuardianCanceller`),
    ///         and that canceller must hold CANCELLER_ROLE on the timelock now. A book that simply
    ///         omits the canceller (for example after its role was revoked) fails here instead of
    ///         passing with the council as sole canceller.
    function _guardianVetoSweep(string memory json) internal {
        (bool hasGovTl, address govTl) = _entry(json, "GovernanceTimelock");
        if (!hasGovTl) return;
        address[] memory extra = _allowedExtraCancellers(govTl);
        if (extra.length == 0) {
            _floorFail("GovernanceTimelock has no verified GuardianCanceller in this run's books (guardian veto)");
            return;
        }
        (bool ok, bool has) =
            _readBool(govTl, abi.encodeWithSignature("hasRole(bytes32,address)", TIMELOCK_CANCELLER_ROLE, extra[0]));
        if (!ok || !has) _floorFail("GuardianCanceller lacks CANCELLER on GovernanceTimelock (guardian veto)");
    }

    /// @notice Empty when `canceller` is GOVERNANCE's guardian CANCELLER, answering to `grdTl`.
    function _cancellerProblem(address canceller, address govTl, address grdTl) internal view returns (string memory) {
        (bool okT, address t) = _readAddress(canceller, abi.encodeWithSignature("governanceTimelock()"));
        if (!okT || t != govTl) return "GuardianCanceller cancels on another timelock";
        (bool okG, address g) = _readAddress(canceller, abi.encodeWithSignature("guardian()"));
        if (!okG || g != grdTl) return "GuardianCanceller answers to another guardian";
        (bool okR, bool has) =
            _readBool(govTl, abi.encodeWithSignature("hasRole(bytes32,address)", TIMELOCK_CANCELLER_ROLE, canceller));
        if (!okR || !has) return "GuardianCanceller lacks CANCELLER on GovernanceTimelock";
        return "";
    }

    function _entry(string memory json, string memory name) internal view returns (bool, address) {
        string memory key = string.concat(".contracts.", name);
        if (!vm.keyExistsJson(json, key)) return (false, address(0));
        return (true, vm.parseJsonAddress(json, key));
    }

    function _floorCheck(string memory problem) internal {
        if (bytes(problem).length != 0) _floorFail(problem);
    }

    function _floorFail(string memory problem) internal {
        console.log(string.concat("GENESIS-FLOOR ", problem));
        genesisFloor++;
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
        string memory multisigName = string.concat(string(_slice(n, 0, n.length - suffix.length)), "Multisig");
        string memory key = string.concat(section, ".", multisigName);
        if (!vm.keyExistsJson(json, key)) return "no paired <P>Multisig entry in the same section";
        address council = vm.parseJsonAddress(json, key);
        // Authenticate the paired council (chain#320 P1) as the ceremony's MultisigProposer for this
        // timelock (CREATE2 provenance under "Genesis.<P>Multisig") before it counts as the council.
        string memory mproblem =
            _multisigProposerProblem(council, target, string.concat(GENESIS_SALT_PREFIX, multisigName));
        if (bytes(mproblem).length != 0) return string.concat(multisigName, ": ", mproblem);
        return _timelockHolderProblem(target, council, _allowedExtraCancellers(target));
    }

    /// GOVERNANCE timelock -> the verified GuardianCanceller a book in this run lists beside it.
    address[] internal cancellerTimelocks;
    address[] internal cancellerOf;

    /// @notice When `json` lists a GuardianCanceller, verify it against the book's own
    ///         GovernanceTimelock / GuardianTimelock / GuardianMultisig (`_bookGuardianCanceller`)
    ///         and record it as that timelock's one permitted extra canceller. A listed canceller
    ///         that does not verify, or two books naming different cancellers for the same
    ///         timelock, is a TIMELOCK-HOLDERS failure and permits nothing.
    function _registerGuardianCanceller(string memory json) internal {
        if (!vm.keyExistsJson(json, ".contracts.GuardianCanceller")) return;
        if (!vm.keyExistsJson(json, ".contracts.GovernanceTimelock")) {
            _holderFail("GuardianCanceller listed without a GovernanceTimelock");
            return;
        }
        address govTl = vm.parseJsonAddress(json, ".contracts.GovernanceTimelock");
        (string memory problem, address canceller) = _bookGuardianCanceller(json, govTl);
        if (bytes(problem).length != 0) {
            _holderFail(problem);
            return;
        }
        for (uint256 i = 0; i < cancellerTimelocks.length; i++) {
            if (cancellerTimelocks[i] != govTl) continue;
            if (cancellerOf[i] != canceller) {
                _holderFail("two books name different GuardianCancellers for one GovernanceTimelock");
                cancellerOf[i] = address(0);
            }
            return;
        }
        cancellerTimelocks.push(govTl);
        cancellerOf.push(canceller);
    }

    /// @notice The extra canceller `timelock` may carry: its verified GuardianCanceller, or none.
    function _allowedExtraCancellers(address timelock) internal view returns (address[] memory extra) {
        for (uint256 i = 0; i < cancellerTimelocks.length; i++) {
            if (cancellerTimelocks[i] == timelock && cancellerOf[i] != address(0)) {
                extra = new address[](1);
                extra[0] = cancellerOf[i];
                return extra;
            }
        }
        return new address[](0);
    }

    function _holderFail(string memory problem) internal {
        console.log(string.concat("TIMELOCK-HOLDERS ", problem));
        timelockHolders++;
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; i++) {
            out[i - from] = b[i];
        }
    }
}
