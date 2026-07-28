// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {GovernanceTemplateRegistry} from "../src/quorum/GovernanceTemplateRegistry.sol";
import {ThresholdApproval} from "../src/quorum/ThresholdApproval.sol";
import {ClassificationGate} from "../src/quorum/ClassificationGate.sol";
import {BudgetedAutonomy} from "../src/quorum/BudgetedAutonomy.sol";
import {SegregationOfDuties} from "../src/quorum/SegregationOfDuties.sol";
import {TimeBoundedElevation} from "../src/quorum/TimeBoundedElevation.sol";
import {ChangeControlBoard} from "../src/quorum/ChangeControlBoard.sol";
import {SupplierAdmission} from "../src/quorum/SupplierAdmission.sol";
import {IncidentEscalation} from "../src/quorum/IncidentEscalation.sol";

/// @title RegisterSeedTemplates — the eight seed templates, under a devnet CID
/// @notice citrate-quorum, owner decision D-2 (2026-07-27).
///
/// `GovernanceTemplateRegistry.register` requires a non-empty `auditCID` by
/// design: that requirement is the whole reason the registry exists, and QRM-S6.9
/// deliberately registered NOTHING rather than pass a placeholder.
///
/// The owner's decision was to register on devnet against a CID whose **content
/// states in plain text that this is not an audit**. That content is
/// `contracts/audit/UNAUDITED-DEVNET-2026-07-27.txt`, pinned at
/// `bafkreibc3llznx4vvnbabhjdkcj4alz372xijq4kzaiagrpnouv2vv6tdy` — a real
/// content-addressed CID, so anyone can verify the bytes hash to it, and anyone
/// who follows it reads "THIS IS NOT AN AUDIT" as the first line.
///
/// The constraint that survives the decision: **nothing registered here may be
/// described to a customer as audited.** The field is named `auditCID` and a
/// reader will assume it means an audit, which is exactly why the document it
/// points at has to say otherwise.
///
/// ## `initCodeHash` is computed here, not transcribed
///
/// Each row pins `keccak256(type(T).creationCode)` read from the compiler at
/// broadcast time. A hash copied from a build log by hand is a hash nobody
/// checked, and this is the value the factory's GF-2 refuses mismatches against
/// — the single number the whole audit boundary rests on.
///
/// ## Re-running
///
/// `register` reverts with `TemplateExists` on a duplicate `(name, version)`.
/// This script therefore skips rows already present rather than aborting, so it
/// is safe to re-run after a partial failure — but it never overwrites, because
/// TR-1 makes a registered row immutable and that is the point.
contract RegisterSeedTemplates is Script {
    /// The pinned notice. See the header.
    string constant AUDIT_CID = "bafkreibc3llznx4vvnbabhjdkcj4alz372xijq4kzaiagrpnouv2vv6tdy";
    uint32 constant VERSION = 1;

    function run() external {
        address registryAddr = vm.envAddress("TEMPLATE_REGISTRY");
        require(registryAddr.code.length > 0, "TEMPLATE_REGISTRY has no code");
        GovernanceTemplateRegistry reg = GovernanceTemplateRegistry(registryAddr);

        string[8] memory names = [
            "ThresholdApproval",
            "ClassificationGate",
            "BudgetedAutonomy",
            "SegregationOfDuties",
            "TimeBoundedElevation",
            "ChangeControlBoard",
            "SupplierAdmission",
            "IncidentEscalation"
        ];
        bytes32[8] memory codeHashes = [
            keccak256(type(ThresholdApproval).creationCode),
            keccak256(type(ClassificationGate).creationCode),
            keccak256(type(BudgetedAutonomy).creationCode),
            keccak256(type(SegregationOfDuties).creationCode),
            keccak256(type(TimeBoundedElevation).creationCode),
            keccak256(type(ChangeControlBoard).creationCode),
            keccak256(type(SupplierAdmission).creationCode),
            keccak256(type(IncidentEscalation).creationCode)
        ];
        // keccak256 of contracts/schemas/<name>.params.json, read from disk so
        // the pinned hash and the file on disk cannot disagree.
        bytes32[8] memory schemaHashes;
        for (uint256 i = 0; i < 8; i++) {
            string memory path =
                string.concat(vm.projectRoot(), "/schemas/", names[i], ".params.json");
            schemaHashes[i] = keccak256(bytes(vm.readFile(path)));
        }

        vm.startBroadcast();
        uint256 registered;
        uint256 skipped;
        for (uint256 i = 0; i < 8; i++) {
            bytes32 id = reg.templateId(names[i], VERSION);
            if (reg.exists(id)) {
                console2.log("skip (already registered):", names[i]);
                skipped++;
                continue;
            }
            reg.register(names[i], VERSION, codeHashes[i], schemaHashes[i], AUDIT_CID);
            console2.log("registered:", names[i]);
            console2.logBytes32(id);
            registered++;
        }
        vm.stopBroadcast();

        console2.log("=== seed templates ===");
        console2.log("registered:", registered);
        console2.log("skipped:", skipped);
        console2.log("auditCID:", AUDIT_CID);
        console2.log("NOT AN AUDIT - devnet only. See the CID's own content.");
    }
}
