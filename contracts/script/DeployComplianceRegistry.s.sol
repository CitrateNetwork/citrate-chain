// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

import "../src/edu/InstitutionTreeV1.sol";
import "../src/edu/ComplianceRegistry.sol";

/**
 * @title DeployComplianceRegistry
 * @notice Deploys InstitutionTreeV1 + ComplianceRegistry in dependency order
 *         and seeds a CMO/district/school + signs sample compliance gates so
 *         the GUI's CMO portal panels have data to render.
 *
 * Designed for both:
 *   - E6.7 E2E test setup (anvil/devnet)
 *   - Genesis ceremony (mainnet pre-launch)
 *
 * Run:
 *   forge script script/DeployComplianceRegistry.s.sol \
 *     --rpc-url http://localhost:8545 \
 *     --account ceremony-deployer \
 *     --sender $DEPLOYER_ADDRESS \
 *     --broadcast -vvvv
 *
 * Required env vars:
 *   CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS — deployer / governance
 *
 * Optional env vars (E6.7 E2E mode — seed sample data):
 *   CMO_PORTAL_SEED_E2E         — set to "1" to register a sample
 *                                  CMO/district/3-school portfolio and sign
 *                                  full compliance for school 1, partial for
 *                                  school 2, expired for school 3
 *   E2E_CMO_ADMIN               — admin for the sample CMO (default: deployer)
 *   E2E_DISTRICT_ADMIN          — admin for the sample district (default: deployer)
 *   E2E_SCHOOL_ADMIN            — admin for the sample school (default: deployer)
 *
 * Output (printed to console + saved to deployments JSON in CI):
 *   institutionTree=<addr>
 *   complianceRegistry=<addr>
 *   sampleCmoHash=<bytes32>
 *   sampleSchool1Hash=<bytes32>
 *   sampleSchool2Hash=<bytes32>
 *   sampleSchool3Hash=<bytes32>
 */
contract DeployComplianceRegistry is ScriptEnv {
    // Sample tenancy IDs — deterministic so E2E tests can reproduce them
    bytes32 internal constant E2E_CMO_HASH = keccak256("E2E-CMO-KIPP");
    bytes32 internal constant E2E_DIST_HASH = keccak256("E2E-DIST-NJ");
    bytes32 internal constant E2E_SCH1_HASH = keccak256("E2E-SCH-NEWARK");
    bytes32 internal constant E2E_SCH2_HASH = keccak256("E2E-SCH-BAYONNE");
    bytes32 internal constant E2E_SCH3_HASH = keccak256("E2E-SCH-JC");

    // State enum index: 0=CA, 1=NY, 2=IL, 3=TX, 4=CO, 255=Other
    uint8 internal constant STATE_NJ = 255; // Other (NJ not in enum)

    function run() external {
        address deployer = deployerAddress();
        address cmoAdmin = envAddressOr("E2E_CMO_ADMIN", deployer);
        address districtAdmin = envAddressOr("E2E_DISTRICT_ADMIN", deployer);
        address schoolAdmin = envAddressOr("E2E_SCHOOL_ADMIN", deployer);

        bool seedE2E = envUintOr("CMO_PORTAL_SEED_E2E", 0) == 1;

        console.log("=== Deploying CMO Portal Contracts ===");
        console.log("Deployer/Governance:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("Seed E2E sample data:", seedE2E);

        vm.startBroadcast();

        // 1. InstitutionTreeV1 (governance-owned)
        InstitutionTreeV1 tree = new InstitutionTreeV1(deployer);
        console.log("institutionTree=", address(tree));

        // 2. ComplianceRegistry (depends on tree address)
        ComplianceRegistry reg = new ComplianceRegistry(deployer, address(tree));
        console.log("complianceRegistry=", address(reg));

        if (seedE2E) {
            _seedE2EData(tree, reg, cmoAdmin, districtAdmin, schoolAdmin);
        }

        vm.stopBroadcast();

        console.log("=== Deployment Complete ===");
        console.log("Update DEPLOYED_ADDRESSES.md with:");
        console.log("  - institution_tree:", address(tree));
        console.log("  - compliance_registry:", address(reg));
    }

    function _seedE2EData(
        InstitutionTreeV1 tree,
        ComplianceRegistry reg,
        address cmoAdmin,
        address districtAdmin,
        address schoolAdmin
    ) internal {
        console.log("--- Seeding E2E sample data ---");
        console.log("sampleCmoHash=", uint256(E2E_CMO_HASH));
        console.log("sampleDistrictHash=", uint256(E2E_DIST_HASH));
        console.log("sampleSchool1Hash=", uint256(E2E_SCH1_HASH));
        console.log("sampleSchool2Hash=", uint256(E2E_SCH2_HASH));
        console.log("sampleSchool3Hash=", uint256(E2E_SCH3_HASH));

        // Register tenancy: CMO → 1 district → 3 schools (all in NJ)
        // Deployer is governance and may register the CMO.
        tree.registerCmo(E2E_CMO_HASH, cmoAdmin, STATE_NJ);

        // The CMO admin (or governance) registers the district. Since we're
        // running broadcast as deployer (= governance), governance registers
        // the district directly.
        tree.registerDistrict(E2E_CMO_HASH, E2E_DIST_HASH, districtAdmin, STATE_NJ);

        // The district admin registers schools. If deployer != districtAdmin,
        // governance is also authorized.
        tree.registerSchool(E2E_DIST_HASH, E2E_SCH1_HASH, schoolAdmin, STATE_NJ);
        tree.registerSchool(E2E_DIST_HASH, E2E_SCH2_HASH, schoolAdmin, STATE_NJ);
        tree.registerSchool(E2E_DIST_HASH, E2E_SCH3_HASH, schoolAdmin, STATE_NJ);

        // Sign sample compliance gates. Note: schools are STATE_NJ (255),
        // so only the 4 federal gates are applicable (state gates 4..8 are
        // NotApplicable for NJ schools).
        //
        // Pattern (matches E6.5 stub colors so visual review is consistent):
        //   School 1 (Newark):   all 4 federal gates Signed → Green
        //   School 2 (Bayonne):  3 of 4 federal Signed (DPA pending) → Yellow
        //   School 3 (JC):       3 of 4 federal Signed, CIPA expired → Red

        uint64 oneYear = uint64(block.timestamp + 365 days);
        uint64 thirtyDaysFromNow = uint64(block.timestamp + 30 days);

        // School 1: full compliance
        if (msg.sender == schoolAdmin) {
            reg.recordSigned(E2E_SCH1_HASH, 0 /*DPA*/, keccak256("env-sch1-dpa"), oneYear);
            reg.recordSigned(E2E_SCH1_HASH, 1 /*FERPA*/, keccak256("env-sch1-ferpa"), oneYear);
            reg.recordSigned(E2E_SCH1_HASH, 2 /*COPPA*/, keccak256("env-sch1-coppa"), oneYear);
            reg.recordSigned(E2E_SCH1_HASH, 3 /*CIPA*/, keccak256("env-sch1-cipa"), oneYear);

            // School 2: DPA NOT signed (Yellow), others signed
            reg.recordSigned(E2E_SCH2_HASH, 1 /*FERPA*/, keccak256("env-sch2-ferpa"), oneYear);
            reg.recordSigned(E2E_SCH2_HASH, 2 /*COPPA*/, keccak256("env-sch2-coppa"), oneYear);
            reg.recordSigned(E2E_SCH2_HASH, 3 /*CIPA*/, keccak256("env-sch2-cipa"), oneYear);

            // School 3: CIPA signed but with short window so it expires soon (Red after warp)
            reg.recordSigned(E2E_SCH3_HASH, 0 /*DPA*/, keccak256("env-sch3-dpa"), oneYear);
            reg.recordSigned(E2E_SCH3_HASH, 1 /*FERPA*/, keccak256("env-sch3-ferpa"), oneYear);
            reg.recordSigned(E2E_SCH3_HASH, 2 /*COPPA*/, keccak256("env-sch3-coppa"), oneYear);
            reg.recordSigned(E2E_SCH3_HASH, 3 /*CIPA*/, keccak256("env-sch3-cipa-short"), thirtyDaysFromNow);
        } else {
            console.log(
                "WARN: deployer is not E2E_SCHOOL_ADMIN; skipping compliance signing. "
                "Set E2E_SCHOOL_ADMIN=$DEPLOYER_ADDRESS to seed full data."
            );
        }

        console.log("--- E2E sample data seeded ---");
    }
}
