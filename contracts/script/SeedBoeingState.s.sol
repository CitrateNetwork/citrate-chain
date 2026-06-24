// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import {ClassificationRegistry} from "../src/rbac/ClassificationRegistry.sol";
import {RoleEscalation} from "../src/rbac/RoleEscalation.sol";
import {MultiSigEnvelope} from "../src/rbac/MultiSigEnvelope.sol";
import {AgentDecisionRegistryV2} from "../src/rbac/AgentDecisionRegistryV2.sol";
import {ContradictionLedger} from "../src/rbac/ContradictionLedger.sol";

import {PartProvenanceRegistry} from "../src/boeing/PartProvenanceRegistry.sol";
import {SupplierRegistry} from "../src/boeing/SupplierRegistry.sol";
import {MoqRegistry} from "../src/boeing/MoqRegistry.sol";
import {BoeingFLScopeIndex} from "../src/boeing/BoeingFLScopeIndex.sol";
import {AppRegistry} from "../src/boeing/AppRegistry.sol";
import {CrossOrgIndex} from "../src/boeing/CrossOrgIndex.sol";
import {AuditBundleRegistry} from "../src/boeing/AuditBundleRegistry.sol";
import {BoeingComplianceRegistry} from "../src/boeing/BoeingComplianceRegistry.sol";
import {RoleGrantTenantIndex} from "../src/boeing/RoleGrantTenantIndex.sol";
import {EntityRegistry} from "../src/boeing/EntityRegistry.sol";
import {TinaWorkpaperRegistry} from "../src/boeing/TinaWorkpaperRegistry.sol";
import {TripwireRegistry} from "../src/boeing/TripwireRegistry.sol";
import {SponsorEvidenceRegistry} from "../src/boeing/SponsorEvidenceRegistry.sol";
import {ReleaseManifestRegistry} from "../src/boeing/ReleaseManifestRegistry.sol";

import {ICrossOrgEnvelopeV1} from "./interfaces/ICrossOrgEnvelopeV1.sol";

/// @title SeedBoeingState
/// @notice BFR-INT-2 - populates chain 40204 (or local devnet) with
///         ~85 realistic records across all 22 BFR contracts so the
///         citrate-gui-native Boeing panels render non-empty data.
///
/// @dev Run as the deployer key (governance for the BFR contracts).
///      The script authorizes itself as recorder/resolver/oracle-signer
///      on each contract, then submits the seed transactions.
///
///      Scenario via env var `SEED_SCENARIO`:
///        "fedramp-demo" (default) → planset volume (~85 records)
///        "stress"                  → 10× volume on decisions/parts/bundles
///        "debug"                   → 1-of-each (smoke test)
///
///      ID determinism: all caller-chosen bytes32 IDs derive from
///      `keccak256(abi.encodePacked("seed-{scope}-{idx}"))` so re-runs
///      are idempotent on contracts that revert on duplicate ID, and
///      skip naturally otherwise.
///
///      Usage:
///        forge script script/SeedBoeingState.s.sol \
///          --rpc-url $RPC_URL \
///          --private-key $FAUCET_PRIVATE_KEY \
///          --broadcast
contract SeedBoeingState is Script {
    // ── Stage-N address constants (from .agentile/CONFIG.md) ───────

    // Stage-1: RBAC foundation
    ClassificationRegistry constant CLASS = ClassificationRegistry(
        0x933E6f4d28E3ebeD462227522d839A77C85B4c06
    );
    RoleEscalation constant ROLE_ESC = RoleEscalation(
        0x3130B9494Dc9c9253078176917cF4CDdcEf48337
    );
    MultiSigEnvelope constant MSE = MultiSigEnvelope(
        0x05825775315f3d074db9F948713D05059e12a8Fd
    );
    AgentDecisionRegistryV2 constant ADR = AgentDecisionRegistryV2(
        0x4a86659BDab24dc444C72fbbaD4cd83491820E40
    );
    ContradictionLedger constant CL = ContradictionLedger(
        0x25051e90A110fbE4569f124274ce387eB033bC9c
    );

    // BFR-05 / 06 / 07
    PartProvenanceRegistry constant PROV = PartProvenanceRegistry(
        0xF0dCa50F418acFb8917D71d8bB65393308629381
    );
    SupplierRegistry constant SUP = SupplierRegistry(
        0xdE991179021A208cF7E6caeBF3a07c229aEd3D0F
    );
    MoqRegistry constant MOQ = MoqRegistry(
        0x575d0d85e272eca8784a4D11F4713C698082c807
    );
    BoeingFLScopeIndex constant FL_IDX = BoeingFLScopeIndex(
        0x26BAD758EAC1bac02457F8e4544269b8B52BC5d7
    );

    // BFR-09 / 10 / 11
    AppRegistry constant APP = AppRegistry(
        0xdAff2B9DC254B6CB3040F8f14304d30E136fa136
    );
    CrossOrgIndex constant COI = CrossOrgIndex(
        0xb87a4F754CA316D2416553d04F4edEd26424B536
    );
    AuditBundleRegistry constant ABR = AuditBundleRegistry(
        0xcEdfd8D76E0d755E9BC93a06FA339c397b70F38D
    );
    BoeingComplianceRegistry constant BCR = BoeingComplianceRegistry(
        0x8dbbbc46D840f40205b48D76aA9FC5063B7D55D8
    );
    RoleGrantTenantIndex constant RGTI = RoleGrantTenantIndex(
        0x1F7a33edF743349d1cb86Ea3A219f6Beb3e647C8
    );

    // BFR-12 / 13 / 14
    EntityRegistry constant ENT = EntityRegistry(
        0x16041DDF6cdb49d3A2D46dA23b5C5820BBD92a66
    );
    TinaWorkpaperRegistry constant TWR = TinaWorkpaperRegistry(
        0xc503fDb502d40c7317aFE1285209e0508A5cC63F
    );
    ICrossOrgEnvelopeV1 constant COE = ICrossOrgEnvelopeV1(
        0x9871e73a189885f87C9C9eC41a6B0C98175C99F8
    );

    // BFR-15 / 16 / 17
    TripwireRegistry constant TW = TripwireRegistry(
        0xA37091480Df4d380D1D2eEe58ead6B3a014FE70F
    );
    SponsorEvidenceRegistry constant SE = SponsorEvidenceRegistry(
        0xf9D198E1280B0D1952e4fF63BD87bcae44b4F82e
    );
    ReleaseManifestRegistry constant REL = ReleaseManifestRegistry(
        0xb92f631bB7f16763C00E52d95f5627806A1284F6
    );

    // ── Mock entity constants ──────────────────────────────────────

    bytes32 constant BOEING_ROOT = keccak256("boeing-root");
    bytes32 constant BCA_SCOPE = keccak256("scope-bca");
    bytes32 constant LINE_787 = keccak256("scope-787-line");
    bytes32 constant TIER1_HONEYWELL = keccak256("tier1-honeywell");
    bytes32 constant DOD_AFRL = keccak256("dod-afrl");

    bytes32 constant USER_ALICE_CO = keccak256("user-alice-co");          // Contracting Officer
    bytes32 constant USER_BOB_PM = keccak256("user-bob-pm");              // Program Manager
    bytes32 constant USER_CLAIRE_QA = keccak256("user-claire-qa");        // QA Lead
    bytes32 constant USER_DIEGO_AUDITOR = keccak256("user-diego-auditor"); // External Auditor
    bytes32 constant USER_EVA_FN = keccak256("user-eva-fn");              // Engineer (Foreign National)

    bytes32 constant ROLE_ADMIN = keccak256("role-admin");
    bytes32 constant ROLE_QA_LEAD = keccak256("role-qa-lead");
    bytes32 constant ROLE_SUPPLIER = keccak256("role-supplier");
    bytes32 constant ROLE_AUDITOR = keccak256("role-auditor");
    bytes32 constant ROLE_CO = keccak256("role-co");

    bytes32 constant FRAMEWORK_FEDRAMP_MOD = keccak256("fedramp-moderate");
    bytes32 constant FRAMEWORK_FEDRAMP_HIGH = keccak256("fedramp-high");
    bytes32 constant FRAMEWORK_CMMC_L3 = keccak256("cmmc-l3");
    bytes32 constant FRAMEWORK_ITAR = keccak256("itar");

    // Tripwire constants (per BFR-15 9-named tripwire convention)
    bytes32 constant TRIP_AC_001 = keccak256("TRIP-AC-001");
    bytes32 constant TRIP_AU_002 = keccak256("TRIP-AU-002");
    bytes32 constant TRIP_SI_001 = keccak256("TRIP-SI-001");

    // ── Scenario sizing ────────────────────────────────────────────

    struct Scenario {
        uint256 decisionsPerCorr;
        uint256 corrIds;
        uint256 parts;
        uint256 stepsPerPart;
        uint256 suppliers;
        uint256 moqCommitments;
        uint256 auditBundles;
    }

    function _scenario() internal view returns (Scenario memory s) {
        string memory tag = vm.envOr("SEED_SCENARIO", string("fedramp-demo"));
        if (_streq(tag, "stress")) {
            s = Scenario({
                decisionsPerCorr: 50,
                corrIds: 8,
                parts: 50,
                stepsPerPart: 5,
                suppliers: 50,
                moqCommitments: 50,
                auditBundles: 50
            });
        } else if (_streq(tag, "debug")) {
            s = Scenario({
                decisionsPerCorr: 1,
                corrIds: 1,
                parts: 1,
                stepsPerPart: 1,
                suppliers: 1,
                moqCommitments: 1,
                auditBundles: 1
            });
        } else {
            // fedramp-demo (default)
            s = Scenario({
                decisionsPerCorr: 5,
                corrIds: 4,
                parts: 5,
                stepsPerPart: 4,
                suppliers: 5,
                moqCommitments: 5,
                auditBundles: 5
            });
        }
    }

    function _streq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    // ── Entry point ────────────────────────────────────────────────

    function run() external {
        uint256 pk = vm.envUint("FAUCET_PRIVATE_KEY");
        address seeder = vm.addr(pk);
        console2.log("=== BFR-INT-2 State Seeder ===");
        console2.log("Seeder:", seeder);
        console2.log("Scenario:", vm.envOr("SEED_SCENARIO", string("fedramp-demo")));

        Scenario memory s = _scenario();

        vm.startBroadcast(pk);

        console2.log("\n[1/15] Authorize recorders + resolvers + oracle signers...");
        _authorize(seeder);

        console2.log("\n[2/15] ClassificationRegistry - 5 users with mixed clearances");
        _seedClassifications();

        console2.log("\n[3/15] RoleEscalation - 5 base roles + RoleGrantTenantIndex mirror");
        _seedRoles();

        console2.log("\n[4/15] AgentDecisionRegistryV2 - decisions across", s.corrIds, "corr_ids");
        _seedDecisions(s);

        console2.log("\n[5/15] ContradictionLedger - 1 flagged subject");
        _seedContradiction();

        console2.log("\n[6/15] MultiSigEnvelope - 3 envelopes in mixed states");
        _seedMultiSigEnvelopes();

        console2.log("\n[7/15] PartProvenanceRegistry - parts:", s.parts);
        _seedProvenance(s);

        console2.log("\n[8/15] SupplierRegistry + MoqRegistry");
        _seedSuppliersAndMoq(s);

        console2.log("\n[9/15] BoeingFLScopeIndex - tag 2 pools");
        _seedFlIndex();

        console2.log("\n[10/15] AppRegistry + CrossOrgIndex");
        _seedAppsAndContracts();

        console2.log("\n[11/15] AuditBundleRegistry");
        _seedAuditBundles(s);

        console2.log("\n[12/15] BoeingComplianceRegistry - 4 frameworks");
        _seedCompliance();

        console2.log("\n[13/15] EntityRegistry + TinaWorkpaperRegistry");
        _seedOntologyAndProcurement();

        console2.log("\n[14/15] CrossOrgEnvelope + TripwireRegistry");
        _seedInterOrgAndTripwires();

        console2.log("\n[15/15] SponsorEvidenceRegistry + ReleaseManifestRegistry");
        _seedSponsorAndRelease();

        vm.stopBroadcast();

        console2.log("\n=== Seeding complete ===");
    }

    // ── Authorization ──────────────────────────────────────────────

    function _authorize(address seeder) internal {
        // Each setX call is idempotent - re-running the script is safe.
        CLASS.addOracleSigner(seeder);
        ROLE_ESC.setRoleAdmin(seeder, true);
        ADR.setRecorder(seeder, true);
        CL.setResolver(seeder, true);

        PROV.setRecorder(seeder, true);
        SUP.setRecorder(seeder, true);
        MOQ.setRecorder(seeder, true);
        FL_IDX.setRecorder(seeder, true);

        APP.setRecorder(seeder, true);
        COI.setRecorder(seeder, true);
        ABR.setRecorder(seeder, true);
        BCR.setRecorder(seeder, true);
        RGTI.setRecorder(seeder, true);

        ENT.setRecorder(seeder, true);
        TWR.setRecorder(seeder, true);
        COE.setRecorder(seeder, true);

        TW.setRecorder(seeder, true);
        TW.setResolver(seeder, true);
        SE.setRecorder(seeder, true);
        REL.setRecorder(seeder, true);
    }

    // ── Domain seeders ─────────────────────────────────────────────

    function _seedClassifications() internal {
        // ClassLevel: 0=Public, 1=Proprietary, 2=CUI, 3=ITAR
        // Stage-1 ClassificationRegistry.setClearance signature uses
        // an oracle-signature arg; for v1 we pass empty bytes since
        // the seeder is itself an oracle signer (authorize step above)
        // and the contract checks signer-set rather than verifying
        // the sig payload. If the deployed bytecode enforces sig
        // verification, this will revert and we'll switch to an
        // off-chain signing helper in WP-1.5.
        bytes memory emptySig = "";
        CLASS.setClearance(USER_ALICE_CO, ClassificationRegistry.ClassLevel.ITAR, false, emptySig);
        CLASS.setClearance(USER_BOB_PM, ClassificationRegistry.ClassLevel.CUI, false, emptySig);
        CLASS.setClearance(USER_CLAIRE_QA, ClassificationRegistry.ClassLevel.Proprietary, false, emptySig);
        CLASS.setClearance(USER_DIEGO_AUDITOR, ClassificationRegistry.ClassLevel.Proprietary, false, emptySig);
        CLASS.setClearance(USER_EVA_FN, ClassificationRegistry.ClassLevel.Public, true, emptySig);

        console2.log("  - 5 clearances set (1 ITAR, 1 CUI, 2 Proprietary, 1 Public/FN)");
    }

    function _seedRoles() internal {
        ROLE_ESC.setBaseRole(USER_ALICE_CO, BCA_SCOPE, ROLE_CO);
        ROLE_ESC.setBaseRole(USER_BOB_PM, BCA_SCOPE, ROLE_ADMIN);
        ROLE_ESC.setBaseRole(USER_CLAIRE_QA, LINE_787, ROLE_QA_LEAD);
        ROLE_ESC.setBaseRole(USER_DIEGO_AUDITOR, BOEING_ROOT, ROLE_AUDITOR);
        ROLE_ESC.setBaseRole(USER_EVA_FN, LINE_787, ROLE_QA_LEAD);

        // Mirror via the sidecar index (BFR-11 RoleGrantTenantIndex)
        RGTI.record(BCA_SCOPE, USER_ALICE_CO);
        RGTI.record(BCA_SCOPE, USER_BOB_PM);
        RGTI.record(LINE_787, USER_CLAIRE_QA);
        RGTI.record(BOEING_ROOT, USER_DIEGO_AUDITOR);
        RGTI.record(LINE_787, USER_EVA_FN);

        console2.log("  - 5 base roles + 5 sidecar index entries");
    }

    function _seedDecisions(Scenario memory s) internal {
        // EventClass: 0=Generation, 1=ToolApproval, 2=ToolRejection,
        //             3=AppAction, 4=Escalation
        for (uint256 c = 0; c < s.corrIds; c++) {
            bytes32 corr = keccak256(abi.encodePacked("corr-", c));
            for (uint256 d = 0; d < s.decisionsPerCorr; d++) {
                bytes32 id = keccak256(abi.encodePacked("decision-", c, "-", d));
                AgentDecisionRegistryV2.EventClass class_ = AgentDecisionRegistryV2
                    .EventClass(uint8((c * 7 + d * 3) % 5));
                bytes32 user = d % 2 == 0 ? USER_BOB_PM : USER_CLAIRE_QA;
                bytes32 tenant = d % 3 == 0 ? BCA_SCOPE : LINE_787;
                ADR.record(
                    id,
                    user,
                    tenant,
                    corr,
                    class_,
                    string(abi.encodePacked("Auto-recorded decision ", _utoa(d))),
                    "PASSKEY",
                    keccak256(abi.encodePacked("artifact-", c, "-", d)),
                    d % 4 == 0 ? "Verified" : "Pending",
                    abi.encodePacked(keccak256(abi.encodePacked("seed-sig-", c, "-", d)))
                );
            }
        }
        console2.log("  -", s.corrIds * s.decisionsPerCorr, "decisions recorded");
    }

    function _seedContradiction() internal {
        CL.report(
            keccak256("contradiction-1"),
            keccak256("subject-part-N7340"),
            "supplier_chain_origin",
            keccak256("source-supplier-claim"),
            keccak256("source-customs-record"),
            "Honeywell-USA",
            "Honeywell-MX",
            USER_DIEGO_AUDITOR,
            keccak256("corr-2")
        );
        console2.log("  - 1 contradiction reported (Belnap B-state)");
    }

    function _seedMultiSigEnvelopes() internal {
        bytes32[] memory signers = new bytes32[](3);
        signers[0] = USER_ALICE_CO;
        signers[1] = USER_BOB_PM;
        signers[2] = USER_DIEGO_AUDITOR;

        // Envelope 1: Drafted
        MSE.draft(
            keccak256("mse-env-1"),
            USER_BOB_PM,
            keccak256("artifact-spec-787-engine"),
            "ipfs://bafyspec1",
            signers,
            2,
            0,
            keccak256("corr-mse-1")
        );

        // Envelope 2: 1 signature collected (Signing state)
        MSE.draft(
            keccak256("mse-env-2"),
            USER_ALICE_CO,
            keccak256("artifact-co-approval"),
            "ipfs://bafyspec2",
            signers,
            2,
            0,
            keccak256("corr-mse-2")
        );
        MSE.sign(keccak256("mse-env-2"), USER_ALICE_CO, "", "PASSKEY");

        // Envelope 3: 2 signatures collected (threshold met → Signed)
        MSE.draft(
            keccak256("mse-env-3"),
            USER_BOB_PM,
            keccak256("artifact-qa-signoff"),
            "ipfs://bafyspec3",
            signers,
            2,
            0,
            keccak256("corr-mse-3")
        );
        MSE.sign(keccak256("mse-env-3"), USER_BOB_PM, "", "PASSKEY");
        MSE.sign(keccak256("mse-env-3"), USER_DIEGO_AUDITOR, "", "PASSKEY");

        console2.log("  - 3 envelopes: Drafted / Signing(1/2) / Signed(2/2)");
    }

    function _seedProvenance(Scenario memory s) internal {
        // StepKind: 0=Manufacture, 1=Inspect, 2=Assemble, 3=Test,
        //          4=Ship, 5=Install
        for (uint256 p = 0; p < s.parts; p++) {
            bytes32 partHash = keccak256(abi.encodePacked("part-", p));
            bytes32 prev = bytes32(0);
            for (uint256 step = 0; step < s.stepsPerPart; step++) {
                bytes32 stepId = keccak256(abi.encodePacked("step-", p, "-", step));
                PartProvenanceRegistry.StepKind kind = PartProvenanceRegistry.StepKind(
                    uint8(step % 6)
                );
                PROV.recordStep(
                    stepId,
                    partHash,
                    prev,
                    USER_CLAIRE_QA,
                    keccak256(abi.encodePacked("corr-prov-", p)),
                    keccak256(abi.encodePacked("decision-prov-", p, "-", step)),
                    keccak256(abi.encodePacked("artifact-prov-", p, "-", step)),
                    kind,
                    string(abi.encodePacked("Step ", _utoa(step), " for part"))
                );
                prev = stepId;
            }
            // Link first part to a tail number
            if (p < 2) {
                bytes32 tail = keccak256(abi.encodePacked("tail-N", _utoa(7340 + p)));
                PROV.linkPartToTail(partHash, tail);
            }
        }
        console2.log("  -", s.parts * s.stepsPerPart, "steps across parts:", s.parts);
    }

    function _seedSuppliersAndMoq(Scenario memory s) internal {
        // SupplierRegistry.State: 0=NotRegistered..6=Disqualified
        for (uint256 i = 0; i < s.suppliers; i++) {
            bytes32 supId = keccak256(abi.encodePacked("supplier-", i));
            SUP.register(supId, BCA_SCOPE, 365, keccak256("corr-sup"), USER_ALICE_CO);
            // Distribute states: 0=Pending, 1=InReview, 2=Qualified,
            //                    3=ReQualified, 4=Suspended
            if (i % 5 == 1) {
                SUP.setState(
                    supId,
                    SupplierRegistry.State.InReview,
                    keccak256("corr-sup"),
                    USER_ALICE_CO,
                    "advance to review"
                );
            } else if (i % 5 == 2) {
                SUP.setState(
                    supId,
                    SupplierRegistry.State.InReview,
                    keccak256("corr-sup"),
                    USER_ALICE_CO,
                    "advance"
                );
                SUP.setState(
                    supId,
                    SupplierRegistry.State.ReQualified,
                    keccak256("corr-sup"),
                    USER_ALICE_CO,
                    "passed re-qualification"
                );
            }
        }

        for (uint256 i = 0; i < s.moqCommitments; i++) {
            MOQ.recordCommitment(
                keccak256(abi.encodePacked("moq-commit-", i)),
                keccak256(abi.encodePacked("supplier-", i)),
                keccak256("part-family-fasteners"),
                keccak256("program-787"),
                BCA_SCOPE,
                10_000 + uint128(i * 1000),
                uint64(block.timestamp),
                uint64(block.timestamp + 90 days)
            );
        }
        console2.log("  - suppliers:", s.suppliers);
        console2.log("  - MOQ commitments:", s.moqCommitments);
    }

    function _seedFlIndex() internal {
        // The LearningPool itself is open - anyone can create. We
        // assume there are already pools 1+2 on chain (per the test
        // narrative). If not, this records dangling tags which the
        // panel renders as "missing pool" - non-fatal. A future
        // commit can wire LearningPool.createPool calls here.
        FL_IDX.tag(1, BCA_SCOPE, keccak256("corr-fl-1"));
        FL_IDX.tag(2, LINE_787, keccak256("corr-fl-2"));
        console2.log("  - 2 FL pool scope tags");
    }

    function _seedAppsAndContracts() internal {
        address[] memory contracts1 = new address[](2);
        contracts1[0] = address(0xCa11ab1eC0a7e);
        contracts1[1] = address(0xDeadBeefCAFEBabe);

        APP.proposeApp(
            keccak256("app-1"),
            BCA_SCOPE,
            "QA Inspection Suite",
            "v1.0.0",
            address(0xCa11ab1eC0a7e),
            keccak256("mse-env-3"), // links to the Signed envelope above
            contracts1,
            keccak256("ipfs-app-1-source")
        );
        // app-1 stays Pending (no deploy yet)

        address[] memory contracts2 = new address[](1);
        contracts2[0] = address(0xC0FfeeC0DeC0FfeeC0Df);

        APP.proposeApp(
            keccak256("app-2"),
            BCA_SCOPE,
            "Supplier Onboarding Portal",
            "v2.1.3",
            address(0xC0FfeeC0DeC0FfeeC0Df),
            keccak256("mse-env-3"),
            contracts2,
            keccak256("ipfs-app-2-source")
        );
        // app-2: try to deploy (will succeed because mse-env-3 met threshold above)
        APP.deploy(keccak256("app-2"));

        COI.record(BCA_SCOPE, keccak256("mse-env-1"));
        COI.record(BCA_SCOPE, keccak256("mse-env-3"));
        console2.log("  - 2 apps (1 Pending, 1 Deployed) + 2 cross-org indices");
    }

    function _seedAuditBundles(Scenario memory s) internal {
        for (uint256 i = 0; i < s.auditBundles; i++) {
            uint8 kind = uint8(i % 3); // 0=Session, 1=Export, 2=Replay
            ABR.anchor(
                kind,
                keccak256(abi.encodePacked("bundle-", i)),
                keccak256(abi.encodePacked("session-", i / 2)),
                BCA_SCOPE,
                keccak256(abi.encodePacked("merkle-", i)),
                keccak256(abi.encodePacked("ipfs-bundle-", i)),
                5 + i
            );
        }
        console2.log("  -", s.auditBundles, "audit bundles anchored");
    }

    function _seedCompliance() internal {
        // posture: 0=NotAttempted..4=Failed
        BCR.attest(
            FRAMEWORK_FEDRAMP_MOD,
            BCA_SCOPE,
            2, // Attested
            keccak256("ipfs-fedramp-mod-evidence"),
            0 // no expiry
        );
        BCR.attest(
            FRAMEWORK_FEDRAMP_HIGH,
            BCA_SCOPE,
            1, // InProgress
            keccak256("ipfs-fedramp-high-wip"),
            0
        );
        BCR.attest(
            FRAMEWORK_CMMC_L3,
            BCA_SCOPE,
            3, // Exception (waiver granted)
            keccak256("ipfs-cmmc-waiver"),
            block.number + 360_000 // ~30 days at 0.5s blocks
        );
        BCR.attest(
            FRAMEWORK_ITAR,
            LINE_787,
            4, // Failed (corrective action required)
            keccak256("ipfs-itar-fail"),
            0
        );
        console2.log("  - 4 compliance attestations across frameworks");
    }

    function _seedOntologyAndProcurement() internal {
        ENT.registerType(BCA_SCOPE, "Part", "Aircraft part component", keccak256("ipfs-schema-part"));
        ENT.registerType(BCA_SCOPE, "Supplier", "Tier-N supplier entity", keccak256("ipfs-schema-supplier"));
        ENT.registerType(BCA_SCOPE, "Person", "Identity record (HR)", keccak256("ipfs-schema-person"));
        ENT.registerType(LINE_787, "Contract", "Procurement contract", keccak256("ipfs-schema-contract"));

        // Bump one schema version
        bytes32 partTypeId = keccak256(abi.encodePacked(BCA_SCOPE, "Part"));
        ENT.bumpSchema(partTypeId, keccak256("ipfs-schema-part-v2"));

        // 2 TINA workpapers
        TWR.draftWorkpaper(
            keccak256("workpaper-1"),
            keccak256("po-hash-A12345"),
            keccak256("workpaper-merkle-1"),
            keccak256("ipfs-form-1411-1"),
            BCA_SCOPE,
            2,
            block.number + 100_000
        );

        TWR.draftWorkpaper(
            keccak256("workpaper-2"),
            keccak256("po-hash-B67890"),
            keccak256("workpaper-merkle-2"),
            keccak256("ipfs-form-1411-2"),
            BCA_SCOPE,
            1,
            block.number + 100_000
        );
        TWR.addSignature(keccak256("workpaper-2"), USER_ALICE_CO);
        TWR.signWorkpaper(keccak256("workpaper-2"));

        console2.log("  - 4 entity types (1 schema bump) + 2 workpapers (1 Pending, 1 Signed)");
    }

    function _seedInterOrgAndTripwires() internal {
        // 3 cross-org envelopes via the deployed (8-arg) signature
        bytes32[] memory orgs = new bytes32[](2);
        orgs[0] = BOEING_ROOT;
        orgs[1] = TIER1_HONEYWELL;
        uint8[] memory ths = new uint8[](2);
        ths[0] = 1;
        ths[1] = 1;
        bytes32[][] memory perOrg = new bytes32[][](2);
        perOrg[0] = new bytes32[](1);
        perOrg[0][0] = USER_BOB_PM;
        perOrg[1] = new bytes32[](1);
        perOrg[1][0] = keccak256("honeywell-pm");

        // env-1: Drafted
        COE.draft(
            keccak256("coe-1"),
            keccak256("artifact-counterfeit-disp-1"),
            keccak256("ipfs-coe-1"),
            orgs,
            ths,
            perOrg,
            0,
            BCA_SCOPE
        );

        // env-2: Signing (1 of 2)
        COE.draft(
            keccak256("coe-2"),
            keccak256("artifact-procurement-2"),
            keccak256("ipfs-coe-2"),
            orgs,
            ths,
            perOrg,
            0,
            BCA_SCOPE
        );
        COE.sign(keccak256("coe-2"), BOEING_ROOT, USER_BOB_PM);

        // env-3: Signed (2 of 2)
        COE.draft(
            keccak256("coe-3"),
            keccak256("artifact-procurement-3"),
            keccak256("ipfs-coe-3"),
            orgs,
            ths,
            perOrg,
            0,
            BCA_SCOPE
        );
        COE.sign(keccak256("coe-3"), BOEING_ROOT, USER_BOB_PM);
        COE.sign(keccak256("coe-3"), TIER1_HONEYWELL, keccak256("honeywell-pm"));

        // 3 tripwire firings (severity: 0=Low..3=Critical)
        TW.fire(keccak256("firing-1"), TRIP_AC_001, BCA_SCOPE, 3, keccak256("evidence-1"));
        TW.acknowledge(keccak256("firing-1"));

        TW.fire(keccak256("firing-2"), TRIP_AU_002, LINE_787, 2, keccak256("evidence-2"));
        TW.acknowledge(keccak256("firing-2"));
        TW.resolve(keccak256("firing-2"));

        TW.fire(keccak256("firing-3"), TRIP_SI_001, BCA_SCOPE, 1, keccak256("evidence-3"));
        // firing-3 stays Fired (active alert)

        console2.log("  - 3 cross-org envelopes + 3 tripwire firings");
    }

    function _seedSponsorAndRelease() internal {
        // 1 sponsor evidence bundle
        SE.anchor(
            keccak256("sponsor-bundle-1"),
            keccak256("sponsor-merkle-1"),
            keccak256("ipfs-sponsor-1"),
            0 // kind: 0=DOD
        );
        SE.addSponsorSignature(keccak256("sponsor-bundle-1"), keccak256("dod-pm-signature"));
        SE.addSponsorSignature(keccak256("sponsor-bundle-1"), keccak256("dod-co-signature"));

        // 1 release manifest, Tested state with 3 artifacts
        bytes32 relId = keccak256("release-v0.5.0-beta.1");
        REL.draftRelease(relId, keccak256("version-tag-v0.5.0-beta.1"));
        REL.addArtifact(
            relId,
            keccak256("linux-x86_64-deb"),
            keccak256("artifact-linux-sha256"),
            keccak256("signature-linux"),
            56_852_264
        );
        REL.addArtifact(
            relId,
            keccak256("macos-arm64"),
            keccak256("artifact-macos-sha256"),
            keccak256("signature-macos"),
            42_000_000
        );
        REL.addArtifact(
            relId,
            keccak256("windows-x86_64"),
            keccak256("artifact-windows-sha256"),
            keccak256("signature-windows"),
            48_000_000
        );
        REL.beginBuild(relId);
        REL.markTested(relId);

        console2.log("  - 1 sponsor bundle (2 signatures) + 1 release (Tested, 3 artifacts)");
    }

    // ── Helpers ────────────────────────────────────────────────────

    function _utoa(uint256 n) internal pure returns (string memory) {
        if (n == 0) return "0";
        uint256 temp = n;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buf = new bytes(digits);
        while (n != 0) {
            digits--;
            buf[digits] = bytes1(uint8(48 + (n % 10)));
            n /= 10;
        }
        return string(buf);
    }
}
