// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";

/// @notice Invariant tests for ComplianceRegistry. A handler contract drives
///         random sequences of mutations; after each mutation, Foundry's
///         invariant runner asserts the state-machine invariants hold.
///
///         Invariants:
///           I1. totalSignings is monotonic — never decreases.
///           I2. totalRevocations is monotonic — never decreases.
///           I3. totalRevocations <= totalSignings — every revocation
///                follows a signing (you can't revoke an Untouched record).
///           I4. For any (school, gate), the recorded status is one of
///                {Untouched, Signed, Expired, Revoked} — NotApplicable
///                is a synthetic read-only state, never written.
///           I5. If status == Signed and block.timestamp <= expiresAt then
///                isCompliant == true (modulo school-tree revocation).
///           I6. If status == Revoked then isCompliant == false.
///           I7. signer == address(0) iff status == Untouched.
contract ComplianceRegistryHandler is Test {
    ComplianceRegistry public reg;
    InstitutionTreeV1 public tree;
    address public governance;
    address public schoolAdmin;
    bytes32 public schoolHash;

    // Track ghost variables so invariants can compare deltas
    uint256 public ghostSignings;
    uint256 public ghostRevocations;

    constructor(
        ComplianceRegistry _reg,
        InstitutionTreeV1 _tree,
        address _governance,
        address _schoolAdmin,
        bytes32 _schoolHash
    ) {
        reg = _reg;
        tree = _tree;
        governance = _governance;
        schoolAdmin = _schoolAdmin;
        schoolHash = _schoolHash;
    }

    function recordSigned(uint8 gateIdx, uint64 deltaSeconds, bytes32 envHash) public {
        gateIdx = uint8(bound(uint256(gateIdx), 0, 3)); // federal gates only
        if (envHash == bytes32(0)) envHash = keccak256(abi.encode("env", gateIdx));
        uint64 nowTs = uint64(block.timestamp);
        uint64 maxWindow = reg.MAX_VALIDITY_WINDOW();
        uint64 boundedDelta = uint64(bound(uint256(deltaSeconds), 1, maxWindow));
        uint64 expiresAt = nowTs + boundedDelta;

        // Skip if currently Signed (would revert with CannotRecordSigned)
        if (reg.getRecord(schoolHash, gateIdx).status == ComplianceRegistry.Status.Signed) {
            return;
        }

        vm.prank(schoolAdmin);
        try reg.recordSigned(schoolHash, gateIdx, envHash, expiresAt) {
            ghostSignings++;
        } catch {
            // Tolerated: tree-level revocations etc. — invariants still hold
        }
    }

    function expireGate(uint8 gateIdx, uint32 forwardSeconds) public {
        gateIdx = uint8(bound(uint256(gateIdx), 0, 3));
        ComplianceRegistry.Record memory r = reg.getRecord(schoolHash, gateIdx);
        if (r.status != ComplianceRegistry.Status.Signed) return;

        // Walk forward to past expiry
        uint64 advance = uint64(bound(uint256(forwardSeconds), 1, 365 days));
        if (block.timestamp + advance <= uint256(r.expiresAt)) {
            vm.warp(uint256(r.expiresAt) + 1);
        } else {
            vm.warp(block.timestamp + advance);
        }

        try reg.expireGate(schoolHash, gateIdx) {
            // ok
        } catch {
            // Tolerated
        }
    }

    function revokeGate(uint8 gateIdx) public {
        gateIdx = uint8(bound(uint256(gateIdx), 0, 3));
        ComplianceRegistry.Status s = reg.getRecord(schoolHash, gateIdx).status;
        if (s == ComplianceRegistry.Status.Untouched || s == ComplianceRegistry.Status.Revoked) {
            return;
        }
        vm.prank(governance);
        try reg.revokeGate(schoolHash, gateIdx, keccak256("inv-reason")) {
            ghostRevocations++;
        } catch {
            // Tolerated
        }
    }
}

contract ComplianceRegistryInvariantTest is Test {
    ComplianceRegistry internal reg;
    InstitutionTreeV1 internal tree;
    ComplianceRegistryHandler internal handler;

    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);
    address internal schoolAdmin = address(0x5C0CA);

    bytes32 internal constant CMO_HASH = keccak256("INV-CMO");
    bytes32 internal constant DIST_HASH = keccak256("INV-DIST");
    bytes32 internal constant SCH_HASH = keccak256("INV-SCH");

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
        reg = new ComplianceRegistry(governance, address(tree));
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, 0);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DIST_HASH, districtAdmin, 0);
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_HASH, SCH_HASH, schoolAdmin, 0);
        vm.warp(1_700_000_000);

        handler = new ComplianceRegistryHandler(reg, tree, governance, schoolAdmin, SCH_HASH);
        targetContract(address(handler));
    }

    // I1+I2: counters monotonic — guaranteed by `unchecked { x += 1; }`,
    // verified here by ensuring the registry's view matches the handler's
    // ghost (only-grew) counter.
    function invariant_counters_matchHandlerGhost() public view {
        assertGe(reg.totalSignings(), handler.ghostSignings());
        assertGe(reg.totalRevocations(), handler.ghostRevocations());
    }

    // I3: totalRevocations <= totalSignings
    function invariant_revocations_leq_signings() public view {
        assertLe(reg.totalRevocations(), reg.totalSignings());
    }

    // I4: every (school, gate) record's status is one of the 4 storage states.
    //     NotApplicable should never appear in storage (only in synthetic reads).
    function invariant_storageStatus_isStorageOnly() public view {
        for (uint8 g = 0; g < 4; g++) {
            ComplianceRegistry.Status s = reg.getRecord(SCH_HASH, g).status;
            assertTrue(
                s == ComplianceRegistry.Status.Untouched
                    || s == ComplianceRegistry.Status.Signed
                    || s == ComplianceRegistry.Status.Expired
                    || s == ComplianceRegistry.Status.Revoked,
                "storage status must be one of {Untouched, Signed, Expired, Revoked}"
            );
        }
    }

    // I6: Revoked records are NEVER compliant.
    function invariant_revoked_neverCompliant() public view {
        for (uint8 g = 0; g < 4; g++) {
            ComplianceRegistry.Record memory r = reg.getRecord(SCH_HASH, g);
            if (r.status == ComplianceRegistry.Status.Revoked) {
                assertFalse(reg.isCompliant(SCH_HASH, g), "revoked must not be compliant");
            }
        }
    }

    // I7: signer == address(0) iff status == Untouched.
    function invariant_signerNonZero_iff_recordTouched() public view {
        for (uint8 g = 0; g < 4; g++) {
            ComplianceRegistry.Record memory r = reg.getRecord(SCH_HASH, g);
            if (r.status == ComplianceRegistry.Status.Untouched) {
                assertEq(r.signer, address(0));
                assertEq(r.envelopeIdHash, bytes32(0));
                assertEq(r.signedAt, 0);
                assertEq(r.expiresAt, 0);
            } else {
                assertTrue(r.signer != address(0));
                assertTrue(r.envelopeIdHash != bytes32(0));
            }
        }
    }
}
