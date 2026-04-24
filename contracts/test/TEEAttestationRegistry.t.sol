// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../src/TEEAttestationRegistry.sol";

/// @title TEEAttestationRegistryTest — CM-08 WP-08.1 acceptance
/// @notice Verifies the PipelineParallelTEE.tla invariants at
///         contract level: NotAttested → Attested → Expired; Slashed
///         is absorbing.
contract TEEAttestationRegistryTest is Test {
    TEEAttestationRegistry internal registry;

    address internal governance = address(this);
    address internal worker = address(0xCAFE);
    address internal reporter = address(0xB0B);

    bytes32 internal constant MAA_KEY = keccak256("maa-prod");
    bytes32 internal constant NRAS_KEY = keccak256("nras-prod");
    bytes32 internal constant MODEL_HASH = keccak256("model-v1");

    function setUp() public {
        registry = new TEEAttestationRegistry(governance);
        registry.setMaaSigner(MAA_KEY, true);
        registry.setNrasSigner(NRAS_KEY, true);
        vm.deal(reporter, 10 ether);
    }

    function _attest(address who) internal {
        vm.prank(who);
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_submit_transitions_not_attested_to_attested() public {
        assertFalse(registry.isAttested(worker, block.number));
        _attest(worker);
        assertTrue(registry.isAttested(worker, block.number));
    }

    function test_untrusted_signer_reverts() public {
        bytes32 bogusMaa = keccak256("attacker-maa");
        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted MAA signer");
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            bogusMaa,
            NRAS_KEY
        );
    }

    function test_attestation_expires_after_lifetime() public {
        _attest(worker);
        assertTrue(registry.isAttested(worker, block.number));

        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 1);
        assertFalse(registry.isAttested(worker, block.number));
    }

    function test_reattest_extends_expiry() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        uint256 originalExpiry = block.number + lifetime;

        // Advance halfway through the lifetime, then re-attest.
        vm.roll(block.number + lifetime / 2);
        uint256 reattestBlock = block.number;
        _attest(worker);

        // Roll past the ORIGINAL expiry — still attested because
        // fresh expiry = reattestBlock + lifetime > originalExpiry.
        vm.roll(originalExpiry + 100);
        assertTrue(registry.isAttested(worker, block.number),
            "still attested past original expiry thanks to re-attest");

        // Roll past the NEW expiry — now fully expired.
        vm.roll(reattestBlock + lifetime + 1);
        assertFalse(registry.isAttested(worker, block.number));
    }

    function test_slashed_cannot_reattest() public {
        _attest(worker);

        // Force the worker into Slashed via governance path.
        // (In production this goes through reportExpiredServe +
        // finalizeReport; here we simulate the end-state by going
        // through the full flow.)
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 10);

        vm.prank(reporter);
        uint256 reportId = registry.reportExpiredServe{value: 1 ether}(
            worker,
            uint64(block.number - 5), // expired 5 blocks ago
            uint64(block.number - 1)  // served after that
        );

        // Governance upholds, target slashed.
        registry.finalizeReport(reportId, true, 10 ether);

        // Now slashed — re-attest MUST fail.
        vm.prank(worker);
        vm.expectRevert("TEERegistry: slashed cannot re-attest");
        registry.submitAttestation(
            keccak256("vm2"),
            keccak256("gpu2"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_governance_signer_rotation() public {
        bytes32 newMaa = keccak256("maa-rotated");
        registry.setMaaSigner(newMaa, true);
        assertTrue(registry.trustedMaaSigners(newMaa));

        registry.setMaaSigner(MAA_KEY, false);
        assertFalse(registry.trustedMaaSigners(MAA_KEY));

        // Old key no longer works.
        vm.prank(worker);
        vm.expectRevert("TEERegistry: untrusted MAA signer");
        registry.submitAttestation(
            keccak256("vm"),
            keccak256("gpu"),
            MODEL_HASH,
            MAA_KEY,
            NRAS_KEY
        );
    }

    function test_self_report_rejected() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 5);

        vm.deal(worker, 10 ether);
        vm.prank(worker);
        vm.expectRevert("TEERegistry: no self-report");
        registry.reportExpiredServe{value: 1 ether}(
            worker,
            uint64(block.number - 3),
            uint64(block.number - 1)
        );
    }

    function test_wrong_bond_rejected() public {
        _attest(worker);
        uint64 lifetime = registry.ATTESTATION_LIFETIME_BLOCKS();
        vm.roll(block.number + lifetime + 5);

        vm.prank(reporter);
        vm.expectRevert("TEERegistry: wrong bond");
        registry.reportExpiredServe{value: 0.5 ether}(
            worker,
            uint64(block.number - 3),
            uint64(block.number - 1)
        );
    }
}
