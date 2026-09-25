// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../../src/TEEAttestationRegistry.sol";
import {JWTParser} from "../../src/lib/JWTParser.sol";
import {TeeFixture} from "./PBA_L2_024_TEE.t.sol";

contract JWTHarness {
    function top(bytes memory h, bytes memory n) external pure returns (bool) {
        return JWTParser.containsTopLevelClaim(h, n);
    }
}

/// PBA-L2-024: fixed behaviour through the new API + top-level anchoring tripwire.
contract PBA_L2_024_TeeFixed is Test {
    function test_L2_024_topLevelClaimAnchoring() public {
        JWTHarness h = new JWTHarness();
        bytes memory json = bytes('{"a":"1","x-ms-runtime":{"k":"v","m":"x"},"m":"x","z":[1,{"m":"x"}]}');
        assertTrue(h.top(json, bytes('"a":"1"')));
        assertTrue(h.top(json, bytes('"m":"x"')), "top-level member matches");
        assertFalse(h.top(bytes('{"x-ms-runtime":{"m":"x"}}'), bytes('"m":"x"')), "nested member must not match");
        assertFalse(h.top(json, bytes('"')), "lone quote");
        assertFalse(h.top(bytes('{"a":"12"}'), bytes('"a":"1')), "prefix of a value");
        assertFalse(h.top(bytes('{"b":"\\"a\\":\\"1\\""}'), bytes('"a":"1"')), "inside an escaped string");
        assertTrue(h.top(bytes('{ "a" : "1" , "b":2 }'), bytes('"a" : "1"')), "whitespace tolerated");
    }

    function test_L2_024_isAttestedFollowsApproval() public {
        TEEAttestationRegistry r = new TEEAttestationRegistry(address(this));
        r.setStrictCryptographicMode(false);
        r.setMaaSigner(keccak256("maa"), true);
        r.setNrasSigner(keccak256("nras"), true);
        address w = makeAddr("w");
        vm.prank(w);
        r.submitAttestation(keccak256("vm"), keccak256("gpu"), keccak256("model"), keccak256("maa"), keccak256("nras"));
        assertFalse(r.isAttested(w, block.number), "unapproved measurement");
        r.setApprovedVmMeasurement(keccak256("vm"), true);
        assertTrue(r.isAttested(w, block.number));
        r.setApprovedVmMeasurement(keccak256("vm"), false);
        assertFalse(r.isAttested(w, block.number), "revocation de-attests");
        vm.prank(w);
        vm.expectRevert();
        r.setApprovedVmMeasurement(keccak256("x"), true);
    }
}

/// Mutation hardening (PBA-L2-024): a complete, top-level claim that governance
/// has NOT approved must not attest.
contract PBA_L2_024_Unapproved is TeeFixture {
    function test_L2_024_unapprovedTopLevelClaimRefused() public {
        // Refused at submission (fail-fast; the one-shot JWT is not burned and
        // a later approval cannot silently attest this record).
        assertFalse(_submit(bytes('"iss":"sharedeus2.eus2.attest.azure.net"')), "unapproved claim must revert");
        assertFalse(registry.isAttested(worker, block.number), "an unapproved measurement attested a worker");
    }

    function test_L2_024_approvedRealClaimAttests() public {
        bytes memory claim = bytes('"x-ms-vm-measurement":"0xdeadbeefcafe"');
        registry.setApprovedVmMeasurement(keccak256(claim), true);
        assertTrue(_submit(claim));
        assertTrue(registry.isAttested(worker, block.number));
    }
}
