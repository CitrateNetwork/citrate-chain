// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TEEAttestationRegistry} from "../../src/TEEAttestationRegistry.sol";
import {JWTParser} from "../../src/lib/JWTParser.sol";

/// PBA-L2-024: strict-bound TEE admission pins an approved measurement at a
/// top-level claim boundary; `"` is not a measurement.
contract PBA_L2_024_TeeRegression is Test {
    TEEAttestationRegistry registry;
    address worker = address(0xCAFE);
    bytes32 constant MAA_KID_HASH = keccak256("test-kid");
    bytes32 constant NRAS_KEY = keccak256("nras-prod");
    bytes32 constant MODEL_HASH = keccak256("model-v1");
    // Fixture shared with test/RmD3Bound.t.sol (RS256-signed; payload
    // {"iss":…,"x-ms-vm-measurement":"0xdeadbeefcafe","holder":"0x…cafe","iat":…}).
    bytes constant SIGNED_JWT = bytes(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0."
        "eyJpc3MiOiJzaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsIngtbXMtdm0tbWVhc3VyZW1lbnQiOiIweGRlYWRiZWVmY2FmZSIsImhvbGRlciI6IjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwY2FmZSIsImlhdCI6MTc0NTUyMDAwMH0"
    );
    bytes constant MAA_RSA_MODULUS =
        hex"8968a575e3c2896fdf42b735207c0bc76867a80f1b5848a9f29e91c5074c79b3"
        hex"14542429a91fdb004a7176ef2cbfcf9c93255afb9d6c2bd5b549ae386c49b1e4"
        hex"719069adffe155a6a876ed696f856c7a6448ab7779dbb9705c5c05ed93f04d73"
        hex"dd9d8fc227b35b7682150124e57e6a66ebafcf9d90780fb0a7cb92248c5c0c8e"
        hex"77815f3acd82f20f8e55fb99c43e2d008f1097f409cd916a891189cb976cbade"
        hex"39dddaf5491eac484a4c9a6066ff18dd40754fb346e7289b4d7182ec7e9b2f83"
        hex"1a7045c903dfd85e02bbc064c0005ba0a7bd18f5a476bb3a27d8dbe5eda6f2aa"
        hex"e3af31c6b0e8dd1f4eff4d5a7497335125818898150ad7e50fc890cc0a405929";
    bytes constant MAA_RSA_EXPONENT = hex"010001";
    bytes constant MAA_RSA_SIGNATURE =
        hex"239f979fd70d784ca8a32dd63bcc1d6ce9a06532d0f15c24155e544be7f84644"
        hex"d6fcc420252f52814f9701c068981b6d05c240479182adb4468f3761626f7f4f"
        hex"60b3eed7cc32775fc5180ee19bf03c2171dfd3f25be85ee5de36446d722668cf"
        hex"15217a0d843ab4b2924a28e3c76adf9526cd3513014ea411fbd568bb23268bee"
        hex"b281c06f09d47f4230ebc18fc344ad14894c3e3717f048f824cc282338514599"
        hex"4582ce27ff11f609a2aaa1bae73e16adde69798d553a2a8eafe0efcb57b9c4a8"
        hex"f145493685e879d8c402dedca81186dfcec2a9f1a885ea41451fb4a88a65b96a"
        hex"57cc68dedbeac606ad991624fb91aaec068c0e7277d170a04505732a23a2c197";

    function setUp() public {
        registry = new TEEAttestationRegistry(address(this));
        registry.setNrasSigner(NRAS_KEY, true);
        registry.proposeMaaRsaKey(MAA_KID_HASH, MAA_RSA_MODULUS, MAA_RSA_EXPONENT, true);
        vm.roll(vm.getBlockNumber() + uint256(registry.RSA_KEY_TIMELOCK_BLOCKS()) + 1);
        registry.finalizeMaaRsaKey(MAA_KID_HASH);
    }

    function _submit(bytes memory claim) internal returns (bool ok) {
        vm.prank(worker);
        try registry.submitAttestationStrictBound(
            SIGNED_JWT, MAA_RSA_SIGNATURE, MAA_KID_HASH, claim, keccak256("gpu"), MODEL_HASH, NRAS_KEY
        ) {
            ok = true;
        } catch {}
    }

    /// The finding's tripwire: a valid JWT with `vmMeasurementClaim = "\""`
    /// must not attest.
    function test_L2_024_loneQuoteIsNotAMeasurement() public {
        _submit(bytes('"'));
        assertFalse(registry.isAttested(worker, block.number), "a lone quote attested a worker");
    }

    /// A substring of the real claim (not a whole top-level member) is refused
    /// even when its hash were approved.
    function test_L2_024_partialClaimRefused() public {
        bytes memory partial_ = bytes('"x-ms-vm-measurement":"0xdead');
        (bool ok,) = address(registry).call(
            abi.encodeWithSignature("setApprovedVmMeasurement(bytes32,bool)", keccak256(partial_), true)
        );
        ok;
        _submit(partial_);
        assertFalse(registry.isAttested(worker, block.number), "a partial claim attested a worker");
    }
}


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
