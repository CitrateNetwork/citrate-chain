// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployP256Verifier} from "../../script/aa/DeployP256Verifier.s.sol";
import {DeployAA} from "../../script/aa/DeployAA.s.sol";
import {DevP256Verifier} from "../../script/aa/lib/DevP256Verifier.sol";

/// PBA-L2-011: DeployP256Verifier only ever puts the exact init code whose
/// CREATE2 address is P256.VERIFIER there; anything else is refused before
/// broadcasting.
contract PBA_L2_011_Fixed is Test {
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function test_L2_011_wrongInitCodeRefused() public {
        DeployP256Verifier d = new DeployP256Verifier();
        vm.setEnv("P256_VERIFIER_INITCODE", "0x600160005260206000f3");
        vm.expectRevert(bytes("init code/salt do not produce P256.VERIFIER; refusing"));
        d.run();
    }

    function test_L2_011_addressFormulaMatchesCreate2() public {
        DeployP256Verifier d = new DeployP256Verifier();
        bytes memory code = hex"600160005260206000f3";
        assertEq(d.computeAddress(bytes32(uint256(7)), code), vm.computeCreate2Address(bytes32(uint256(7)), keccak256(code), FACTORY));
    }

    function test_L2_011_noopWhenVerifierPresent() public {
        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, hex"600160005260206000f3");
        DeployP256Verifier d = new DeployP256Verifier();
        d.run(); // must not require P256_VERIFIER_INITCODE when already provisioned
    }
}

/// PBA-L2-011 dev path: on anvil DeployAA provisions a working local verifier
/// instead of hard-failing; the vendored runtime really verifies P-256.
contract PBA_L2_011_DevPath is Test {
    address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function test_L2_011_devRuntimeVerifiesRealSignatures() public {
        vm.etch(VERIFIER, DevP256Verifier.runtime());
        uint256 pk = 0xA11CE;
        bytes32 h = keccak256("citrate passkey");
        (bytes32 r, bytes32 s) = vm.signP256(pk, h);
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        (bool ok, bytes memory ret) = VERIFIER.staticcall(abi.encode(h, r, s, x, y));
        assertTrue(ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1, "valid signature accepted");
        (ok, ret) = VERIFIER.staticcall(abi.encode(keccak256("other"), r, s, x, y));
        assertTrue(!(ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1), "wrong message rejected");
    }

    function test_L2_011_deployAAOnAnvilProvisionsDevVerifier() public {
        vm.chainId(31337);
        vm.setEnv("CITRATE_AA_IDENTITY_SIGNER", "0x8A9062625E98666Fc0072Ee2E7CB8AB08Bd1b651");
        vm.setEnv("CITRATE_AA_OWNER", "0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732");
        vm.setEnv("CITRATE_AA_SPONSOR_SIGNER", "0x676b00c12A958de4901CFa1c81C84086C5DA8ed8");
        DeployAA aa = new DeployAA();
        aa.run();
        assertGt(VERIFIER.code.length, 0, "dev verifier installed on anvil");
    }
}
