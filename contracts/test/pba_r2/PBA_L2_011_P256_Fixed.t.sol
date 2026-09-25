// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployP256Verifier} from "../../script/aa/DeployP256Verifier.s.sol";

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
