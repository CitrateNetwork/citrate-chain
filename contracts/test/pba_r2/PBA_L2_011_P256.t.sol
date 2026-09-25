// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAA} from "../../script/aa/DeployAA.s.sol";

/// PBA-L2-011 (deploy-script part), pre-bounty audit 2026-09-24: the AA
/// ceremony must not advertise the passkey validator on a chain where the
/// P-256 verifier it hard-codes has no code (every passkey signature would fail
/// closed and passkey-rooted wallets could never sign).
contract PBA_L2_011_Regression is Test {
    address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function test_L2_011_deployAARefusesWithoutVerifier() public {
        assertEq(VERIFIER.code.length, 0, "precondition: no verifier (as on 40204 today)");
        vm.setEnv("CITRATE_AA_IDENTITY_SIGNER", "0x8A9062625E98666Fc0072Ee2E7CB8AB08Bd1b651");
        vm.setEnv("CITRATE_AA_OWNER", "0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732");
        vm.setEnv("CITRATE_AA_SPONSOR_SIGNER", "0x676b00c12A958de4901CFa1c81C84086C5DA8ed8");
        DeployAA aa = new DeployAA();
        vm.expectRevert(bytes("P256 verifier has no code; run script/aa/DeployP256Verifier.s.sol first"));
        aa.run();
    }
}
