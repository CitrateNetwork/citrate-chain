// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CitratePrecompiles, AnchorProofs, IAnchorRegistryView} from "../../src/lib/CitratePrecompiles.sol";

/// Thin external wrapper so `vm.expectRevert` can observe library reverts.
contract PrecompileCaller {
    function modelInference(bytes32 id, address caller, bytes memory input) external view returns (bytes memory) {
        return CitratePrecompiles.modelInference(id, caller, input);
    }

    function loraApply(bytes memory w, bytes memory b, bytes memory a, bytes memory alpha)
        external
        view
        returns (bytes memory)
    {
        return CitratePrecompiles.loraApply(w, b, a, alpha);
    }

    function loraMerge(bytes memory packed) external view returns (bytes memory) {
        return CitratePrecompiles.loraMerge(packed);
    }

    function anchorCommitment(bytes memory proof) external view returns (bytes32) {
        return CitratePrecompiles.memoryAnchorCommitment(proof);
    }

    function deviceLinkValid(bytes memory body) external view returns (bool) {
        return CitratePrecompiles.deviceLinkValid(body);
    }

    function deviceRevocationValid(bytes memory body) external view returns (bool) {
        return CitratePrecompiles.deviceRevocationValid(body);
    }

    function isRecordAnchored(IAnchorRegistryView reg, bytes memory proof) external view returns (bool) {
        return AnchorProofs.isRecordAnchored(reg, proof);
    }
}

/// Stand-in for a node that serves a precompile: echoes `tag || input`.
contract EchoStandIn {
    fallback(bytes calldata input) external returns (bytes memory) {
        return bytes.concat(bytes("ok:"), input);
    }
}

/// Stand-in that returns a fixed word.
contract WordStandIn {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(1));
    }
}

/// Stand-in that returns a 31-byte answer (a shape the library must refuse).
contract ShortStandIn {
    fallback(bytes calldata) external returns (bytes memory) {
        return new bytes(31);
    }
}

/// Stand-in that returns a word that is neither 0 nor 1.
contract TwoStandIn {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(2));
    }
}

contract Registry is IAnchorRegistryView {
    mapping(bytes32 => bool) public anchored;

    function set(bytes32 r) external {
        anchored[r] = true;
    }

    function isAnchored(bytes32 r) external view returns (bool) {
        return anchored[r];
    }
}

/// HUP-S7.2 / F-1: a chain without the precompile (forge's EVM here, like anvil
/// and a Citrate node below the fork height) must FAIL the call, never answer.
contract CitratePrecompilesFailClosedTest is Test {
    PrecompileCaller internal c;

    function setUp() public {
        c = new PrecompileCaller();
    }

    function _unavailable(address p) internal {
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileUnavailable.selector, p));
    }

    function test_everyHelperFailsClosedWithoutThePrecompile() public {
        _unavailable(address(0x0101));
        c.modelInference(bytes32(uint256(1)), address(this), hex"00");
        _unavailable(address(0x0112));
        c.loraApply(hex"01", hex"02", hex"03", hex"04");
        _unavailable(address(0x0113));
        c.loraMerge(hex"01");
        _unavailable(address(0x0121));
        c.anchorCommitment(hex"00");
        _unavailable(address(0x0122));
        c.deviceLinkValid(hex"00");
        _unavailable(address(0x0122));
        c.deviceRevocationValid(hex"00");
    }

    function test_anchorProofFailsClosedRatherThanReportingFalse() public {
        Registry reg = new Registry();
        _unavailable(address(0x0121));
        c.isRecordAnchored(reg, hex"00");
    }

    function test_modelInferenceUsesTheNativePackedLayout() public {
        vm.etch(address(0x0101), type(EchoStandIn).runtimeCode);
        bytes memory out = c.modelInference(bytes32(uint256(0xAB)), address(0xCAFE), hex"1122");
        assertEq(out, bytes.concat(bytes("ok:"), abi.encodePacked(bytes32(uint256(0xAB)), address(0xCAFE), hex"1122")));
    }

    function test_wrongOutputShapesAreRefused() public {
        vm.etch(address(0x0121), type(ShortStandIn).runtimeCode);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileBadOutput.selector, address(0x0121), 31));
        c.anchorCommitment(hex"00");
        vm.etch(address(0x0122), type(TwoStandIn).runtimeCode);
        vm.expectRevert(abi.encodeWithSelector(CitratePrecompiles.PrecompileBadOutput.selector, address(0x0122), 32));
        c.deviceLinkValid(hex"00");
    }

    function test_agentOpsPrefixesTheOperation() public {
        vm.etch(address(0x0122), type(WordStandIn).runtimeCode);
        vm.expectCall(address(0x0122), bytes.concat(bytes1(0x01), hex"BEEF"));
        assertTrue(c.deviceLinkValid(hex"BEEF"));
        vm.expectCall(address(0x0122), bytes.concat(bytes1(0x02), hex"BEEF"));
        assertTrue(c.deviceRevocationValid(hex"BEEF"));
    }

    function test_anchorProofNeedsBothAValidProofAndARegisteredCommitment() public {
        Registry reg = new Registry();
        // Stand-in returns commitment 0x..01 for any proof.
        vm.etch(address(0x0121), type(WordStandIn).runtimeCode);
        assertFalse(c.isRecordAnchored(reg, hex"00"), "valid proof, commitment not anchored");
        reg.set(bytes32(uint256(1)));
        assertTrue(c.isRecordAnchored(reg, hex"00"));
    }
}
