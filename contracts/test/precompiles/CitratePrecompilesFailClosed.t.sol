// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CitratePrecompiles, AnchorProofs, IAnchorRegistryView} from "../../src/lib/CitratePrecompiles.sol";
import {AnchorRegistry} from "../../src/cit_agent/AnchorRegistry.sol";

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

    function isRecordAnchored(IAnchorRegistryView reg, address committer, bytes memory proof)
        external
        view
        returns (bool)
    {
        return AnchorProofs.isRecordAnchored(reg, committer, proof);
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

/// Stand-in that returns the zero word (an invalid anchor proof).
contract ZeroWordStandIn {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(0));
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

    address internal constant AGENT = address(0xA6E7);

    function _reg() internal returns (AnchorRegistry) {
        return new AnchorRegistry();
    }

    function _view(AnchorRegistry reg) internal pure returns (IAnchorRegistryView) {
        return IAnchorRegistryView(address(reg));
    }

    function test_anchorProofFailsClosedRatherThanReportingFalse() public {
        AnchorRegistry reg = _reg();
        _unavailable(address(0x0121));
        c.isRecordAnchored(_view(reg), AGENT, hex"00");
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
        AnchorRegistry reg = _reg();
        // Stand-in returns commitment 0x..01 for any proof.
        vm.etch(address(0x0121), type(WordStandIn).runtimeCode);
        assertFalse(c.isRecordAnchored(_view(reg), AGENT, hex"00"), "valid proof, commitment not anchored");
        vm.prank(AGENT);
        reg.anchor(AnchorRegistry.AnchorKind.NightlyMerkle, bytes32(uint256(1)));
        assertTrue(c.isRecordAnchored(_view(reg), AGENT, hex"00"));
    }

    /// `AnchorRegistry.anchor` is open to every caller: a commitment anchored
    /// by another account proves nothing about the agent's own log.
    function test_anchorProofIgnoresCommitmentsAnchoredBySomeoneElse() public {
        AnchorRegistry reg = _reg();
        vm.etch(address(0x0121), type(WordStandIn).runtimeCode);
        vm.prank(address(0xBAD));
        reg.anchor(AnchorRegistry.AnchorKind.NightlyMerkle, bytes32(uint256(1)));
        assertFalse(c.isRecordAnchored(_view(reg), AGENT, hex"00"), "another committer's anchor");
        assertTrue(c.isRecordAnchored(_view(reg), address(0xBAD), hex"00"), "its own committer still proves");
    }

    /// Only a nightly-root anchor is a day commitment.
    function test_anchorProofIgnoresOtherAnchorKinds() public {
        AnchorRegistry reg = _reg();
        vm.etch(address(0x0121), type(WordStandIn).runtimeCode);
        vm.prank(AGENT);
        reg.anchor(AnchorRegistry.AnchorKind.PerCapsule, bytes32(uint256(1)));
        assertFalse(c.isRecordAnchored(_view(reg), AGENT, hex"00"), "per-capsule anchor is not a day commitment");
    }

    /// An invalid proof (zero commitment) and an unset committer never prove.
    function test_anchorProofRejectsZeroCommitmentAndZeroCommitter() public {
        AnchorRegistry reg = _reg();
        vm.prank(AGENT);
        reg.anchor(AnchorRegistry.AnchorKind.NightlyMerkle, bytes32(0));
        vm.etch(address(0x0121), type(ZeroWordStandIn).runtimeCode);
        assertFalse(c.isRecordAnchored(_view(reg), AGENT, hex"00"), "zero = invalid proof");
        vm.etch(address(0x0121), type(WordStandIn).runtimeCode);
        assertFalse(c.isRecordAnchored(_view(reg), address(0), hex"00"), "no committer named");
    }
}
