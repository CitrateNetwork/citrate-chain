// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title CitratePrecompiles: fail-closed calls to Citrate precompiles
/// @notice HUP-S7.2 (federation F-1 / F-2 / F-3). One place that knows the
///         precompile addresses and their native input encodings, and that
///         refuses to treat "no answer" as an answer.
///
/// @dev Why this exists. A CALL or STATICCALL to an address with no code
///      SUCCEEDS with empty returndata. A contract that checks only the success
///      flag therefore reads "the precompile is not on this chain" as "the
///      precompile said yes" (or as an empty result it then pays for). Every
///      helper here requires the exact output shape and reverts with
///      `PrecompileUnavailable` otherwise, so a node or a test chain without the
///      precompile (anvil, forge, a Citrate node below the activation height)
///      fails the transaction instead of silently doing nothing.
///
///      Encoding decision (F-1): contracts encode each precompile's NATIVE input
///      (an in-contract adapter); the node does not decode Solidity ABI
///      selectors. The precompiles are pure byte functions with frozen layouts
///      (spec: `docs/precompiles/AGENT_PRECOMPILES.md`, ADR
///      `.agentile/adrs/ADR-2026-10-01-agent-precompiles.md`).
///
///      Availability on chain 40204 today:
///        * 0x0101 MODEL_INFERENCE / 0x0106 MODEL_ENCRYPTION are NOT exposed to
///          contract code (non-deterministic inference is not a consensus
///          operation, audit C-01). Calls fail closed.
///        * 0x0112 / 0x0113 / 0x0121 / 0x0122 exist only from the agent
///          precompile fork height, which is not scheduled. Calls fail closed.
library CitratePrecompiles {
    /// 0x0101 MODEL_INFERENCE. Native input: model_id (32) || caller (20) || input.
    address internal constant MODEL_INFERENCE = address(0x0101);
    /// 0x0106 MODEL_ENCRYPTION. Native input: op (1) || operation-specific bytes.
    address internal constant MODEL_ENCRYPTION = address(0x0106);
    /// 0x0112 LORA_APPLY. Input: W || B || A || alpha (Q16.16 tensors). Output: tensor.
    address internal constant LORA_APPLY = address(0x0112);
    /// 0x0113 LORA_MERGE. Input: n (1) || n x (B_i || A_i || alpha_i || w_i). Output: tensor.
    address internal constant LORA_MERGE = address(0x0113);
    /// 0x0121 MEMORY_ANCHOR_VERIFY. Output: day commitment, or zero for an invalid proof.
    address internal constant MEMORY_ANCHOR_VERIFY = address(0x0121);
    /// 0x0122 AGENT_OPS. Input: op (1) || body. Output: one word, 1 or 0.
    address internal constant AGENT_OPS = address(0x0122);

    uint8 internal constant OP_DEVICE_LINK_VERIFY = 0x01;
    uint8 internal constant OP_DEVICE_REVOCATION_VERIFY = 0x02;

    /// The precompile did not answer: the call failed, or it returned nothing
    /// (no precompile at that address on this chain or at this height).
    error PrecompileUnavailable(address precompile);
    /// The precompile answered with a shape this library does not accept.
    error PrecompileBadOutput(address precompile, uint256 length);

    /// STATICCALL `precompile`; revert unless it succeeds with non-empty output.
    function callNonEmpty(address precompile, bytes memory input) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = precompile.staticcall(input);
        if (!ok || out.length == 0) revert PrecompileUnavailable(precompile);
    }

    /// STATICCALL `precompile`; revert unless it succeeds with exactly one word.
    function callWord(address precompile, bytes memory input) internal view returns (bytes32 word) {
        bytes memory out = callNonEmpty(precompile, input);
        if (out.length != 32) revert PrecompileBadOutput(precompile, out.length);
        word = abi.decode(out, (bytes32));
    }

    /// 0x0101 in its native packed layout. Fails closed wherever the node does
    /// not serve inference to contract code (every 40204 node today).
    function modelInference(bytes32 modelId, address caller, bytes memory input)
        internal
        view
        returns (bytes memory)
    {
        return callNonEmpty(MODEL_INFERENCE, abi.encodePacked(modelId, caller, input));
    }

    /// 0x0106 with an already-packed operation input.
    function modelEncryption(bytes memory packed) internal view returns (bytes memory) {
        return callNonEmpty(MODEL_ENCRYPTION, packed);
    }

    /// 0x0112: `W + (alpha / r) (B . A)` over Q16.16 tensors in the canonical
    /// tensor format; returns the output tensor.
    function loraApply(bytes memory w, bytes memory b, bytes memory a, bytes memory alpha)
        internal
        view
        returns (bytes memory)
    {
        return callNonEmpty(LORA_APPLY, bytes.concat(w, b, a, alpha));
    }

    /// 0x0113 with an already-packed input (`n || n x (B_i || A_i || alpha_i || w_i)`).
    function loraMerge(bytes memory packed) internal view returns (bytes memory) {
        return callNonEmpty(LORA_MERGE, packed);
    }

    /// 0x0121: the day commitment a nightly-anchor inclusion proof proves
    /// membership in, or zero when the proof is invalid. `proofInput` is the
    /// packed layout of the spec.
    function memoryAnchorCommitment(bytes memory proofInput) internal view returns (bytes32) {
        return callWord(MEMORY_ANCHOR_VERIFY, proofInput);
    }

    /// 0x0122 DEVICE_LINK_VERIFY: true iff the three signatures and the fields
    /// of the DeviceLink in `body` are valid.
    function deviceLinkValid(bytes memory body) internal view returns (bool) {
        return _flag(callWord(AGENT_OPS, bytes.concat(bytes1(OP_DEVICE_LINK_VERIFY), body)));
    }

    /// 0x0122 DEVICE_REVOCATION_VERIFY.
    function deviceRevocationValid(bytes memory body) internal view returns (bool) {
        return _flag(callWord(AGENT_OPS, bytes.concat(bytes1(OP_DEVICE_REVOCATION_VERIFY), body)));
    }

    function _flag(bytes32 word) private pure returns (bool) {
        if (word == bytes32(uint256(1))) return true;
        if (word == bytes32(0)) return false;
        revert PrecompileBadOutput(AGENT_OPS, 32);
    }
}

/// The read side of `AnchorRegistry` used by `AnchorProofs`. `AnchorView`
/// is ABI-identical to `AnchorRegistry.Anchor` (the enum `kind` is a uint8).
interface IAnchorRegistryView {
    struct AnchorView {
        uint8 kind;
        bytes32 root;
        address committer;
        uint256 blockNumber;
        uint256 timestamp;
    }

    function isAnchored(bytes32 root) external view returns (bool);
    function getAnchor(bytes32 root) external view returns (AnchorView memory);
}

/// @title AnchorProofs: prove that one decision record was anchored by its agent
/// @notice US-7.2 AC3 on chain: a record is anchored iff its inclusion proof
///         verifies (0x0121) AND the day commitment it proves is recorded in
///         `AnchorRegistry` as a nightly root BY THE EXPECTED COMMITTER.
/// @dev `AnchorRegistry.anchor` is open to every caller, so "this commitment is
///      in the registry" alone says nothing about whose log it came from: any
///      account can build a day tree over any record hash and anchor it. The
///      caller therefore names the account whose nightly anchors it trusts
///      (the agent's anchoring address), and only that account's nightly
///      anchor counts.
library AnchorProofs {
    /// `AnchorRegistry.AnchorKind.NightlyMerkle`.
    uint8 internal constant KIND_NIGHTLY_MERKLE = 2;

    function isRecordAnchored(IAnchorRegistryView registry, address committer, bytes memory proofInput)
        internal
        view
        returns (bool)
    {
        if (committer == address(0)) return false;
        bytes32 commitment = CitratePrecompiles.memoryAnchorCommitment(proofInput);
        if (commitment == bytes32(0) || !registry.isAnchored(commitment)) return false;
        IAnchorRegistryView.AnchorView memory a = registry.getAnchor(commitment);
        return a.kind == KIND_NIGHTLY_MERKLE && a.committer == committer && a.root == commitment;
    }
}
