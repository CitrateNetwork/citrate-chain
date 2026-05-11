// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ICrossOrgEnvelopeV1
/// @notice Pre-Stage-12-v2 ABI shim for the deployed `CrossOrgEnvelope`
///         at `0x9871e73a189885f87c9c9ec41a6b0c98175c99f8` (chain 40204).
///
///         The current source (post-DPF-amendment 2026-05-11 PM) adds
///         a 9th `uint8 artifact_max_class` parameter to `draft(...)`
///         for the classification-boundary gate. That source is NOT
///         deployed yet — the Stage-12-v2 redeploy is operator POAM.
///         Seeders MUST call the 8-arg signature this interface
///         exposes to match the on-chain bytecode.
///
///         When Stage-12-v2 deploys, the seed script swaps to the
///         current source's `CrossOrgEnvelope` import and adds the
///         max_class arg per call.
interface ICrossOrgEnvelopeV1 {
    function draft(
        bytes32 envelope_id,
        bytes32 artifact_root,
        bytes32 artifact_cid,
        bytes32[] calldata org_roots,
        uint8[] calldata thresholds,
        bytes32[][] calldata signers_per_org,
        uint256 expires_at_block,
        bytes32 scope
    ) external;

    function sign(bytes32 envelope_id, bytes32 org_root, bytes32 signer) external;
    function markDelivered(bytes32 envelope_id) external;
    function accept(bytes32 envelope_id) external;
    function setRecorder(address recorder, bool authorized) external;
}
