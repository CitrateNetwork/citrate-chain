// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// Test stand-in for a node that serves 0x0101 MODEL_INFERENCE to contract
/// code, speaking the precompile's NATIVE layout (model_id (32) || caller (20)
/// || input). Etched at 0x0101 by tests that exercise the served path; without
/// it, inference fails closed (`CitratePrecompiles.PrecompileUnavailable`).
/// Returns `"out:" || input` so tests can assert on the payload.
contract ModelPrecompileMock {
    fallback(bytes calldata data) external returns (bytes memory) {
        require(data.length >= 52, "native layout: model_id || caller || input");
        return bytes.concat(bytes("out:"), data[52:]);
    }
}
