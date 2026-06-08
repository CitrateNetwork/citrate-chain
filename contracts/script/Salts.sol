// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title Salts — the CREATE2 salt registry for chain 40204
 * @notice Single source of truth for the deterministic-deploy salts. Every
 *         contract in the ceremony is deployed via `new X{salt: Salts.of("X")}(…)`,
 *         which Foundry routes through the genesis Arachnid CREATE2 deployer
 *         (0x4e59b44847b379578588920cA78FbF26c0B4956C). The resulting address is
 *
 *           keccak256(0xff ++ 0x4e59… ++ salt ++ keccak256(init_code))[12:]
 *
 *         which depends ONLY on (deployer=0x4e59…, salt, init_code) — NOT on
 *         deploy order or the broadcasting EOA's nonce. So every reroll that
 *         deploys the same bytecode with the same constructor args lands every
 *         contract at the same address. (init_code = creationCode ++ abi.encode(args);
 *         `bytecode_hash = "none"` in foundry.toml strips the metadata hash so
 *         creationCode is reproducible.)
 *
 * @dev VERSION is the global namespace. Bumping it is a deliberate full
 *      redeploy — it moves EVERY address. Treat it like an ABI: changing it
 *      is a breaking change. To redeploy a SINGLE contract to a fresh address
 *      without moving the others, append a per-contract suffix to its name at
 *      the call site, e.g. `Salts.of("ComputePool.v2")`.
 *
 *      DETERMINISM INPUTS (all must be pinned for addresses to be stable):
 *        1. deployer EOA — irrelevant to the address (CREATE2 uses 0x4e59…),
 *           BUT several constructors take `deployer` as an arg (governance/treasury),
 *           so the genesis-allocated DEPLOYER (0x4250675F…) must stay constant.
 *        2. salts — this file.
 *        3. creationCode — solc 0.8.26 + optimizer(200) + bytecode_hash=none (foundry.toml).
 *        4. constructor args — the literals in the deploy scripts.
 */
library Salts {
    /// Global salt namespace. Bump to force a full-stack redeploy.
    string internal constant VERSION = "citrate.v1.";

    /// Deterministic salt for a contract by canonical name.
    function salt(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(VERSION, name));
    }
}
