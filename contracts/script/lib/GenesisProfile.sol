// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./AdminChecks.sol";

/// @title GenesisProfile: one chain-id source and one set of genesis floors for the C4 scripts
/// @notice The genesis profile (chain 40204) is chosen from the chain id the NODE reports, not
///         only from forge's simulated `block.chainid`. Forge lets the operator set the simulated
///         id independently of the node (`--chain-id`, `--chain`, `FOUNDRY_CHAIN_ID`), so a
///         `block.chainid` check alone can be steered off the genesis profile while the run
///         still broadcasts to a 40204 node. `_resolveChainProfile` therefore:
///           - asks the node (`vm.rpc("eth_chainId", "[]")` on the active fork) and refuses any
///             mismatch with `block.chainid`, in either direction;
///           - fails closed when there is no node to ask (pure simulation, no --rpc-url) and the
///             genesis profile would apply, since the floors could not be tied to a real chain.
///         Every C4 script resolves its profile here before it broadcasts (or, for the
///         read-only CheckDeployedAdmins gate, before it reads the book).
///
///         Floors (owner decision): GOVERNANCE minDelay >= 48 h, council m >= 3 of n >= 5.
abstract contract GenesisProfile is Script, AdminChecks {
    /// The chain id that is always deployed under the genesis profile.
    uint256 public constant GENESIS_CHAIN_ID = 40204;
    uint256 public constant GENESIS_GOV_MIN_DELAY = 48 hours;
    uint256 public constant GENESIS_GOV_MIN_THRESHOLD = 3;
    uint256 public constant GENESIS_GOV_MIN_OWNERS = 5;

    string internal constant GENESIS_NEEDS_NODE =
        "genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)";

    struct ChainProfile {
        bool genesis; // the genesis floors apply
        bool nodeChecked; // eth_chainId was read and equals block.chainid
        uint256 nodeChainId; // the id the node reported (0 when not checked)
    }

    /// @notice Resolve the profile for this run. `forced` applies the genesis profile on any
    ///         chain id. Reverts on a node / simulation chain-id mismatch, and when the genesis
    ///         profile applies but no node can be asked.
    function _resolveChainProfile(bool forced) internal returns (ChainProfile memory p) {
        (bool ok, uint256 node) = _nodeChainId();
        if (ok) {
            require(
                node == block.chainid,
                string.concat(
                    "chain id mismatch: node reports ",
                    vm.toString(node),
                    ", forge simulates ",
                    vm.toString(block.chainid),
                    " (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
                )
            );
            (p.nodeChecked, p.nodeChainId) = (true, node);
        }
        p.genesis = forced || block.chainid == GENESIS_CHAIN_ID;
        require(ok || !p.genesis, GENESIS_NEEDS_NODE);
    }

    /// @notice The chain id the node behind the active fork reports, or (false, 0) when there
    ///         is no fork URL to ask. A response that is not a chain id reverts.
    /// @dev Virtual only so tests can stand in for a node; scripts never override it.
    function _nodeChainId() internal virtual returns (bool ok, uint256 id) {
        try vm.rpc("eth_chainId", "[]") returns (bytes memory r) {
            return (true, _decodeChainId(r));
        } catch {
            return (false, 0);
        }
    }

    /// @notice vm.rpc hands back the quantity's big-endian bytes ("0x9d0c" -> 0x9d0c).
    function _decodeChainId(bytes memory r) internal pure returns (uint256) {
        require(r.length != 0 && r.length <= 32, "eth_chainId: unreadable response");
        return uint256(bytes32(r)) >> (8 * (32 - r.length));
    }
}
