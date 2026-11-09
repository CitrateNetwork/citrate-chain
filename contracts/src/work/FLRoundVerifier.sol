// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IVerifier} from "./IVerifier.sol";

/// @notice The FederatedRoundLedger reads this verifier needs (contracts/src/FederatedRoundLedger.sol).
interface IFederatedRoundLedgerReads {
    function roundIdOf(bytes32 clusterId, uint64 ordinal) external view returns (bytes32);
    function isAccepted(bytes32 roundId) external view returns (bool);
    function recordDigest(bytes32 roundId) external view returns (bytes32);
}

/// @title FLRoundVerifier: an FL_ROUND offer is verified when its FederatedRoundLedger round is Accepted
/// @notice 0.6.0 planset 06 §3. Mirrors citrate-settlement `fl_gate.rs` (FRL Accepted and the
///         payout commits to the round's `recordDigest`), which stays as the off-chain pre-check.
///
///         The offer's `bindRef` is the FRL round id, `roundIdOf(clusterId, ordinal)`: FRL already
///         derives it from the cluster and ordinal (and the chain id and ledger address), so the
///         verifier needs no registration step and no decoding. A cluster id is derived from the
///         registering coordinator's address, so a third party cannot commit a round under the
///         cluster an offer binds (06 §3).
///
///         No owner, no state, no value. The ledger address is immutable (06 §6).
contract FLRoundVerifier is IVerifier {
    IFederatedRoundLedgerReads public immutable frl;

    error ZeroLedger();

    /// @param frl_ the genesis FederatedRoundLedger (CREATE2 address from the canonical book)
    constructor(IFederatedRoundLedgerReads frl_) {
        if (address(frl_) == address(0)) revert ZeroLedger();
        frl = frl_;
    }

    /// @notice The `bindRef` a poster passes to `WorkMarket.open` for round `ordinal` of `clusterId`.
    function bindRefOf(bytes32 clusterId, uint64 ordinal) external view returns (bytes32) {
        return frl.roundIdOf(clusterId, ordinal);
    }

    /// @inheritdoc IVerifier
    function accepted(uint256, bytes32 bindRef) external view returns (bool, bytes32) {
        if (!frl.isAccepted(bindRef)) return (false, bytes32(0));
        return (true, frl.recordDigest(bindRef));
    }
}
