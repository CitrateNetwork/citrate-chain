// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IVerifier, IWorkMarket} from "./IVerifier.sol";
import {FederatedRoundLedger} from "../FederatedRoundLedger.sol";

/// @notice The FederatedRoundLedger reads this verifier needs (contracts/src/FederatedRoundLedger.sol).
interface IFederatedRoundLedgerReads {
    function roundIdOf(bytes32 clusterId, uint64 ordinal) external view returns (bytes32);
    function isAccepted(bytes32 roundId) external view returns (bool);
    function recordDigest(bytes32 roundId) external view returns (bytes32);
    function getRound(bytes32 roundId) external view returns (FederatedRoundLedger.Round memory);
    function getCluster(bytes32 clusterId) external view returns (FederatedRoundLedger.Cluster memory);
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
///         A round's acceptance rests on its cluster's coordinator and challenge window, so an
///         offer is verified only when:
///         - the offer names this verifier, is an FL_ROUND offer and binds this round;
///         - the offer's coordinator is the round's cluster coordinator (the party that commits
///           the round is the party that posts and is bonded for the payout); and
///         - the cluster's FRL challenge window is at least `MIN_CHALLENGE_WINDOW` blocks.
///
///         Offers are read from the market that asks (`msg.sender`), as TaskVerifier does; a
///         contract that is not a real market only ever learns about its own offers.
///
///         No owner, no state, no value. The ledger address is immutable (06 §6).
contract FLRoundVerifier is IVerifier {
    /// @notice The least FRL challenge window (in blocks) a cluster must have for its rounds to
    ///         back a WorkMarket payout: about one hour at the 2 s producer cadence. FRL counts the
    ///         window in `block.number`, which merged DAG blocks can repeat, so this is a floor on
    ///         the count, not an exact duration.
    uint64 public constant MIN_CHALLENGE_WINDOW = 1800;

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
    /// @dev `msg.sender` is the market asking.
    function accepted(uint256 offerId, bytes32 bindRef) external view returns (bool, bytes32) {
        return acceptedFor(IWorkMarket(msg.sender), offerId, bindRef);
    }

    /// @notice `accepted` as `market` would see it (for off-chain readers).
    function acceptedFor(IWorkMarket market, uint256 offerId, bytes32 bindRef) public view returns (bool, bytes32) {
        if (address(market).code.length == 0) return (false, bytes32(0));
        // slither-disable-next-line unused-return (only the fields this check needs are read)
        (IWorkMarket.Kind kind,,, address verifier, address coordinator, bytes32 offerBind) =
            market.offerParties(offerId);
        if (verifier != address(this) || kind != IWorkMarket.Kind.FL_ROUND || offerBind != bindRef) {
            return (false, bytes32(0));
        }
        if (!frl.isAccepted(bindRef)) return (false, bytes32(0));
        FederatedRoundLedger.Cluster memory c = frl.getCluster(frl.getRound(bindRef).clusterId);
        if (c.coordinator != coordinator || c.rules.challengeWindow < MIN_CHALLENGE_WINDOW) {
            return (false, bytes32(0));
        }
        return (true, frl.recordDigest(bindRef));
    }
}
