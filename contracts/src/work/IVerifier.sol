// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title IVerifier: the per-kind verification hook WorkMarket consults before a payout
/// @notice 0.6.0 planset 06 §2. A verifier answers one question: is the work bound to
///         `offerId` verified, and what digest must the payout root commit to?
interface IVerifier {
    /// @return ok     true once the work bound to `offerId` is verified
    /// @return digest what the payout root must commit to (`payoutRoot = keccak(digest ‖ leavesRoot)`)
    function accepted(uint256 offerId, bytes32 bindRef) external view returns (bool ok, bytes32 digest);
}

/// @title IWorkMarket: the read surface verifiers use to learn who the parties of an offer are
interface IWorkMarket {
    enum Kind {
        FL_ROUND,
        TASK
    }

    enum State {
        Open,
        Running,
        PayoutPosted,
        Disputed,
        Closed,
        Expired
    }

    function offerParties(uint256 id)
        external
        view
        returns (Kind kind, State state, address poster, address verifier, address coordinator, bytes32 bindRef);

    /// @notice Bumps each time a subjective dispute on `id` is upheld: a result the requester
    ///         rejected that way must not count as verified again (TaskVerifier scopes results to it).
    function resultEpochOf(uint256 id) external view returns (uint32);
}
