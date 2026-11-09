// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IVerifier, IWorkMarket} from "./IVerifier.sol";

/// @title TaskVerifier: a TASK offer is verified when the requester accepts the result, or once the
///        review window passes
/// @notice 0.6.0 planset 06 §4. The offer's coordinator is the selected worker: it submits a result
///         hash here, which starts the review window. The requester (the offer's poster) can accept
///         it at once; otherwise it is accepted when the window ends. A requester who thinks the
///         result is bad disputes the posted payout in WorkMarket (06 §2.2: the group admin rules
///         for group tasks, refund-after-timeout for open tasks); the dispute freezes the payout
///         there, which is what "no dispute" in 06 §4 rests on.
///
///         Results are kept per market (`market` = the WorkMarket that asks). The verifier therefore
///         has no constructor dependency on the market, which keeps the genesis CREATE2 addresses
///         acyclic: WorkMarket's block-0 allowlist names this contract, so this contract cannot
///         also name WorkMarket in its init code. A contract that is not a real market only ever
///         reads and writes its own namespace.
///
///         No owner, no value. The review window is immutable (06 §6).
contract TaskVerifier is IVerifier {
    uint64 public constant MIN_REVIEW_WINDOW = 1 hours;
    uint64 public constant MAX_REVIEW_WINDOW = 30 days;

    uint64 public immutable reviewWindow;

    struct Result {
        bytes32 resultHash;
        uint64 submittedAt;
        bool requesterAccepted;
    }

    mapping(address market => mapping(uint256 offerId => Result)) internal _results;

    event ResultSubmitted(
        address indexed market, uint256 indexed offerId, address indexed worker, bytes32 resultHash, uint64 reviewEndsAt
    );
    event ResultAccepted(
        address indexed market, uint256 indexed offerId, address indexed requester, bytes32 resultHash
    );

    error BadReviewWindow();
    error NotTaskOffer();
    error NotWorker();
    error NotRequester();
    error WrongState();
    error BadResult();
    error AlreadyAccepted();

    /// @param reviewWindow_ seconds a requester has to accept or dispute before auto-acceptance
    constructor(uint64 reviewWindow_) {
        if (reviewWindow_ < MIN_REVIEW_WINDOW || reviewWindow_ > MAX_REVIEW_WINDOW) revert BadReviewWindow();
        reviewWindow = reviewWindow_;
    }

    /// @notice The selected worker submits (or, before acceptance, replaces) its result hash.
    ///         Replacing restarts the review window. Only while the offer is Open or Running.
    function submit(IWorkMarket market, uint256 offerId, bytes32 resultHash) external {
        revert("red: not implemented");
    }

    /// @notice The requester accepts the submitted result, by hash, so it cannot accept a result it
    ///         has not seen or one the worker replaced after it looked.
    function accept(IWorkMarket market, uint256 offerId, bytes32 resultHash) external {
        revert("red: not implemented");
    }

    /// @inheritdoc IVerifier
    /// @dev `msg.sender` is the market asking.
    function accepted(uint256 offerId, bytes32 bindRef) external view returns (bool, bytes32) {
        return acceptedFor(IWorkMarket(msg.sender), offerId, bindRef);
    }

    /// @notice `accepted` as `market` would see it (for off-chain readers).
    function acceptedFor(IWorkMarket market, uint256 offerId, bytes32 bindRef) public view returns (bool, bytes32) {
        revert("red: not implemented");
    }

    function resultOf(IWorkMarket market, uint256 offerId) external view returns (Result memory) {
        return _results[address(market)][offerId];
    }
}
