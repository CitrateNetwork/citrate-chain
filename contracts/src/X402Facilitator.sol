// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./WrappedSALT.sol";
import "./lib/AccessControl.sol";
import "./lib/ReentrancyGuard.sol";

/// @title X402Facilitator
/// @notice Settlement contract for x402 payment protocol on Citrate.
/// @dev Facilitates authorized transfers via EIP-3009 signatures, with configurable fees.
///
/// Cross-chain routing future:
///   - Multi-chain facilitator can route payments across bridge-connected chains.
///   - Settlement proofs can be relayed via the Citrate bridge relay for cross-shard payments.
///   - Level 3 upgrade: validator-embedded facilitator settles as part of block production.
contract X402Facilitator is AccessControl, ReentrancyGuard {
    bytes32 public constant FACILITATOR_ROLE = keccak256("FACILITATOR_ROLE");

    WrappedSALT public immutable wSALT;
    address public treasury;
    uint256 public feeBps; // Fee in basis points (1 bps = 0.01%)

    struct PaymentAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    event PaymentSettled(
        address indexed from,
        address indexed to,
        uint256 value,
        uint256 fee,
        bytes32 nonce
    );

    event BatchSettled(uint256 count, uint256 totalValue, uint256 totalFees);
    event FeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /// @param _wSALT   Address of the WrappedSALT contract
    /// @param _treasury Address to receive facilitator fees
    /// @param _feeBps  Initial fee in basis points (max 1000 = 10%)
    constructor(address _wSALT, address _treasury, uint256 _feeBps) {
        require(_wSALT != address(0), "X402: zero wSALT address");
        require(_treasury != address(0), "X402: zero treasury address");
        require(_feeBps <= 1000, "X402: fee exceeds 10%");

        wSALT = WrappedSALT(payable(_wSALT));
        treasury = _treasury;
        feeBps = _feeBps;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FACILITATOR_ROLE, msg.sender);
    }

    /// @notice Settle a single x402 payment via transferWithFeeAuthorization.
    ///
    /// RM-B1 / WP-D2.1 (audit SOL-01): pre-fix the facilitator pulled
    /// the fee via a separate `wSALT.transferFrom(from, treasury, fee)`
    /// which silently required the user to have ERC-20-approved this
    /// contract — breaking x402's gasless-UX claim. Post-fix the
    /// settlement uses `wSALT.transferWithFeeAuthorization` which
    /// consumes ONE signed EIP-3009 authorization for the gross
    /// `value` and splits internally inside wSALT.
    function settlePayment(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant onlyRole(FACILITATOR_ROLE) {
        require(value > 0, "X402: zero value");

        uint256 fee = (value * feeBps) / 10000;

        // SOL-01 fix: single signed authorization splits internally.
        wSALT.transferWithFeeAuthorization(
            from, to, treasury, value, fee,
            validAfter, validBefore, nonce, v, r, s
        );

        emit PaymentSettled(from, to, value - fee, fee, nonce);
    }

    /// @notice Settle multiple x402 payments in a single transaction
    function batchSettle(PaymentAuthorization[] calldata payments)
        external
        nonReentrant
        onlyRole(FACILITATOR_ROLE)
    {
        uint256 totalValue;
        uint256 totalFees;

        for (uint256 i = 0; i < payments.length; i++) {
            PaymentAuthorization calldata p = payments[i];
            require(p.value > 0, "X402: zero value in batch");

            uint256 fee = (p.value * feeBps) / 10000;

            // SOL-01 fix: single signed authorization splits internally.
            wSALT.transferWithFeeAuthorization(
                p.from, p.to, treasury, p.value, fee,
                p.validAfter, p.validBefore, p.nonce,
                p.v, p.r, p.s
            );

            uint256 netValue = p.value - fee;
            totalValue += netValue;
            totalFees += fee;

            emit PaymentSettled(p.from, p.to, netValue, fee, p.nonce);
        }

        emit BatchSettled(payments.length, totalValue, totalFees);
    }

    /// @notice Update facilitator fee (admin only)
    /// @param newFeeBps New fee in basis points (max 1000 = 10%)
    function setFacilitatorFee(uint256 newFeeBps) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newFeeBps <= 1000, "X402: fee exceeds 10%");
        uint256 oldFeeBps = feeBps;
        feeBps = newFeeBps;
        emit FeeUpdated(oldFeeBps, newFeeBps);
    }

    /// @notice Update treasury address (admin only)
    function setTreasury(address newTreasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTreasury != address(0), "X402: zero treasury address");
        address oldTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }
}
