// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    /// @notice Settle a single x402 payment via transferWithAuthorization
    /// @dev Calls wSALT.transferWithAuthorization for (value - fee) to recipient,
    ///      then transfers fee to treasury via a separate authorization or direct transfer.
    ///      For simplicity, this implementation transfers full value to `to`, then `to` is
    ///      expected to include fee in the signed value. The facilitator takes its cut
    ///      from `from`'s balance via a separate fee authorization.
    ///
    ///      Simplified flow: from -> to (full value via auth), fee handled off-chain.
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
        uint256 netValue = value - fee;

        // Execute the authorized transfer for net value
        wSALT.transferWithAuthorization(from, to, netValue, validAfter, validBefore, nonce, v, r, s);

        // Transfer fee to treasury (requires from to have approved this contract)
        if (fee > 0) {
            wSALT.transferFrom(from, treasury, fee);
        }

        emit PaymentSettled(from, to, netValue, fee, nonce);
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
            uint256 netValue = p.value - fee;

            wSALT.transferWithAuthorization(
                p.from, p.to, netValue,
                p.validAfter, p.validBefore, p.nonce,
                p.v, p.r, p.s
            );

            if (fee > 0) {
                wSALT.transferFrom(p.from, treasury, fee);
            }

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
