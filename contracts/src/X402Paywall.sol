// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./WrappedSALT.sol";

/// @title X402Paywall
/// @notice Reference implementation for gating resource access behind x402 payment verification.
/// @dev This contract demonstrates how an API provider can verify that payment was made
///      before granting access to a resource. Used for documentation and testing purposes.
///
///      Production usage pattern:
///      1. Client requests resource via HTTP, receives 402 Payment Required
///      2. Client signs a transferWithAuthorization to the resource provider
///      3. Resource provider calls verifyAndGrant() to verify payment + grant access
///      4. If valid, resource provider serves the content
contract X402Paywall {
    WrappedSALT public immutable wSALT;
    address public immutable provider;
    uint256 public resourcePrice;

    mapping(bytes32 => bool) public accessGranted;

    event AccessGranted(address indexed payer, bytes32 indexed resourceId, uint256 amount);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    constructor(address _wSALT, uint256 _resourcePrice) {
        require(_wSALT != address(0), "Paywall: zero wSALT");
        wSALT = WrappedSALT(payable(_wSALT));
        provider = msg.sender;
        resourcePrice = _resourcePrice;
    }

    /// @notice Verify payment authorization and grant access to a resource
    /// @param resourceId Identifier of the resource being accessed
    /// @param from       Payer's address
    /// @param value      Payment amount (must be >= resourcePrice)
    /// @param validAfter Earliest valid timestamp
    /// @param validBefore Latest valid timestamp
    /// @param nonce      Authorization nonce
    /// @param v          Signature v
    /// @param r          Signature r
    /// @param s          Signature s
    function verifyAndGrant(
        bytes32 resourceId,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(value >= resourcePrice, "Paywall: insufficient payment");
        require(!accessGranted[keccak256(abi.encodePacked(from, resourceId))], "Paywall: already granted");

        // Execute the payment via transferWithAuthorization
        wSALT.transferWithAuthorization(from, provider, value, validAfter, validBefore, nonce, v, r, s);

        // Grant access
        accessGranted[keccak256(abi.encodePacked(from, resourceId))] = true;
        emit AccessGranted(from, resourceId, value);
    }

    /// @notice Check if access has been granted
    function hasAccess(address payer, bytes32 resourceId) external view returns (bool) {
        return accessGranted[keccak256(abi.encodePacked(payer, resourceId))];
    }

    /// @notice Update resource price (provider only)
    function setPrice(uint256 newPrice) external {
        require(msg.sender == provider, "Paywall: not provider");
        uint256 oldPrice = resourcePrice;
        resourcePrice = newPrice;
        emit PriceUpdated(oldPrice, newPrice);
    }
}
