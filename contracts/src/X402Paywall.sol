// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

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

    /// RM-B1 / WP-D5.4 (audit SOL-12): paywall access is now
    /// time-bound. `accessGrantedUntil[key]` is the timestamp
    /// when access expires (0 = never granted; > now = granted).
    /// `accessTTL` is the duration applied at grant time.
    mapping(bytes32 => uint256) public accessGrantedUntil;
    uint256 public accessTTL;
    /// Default TTL: 24 hours. Provider can override via setAccessTTL.
    uint256 public constant DEFAULT_ACCESS_TTL = 1 days;

    event AccessGranted(address indexed payer, bytes32 indexed resourceId, uint256 amount, uint256 expiresAt);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);
    event AccessTtlUpdated(uint256 oldTtl, uint256 newTtl);

    constructor(address _wSALT, uint256 _resourcePrice) {
        require(_wSALT != address(0), "Paywall: zero wSALT");
        wSALT = WrappedSALT(payable(_wSALT));
        provider = msg.sender;
        resourcePrice = _resourcePrice;
        accessTTL = DEFAULT_ACCESS_TTL;
    }

    /// @notice Verify payment authorization and grant access to a resource
    /// @param resourceId Identifier of the resource being accessed
    /// @param from       Payer's address
    /// @param value      Payment amount (must be >= resourcePrice)
    /// @param validAfter Earliest valid timestamp
    /// @param validBefore Latest valid timestamp
    /// @param nonce      Authorization nonce. C047: MUST equal
    ///        `keccak256(abi.encode(resourceId, salt))` so the resource is
    ///        cryptographically bound to the EIP-3009 authorization (whose
    ///        signed fields do not include `resourceId`). Without this a
    ///        front-runner could replay the same authorization against a
    ///        different `resourceId`, burning the one-shot nonce and paying the
    ///        provider while granting access to the wrong resource — the
    ///        payer's legitimate call then reverts "authorization already used".
    /// @param salt       Per-purchase salt that, with `resourceId`, derives the
    ///        nonce — lets a payer re-purchase the same resource after expiry
    ///        with a fresh, still-bound nonce.
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
        bytes32 salt,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(value >= resourcePrice, "Paywall: insufficient payment");
        // C047: the nonce must commit to the resource being granted.
        require(nonce == keccak256(abi.encode(resourceId, salt)), "Paywall: nonce not bound to resource");
        bytes32 key = keccak256(abi.encodePacked(from, resourceId));
        // SOL-12 fix: allow re-purchase after expiry. Pre-fix the
        // access flag was permanent; re-purchase was blocked.
        require(
            accessGrantedUntil[key] < block.timestamp,
            "Paywall: access still active"
        );

        // Execute the payment via transferWithAuthorization
        wSALT.transferWithAuthorization(from, provider, value, validAfter, validBefore, nonce, v, r, s);

        // Grant access until (now + accessTTL).
        uint256 expiresAt = block.timestamp + accessTTL;
        accessGrantedUntil[key] = expiresAt;
        emit AccessGranted(from, resourceId, value, expiresAt);
    }

    /// @notice Check if access is currently granted (within TTL).
    /// SOL-12: returns true iff `expiresAt > now`.
    function hasAccess(address payer, bytes32 resourceId) external view returns (bool) {
        return accessGrantedUntil[keccak256(abi.encodePacked(payer, resourceId))] > block.timestamp;
    }

    /// @notice Update resource price (provider only)
    function setPrice(uint256 newPrice) external {
        require(msg.sender == provider, "Paywall: not provider");
        uint256 oldPrice = resourcePrice;
        resourcePrice = newPrice;
        emit PriceUpdated(oldPrice, newPrice);
    }

    /// @notice Update access TTL (provider only).
    /// RM-B1 / WP-D5.4 (audit SOL-12).
    function setAccessTTL(uint256 newTTL) external {
        require(msg.sender == provider, "Paywall: not provider");
        require(newTTL > 0, "Paywall: zero TTL");
        uint256 oldTtl = accessTTL;
        accessTTL = newTTL;
        emit AccessTtlUpdated(oldTtl, newTTL);
    }
}
