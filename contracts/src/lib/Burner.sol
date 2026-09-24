// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title Burner
/// @notice A permanent value-sink contract. Reverts on every entry.
///
/// RM-B1 / WP-D5.9 (audit SOL-19): pre-fix `ComputeMarketplace`
/// burned ETH by sending to `0xdead`. ETH cannot be sent to
/// `address(0)` so `0xdead` is a common sentinel — but `0xdead`
/// is just an unowned address. Anyone who someday controls the
/// private key for `0xdead` (preimage attack, leaked key,
/// future cryptanalysis) can sweep the accumulated balance.
///
/// A Burner contract that reverts on `receive` and `fallback`
/// makes the value provably unrecoverable: any `call{value:}`
/// to it reverts the calling tx, so funds can never enter the
/// Burner via low-level call. To still "burn" value the caller
/// uses the explicit `burn()` payable function which records the
/// receipt then reverts only the post-record write — but Solidity
/// doesn't support partial reverts that way. Instead we use the
/// SELFDESTRUCT-equivalent pattern: `burn()` accepts the value
/// and emits a Burned event; the Ether stays on the contract
/// forever because every other entry path reverts, and SELFDESTRUCT
/// is post-Cancun a no-op for non-empty contracts. The accumulated
/// balance is permanently locked.
contract Burner {
    event Burned(address indexed from, uint256 amount);

    /// @notice Accept and permanently lock the sent value.
    /// Once accepted, the funds cannot be retrieved by any path:
    /// no withdraw function, no receive (reverts), no fallback (reverts).
    function burn() external payable {
        emit Burned(msg.sender, msg.value);
    }

    /// @dev Reverts on every plain transfer to make it visible
    /// when callers accidentally try to use this address as a
    /// regular recipient. Use `burn()` instead.
    receive() external payable {
        revert("Burner: use burn() to lock value");
    }

    /// @dev Reverts on every fallback call.
    fallback() external payable {
        revert("Burner: no callable methods");
    }
}
