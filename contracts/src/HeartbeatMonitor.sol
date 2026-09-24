// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";
import "./interfaces/INematocystSlashing.sol";

/// @title HeartbeatMonitor — Provider Liveness Checking
/// @notice Implements the heartbeat monitoring system from HeartbeatLiveness.tla.
///         Providers must send heartbeat transactions every `heartbeatInterval` blocks.
///         Missing heartbeats increment a counter. When the counter reaches `maxMissed`,
///         the provider is automatically suspended and slashed via NematocystSlashing.
///
///         TLA+ Invariants enforced:
///           INV-1 TypeOK            — all fields within valid ranges
///           INV-2 HeartbeatResets   — heartbeat received => missedCount = 0
///           INV-3 MissedBounded    — missedCount <= maxMissed
///           INV-4 SuspensionAutomatic — missedCount >= maxMissed => suspended
///           INV-5 BlockMonotonic   — block numbers only increase (enforced by EVM)
///           INV-6 InactiveNoHeartbeat — inactive providers have lastHeartbeat = 0
///           INV-7 ActiveHasHeartbeat — active providers have lastHeartbeat >= 1
///           INV-8 SuspendedMissedMax — suspended providers have missedCount >= maxMissed
///
/// @dev WP-CI.1 — Compute Infrastructure: Heartbeat Monitor
contract HeartbeatMonitor is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    struct ProviderHealth {
        uint256 lastHeartbeat;    // block number of last heartbeat
        uint256 missedCount;      // consecutive missed heartbeats
        bool suspended;           // whether provider is currently suspended
        uint256 suspendedAt;      // block number when suspended
    }

    // ── State ───────────────────────────────────────────────────────

    /// @notice Blocks between required heartbeats (default 100 ~ 3 min at 2s blocks).
    uint256 public heartbeatInterval;

    /// @notice Maximum consecutive missed heartbeats before suspension (default 3).
    uint256 public maxMissed;

    /// @notice Provider health records.
    mapping(address => ProviderHealth) public health;

    /// @notice Set of registered providers (for enumeration/queries).
    mapping(address => bool) public registered;

    /// @notice NematocystSlashing contract for triggering slashes on suspension.
    INematocystSlashing public slashingContract;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Events ──────────────────────────────────────────────────────

    event ProviderRegistered(address indexed provider, uint256 blockNumber);
    event HeartbeatReceived(address indexed provider, uint256 blockNumber);
    event HeartbeatMissed(address indexed provider, uint256 missedCount);
    event ProviderSuspended(address indexed provider, uint256 blockNumber, uint256 missedCount);
    event ProviderReactivated(address indexed provider, uint256 blockNumber);
    event HeartbeatIntervalUpdated(uint256 oldInterval, uint256 newInterval);
    event MaxMissedUpdated(uint256 oldMax, uint256 newMax);
    event SlashingContractUpdated(address oldContract, address newContract);
    // GovernanceTransferred event provided by Governable mixin.

    // ── Modifiers ───────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    // ── Constructor ─────────────────────────────────────────────────

    /// @param _heartbeatInterval Blocks between required heartbeats.
    /// @param _maxMissed Maximum consecutive missed heartbeats before suspension.
    constructor(uint256 _heartbeatInterval, uint256 _maxMissed)
        Governable(msg.sender)
    {
        require(_heartbeatInterval >= 1, "Interval must be >= 1");
        require(_maxMissed >= 1, "MaxMissed must be >= 1");

        heartbeatInterval = _heartbeatInterval;
        maxMissed = _maxMissed;
    }

    // ── Provider Registration ───────────────────────────────────────

    /// @notice Register as a provider. Sets initial heartbeat to current block.
    /// @dev Satisfies TLA+ Activate: providerStatus -> Active, lastHeartbeat = currentBlock,
    ///      missedCount = 0.
    ///      INV-7 (ActiveHasHeartbeat): lastHeartbeat set to block.number >= 1.
    function register() external {
        require(!registered[msg.sender], "Already registered");

        registered[msg.sender] = true;

        // Initialize health field-by-field to reduce stack pressure
        ProviderHealth storage h = health[msg.sender];
        h.lastHeartbeat = block.number;
        h.missedCount = 0;
        h.suspended = false;
        h.suspendedAt = 0;

        emit ProviderRegistered(msg.sender, block.number);
    }

    // ── Heartbeat ───────────────────────────────────────────────────

    /// @notice Provider sends a heartbeat to prove liveness.
    /// @dev Satisfies TLA+ Heartbeat: lastHeartbeat = currentBlock, missedCount = 0.
    ///      INV-2 (HeartbeatResets): missedCount is reset to 0 on heartbeat.
    ///      INV-7 (ActiveHasHeartbeat): lastHeartbeat updated to current block.
    function heartbeat() external {
        require(registered[msg.sender], "Not registered");
        require(!health[msg.sender].suspended, "Provider is suspended");

        health[msg.sender].lastHeartbeat = block.number;
        health[msg.sender].missedCount = 0;

        emit HeartbeatReceived(msg.sender, block.number);
    }

    // ── Heartbeat Checking ──────────────────────────────────────────

    /// @notice Anyone can check and flag a missed heartbeat for a provider.
    /// @dev Satisfies TLA+ DetectMissed:
    ///      - currentBlock - lastHeartbeat > HeartbeatInterval => missedCount++
    ///      - if missedCount >= MaxMissed => suspended = true
    ///      INV-3 (MissedBounded): missedCount capped at maxMissed.
    ///      INV-4 (SuspensionAutomatic): missedCount >= maxMissed => suspended.
    ///      INV-8 (SuspendedMissedMax): suspension only occurs at maxMissed.
    /// @param provider The provider address to check.
    function checkHeartbeat(address provider) external {
        require(registered[provider], "Not registered");
        require(!health[provider].suspended, "Already suspended");

        ProviderHealth storage h = health[provider];

        // Check if enough blocks have passed since last heartbeat
        require(
            block.number > h.lastHeartbeat + heartbeatInterval,
            "Heartbeat not yet due"
        );

        // Increment missed count (INV-3: bounded by maxMissed via suspension logic)
        h.missedCount++;

        emit HeartbeatMissed(provider, h.missedCount);

        // INV-4: SuspensionAutomatic — auto-suspend at maxMissed
        if (h.missedCount >= maxMissed) {
            h.suspended = true;
            h.suspendedAt = block.number;

            emit ProviderSuspended(provider, block.number, h.missedCount);

            // Integration: trigger Tier 1 (Latency) slash via NematocystSlashing
            if (address(slashingContract) != address(0)) {
                // Tier 0 = Latency in NematocystSlashing.SlashTier enum
                try slashingContract.slash(
                    provider,
                    0, // SlashTier.Latency
                    abi.encodePacked("heartbeat:suspended:", uint256(h.missedCount))
                ) {} catch {
                    // Slash failure should not prevent suspension
                }
            }
        }

        // Update lastHeartbeat to current block to prevent immediate re-check
        // This ensures each missed interval is only counted once
        h.lastHeartbeat = block.number;
    }

    // ── Reactivation ────────────────────────────────────────────────

    /// @notice Reactivate a suspended provider with a fresh heartbeat.
    /// @dev Satisfies TLA+ Reactivate: suspended -> Active, lastHeartbeat = currentBlock,
    ///      missedCount = 0.
    ///      INV-2 (HeartbeatResets): missedCount reset to 0.
    ///      INV-7 (ActiveHasHeartbeat): lastHeartbeat set to current block.
    function reactivate() external {
        require(registered[msg.sender], "Not registered");
        require(health[msg.sender].suspended, "Not suspended");

        health[msg.sender].lastHeartbeat = block.number;
        health[msg.sender].missedCount = 0;
        health[msg.sender].suspended = false;
        health[msg.sender].suspendedAt = 0;

        emit ProviderReactivated(msg.sender, block.number);
    }

    // ── Query Functions ─────────────────────────────────────────────

    /// @notice Check if a provider is active (registered and not suspended).
    /// @param provider The provider address.
    /// @return True if the provider is registered and not suspended.
    function isActive(address provider) external view returns (bool) {
        return registered[provider] && !health[provider].suspended;
    }

    /// @notice Get full health record for a provider.
    /// @param provider The provider address.
    /// @return The ProviderHealth struct.
    function getHealth(address provider) external view returns (ProviderHealth memory) {
        return health[provider];
    }

    /// @notice Check if a provider's heartbeat is overdue.
    /// @param provider The provider address.
    /// @return True if the heartbeat is overdue and can be flagged.
    function isHeartbeatOverdue(address provider) external view returns (bool) {
        if (!registered[provider] || health[provider].suspended) {
            return false;
        }
        return block.number > health[provider].lastHeartbeat + heartbeatInterval;
    }

    /// @notice Get the number of blocks until the next heartbeat is due.
    /// @param provider The provider address.
    /// @return Blocks remaining (0 if overdue or not active).
    function blocksUntilDue(address provider) external view returns (uint256) {
        if (!registered[provider] || health[provider].suspended) {
            return 0;
        }
        uint256 dueAt = health[provider].lastHeartbeat + heartbeatInterval;
        if (block.number >= dueAt) {
            return 0;
        }
        return dueAt - block.number;
    }

    // ── Governance ──────────────────────────────────────────────────

    /// @notice Update heartbeat interval (governance only).
    /// @param newInterval New interval in blocks.
    function setHeartbeatInterval(uint256 newInterval) external onlyGovernance {
        require(newInterval >= 1, "Interval must be >= 1");
        uint256 old = heartbeatInterval;
        heartbeatInterval = newInterval;
        emit HeartbeatIntervalUpdated(old, newInterval);
    }

    /// @notice Update max missed threshold (governance only).
    /// @param newMax New maximum missed count.
    function setMaxMissed(uint256 newMax) external onlyGovernance {
        require(newMax >= 1, "MaxMissed must be >= 1");
        uint256 old = maxMissed;
        maxMissed = newMax;
        emit MaxMissedUpdated(old, newMax);
    }

    /// @notice Set or update the NematocystSlashing contract reference.
    /// @param _slashingContract Address of the NematocystSlashing contract.
    function setSlashingContract(address _slashingContract) external onlyGovernance {
        address old = address(slashingContract);
        slashingContract = INematocystSlashing(_slashingContract);
        emit SlashingContractUpdated(old, _slashingContract);
    }

    // transferGovernance / acceptGovernance are inherited from Governable.
}
