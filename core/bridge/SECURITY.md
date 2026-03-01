# Bridge Security Model

## Trust Model

### Oracle Quorum (M-of-N)
- **Threshold**: M attestations required from N registered oracles before processing any cross-chain event
- **Default**: M=2, N=3 (configurable via `BridgeConfig.oracle_threshold`)
- **Attestation**: Each oracle independently verifies the Ethereum event and signs `(event_id || event_hash)`
- **Consistency check**: All oracle attestations must agree on event hash; disagreements trigger rejection

### Finality Requirements
- **Ethereum (Sepolia)**: Events require `confirmation_depth` block confirmations (default: 12) before processing
- **Citrate**: Withdrawals require block finality via committee BFT checkpoint
- **Reorg handling**: If source chain head regresses, relay waits for new confirmations

### Event Deduplication
- Every processed event is tracked by its unique `EventId` (SHA3 of tx_hash + log_index)
- The relay state maintains a persistent event log
- Duplicate events are rejected without state mutation

## Threat Vectors

### Double-Spend
- **Attack**: Submit same deposit event twice to get double SALT credit
- **Mitigation**: Event deduplication by `EventId`; state persisted to survive relay restarts
- **Residual risk**: State corruption could bypass dedup; mitigated by receipt hash verification

### Oracle Collusion
- **Attack**: M oracles collude to attest to a fabricated event
- **Mitigation**: M-of-N threshold (diversity), oracle rotation, slash-on-detection
- **Residual risk**: If M oracles are compromised simultaneously; mitigated by monitoring attestation patterns

### Relay Failure / Crash
- **Attack**: Relay crashes mid-processing, leaving partial state
- **Mitigation**: Event status tracking (Pending → Processed); failed events can be retried
- **Residual risk**: SALT credited but NFT metadata not generated; mitigated by receipt verification

### Deposit Amount Manipulation
- **Attack**: Submit deposit with manipulated amount_wei
- **Mitigation**: Oracle attestations verify on-chain event data independently
- **Residual risk**: Oracle compromise; mitigated by cross-checking against block explorer

### Bridge Contract Upgrade
- **Attack**: Malicious contract upgrade changes event semantics
- **Mitigation**: Pin to specific contract address; relay validates contract address matches config
- **Residual risk**: Proxy upgrade pattern could change implementation; requires governance approval

## Emergency Procedures

### Emergency Pause
1. Call `relay.pause("reason")` on the relay service
2. All event processing stops immediately
3. No new SALT credits or withdrawals processed
4. Events continue to be fetched and queued (not lost)
5. Resume with `relay.resume()` after investigation

### State Recovery
1. Export relay state: `state.to_json()`
2. Identify problematic events in the event log
3. Manually update event statuses if needed
4. Restore from known-good state: `RelayState::from_json()`

### Oracle Rotation
1. Deactivate compromised oracle: `registry.deactivate_oracle(id)`
2. Register replacement oracle: `registry.register_oracle(new_id, name)`
3. Update threshold if needed: `registry.set_threshold(new_m)`

## Monitoring Requirements

### Alerts (Critical)
- Relay heartbeat missing > 60 seconds
- Relay lag > 50 blocks
- Active oracles < threshold
- Deposit/withdrawal failure rate > 10%

### Alerts (Warning)
- Events pending > 100
- Oracle attestation latency > 30 seconds
- Bonding curve multiplier > 2.5x (approaching cap)

### Metrics (Prometheus)
See `metrics.rs` for full metric definitions:
- `citrate_bridge_deposits_total`
- `citrate_bridge_deposits_failed_total`
- `citrate_bridge_withdrawals_total`
- `citrate_bridge_salt_credited_total`
- `citrate_bridge_relay_lag_blocks`
- `citrate_bridge_active_oracles`
- `citrate_bridge_events_pending`
- `citrate_bridge_last_eth_block`
