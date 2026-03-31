# config/

Network-level configuration files for the Citrate node.

## Files

### bootstrap-nodes.json

Multiaddr bootstrap peer lists organized by network:

- **mainnet** -- placeholder entries (not yet launched)
- **testnet** -- 4 bootstrap nodes across US East, US West, Europe, and Asia
- **devnet** -- two localhost peers on ports 30303/30304
- **local** -- empty (no bootstrapping needed)

Format: `/ip4/<ip>/tcp/<port>/p2p/<peer_id>`

### institutional_rewards.toml

Reward and slashing parameters for school/institutional node operators.
Referenced by `core/economics/src/institutional.rs`.

Key settings:
- Block validation: 150 SALT/month base reward
- Uptime bonus: 1.2x multiplier above 90% uptime threshold
- Model hosting: 25 SALT per model per 30-day epoch
- Slashing: 5-15% of stake depending on offense type
- Schools are NOT penalized for scheduled downtime
