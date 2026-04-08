---
created: 2026-04-07T06:00:00Z
branch: quorum-execution-v1
author: Claude (zooid: architect)
sprint: level-a
status: active
scope: Ceremony key handling protocol
---

# Keystore Protocol

## Purpose

Define exactly how signing keys are created, stored, used, and rotated for the genesis ceremony. No keys written to environment variables. No keys committed to the repo. No keys transmitted over the network unencrypted.

## Key Inventory

The ceremony uses four distinct key classes. Each has a different owner, different storage, and different rotation policy.

| Key Class | Owner | Storage | Rotation |
|-----------|-------|---------|----------|
| **Deployer** | Ceremony operator | Foundry keystore on the deployer host | Per ceremony (burn after one use) |
| **Governance** | Multisig (3-of-5 post-ceremony) | Hardware wallet per signer | Only via governance vote |
| **Bootnode** | Each bootnode operator | Systemd-managed encrypted keyring | Per-node lifecycle |
| **Relayer** | Pilot operations | Foundry keystore, rotatable | Monthly or on suspicion |

## Storage Mechanism: Foundry Keystore

Foundry's `cast wallet import` provides encrypted key storage that the ceremony script uses. Keys are encrypted with a passphrase, stored in `~/.foundry/keystores/<name>`, and accessed by keystore account name during the ceremony.

### Creating a key

```bash
# On the deployer host (provision-host.sh deployer has already run)
sudo -u citrate -i

# Generate a new key and save encrypted
cast wallet new --json > /tmp/ceremony-deployer.json
# NOTE: This writes the plaintext key to /tmp. See "Cleanup" section below.

# Import into Foundry keystore
# You will be prompted for a passphrase — use a strong passphrase from a password manager
cast wallet import ceremony-deployer --private-key "$(jq -r '.[0].private_key' /tmp/ceremony-deployer.json)"

# Immediately shred the plaintext file
shred -u /tmp/ceremony-deployer.json

# Verify import
cast wallet list
# Expected output includes: ceremony-deployer (Local)
```

### Using a keystore entry

```bash
# The ceremony script uses the account name in the default Foundry keystore folder
export CEREMONY_DEPLOYER_ACCOUNT="ceremony-deployer"
export CEREMONY_DEPLOYER_ADDRESS="$(cast wallet address --keystore "$HOME/.foundry/keystores/$CEREMONY_DEPLOYER_ACCOUNT")"

# The script will prompt for the passphrase when forge needs to sign
./ceremony.sh
```

### Key properties enforced by this protocol

- **Never touches git**: keystore files live in `$HOME/.foundry/keystores/`, not the repo
- **Never in env vars**: we pass the keystore account name, not the key itself, through env
- **Never transmitted**: keys are created on the deployer host and never leave it
- **Prompt-gated**: every signing operation requires the operator to re-enter the passphrase
- **Single-use for deployer**: the deployer key signs one ceremony's worth of transactions and is then retired

## Ceremony Key Lifecycle

### Pre-ceremony (T-7 days)

1. Operator procures a fresh hardware device for the deployer role (clean laptop or dedicated VM)
2. Operator installs Foundry via `provision-host.sh deployer`
3. Operator generates ceremony-deployer key with a passphrase from their password manager
4. Operator verifies `cast wallet list` shows the entry
5. Operator captures the deployer address and reports it to the auditor and stakeholder out-of-band (signed message, phone verification, in-person)
6. Stakeholder funds the deployer address with enough gas to deploy the full contract suite (ceremony budget — see `CEREMONY_CHECKLIST.md`)
7. Auditor verifies the funding transaction and the deployer address match the reported values

### During ceremony (T-0)

1. Operator sets `CEREMONY_DEPLOYER_ACCOUNT` and `CEREMONY_DEPLOYER_ADDRESS` env vars
2. Operator runs `ceremony.sh` in rehearsal mode first
3. Rehearsal passes — operator runs ceremony.sh in real mode
4. Every `forge script` invocation prompts for the keystore passphrase
5. The passphrase is entered by the operator; no automation has access to it
6. Ceremony completes, proof bundle is generated, signatures collected

### Post-ceremony (T+1 day)

1. Deployer key is **retired**: a flag file is written to the keystore directory noting the ceremony it served
2. Deployer key is **NOT deleted**: it remains in the keystore as part of the proof bundle for auditor inspection
3. Operator commits the retirement flag file to a private ops repo (not the main monorepo)
4. Subsequent operations (relayer updates, monitoring) use a different key class

### Emergency rotation

If a deployer key is suspected compromised during the ceremony window:

1. ABORT the ceremony immediately — do not attempt to continue
2. Generate a new deployer key following the pre-ceremony steps
3. Report the abort to the auditor and stakeholder
4. Restart the ceremony from Step 00 (preflight) on a fresh host
5. The compromised key must not be used again — delete the keystore entry and shred the passphrase

## Passphrase Policy

- Minimum length: 20 characters
- Must be generated by a password manager (1Password, Bitwarden, etc.)
- Must not be reused across keys
- Must not be shared over email, chat, or SMS
- Backup: stored in the same password manager under a ceremony-specific vault

If the passphrase is lost, the keystore entry is unrecoverable. This is intentional — retired deployer keys are write-only audit artifacts.

## What This Protocol Does NOT Cover

- **Governance multisig setup**: that's a separate document (`.agentile/launch/GOVERNANCE_MULTISIG_SETUP.md` — to be written)
- **Hardware wallet integration**: ceremony uses Foundry keystore only. Hardware wallets are for governance keys, not the one-shot deployer key.
- **HSM integration**: for mainnet/production, we will migrate to HSM-backed signing. This protocol is testnet pilot scope.
- **Key escrow**: there is no key escrow. Lost keys stay lost.

## Cleanup Checklist

After every ceremony run (rehearsal OR real):

- [ ] All plaintext key files (`/tmp/*.json` etc.) shredded with `shred -u`
- [ ] No key material in shell history (`history -c; rm ~/.bash_history; history -w`)
- [ ] No key material in systemd journal (`journalctl --vacuum-time=1s` if anything leaked)
- [ ] Passphrase removed from clipboard
- [ ] Terminal session closed

## References

- `ceremony.sh` — uses `CEREMONY_DEPLOYER_ACCOUNT` env var per this protocol
- `provision-host.sh deployer` — installs Foundry in a way that supports this protocol
- `CEREMONY_CHECKLIST.md` — pre-ceremony procurement checklist including funding the deployer address
- `AUDITOR_PRE_SIGNOFF.md` — the document the auditor signs to verify this protocol was followed
