# bootnode-keys/

Pre-generated Noise keypairs for the testnet-beta bootnodes. Each file is
**64 bytes** in the format `private || public` (32 + 32 bytes), produced by
[`core/network/examples/gen_bootnode_keys.rs`](../../core/network/examples/gen_bootnode_keys.rs)
using the production `citrate_network::NoiseKeypair::generate()` code path.

## Files (gitignored)

```
boot1.noise.key   →  uploaded to nyc1 droplet  →  /home/citrate/.citrate/noise.key
boot2.noise.key   →  uploaded to sfo3 droplet  →  /home/citrate/.citrate/noise.key
boot3.noise.key   →  uploaded to fra1 droplet  →  /home/citrate/.citrate/noise.key
```

These are **private** keys. They are listed in `.gitignore` and **must never
be committed**. The matching public peer IDs are baked into
[`node/config/testnet-beta.toml`](../../node/config/testnet-beta.toml) under
`bootstrap_nodes = [...]`.

## Regenerating

If you ever need to regenerate (new chain, key compromise, key loss):

```bash
cargo run --release --example gen_bootnode_keys -p citrate-network -- \
    --count 3 \
    --out-dir ./tools/bootnode-keys \
    --host-template 'boot{i}.citrate.network' \
    --port 30303
```

The example prints a copy-pasteable `bootstrap_nodes = [...]` block. Paste it
into `node/config/testnet-beta.toml`, commit, then re-upload the new
`.noise.key` files to each droplet **before** restarting `citrate-node` on
the droplets (otherwise the node generates a fresh random key and the baked-in
peer IDs no longer match).

## Per-droplet upload

```bash
# After bootnode provisioning, before starting citrate-node on the droplet:
for i in 1 2 3; do
  ip="$(doctl compute droplet get citrate-boot-$i --format PublicIPv4 --no-header)"
  scp tools/bootnode-keys/boot${i}.noise.key \
      root@$ip:/home/citrate/.citrate/noise.key
  ssh root@$ip \
      'chown citrate:citrate /home/citrate/.citrate/noise.key && \
       chmod 600 /home/citrate/.citrate/noise.key'
done
```

Then start (or restart) `citrate-node` on each droplet:

```bash
ssh root@$ip 'systemctl restart citrate-node && \
              journalctl -u citrate-node --since "10 seconds ago" | grep -i "noise identity"'
```

The log line should show `noise identity: <first 16 hex chars>...` matching
the public-key prefix in `bootstrap_nodes`.

## Threat model + custody

- **Scope:** these keys authenticate the bootnodes as the canonical
  `boot{1,2,3}` discovery peers. Compromise allows an attacker to impersonate
  a bootnode and serve a wrong peer-list to new nodes. Compromise does **not**
  allow chain-state custody, validator key custody, or fund movement.
- **Custody:** operator workstation (Larry's machine) + the 3 droplet data
  dirs. Backup encrypted (age, gpg, or 1Password) outside the repo if the
  operator wants point-in-time recovery without a full re-roll.
- **Rotation:** if compromised, re-run the regeneration steps above. The
  shipped binary's peer IDs become stale; partners auto-reconnect after they
  receive a v0.5.0-betaN release with the new `bootstrap_nodes`.

See [`docs/PUBLIC_TESTNET.md`](../../../citrate-labs/docs/PUBLIC_TESTNET.md)
and `citrate-compliance/runbooks/infrastructure/bootnode-provisioning.md`
for the broader bootnode operational model.
