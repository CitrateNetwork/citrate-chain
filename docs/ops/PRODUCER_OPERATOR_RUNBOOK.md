---
created: 2026-10-19T09:00:00Z
branch: ops/c3p-producer-runbook
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
workstream: C3 Producers & finality (betanet board), item C3-P
verified_against: citrate-chain origin/main c384fc98; live 40204 at block ~512,700; contracts/addresses/40204.json
---

# Producer operator runbook

This is for a person or organization running one of the block producers on the Citrate network. It goes from an empty server to a registered, staked, block-producing validator. Commands assume Ubuntu 22.04 or 24.04 LTS and a shell as root unless a step says otherwise.

The tools live in [`scripts/producers/`](../../scripts/producers/README.md). Each has `--dry-run` and refuses to act on a network profile that the chain team hasn't marked ready.

## 0. What is true today, and what you are joining

| Topic | State on live 40204 (2026-10-19) | Source |
|---|---|---|
| Producers | One producer. 5 validators are registered and eligible; 1 proposes blocks | `verify_producer.py` network summary; UI truth contract §4 |
| Checkpoint finality | Specified, not running. The producer half is in review with its switch compiled OFF for 40204. The `finalized` tag returns genesis | `docs/consensus/CHECKPOINT_FINALITY_WIRING.md`; PR #321 |
| Proposer eligibility | Stake-gated by `ValidatorRegistry` (minStake 32,000 SALT), judged against each block's epoch snapshot | `contracts/src/ValidatorRegistry.sol`; `core/consensus/src/vrf.rs` |
| Block time | 2 s | UI truth contract §2 |

The betanet goal (board item C3) is at least four producers on separate hosts **and** separate operators, running at rehearsal 1 on 2026-11-13. Separate means no shared cloud account, no shared administrators and no shared keys. Several nodes under one operator count as one.

Words in this runbook for validator state follow the UI truth contract (`docs/ui-truth/UI_TRUTH_CONTRACT.md` §1): *Not a validator*, *Registered · active from epoch N*, *Validator active*, *Producing blocks*, *Exiting*, *Slashed*. Don't describe a validator as "finalizing" or "validating" anywhere.

### Who does what

| Step | Operator | Chain team |
|---|---|---|
| Host, OS, firewall | Provides and hardens it (§1–2) | Reviews the preflight output |
| Release binary | Installs and verifies it (§3) | Publishes the release from `main` and announces its fingerprint |
| Staker key | **Generates it on their own hardware** and shares only the address (§4) | Funds the address (genesis allocation or transfer) |
| Proposer key | The node mints it on the operator's host; the operator backs it up (§5) | Receives only the public key |
| Registration | Signs and sends the transaction with their own wallet (§6) | Checks it with `verify_producer.py` |
| Mining on | Turns it on once the validator is active (§8) | Watches the producer count |

Nobody but the operator ever holds the operator's staker key or proposer key. The chain team will never ask for either. If someone does, report it to security@citrate.ai.

## 1. Host requirements

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| CPU | 4 vCPU, x86_64 or aarch64 | 8 vCPU | Release artifacts exist for these two architectures. Small 2-vCPU hosts have run out of memory in the past |
| Memory | 8 GiB | 16 GiB | A healthy producer sits near 1 GB RSS (`docs/OPERATIONS.md`). Replays and state rebuilds peak much higher |
| Disk | 100 GiB free on SSD, persistent | 200 GiB, alarm at 80% used | A full disk once stopped the chain. Never tmpfs or overlay |
| Network | Static public IP or DNS name, inbound TCP 30303 | ≥ 100 Mbit/s, unmetered | P2P. RPC (8545/8546) and metrics (9090) stay on loopback |
| Clock | NTP synchronized | chrony or systemd-timesyncd | Block timestamps are checked against the parent block |
| Placement | Not on the same provider account, region or administrator as another producer | Different providers | One outage or one compromised account must not take out two producers |

Run the preflight before anything else and send its output to the chain team:

```bash
sudo python3 scripts/producers/preflight.py --profile 40204-r1005
```

It checks architecture, OS, CPU, memory, disk, NTP, the service user, data-dir and key-file permissions (by `stat` only: it never reads a key), sshd, the firewall, listening ports, the journald cap, the binary hash and fingerprint, and that bootnodes and the public RPC are reachable. FAIL lines must be fixed. WARN lines are fixed or explained. With `--expect-sha256`, a binary whose hash does not match is never executed: the fingerprint line then reads FAIL "not checked". Reinstall from the release (§3) and rerun.

## 2. OS hardening

```bash
# Patches and automatic security updates
apt-get update && apt-get -y upgrade
apt-get -y install unattended-upgrades ufw chrony jq curl python3
dpkg-reconfigure -f noninteractive unattended-upgrades

# Service user (no login shell needed) and directories
useradd --system --home-dir /var/lib/citrate --create-home --shell /usr/sbin/nologin citrate
install -d -o citrate -g citrate -m 0700 /var/lib/citrate/data
install -d -m 0755 /etc/citrate

# SSH: keys only, no root password login
cat > /etc/ssh/sshd_config.d/10-citrate.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl reload ssh

# Firewall: SSH and P2P in, nothing else. RPC and metrics are never opened.
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp && ufw allow 30303/tcp
ufw --force enable

# Cap the journal so a log flood can't fill the disk
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=1G\nSystemKeepFree=10G\n' > /etc/systemd/journald.conf.d/citrate.conf
systemctl restart systemd-journald

timedatectl set-ntp true
```

Rules for the host's lifetime:

- **Never build on a producer.** Install release artifacts only. Build trees filled a producer's disk once and stopped the chain.
- Restrict SSH to your own admin IPs (or a VPN) at the provider firewall as well.
- Put a disk alarm at 80% used (§9).
- Keep `/var/lib/citrate/data` on the persistent root volume or a dedicated attached volume.

## 3. Install the node from a release built from `main`

Producers run only binaries the chain team has released from `main`, never a branch build and never a local build. The chain team announces, per release: the tag, each tarball's SHA-256 and the `citrate-node consensus` fingerprint.

Run the block below as one paste. It runs in its own `bash` with `set -euo pipefail`, so the first failed step ends it and nothing after that step runs. Fill in the four values from the announcement first. A placeholder left in place fails the checks.

<!-- runbook-test: install-block. scripts/producers/tests/test_runbook_install_block.py runs this exact block against good and bad fixtures. -->
```bash
bash <<'INSTALL_CITRATE_NODE'
set -euo pipefail
TAG='PASTE-ANNOUNCED-TAG'                           # e.g. v0.5.2
ARCH='x86_64-unknown-linux-gnu'                     # or aarch64-unknown-linux-gnu
EXPECTED_SHA256='PASTE-ANNOUNCED-TARBALL-SHA256'    # 64 hex characters
EXPECTED_FINGERPRINT='PASTE-ANNOUNCED-FINGERPRINT'  # 0x + 32 hex characters
INSTALL_DIR='/usr/local/bin'
BASE="https://github.com/CitrateNetwork/citrate-chain/releases/download/$TAG"
TARBALL="citrate-chain-$ARCH.tar.gz"
IDENTITY='^https://github\.com/CitrateNetwork/citrate-chain/\.github/workflows/(release|release-tier2)\.yml@refs/(heads/main|tags/v[0-9A-Za-z._-]+)$'

refuse() { echo "REFUSED: $*. Nothing was installed. Tell the chain team." >&2; exit 1; }

if ! command -v cosign >/dev/null; then refuse "cosign is not installed"; fi

# Download, verify, unpack and run from one fresh private directory (mode 0700).
# The file that is installed is a copy of the verified binary that never runs.
WORK="$(mktemp -d)"
NEW=''
trap 'rm -rf -- "${WORK:?}"; if [ -n "$NEW" ]; then rm -f -- "$NEW"; fi' EXIT
cd "$WORK"
for f in "$TARBALL" "$TARBALL.sig" "$TARBALL.pem"; do
  if ! curl -fsSL --proto '=https' -o "$f" "$BASE/$f"; then refuse "download of $f failed"; fi
done

# 1. The tarball's SHA-256 against the announced value
ACTUAL_SHA256="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then refuse "tarball SHA-256 is $ACTUAL_SHA256, not the announced one"; fi

# 2. Sigstore signature, signed by the chain repo's release workflow on main or a tag
if ! cosign verify-blob "$TARBALL" \
    --signature "$TARBALL.sig" --certificate "$TARBALL.pem" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp "$IDENTITY"; then
  refuse "cosign signature check failed"
fi

# 3. Unpack the verified tarball and hash its binary before anything runs. Two private
#    copies are made: run/ is executed for the fingerprint check, keep/ never runs and is
#    the one installed. Every later step compares against the hash taken here.
mkdir stage
tar -xzf "$TARBALL" -C stage --no-same-owner
REL="stage/citrate-chain-$ARCH"
if [ -L "$REL" ]; then refuse "the tarball's citrate-chain-$ARCH is a symlink"; fi
if [ ! -d "$REL" ]; then refuse "the tarball has no citrate-chain-$ARCH directory"; fi
BIN="$REL/citrate-node"
if [ -L "$BIN" ]; then refuse "the tarball's citrate-node is a symlink"; fi
if [ ! -f "$BIN" ]; then refuse "the tarball has no citrate-chain-$ARCH/citrate-node"; fi
BIN_SHA256="$(sha256sum "$BIN" | cut -d' ' -f1)"
sha_is() { [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$BIN_SHA256" ]; }
mkdir -m 0700 run keep
cp -- "$BIN" run/citrate-node
cp -- "$BIN" keep/citrate-node
chmod 0700 run/citrate-node
chmod 0400 keep/citrate-node
if ! sha_is run/citrate-node; then refuse "the copy to run differs from the verified binary"; fi
if ! sha_is keep/citrate-node; then refuse "the copy to install differs from the verified binary"; fi
GOT_FINGERPRINT="$(RUST_LOG=error ./run/citrate-node consensus --json | python3 -c 'import json,sys; l=sys.stdin.read().splitlines(); print(json.loads("\n".join(l[l.index("{"):]))["fingerprint"])')"
if [ "$GOT_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then refuse "consensus fingerprint is $GOT_FINGERPRINT, not the announced one"; fi
if ! sha_is run/citrate-node; then refuse "the binary changed during the fingerprint check"; fi
if ! sha_is keep/citrate-node; then refuse "the copy to install changed during the fingerprint check"; fi

# 4. Install the copy that never ran: into a fresh private file in the install dir, hash
#    it there, keep the old binary as .prev (a hard link, so a symlink at .prev is replaced,
#    never followed), and rename into place.
NEW="$(mktemp "$INSTALL_DIR/.citrate-node.new.XXXXXX")"
install -m 0755 keep/citrate-node "$NEW"
if ! sha_is "$NEW"; then refuse "the installed copy differs from the verified binary"; fi
if [ -f "$INSTALL_DIR/citrate-node" ]; then ln -f -- "$INSTALL_DIR/citrate-node" "$INSTALL_DIR/citrate-node.prev"; fi
mv -f -- "$NEW" "$INSTALL_DIR/citrate-node"
NEW=''
echo "INSTALLED citrate-node $TAG ($ARCH): tarball SHA-256 $ACTUAL_SHA256, fingerprint $GOT_FINGERPRINT"
INSTALL_CITRATE_NODE
```

The block checks these in order and stops at the first failure:

1. `cosign` is present.
2. Every file downloaded.
3. The tarball's SHA-256 equals the announced value.
4. The Sigstore signature and signer identity verify.
5. The unpacked binary's `citrate-node consensus` fingerprint equals the announced one.
6. No copy of the binary changed while it ran, and the installed file has the verified binary's hash.

The binary runs only after the hash and the signature pass. That first run is the fingerprint check, from a private copy. The file installed is a second private copy that never runs, and every copy is compared with the hash of the binary as unpacked, before it ran. The binary is installed only after all the checks pass. On any failure the block prints `REFUSED: …`, exits non-zero and leaves `/usr/local/bin` as it was. Don't work around a refusal. Tell the chain team.

Install `cosign` from the Sigstore project's own signed release. The identity regexp is the one `scripts/deploy_testnet.sh` enforces. `scripts/producers/tests/test_runbook_install_block.py` runs this exact block from this file against a bad hash, a bad signature, a bad fingerprint, a missing `cosign`, a failed download, a symlinked binary or release directory, and a binary that changes itself or its copies while it runs, and checks that each one refuses. It also checks that symlinks at `citrate-node.prev` or `citrate-node.new` are not followed and that the release file's mode and owner are not carried over.

Then get the tools at the same tag. Set `TAG` in your shell to the announced tag first, because the block above ran in its own shell: `git clone --depth 1 --branch "$TAG" https://github.com/CitrateNetwork/citrate-chain /opt/citrate-chain`. The commands below run from `/opt/citrate-chain`.

## 4. Keys: what exists, who makes it, where it lives

| Key | Type | Made by | Lives | Used for |
|---|---|---|---|---|
| **Staker** (also the coinbase) | secp256k1, an EVM address | The operator, on their own hardware wallet or an offline machine | Off the producer host | Sends `registerValidator` with the stake; receives the producer's rewards; claims them; unbonds |
| **Proposer** (`proposer.key`) | ed25519 seed, 32 bytes | The node, on its first start with a coinbase set | `/var/lib/citrate/data/proposer.key`, mode 0600 | Signs every block; signs the registration proof; signs checkpoint finality votes once finality runs (§7) |
| **P2P identity** (`noise.key`) | x25519 | The node, on first start | `/var/lib/citrate/data/noise.key`, mode 0600 | The node's peer identity |

**The staker address must be the node's coinbase.** Consensus rejects a block whose coinbase isn't the registered staker of its proposer (`core/execution/src/executor.rs`, check 3c). The board calls these "staker and coinbase keys". On this chain they are one key, and the config generator enforces it.

Generate the staker key where it will stay:

- **Recommended:** a hardware wallet (Ledger or Trezor). Use a fresh account that holds nothing else. Write down the address.
- **Alternative:** on an offline machine, `cast wallet new <keystore-dir>` with a strong password (never an empty one). Back up the encrypted keystore and the password separately, offline.

Never put the staker key on the producer host. The node doesn't need it: rewards vest into the registry under the staker's name and are claimed later from the wallet.

Send the chain team the **staker address** only. They fund it with the stake plus gas (C2 genesis spec D2/D7: at least minStake + gas, about 32,100 SALT).

## 5. Configure and start (mining off)

```bash
python3 scripts/producers/gen_node_config.py --profile 40204-r1005 --staker 0xYOUR_STAKER_ADDRESS
cp /etc/citrate/citrate-node.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now citrate-node
journalctl -u citrate-node -f      # watch it sync
```

This writes three files to `/etc/citrate`:

- `node.toml`: the profile's chain id, bootnodes and checkpoint parameters; RPC on loopback; mining **off**; coinbase set to your staker address.
- `citrate-node.env`: the network's consensus environment (`CITRATE_VALIDATOR_REGISTRY`, `CITRATE_VALIDATOR_ACTIVATION_HEIGHT`, `CITRATE_BLOCK_V2`, `CITRATE_DAG_PRUNE_RETAIN`). Every node on a network must carry identical values, or nodes reach different verdicts on the same block. Never edit it by hand. Regenerate it from the profile.
- `citrate-node.service`: runs `/usr/local/bin/citrate-node` as `citrate` with systemd sandboxing and `Restart=always`.

On this first start the node mints `proposer.key` and `noise.key` in the data dir. **Back both up now** (§7): encrypted, offline, two copies.

Print your proposer public key and send it to the chain team:

```bash
sudo -u citrate citrate-node --config /etc/citrate/node.toml registration-proof
```

The command reads `proposer.key` read-only. It never prints the seed, and it refuses if the file is missing (it never mints one) or readable by anyone but its owner.

The node is synced when `eth_syncing` returns `false` and its head is within 5 blocks of the public RPC:

```bash
curl -s -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_syncing","params":[]}' http://127.0.0.1:8545
```

## 6. Register and stake

Registration needs two signatures: the proposer key signs a proof that you control it, and the staker key signs the transaction. The builder makes the first on the producer host and prints the transaction for you to sign with the second, wherever your staker key lives.

1. **Build** on the producer host, as `citrate`:

   ```bash
   sudo -u citrate python3 scripts/producers/build_registration_tx.py \
     --profile 40204-r1005 --staker 0xYOUR_STAKER_ADDRESS \
     --config /etc/citrate/node.toml --out /tmp/register-tx.json
   ```

   It checks the RPC is the right network (chain id **and** genesis hash). It reads `registrationNonce`, `minStake`, `activeCount`, your balance and your account nonce from public RPC. It refuses if your staker already has a validator, if this proposer key was ever registered (keys are single-use), or if the balance can't cover the stake plus gas. Then it prints the unsigned **legacy** transaction. This chain rejects EIP-1559 transactions.

   The stake defaults to the registry's `minStake`. Pass `--stake-salt` to bond more. Use `--dry-run` to preview with no chain reads; its output is marked DO NOT SIGN.

2. **Sign and send** from the machine with your staker wallet. The builder prints the exact `cast mktx --legacy …` command with the nonce, gas, value, registry address, proposer public key and proof filled in. Before signing, check that the wallet shows: to = the ValidatorRegistry in `contracts/addresses/40204.json`, value = your stake, chain 40204. Submit with `cast publish`.

   The account nonce comes from public RPC. If your staker address was funded at genesis and has already sent transactions, check the nonce in your wallet too: the RPC has under-reported nonces for genesis-funded accounts.

3. **Check:**

   ```bash
   python3 scripts/producers/verify_producer.py --profile 40204-r1005 --staker 0xYOUR_STAKER_ADDRESS
   ```

   Right after registration you see **Registered · active from epoch N**. N is the first epoch whose snapshot (`S(N) = N·1000 − 200`) comes after your registration block. An epoch is 1,000 blocks (about 33 minutes at 2 s blocks). Activation therefore comes between 200 and 1,200 blocks after the registration block, about 7 to 40 minutes, depending on where in the epoch it lands. Don't promise "next epoch" to anyone.

## 7. The finality voting key, and the proposer.key wipe warning

**There is no separate finality key.** Checkpoint finality votes are signed with the same `proposer.key` that signs blocks and is registered in `ValidatorRegistry` (spec decision D-4, implemented in PR #321). The committee for a checkpoint is drawn from the governing epoch snapshot of registered validators at or above minStake. Today every such validator is in it, because the set is smaller than the 100-member committee size. Finality is compiled OFF on 40204 and turns on in a later release, after at least four producers are live and the chain team has watched it finalize (`CHECKPOINT_FINALITY_WIRING.md` §6–7). You won't need to do anything to start voting. A release turns it on.

> **WARNING: never wipe, regenerate or copy `proposer.key`.**
>
> - It **is** your validator. The registry binds your stake to its public key, and a key can be registered only once (`pubkeyEverRegistered`). If you delete it, the node mints a new key that isn't registered and stops producing, without an error. Recovering means a full exit (the bond stays locked for 6 epochs) and a new registration with fresh stake.
> - **Never run the same `proposer.key` on two hosts.** Two nodes with one key sign two different blocks at the same height. That is equivocation, provable by anyone, and slashes the stake. There's no safe hot standby that shares the key.
> - `noise.key` is the node's peer identity. Keep it too. Bootnodes pin peer identities, so changing it breaks those trust entries.
>
> Any "reset the node", "wipe the data dir", "resync from scratch" or "restore from snapshot" procedure keeps both files. The safe sequence:
>
> ```bash
> citrate-watchdog-ctl.sh pause 6 "data reset"          # §9: before anything that replays
> systemctl stop citrate-node
> TS=$(date -u +%Y%m%dT%H%M%SZ); D=/var/lib/citrate/data
> mv $D $D.pre-reset-$TS                                 # archive, don't delete
> install -d -o citrate -g citrate -m 0700 $D
> cp -a $D.pre-reset-$TS/{proposer.key,noise.key} $D/   # identity carried over
> systemctl start citrate-node
> sudo -u citrate citrate-node --config /etc/citrate/node.toml registration-proof   # same pubkey as before?
> ```
>
> Back-ups: two encrypted offline copies of `proposer.key` and `noise.key`, made right after the first start (`tar -C /var/lib/citrate/data -cf - proposer.key noise.key | gpg -c > identity-$(hostname).tar.gpg`). Restore one only to the same host, after the original host is gone for good and can never start again.

## 8. Turn mining on

Turn mining on only when `verify_producer.py` shows the validator **active** and **in the committee** for the governing snapshot:

```bash
python3 scripts/producers/verify_producer.py --profile 40204-r1005 --staker 0x… --require registered,eligible
python3 scripts/producers/verify_producer.py --profile 40204-r1005 --staker 0x… --require committee
python3 scripts/producers/gen_node_config.py --profile 40204-r1005 --staker 0x… --mining on --force
systemctl restart citrate-node
```

The first command must exit 0. The committee check (second command) counts only members that are activation-ready for the governing snapshot **and** at or above minStake, and compares that count with the minimum committee for checkpoint finality (`MIN_FINALITY_COMMITTEE` = 4, quorum ⌊2n/3⌋+1, `core/consensus/src/checkpoint.rs`). It exits 0 only when the validator is in a committee that can finalize. While fewer than four producers qualify (the first producers of a network), it FAILS (exit 1) with "in the checkpoint committee …, but the committee is too small to finalize"; that FAIL is expected during bring-up, and you may turn mining on when the state begins "in the checkpoint committee" (`"in_committee": true` in `--json`). Any other FAIL, such as "below minStake" or "not yet", means stop. The committee check reads the registry at the head, so it reports **UNKNOWN** (exit 3) when the registry changed after the governing snapshot (a registration, a stake change, an unbond, a slash or an executed parameter change) or when its logs cannot be read. UNKNOWN is not a pass: wait for the next snapshot (the message names its block) and run it again. The registry is read from the RPC node's applied state, which lags its block headers while the node syncs or replays after a restart. Before and after the reads, `verify_producer.py` therefore requires `eth_syncing` to be `false` and the head block to be at most `--max-head-age` seconds old (default 120 s on 2 s blocks). If either fails, registered, eligible and committee are all UNKNOWN (exit 3). Run it again once the node has caught up, or point `--rpc` at a node that has.

Within a few hundred blocks the verifier should show **Producing blocks**:

```bash
python3 scripts/producers/verify_producer.py --profile 40204-r1005 --staker 0x… --window 300
```

If it reports blocks with a coinbase other than your staker, stop mining (`--mining off --force`, restart) and check the `[mining] coinbase` value.

## 9. Monitoring and the watchdog

### Watchdog

The height watchdog restarts a producer whose progress has stopped. It runs every 30 s and restarts the node if nothing has moved for 180 s.

```bash
install -m 0755 scripts/ops/watchdog/citrate-height-watchdog.sh scripts/ops/watchdog/citrate-watchdog-ctl.sh /usr/local/bin/
cp scripts/ops/watchdog/citrate-height-watchdog.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now citrate-height-watchdog.timer
citrate-watchdog-ctl.sh resume    # arms it; status must then say ACTIVE
```

It fails closed: it restarts the node only while it is armed (`resume` arms it) and not paused or contained. A fresh install, or a pause file deleted by hand, leaves it restarting nothing and alerting hourly that it is disarmed. The guarantees `pause` gives, and the code and tests behind each one, are listed in `scripts/ops/watchdog/README.md` ("Invariants").

It is sync-aware: while the node reports `eth_syncing`, it tracks `currentBlock`, not the head. That isn't enough on its own. **A restart during a replay throws the replay away**, and some replays hold the head still without reporting progress (a drain after a rollback, a state copy, a rebuild). Restarting a node mid-replay turned a recoverable state rebuild into a halt on 2026-09-27. So:

- **Pause before** any replay, drain, rollback, state copy, data reset or planned rebuild: `citrate-watchdog-ctl.sh pause <hours> "<reason>"` (1–48 h). It returns only after any poll already running has finished, and it waits for any other pause, resume or containment command to finish first; if it prints `NOT confirmed`, don't start the work until a re-run succeeds.
- While paused it restarts nothing. A pause doesn't lift itself: after its deadline the watchdog alerts once an hour, still without restarting, until someone resumes it.
- **Resume after** the node is caught up (`eth_syncing` false, head within 5 blocks of the public RPC): `citrate-watchdog-ctl.sh resume`. Resuming resets the stall clock, so the first poll can't restart a node that is merely catching up.
- `citrate-watchdog-ctl.sh status` shows the state: `ACTIVE`, `PAUSED`, `CONTAINED` or `DISARMED`.
- **Incidents are not pauses.** For a suspected key compromise use `citrate-watchdog-ctl.sh contain` (§11), never `pause` plus `systemctl stop`: a pause is meant to be lifted, and containment turns the watchdog off before the node stops.

Alerts go through `/usr/local/bin/citrate-alert.sh "<title>" "<body>"`. Provide your own (email, pager, chat webhook), executable by root. Set `NODE_LABEL` in a drop-in for the watchdog service if your hostname isn't descriptive.

### What to alert on

| Signal | Source | Alert when |
|---|---|---|
| Node down | `systemctl is-active citrate-node`; local `eth_blockNumber` | Not active, or RPC unanswered for 3 min (the watchdog also restarts) |
| Head stalled | Local `eth_blockNumber` vs public RPC | More than 30 blocks behind for 5 min |
| Applied state behind | `eth_syncing.currentBlock` vs `highestBlock` | The gap grows for 10 min. The node can't produce until it closes |
| No peers | `net_peerCount` | 0 for 60 s |
| Disk | `df /var/lib/citrate/data` | Over 80% used |
| Memory | Process RSS, or `process_resident_memory_bytes` | Over 3 GB for 2 min (`docs/OPERATIONS.md` circuit-breaker) |
| Not producing | `verify_producer.py --require producing --window 1000` hourly from cron | Exit status not 0. Exit 3 means the RPC read failed, which is unknown, not "not producing" |
| Validator state | `verify_producer.py --require registered,eligible` | Anything but *Validator active* |
| Watchdog paused | `citrate-watchdog-ctl.sh status` | Paused longer than planned |

With `CITRATE_METRICS=1` (set by the generated env file) the node serves Prometheus metrics on `127.0.0.1:9090`. Scrape it locally or through an authenticated tunnel. The alert rules in `node/monitoring/alerts/citrate-alerts.yml` apply. Don't expose 9090 publicly.

## 10. Upgrades

- Upgrade only to a release the chain team announces, built from `main`, verified as in §3, with a matching fingerprint.
- Producers upgrade one at a time, never all at once. Wait until the upgraded node is producing again before the next one starts.
- Keep the previous binary as `/usr/local/bin/citrate-node.prev` for rollback.
- Pause the watchdog if the release notes say the upgrade replays state.

## 11. Exit and incidents

- **Leaving:** tell the chain team first. Unbonding (`initiateUnbond`) starts a 6-epoch exit lock. Stop mining when the registry shows *Exiting*. Keep the host and its keys until the exit completes.
- **Suspected key compromise:** contain the node at once, so the key can't sign again, and keep it contained:

  ```bash
  sudo citrate-watchdog-ctl.sh contain "suspected key compromise"
  ```

  Don't use a bare `systemctl stop citrate-node`: the watchdog (§9) restarts a node whose RPC has been unreachable for 3 minutes, which would bring the signer back online. `contain` turns the watchdog off first, in this order: it writes a containment marker the watchdog obeys on every poll with no deadline, waits for a poll already running to finish (the poll lock), disables and stops `citrate-height-watchdog.timer` and its service, and only then stops and disables `citrate-node`, so neither the watchdog nor a reboot starts it again. It stops at the first step that fails and says which one. If it fails, stop the node by hand after the watchdog is off. While contained, `resume` is refused. Check with `citrate-watchdog-ctl.sh status` (shows `CONTAINED`) and `systemctl is-active citrate-node citrate-height-watchdog.timer` (both `inactive`).

  Then email security@citrate.ai. Don't post details publicly. See `SECURITY.md`. Only after the security response is done does `citrate-watchdog-ctl.sh release "<reason>"` lift the containment; it starts nothing and leaves the watchdog disarmed. The node and the watchdog timer are started again by hand when the chain team says so, followed by `citrate-watchdog-ctl.sh resume` to arm the watchdog.
- **Chain halt or fork:** pause the watchdog, don't restart in a loop, collect `journalctl -u citrate-node --since -1h`, and contact the chain team. Don't roll back or wipe anything unless they ask. Any rollback uses `citrate-node rollback` with the chain team's exact height and hash.

## Appendix: the tools

| Tool | What it does | Dry run |
|---|---|---|
| `preflight.py` | Host checks (§1–3) | Lists the checks |
| `gen_node_config.py` | `node.toml`, consensus env, systemd unit for a profile (§5, §8) | Prints the files |
| `citrate-node registration-proof` | Proposer public key; the signed registration proof and calldata (§5–6) | Read-only by design |
| `build_registration_tx.py` | Unsigned `registerValidator` transaction (§6) | No chain reads; output marked DO NOT SIGN |
| `verify_producer.py` | Registered / eligible / committee / producing, from public RPC (§6, §8, §9) | Lists the reads |
| `citrate-watchdog-ctl.sh` | Pause / resume / status of the watchdog (§9); incident containment (§11) | `--dry-run pause …`, `--dry-run contain …` |

Network profiles are `scripts/producers/profiles/<name>.json`. `40204-r1005` is the live network. `rehearsal-1` stays `pending-genesis` until the chain team fills its genesis hash, registry address and bootnodes at the rehearsal genesis cut. Until then the tools refuse it outside `--dry-run`.
