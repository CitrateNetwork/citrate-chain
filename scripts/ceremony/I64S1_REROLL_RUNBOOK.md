---
created: 2026-06-28
branch: feat/i64-s1-phase-c-ceremony
author: saul (Larry Klosowski)
status: ready-for-owner-review
supersedes: handoffs/BUNDLER_DETERMINISTIC_DEPLOYER_AND_GENESIS.md §11 (for the I64-S1 re-roll)
---

# I64-S1 Re-Roll Runbook

The ordered, end-to-end ceremony for the I64-S1 deterministic state-reset re-roll
of chain 40204. This re-roll ships the chain-wide Q16.16 `i32 → i64` widening in
the **node binary / precompiles / genesis** — it does **not** change any contract
bytecode, so every existing address is preserved (no salt `VERSION` bump). The
five federated-learning contracts and the co-op factory that joined the surface
after the last re-roll are **added** (additions-only diff).

> This runbook is the I64-S1-specific superset of handoff §11 (which covered the
> EW-S1 AA re-roll). Where §11 said "build the chain binary", here it is "build
> the **i64** binary + run the parity proof"; where §11 ran only the AA redeploy,
> here `regenesis.sh` deploys the whole stack including the 5 new contracts, and
> the co-op factory is a separate cross-repo ceremony.

**Execution is OWNER-GATED and IRREVERSIBLE** — §3 wipes live validator state.
Do not start until every box in §0 is checked.

---

## §0 — Preconditions (gates)

| Gate | Check |
|---|---|
| **Owner confirms economic params** | ✅ CONFIRMED 2026-06-29 — all 15 pinned constants in `DeployFederatedLearning.s.sol` signed off as-is. The projected addresses in `contracts/addresses/I64S1_PROJECTION.md` are final. |
| **Owner confirms governance = deployer** | ✅ CONFIRMED 2026-06-29 — `ComputePoolPipeline` governance = deployer (`0x4250675F…`); `GOVERNANCE` env left unset. Pipeline lands at the projected `0xc2ddf9…`. Governance transferable post-deploy. |
| **Phase A/B/C merged** | `feat/i64-s1-phase-a-q16-widening`, `…-phase-b-deterministic-deploy`, `…-phase-c-ceremony` merged to `main`. |
| **Parity proof green** | `cargo test --manifest-path core/federated/Cargo.toml` → 9/9 (Q16 ops + the 3 frozen goldens at the pinned kernel rev). |
| **Backups taken** | Validator data dirs archived (ceremony-reroll.sh does this per host); `.env.testnet` backed up. ⚠️ **comms relay master key is NOT yet backed up off-box** (per memory) — back it up before the ceremony or accept the loss-of-relay risk. |
| **`.env.testnet` carries operator role addresses** | The funding step (§7) needs `CITRATE_AA_BUNDLER_OPERATOR_ADDR`, `CITRATE_GATEWAY_OPERATOR_ADDRESS`, `DGX_PROVIDER_ADDRESS`, `DGX_PROVIDER_V2_ADDRESS`, `CITRATE_AA_IDENTITY_SIGNER_ADDR`. `post-reroll-redeploy.sh` (§5) repopulates the `CITRATE_AA_*` block; confirm the DGX + gateway vars are present too. |

---

## §1 — Build the i64 binary + prove parity

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-chain
git checkout main && git pull

# Toolchain is pinned to 1.96.0 (rust-toolchain.toml) — matches the kernel MSRV.
cargo build --release -p citrate-node

# Consensus-critical sanity:
cargo test -p citrate-economics --lib \
  genesis::tests::test_arachnid_deployer_predeployed_in_every_preset
cargo test -p citrate-execution --lib q16            # i64 Q16 unit + saturation
cargo test --manifest-path core/federated/Cargo.toml  # 9/9 parity (ops + frozen goldens)

# Cross-platform fixtures (the re-frozen i64 goldens, e.g. exp(11), exp(16)):
cargo test -p citrate-execution --test q16_cross_platform_fixtures

# Contracts compile clean (no bytecode change expected, but prove it):
cd contracts && forge build && cd ..
```

Do not proceed unless all of the above pass.

---

## §2 — Ordered node reset (the destructive, owner-authorised step)

Reset in **chain-head-first** order so the network re-forms cleanly. The **Noise
static keys persist** (they live outside the chain data dir), so peer IDs and the
peering mesh survive the wipe — only chain state is reset.

**Order: RPC / sequencer node FIRST (it carries chain head), then boot1 → boot2 → boot3.**

On each host, in that order:

```bash
systemctl stop citrate-node
# Archive (not delete) the chain state so a rollback is possible.
# scripts/ceremony/ceremony-reroll.sh does this with a timestamped move:
bash scripts/ceremony/ceremony-reroll.sh --reroll   # archives data dir, keeps env + Noise key
# Drop in the freshly built binary (rsync/scp from §1):
#   rsync target/release/citrate-node root@<host>:/usr/local/bin/citrate-node
systemctl start citrate-node
journalctl -u citrate-node -n 100 -f                # watch the boot
```

Wait until the RPC node reports height > 0 and the boot nodes are gossiping with
it before moving to the next host.

---

## §3 — Verify the re-rolled genesis

```bash
RPC_URL=$(grep '^RPC_URL=' /home/saul/Projects/Citrate-Labs/.env.testnet | head -1 | cut -d= -f2-)

cast chain-id --rpc-url "$RPC_URL"                                  # → 40204
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url "$RPC_URL"
# → 0x7fffffffffff… (the 69-byte Arachnid runtime — genesis WP-B)

DEPLOYER=$(grep '^DEPLOYER_ADDRESS=' /home/saul/Projects/Citrate-Labs/.env.testnet | head -1 | cut -d= -f2-)
cast balance "$DEPLOYER" --rpc-url "$RPC_URL"
# → 10000000000000000000000000 wei (10M SALT, genesis-funded)
```

If any fail, **halt** — the genesis preset or the binary is wrong.

---

## §4 — Vendor EntryPoint v0.7

The AA stack pins to an existing EntryPoint; it's gone after the reset, so deploy
it first (the AA redeploy in §5 pins to it).

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-chain
forge create lib/account-abstraction/contracts/core/EntryPoint.sol:EntryPoint \
  --rpc-url "$RPC_URL" \
  --private-key "$(grep '^DEPLOYER_PRIVATE_KEY=' /home/saul/Projects/Citrate-Labs/.env.testnet | head -1 | cut -d= -f2-)" \
  --broadcast
# Capture the address → update CITRATE_AA_ENTRY_POINT in .env.testnet.
```

---

## §5 — Deploy the whole stack (core + 5 new + AA), then the co-op factory

**5a — Co-op factory FIRST (separate repo).** `regenesis.sh`'s final verify step
checks every address in `40204.json` has code, and that table now includes
`CitrateCooperativeFactory`. Deploy it before regenesis verifies.

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-coop/contracts
forge script script/DeployCoop.s.sol \
  --rpc-url "$RPC_URL" \
  --private-key "$(grep '^DEPLOYER_PRIVATE_KEY=' /home/saul/Projects/Citrate-Labs/.env.testnet | head -1 | cut -d= -f2-)" \
  --sender "$DEPLOYER" --broadcast --slow
# → CitrateCooperativeFactory: 0xa9ded8…  (deterministic; no-arg CREATE2)
```

**5b — Full chain stack (incl. the 5 federated-learning contracts) + AA.**
`regenesis.sh` runs every CREATE2 ceremony in dependency order
(DeployAll → ModelAccessControl → TEE → ComputePoolTraining →
**DeployFederatedLearning** → EduStack → AIGateway), then `--with-aa` chains the
AA redeploy, then regenerates `40204.json`, then asserts code at every address.

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-chain
ENV_TESTNET=/home/saul/Projects/Citrate-Labs/.env.testnet \
  bash scripts/ops/regenesis.sh --with-aa
# → "✅ full stack deployed + canonical table regenerated + all addresses have code."
```

**5c — Post-deploy governance wiring** (NOT in the deterministic set; no address impact):

```bash
# AggregationChallenge: point it at the slashing contract + bootstrap governance.
cast send <AggregationChallenge> 'setSlashingContract(address)' <NematocystSlashing 0xfeb2…> \
  --rpc-url "$RPC_URL" --private-key "$(…DEPLOYER_PRIVATE_KEY…)"
# transferGovernance/acceptGovernance to the intended governor (mirrors NematocystSlashing).
# KYCRegistry: grant the updater role to the production IDP signer.
```

(Addresses for `<…>` come from the regenerated `40204.json`.)

---

## §6 — Verify the address-table diff is additions-only

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-chain
git diff contracts/addresses/40204.json
# Expect: the 45 pre-existing addresses UNCHANGED; only the 6 new keys present
# (KYCRegistry, IPFSIncentivesV2, IPFSIncentivesV3, AggregationChallenge,
#  ComputePoolPipeline, CitrateCooperativeFactory). The CREATE2 determinism
# gate proves no existing address moved:
bash scripts/ci/check-create2-determinism.sh
```

If any pre-existing address changed → **halt and investigate** (a bytecode or
constructor-arg drift slipped in; the re-roll is supposed to be additions-only).

---

## §7 — Fund the operational roles (WP-C1)

The off-chain operator EOAs have zero balance after the reset. Top them up from
the genesis-funded deployer. Dry-run first (sends nothing), then broadcast:

```bash
bash scripts/ops/fund-operational-roles.sh              # DRY-RUN — review the plan
bash scripts/ops/fund-operational-roles.sh --broadcast  # execute
```

Role → target (testnet float) → source:

| Role | env var | target | source |
|---|---|---|---|
| Bundler operator | `CITRATE_AA_BUNDLER_OPERATOR_ADDR` | 100 SALT | deployer |
| Gateway operator signer | `CITRATE_GATEWAY_OPERATOR_ADDRESS` | 100 SALT | deployer |
| DGX compute provider | `DGX_PROVIDER_ADDRESS` | 50 SALT | deployer |
| DGX compute provider v2 | `DGX_PROVIDER_V2_ADDRESS` | 50 SALT | deployer |
| Identity signer | `CITRATE_AA_IDENTITY_SIGNER_ADDR` | 10 SALT | deployer |
| EIP-2771 relayer(s) | `CITRATE_EDU_RELAYER_ADDRESS` (optional) | 50 SALT | deployer |

A role whose env var is unset is reported and skipped — confirm none you need
were silently skipped.

---

## §8 — Sync the federation address pins (WP-Z), then restart droplets

`regenesis.sh` already ran `emit-address-table.sh`. Now push the new addresses to
the seven consumer repos (one small PR each with the JSON diff):

```bash
cd /home/saul/Projects/Citrate-Labs/citrate-explorer          && pnpm sync-addresses
cd ../citrate-inference-gateway && bash scripts/sync-addresses.sh
cd ../citrate-node-agent        && bash scripts/sync-addresses.sh
cd ../citrate-sdk-marketplace   && pnpm sync-addresses
cd ../citrate-native            && bash scripts/sync-addresses.sh
cd ../citrate-boeing-shell      && bash scripts/sync-addresses.sh
cd ../citrate-buyer-webapp      && pnpm sync-addresses
```

Then restart the two stateful droplets with the new AA env (handoff §11.8–11.9):

```bash
# auth.citrate.ai — update CITRATE_AA_* in /opt/citrate-identity/.env, then:
ssh root@157.230.55.191 'cd /opt/citrate-identity && docker compose restart identity'
curl -s https://auth.citrate.ai/aa/config | jq   # every value matches .env.testnet

# bundler — update BUNDLER_ENTRYPOINT in /opt/citrate-bundler/.env, then:
ssh root@159.223.174.220 'cd /opt/citrate-bundler && docker compose down && docker compose up -d'
```

> The hardcoded-address consumers (`citrate-node-agent/crates/chainio/src/addrbook.rs`,
> `sdk-marketplace/src/contracts.ts`, explorer defaults) need a code bump for the
> **new** addresses — existing addresses are unchanged so they keep working. See
> the app-compat matrix (`I64S1_APP_COMPAT_MATRIX.md`) for the per-app rows.

---

## §9 — Smoke (WP-E)

```bash
EP=$(grep '^CITRATE_AA_ENTRY_POINT=' /home/saul/Projects/Citrate-Labs/.env.testnet | head -1 | cut -d= -f2-)
BUNDLER_URL=https://bundler.citrate.ai/rpc EXPECTED_ENTRYPOINT="$EP" \
  bash /home/saul/Projects/Citrate-Labs/citrate-bundler/scripts/smoke.sh
# → exit 0, "bundler boot smoke passed"
```

---

## §10 — Done (live signals)

| Signal | Expected |
|---|---|
| `cast chain-id` | `40204` |
| `cast code <Arachnid>` | 69-byte runtime |
| `cast code <KYCRegistry / …Pipeline / CitrateCooperativeFactory>` | non-empty (the new contracts landed) |
| `cast call <CitrateWalletFactory> 'identitySigner()(address)'` | matches `CITRATE_AA_IDENTITY_SIGNER_ADDR` |
| `curl -s https://auth.citrate.ai/aa/config \| jq` | every value matches `.env.testnet` |
| `bash citrate-bundler/scripts/smoke.sh` | exit 0 |
| `check-create2-determinism.sh` | pass (no existing address moved) |
| App-compat matrix | every row green (`I64S1_APP_COMPAT_MATRIX.md`) |

---

## Rollback

1. **Chain state** — §2 archived (did not delete) each data dir. Stop the nodes,
   restore the archived data dir, and run the OLD binary to return to the
   pre-re-roll chain. (Post-re-roll deploys are lost — expected.)
2. **`.env.testnet`** — `post-reroll-redeploy.sh` wrote a timestamped backup;
   restore it to recover the pre-redeploy keystore block.
3. **Droplets** — `/opt/citrate-{identity,bundler}/.env` have a `.env.bak` if you
   `cp` before editing; `docker compose` keeps one previous image.
