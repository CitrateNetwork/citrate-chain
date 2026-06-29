---
created: 2026-06-28
branch: feat/i64-s1-phase-c-ceremony
author: saul (Larry Klosowski)
status: ready-for-owner-review
---

# I64-S1 App-Compatibility Matrix (WP-C3)

The I64-S1 re-roll changes the **node binary / precompiles / genesis** (the Q16
`i32 → i64` widening). It does **not** change the RPC endpoint and does **not**
move any existing contract address (additions-only — no salt `VERSION` bump).
So the compatibility question for every downstream consumer reduces to two axes:

1. **RPC** — does the app's RPC URL / chain-id change? **No, for all apps.** The
   endpoint stays `https://rpc.citrate.ai`, chain-id stays `40204`. Every app
   reconnects to the re-rolled chain with no config change.
2. **Addresses** — does the app read any of the **6 new** contracts
   (KYCRegistry, IPFSIncentivesV2, IPFSIncentivesV3, AggregationChallenge,
   ComputePoolPipeline, CitrateCooperativeFactory)? If **no**, the app is fully
   preserved (it reads only existing, unchanged addresses). If **yes**, it needs
   a `sync-addresses` pass and — for hardcoded-address consumers — a code bump.

**Verified:** a federation-wide grep for the 6 new contract names across the
consumer repos found references in **only `citrate-node-agent`** (IPFS-incentives
pinning). Every other consumer reads exclusively existing addresses and is a
no-op for this re-roll.

## Matrix

| App | RPC env var | RPC change? | Address source | Reads new addrs? | Action | Status |
|---|---|---|---|---|---|---|
| inference-gateway | `CITRATE_GATEWAY_RPC_URL` | none | `scripts/sync-addresses.sh` → generated | no | reconnect only | ✅ preserved |
| identity / auth | (droplet `/opt/citrate-identity/.env`) | none | `CITRATE_AA_*` pins (.env) | no (AA preserved) | restart w/ same AA env (§8) | ✅ preserved |
| explorer | (Vercel env) | none | `pnpm sync-addresses` → `src/generated/addresses.json` | no | sync (picks up additions; no diff to existing) | ✅ preserved |
| dashboard | (Vercel env) | none | shared generated addresses | no | reconnect only | ✅ preserved |
| buyer-webapp | (Vercel env) | none | `pnpm sync-addresses` | no | reconnect only | ✅ preserved |
| **node-agent** | `CITRATE_RPC_URL` | none | `bash scripts/sync-addresses.sh` + **hardcoded `crates/chainio/src/addrbook.rs`** | **yes — IPFS incentives** (`pinning.rs`, `selectors.rs`, `pinning/src/lib.rs`) | **sync + code bump** addrbook for IPFSIncentivesV2/V3 | ⚠️ needs bump |
| bundler | `BUNDLER_NETWORK_RPC` | none | `BUNDLER_ENTRYPOINT` (.env) | no | restart w/ new EntryPoint (§8) | ✅ preserved |
| comms | (relay env) | none | n/a (no contract reads) | no | reconnect only ⚠️ **master key off-box backup** (§0) | ✅ preserved |
| wallet | `RPC_URL` | none | generated addresses | no | reconnect only | ✅ preserved |
| sdk-marketplace | (consumer env) | none | **hardcoded `src/contracts.ts`** | no (existing only) | none unless exposing new contracts | ✅ preserved* |
| gui-native | `RPC_URL` | none | generated addresses | no | reconnect only | ✅ preserved |
| boeing-shell | (consumer env) | none | `bash scripts/sync-addresses.sh` | no | sync (no diff to existing) | ✅ preserved |

`*` sdk-marketplace hardcodes addresses in `src/contracts.ts`, but only the
**existing** ones (which are unchanged), so it keeps working. It needs a code
bump **only** if/when it wants to expose the new federated-learning contracts.

## The one app that needs work: node-agent

`citrate-node-agent` reads the IPFS-incentives contracts for storage pinning.
After the re-roll it must:

1. `bash scripts/sync-addresses.sh` — pull the regenerated `40204.json` (now
   carrying IPFSIncentivesV2/V3 at their deterministic addresses).
2. Bump the hardcoded `crates/chainio/src/addrbook.rs` for any IPFS-incentives
   address it pins there (the existing addresses are unchanged; this is only for
   newly-exposed V2/V3 if the agent targets them).

## Live-signal checks (mirror runbook §10)

Run after §8 sync + droplet restarts:

```bash
RPC_URL=https://rpc.citrate.ai
cast chain-id --rpc-url "$RPC_URL"                                  # → 40204
cast code 0x4e59b44847b379578588920cA78FbF26c0B4956C --rpc-url "$RPC_URL"  # Arachnid runtime
curl -s https://auth.citrate.ai/aa/config | jq                     # every value matches .env.testnet
curl -s https://bundler.citrate.ai/health                          # ok
```

Every row green + these four signals pass ⇒ WP-C3 satisfied.
