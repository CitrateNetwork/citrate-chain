---
created: 2026-11-07
branch: r1007/s3-state-root
author: Claude Opus 5.5 (lane CHAIN-STATEROOT) for Larry Klosowski
status: draft for second-reviewer review (Matr0xshka, kurtatwork); proposed text for planset 06 section "state root"
adr: ADR-2026-11-03-chain-convergence-r1007 CV-14 (a)+(b), accepted 2026-11-07
---

# The r1007 state root: standard MPT, computed incrementally

This is the exact rule for the `state_root` of a block's post-state from the
`mpt_state_root` activation height (an r1007 genesis rule), and the argument that the
incremental computation is still a pure function of the state. Code:
`core/execution/src/state/mpt.rs` (trie), `mpt_state.rs` (leaf encodings),
`state_db.rs` (`mpt_state_root`, `reference_state_root`), `mpt_state_root.rs`
(activation).

## 1. Activation

- `citrate_execution::mpt_state_root`, resolved like every genesis-keyed rule
  (`citrate_consensus::hardening::GenesisActivations::mpt_state_root`).
- r1005 and r1006: never (it changes every root). r1006's entry is `None` on purpose.
- r1007: its genesis entry must set `mpt_state_root: Some(0)` (the genesis lane adds the
  entry when block 0 exists). Devnets and rehearsals: `[chain] mpt_state_root_height = 0`
  or `CITRATE_MPT_STATE_ROOT_HEIGHT=0`.
- It applies to the post-state of every block at height h with h >= activation and
  h > 0. Genesis (height 0) keeps the legacy root, as for every rule.
- Below the activation the legacy root is unchanged byte for byte.

## 2. Trie (Yellow Paper appendix D)

- A key is a byte string. Its path is its nibbles, high nibble first.
- Nodes:
  - `Leaf = RLP[HP(path, true), value]`
  - `Extension = RLP[HP(path, false), ref(child)]`
  - `Branch = RLP[ref(c_0), ..., ref(c_15), value or ""]`
- HP (hex-prefix): the first nibble is `2*leaf + odd`. An odd path puts its first nibble
  into the low half of the first byte; an even path pads with a zero nibble.
- `ref(n)` is `keccak256(RLP(n))` as a 32-byte string when `len(RLP(n)) >= 32`. Otherwise
  it is `RLP(n)` itself, embedded. An absent branch child is the empty string `0x80`.
- Root = `keccak256(RLP(root node))` at any length. The empty trie's root is
  `keccak256(0x80) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`.
- An empty value means absent: inserting it removes the key.
- Canonical shape: every key/value set has exactly one trie. No branch has fewer than two
  entries (children plus value). No extension has an empty path. No extension's child is
  a leaf or an extension. Removal re-normalizes (`mpt.rs` `normalize`, `join`).

## 3. Leaves (`mpt_state.rs`)

### Account trie (secure)

- Key: `keccak256(address)` (20 bytes in).
- Value:
  - `RLP[nonce, balance, storage_root, code_hash]` when the account has no model
    permissions. This is exactly Ethereum's account, so a standard `eth_getProof`
    verifier checks it.
  - `RLP[nonce, balance, storage_root, code_hash, RLP[m_1, ..., m_k]]` when it has
    `k >= 1` model permissions. Each `m_i` is a 32-byte string, in the account's list order.
- `nonce` and `balance` are RLP integers: big-endian, no leading zero bytes, zero is the
  empty string.
- `storage_root` is the account's storage trie root, `EMPTY_ROOT` when it holds no slot.
- `code_hash` is the account's code hash, or `KECCAK_EMPTY = keccak256("") =
  0xc5d2...a470` when the account has no code. The executor spells "no code" as all zeros,
  and both spellings commit as `KECCAK_EMPTY`.
- An account is absent from the trie when it is empty: nonce 0, balance 0, no code
  (zero or `KECCAK_EMPTY`), `storage_root = EMPTY_ROOT`, no model permissions (EIP-161).
  This keeps the SRP-S3 rule (an empty resident account never moves the root).

### Storage trie (secure, one per account)

- Key: `keccak256(slot key)`, for a slot key of any length.
- Value:
  - a 32-byte slot value `v` (every EVM slot): `RLP(v as an integer)`. A zero value is
    absent, exactly as in Ethereum. A slot that holds 32 zero bytes in the resident map is
    therefore not in the trie.
  - a value of any other length (non-EVM precompile slots, for example the governance
    `PARAM:*` keys): `RLP[v]`, a one-item list. It never collides with an EVM value,
    which is an RLP string.

### Which accounts are committed

- Every resident account, and every address that holds storage but has no resident
  account entry. The governance precompile, for example, writes its `PARAM:` and
  `PENDING:` slots through `set_storage` without creating an account. Such an address
  commits as the default account (nonce 0, balance 0, no code, no model permissions)
  with its storage root, so it is present exactly when it holds a slot that is in the
  storage trie. (`StateDB::committed_account`.)

### What the root commits to

- It commits to the full resident account set and their slots, including the slots of
  storage-only addresses (above). Models and training jobs
  are not committed, as before (purity ADR §5).
- It does not commit to the order of writes, to which node computed it, or to any cache.

## 4. Incremental computation, and why it is still pure

The purity ADR (ADR-2026-07-21-state-root-purity) requires the root to be a pure function
of the committed resident state. It rejected a fold over dirty accounts because dirty
tracking was skipped on purpose by some paths: non-dirtying loads, read-throughs, the
zero-reward guard. The incremental root does not use the dirty set:

1. `AccountManager::root_touched` records every address whose resident entry changes.
   That covers `set_account` (every account setter goes through it), `load_account`
   (hydration, read-through), `restore`, and every storage mutation through `StateDB`
   (`set_storage`, `cache_storage`, `delete_storage`).
   - The account and storage maps are private to `AccountManager` and `StateDB`, so
     there is no other write path.
   - Only the fold clears the set. Persisting and `commit` do not.
2. Each storage trie keeps the slot keys changed since its MPT was last caught up
   (`Trie::mpt`, `pending`).
3. Invariant I-MPT: for every address not in `root_touched`, the account trie's leaf is
   the encoding of its resident entry (absent if it is absent or empty). For every slot
   key not pending, the storage trie's leaf is the encoding of its resident value.
4. The fold re-encodes exactly the touched accounts, after catching up their storage
   tries, then clears the set. Afterwards I-MPT holds with nothing touched.
5. The MPT has one shape per key/value set (§2). Each node caches its own reference,
   and a node is immutable once built, so its cache is a pure function of its contents.
   So the root equals the from-scratch root of the same key/value set.
6. A snapshot holds the account MPT (shared nodes, O(1)) and the root-touched set.
   `restore` puts both back, so I-MPT holds for the restored state. `with_pre_images`
   (the deep undo of S3-4) adds every address its pre-images change.

Checks:
- **From-scratch reference:** `StateDB::reference_state_root` re-encodes every resident
  account and slot and builds the trie in one recursive pass (`mpt::root_from_sorted`:
  no cache, no insert or remove). Debug builds compare every incremental root with it,
  on every fold.
- **Replay:** `tools/replay-ref` compares the two on every replayed chain block, and
  judges the node's committed roots against the from-scratch root.
- **Tests:**
  - `incremental_root_equals_from_scratch`: property test with 400 cases of random
    histories: sets, deletes, re-creates, non-dirtying loads, snapshots, restores, undo
    pre-images.
  - `root_is_pure_function_of_state`.
  - Ethereum vectors and two independent implementations (`mpt_conformance.rs`).

Cost per block: O((touched accounts + changed slots) x depth) node encodings and keccaks,
independent of the state size (bench: `core/execution/tests/state_root_cost.rs`).

## 5. Trie-node store (node-local, not consensus)

- Nodes live in RocksDB `CF_STATE`: `mpt_node:` + hash -> RLP. Per-height root records
  are `mpt_root:` + height. They are written after each applied block's state (the
  executor's persist and reorg-reconcile paths).
- Restart (`boot_state.rs`): the node reuses the trie at the applied tip's record. Every
  node is checked as it loads: its hash, its canonical encoding and the canonical shape.
  Every leaf is checked against the hydrated state:
  - each account leaf must equal the encoding of its resident account;
  - each storage trie must hold exactly the resident slots;
  - every resident account without a leaf must be empty.

  On any difference nothing is installed and the root is built from the state. The
  committed-root boot check that follows is unchanged. So the store saves work and can
  never change a root.
- Pruning is a mark-and-sweep every 1,000 heights over the roots recorded in the undo
  window (`REORG_UNDO_DEPTH` = 10,000 = retention, CV-7a). It keeps every node reachable
  from a window root (account tries and the storage tries their leaves name) and deletes
  the rest, plus the records below the window.

## 6. Proofs (`eth_getProof`)

- `StateDB::get_proof(address, keys)` is the data source for a future `eth_getProof`
  handler (CNV-RPC). Its data source is the node's incremental account and storage MPTs.
- `accountProof` and `storageProof[i].proof` follow geth's convention: the RLP of every
  node on the key's path that is referenced by hash, plus the root node, root first.
  Embedded nodes are inside their parents.
- `storageHash` is the account's storage root. The account leaf is §3's encoding.
- `mpt::verify_proof(root, key, proof)` verifies inclusion and exclusion.
- Under the legacy rule there are no proofs (the accessor refuses).

## 7. Open points for the reviewers

1. The 5-item account (model permissions) is a Citrate extension. A standard verifier
   checks the trie path, but it will not decode such an account. The alternative is a
   separate model-permission commitment.
2. Non-EVM slot values as `RLP[v]`: same remark, for precompile slots only.
3. Trie-node retention equals the undo window. That costs storage (see the bench's
   `node_bytes_per_block`). Restart needs only the tip's trie, so a shorter node window
   would be node-local and reversible.
