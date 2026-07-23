//! SRP-S4 defensive invariant test — the block-reward read-modify-write must be a
//! pure function of the value the state root COMMITS, not of a divergent durable store
//! surfaced by `Executor::get_balance`'s read-through.
//!
//! ⚠️ UPDATE 2026-07-23 — this is NOT the block-5,406 mechanism. DGX instrumentation
//! against the LIVE chain (env-gated `CITRATE_SRP_DEBUG`) proved the reward reads at
//! 5,406 are PURE and RESIDENT (treasury/coinbase `resident=true`, correct values) —
//! REFUTING the read-through hypothesis this test models. The real 5,406 wedge is a
//! FORK/REORG reapply impurity (canonical_apply.rs `reorg_to` + the separately-restored
//! §R' policy cell): `reorg to 968feeaf aborted at 117449ba @ 5406 — claims 2d9381d2,
//! re-execution produced 55286580`. See planset
//! `.agentile/planset/2026-07-22-srp-s4-reorg-reapply-purity.md`. This test is RETAINED
//! as a defensive property guard (the read-through invariant is still worth enforcing),
//! but the AUTHORITATIVE SRP-S4 reproduction is the reorg red test (WP-1.1) + the
//! multi-producer pin (WP-1.2).
//!
//! ## What this reproduces (the live block-5,406 cold-sync wedge)
//!
//! A from-genesis cold-sync of chain 40204 computes `state root 55286580` at block
//! 5,406 while the producer committed `2d9381d2` (proven live, DGX 2026-07-22, on the
//! fleet binary too — not app config, not cross-arch, not restart-poison). 5,405 roots
//! MATCH; 5,406 is an EMPTY block whose only write is the basic reward
//! (`settle_block_rewards` step 1: `set_balance(x, get_balance(x) + r)` for treasury
//! `+1` and `header.coinbase +9`). §R' is a no-op on empty blocks (`share.is_zero()`
//! early-return, executor.rs:1410).
//!
//! The mechanism (executor.rs:806): `get_balance` returns the RESIDENT value if the
//! account is resident, else it **reads the durable STORE and hydrates it**. SRP-S1
//! made `calculate_state_root` fold the RESIDENT map, but the STORE can still hold a
//! divergent balance for the same account (the live "block-2557 class": identical
//! `stateRoot`, divergent `eth_getBalance`). When an account is EVICTED from the
//! resident map (a `snapshot`/`restore` or a `registry_sync` `view_call` read-through
//! at an S(E) snapshot boundary — the post-activation trigger) and then read back, the
//! reward RMW folds the **divergent store value** into the next root → the first block
//! whose fold surfaces the desync (5,406) forks. The continuous producer (account
//! always resident) never read-throughs; a fresh cold-sync does.
//!
//! ## Invariant (the acceptance oracle SRP-S4 adds to S1–S3)
//!
//! `get_balance(x)` MUST equal the balance `calculate_state_root` folds for `x` — for
//! EVERY account, resident or not. No store/resident divergence may enter a
//! root-feeding read (and hence the reward RMW).
//!
//! ## Status (Phase 1 scaffold, per planset WP-1.1)
//!
//! This test is RED on `main`: it demonstrates the get_balance↔root disagreement
//! deterministically by evicting an account whose store image has diverged and reading
//! it back. WP-1.2 pins the ORIGIN of the store↔resident divergence on the live chain
//! (the `state-digest` diff of the local §R' harness) so this reproduction can be
//! tightened to the exact producing sequence; WP-2.1's fix (get_balance/persist keep
//! the store == the root-folded resident map) turns it GREEN.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use citrate_execution::executor::StateStoreTrait;
use citrate_execution::types::AccountState;
use citrate_execution::{Address, Executor, Hash, StateDB};
use primitive_types::U256;

/// Minimal in-memory store: only accounts matter for the reward RMW / read-through.
#[derive(Default)]
struct MemStore {
    accounts: Mutex<HashMap<Address, AccountState>>,
}

impl StateStoreTrait for MemStore {
    fn put_account(&self, address: &Address, account: &AccountState) -> anyhow::Result<()> {
        self.accounts
            .lock()
            .expect("mem store not poisoned")
            .insert(*address, account.clone());
        Ok(())
    }
    fn get_account(&self, address: &Address) -> anyhow::Result<Option<AccountState>> {
        Ok(self
            .accounts
            .lock()
            .expect("mem store not poisoned")
            .get(address)
            .cloned())
    }
    fn put_code(&self, _code_hash: &Hash, _code: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn put_storage(&self, _address: &Address, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn delete_storage(&self, _address: &Address, _key: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The balance `calculate_state_root` currently folds for `x` (the RESIDENT value the
/// root is a commitment to). Read straight off the state DB's resident map — this is
/// the authoritative representation the consensus root hashes.
fn folded_balance(exec: &Executor, x: &Address) -> U256 {
    exec.state_db().accounts.get_balance(x)
}

#[test]
fn srp_s4_reward_rmw_reads_committed_not_divergent_store() {
    let store = Arc::new(MemStore::default());
    let state_db = Arc::new(StateDB::new());
    let exec = Executor::with_storage(state_db.clone(), Some(store.clone()));

    let x = Address([0x11u8; 20]); // model: treasury 0x11..11 (credited +1 every block)
    let committed = U256::from(5_405u64); // the value the block-5,405 root folded for x

    // (1) Commit x = 5405 the normal way: resident + durable store agree; the root is a
    //     commitment to 5405. (Producer and a clean cold-sync both reach this at 5,405.)
    exec.set_balance(&x, committed);
    let snap_before_x = state_db.snapshot(); // NOTE: taken AFTER, see step 3 — captures {x:5405}
    let root_5405 = exec.calculate_state_root();
    assert_eq!(folded_balance(&exec, &x), committed, "precondition: root folds 5405");

    // (2) The durable store diverges from the root-folded resident value — the live
    //     "block-2557 class" (identical stateRoot, divergent eth_getBalance). WP-1.2
    //     pins the exact on-chain sequence that produces this; here we inject it so the
    //     read-through half is testable in isolation.
    let divergent = U256::from(46_492u64); // what the live producer's store actually returned
    store
        .put_account(
            &x,
            &{
                let mut a = AccountState::default();
                a.balance = divergent;
                a
            },
        )
        .expect("inject store divergence");

    // (3) Evict x from the RESIDENT map — exactly what a snapshot/restore or a
    //     registry_sync view_call read-through does at an S(E) boundary. After this, the
    //     NEXT read of x is a store read-through (executor.rs:811-813).
    //     (`snap_before_x` was captured with x already resident, so restore keeps x —
    //     re-take an x-free snapshot to model the eviction faithfully.)
    let x_free = StateDB::new();
    let restore_target = x_free.snapshot(); // an empty resident map
    let _ = &snap_before_x; // documented above; the eviction uses the x-free snapshot
    state_db.restore(restore_target);
    assert!(
        !state_db.accounts.exists(&x),
        "precondition: x evicted from the resident map (next read is a store read-through)"
    );

    // (4) The block-5,406 reward RMW: set_balance(x, get_balance(x) + 1). On `main`,
    //     get_balance read-throughs the DIVERGENT store (46492) instead of the value the
    //     5,405 root committed (5405) — and folds 46493 into the 5,406 root.
    let read = exec.get_balance(&x);
    exec.set_balance(&x, read + U256::from(1u64));
    let _root_5406 = exec.calculate_state_root();

    // INVARIANT: the reward must have read the value the 5,405 root committed (5405),
    // NOT the divergent durable store (46492). This is the exact fork: a clean replay
    // computes 5405+1 and diverges from a node that folded 46492+1.
    assert_eq!(
        read, committed,
        "SRP-S4: the block-reward RMW read a DIVERGENT durable-store balance ({}) via \
         get_balance's read-through instead of the value the state root committed ({}). \
         This is the block-5,406 cold-sync wedge: a from-genesis replay folds the pure \
         value while a read-through surfaces the store desync → StateRootMismatch. Fix: \
         no root-feeding read (and no reward RMW) may surface a store value that diverges \
         from the root-folded resident map. (executor.rs:806 get_balance; :1350 reward \
         set_balance; state_db calculate_state_root.)",
        read, committed
    );
    // The recomputed root must match what the committed 5,405 state + reward implies —
    // i.e. equal to the root of a StateDB that folds x = 5406 directly.
    let oracle = Executor::with_storage(Arc::new(StateDB::new()), None::<Arc<MemStore>>);
    oracle.set_balance(&x, committed + U256::from(1u64));
    assert_eq!(
        exec.calculate_state_root(),
        oracle.calculate_state_root(),
        "SRP-S4: post-reward root folded a divergent store value (impure reward RMW)"
    );
    let _ = root_5405;
}
