// citrate/core/api/src/historical_state.rs
//
// S3-7 (CNV-RPC): account state at a block below the executed head, for
// `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
// `eth_getStorageAt` and `eth_call` with a block tag, and for the tracers.
// Supersedes the strict refusal of chain#425 (`state_tag.rs`, the
// `fix/rpc-historical-tag-fail-closed` line) wherever the state CAN be
// rebuilt; everywhere else that refusal still answers.
//
// DATA SOURCE
//
// The per-block undo records (`StateStore::get_reorg_undo`, `CF_METADATA`
// `reorg_undo:` ‖ height). Each holds, for one block of the applied chain, the
// value every account and storage slot the block wrote had BEFORE the block.
// The node keeps them for the reorg window (`REORG_UNDO_DEPTH` = 10,000
// heights, ADR CV-7a: undo window = retention). So for a block X on the
// applied chain at height n inside that window, the value of a key K after X
// is:
//
//   the pre-image of K in the lowest record in (n, durable tip] that touched
//   K, or, if none did, its value in the flat store at the durable tip.
//
// Two readers use that rule:
//
// * point reads (balance, nonce, code, one slot) walk the records once for
//   the one key, against the flat store (`CF_ACCOUNTS`, `CF_STORAGE`,
//   `CF_CODE`). Cheap; no state root is computed.
// * full state (`eth_call`, traces) applies every pre-image of the range to
//   the executor's in-memory state at the applied tip, the way the node's
//   reorg revert does (`node/src/canonical_apply.rs` `revert_from_undo`), and
//   then REQUIRES the result to reproduce the state root committed in X's
//   header. A state that does not reproduce it is never served.
//
// Every record is checked before it is used: it must name the block the walk
// is on (a selected-parent walk of the stored headers down from the durable
// tip) and that block's parent one height below. A missing, mismatched or
// undecodable record ends the walk with a refusal, never with a guess.
//
// FAIL CLOSED: below the window, off the applied chain, a record missing, or a
// root that does not match: the read is refused with `HISTORICAL_STATE_CODE`
// and a message saying why.

use crate::state_tag::{
    parse_state_tag, require_executed_head_state, StateTag, StateTagPolicy, HISTORICAL_STATE_CODE,
    HISTORICAL_STATE_MESSAGE,
};
use citrate_consensus::types::Hash;
use citrate_execution::executor::{BlockUndo, StateStoreTrait};
use citrate_execution::state::state_db::{AccountPreImage, StoragePreImage};
use citrate_execution::state::StateSnapshot;
use citrate_execution::types::{AccountState, Address};
use citrate_execution::Executor;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Method-budget units charged for a historical point read (balance, nonce,
/// code, storage slot): one walk of up to `REORG_UNDO_DEPTH` small records.
pub const HISTORICAL_POINT_READ_COST: u32 = 20;

/// Method-budget units charged for a historical full-state read (`eth_call`,
/// `eth_estimateGas` at a past block): a merge of the records plus one full
/// state-root computation.
pub const HISTORICAL_FULL_STATE_COST: u32 = 100;

/// Rebuilt full states kept, keyed by block hash (the state after a block is
/// fixed, so an entry never goes stale; it only ages out).
pub const HISTORICAL_STATE_CACHE: usize = 2;

/// Where a state read is served from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRead {
    /// The executed head's state (the node's current state).
    Head,
    /// The state after `hash` at `height`, a block of the applied chain below
    /// the executed head.
    At { hash: Hash, height: u64 },
}

fn refuse(detail: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::ServerError(HISTORICAL_STATE_CODE),
        message: format!("{HISTORICAL_STATE_MESSAGE}: {detail}"),
        data: None,
    }
}

fn internal(detail: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: detail,
        data: None,
    }
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

/// Resolve the block tag of a state read.
///
/// * `Head`: absent, `latest`, `pending`, `finalized`/`safe` (the finality
///   guard has already run), or a tag naming the executed head.
/// * `At`: a number or hash naming a block of the applied chain below the
///   executed head. Whether its state can be rebuilt is decided by the
///   reader, which refuses when it cannot.
/// * Anything else falls through to the chain#425 rule
///   ([`require_executed_head_state`]), with its operator window and its
///   refusals unchanged.
pub fn resolve_state_read(
    tag: Option<&Value>,
    storage: &StorageManager,
    policy: StateTagPolicy,
) -> Result<StateRead, jsonrpc_core::Error> {
    let pinned = parse_state_tag(tag)?;
    let head = crate::canonical_logs::log_tip(storage)
        .map_err(|e| internal(format!("executed head unavailable: {e}")))?;
    if let Some((head_hash, head_height)) = head {
        let below = match pinned {
            StateTag::Number(n) if n < head_height => storage
                .blocks
                .get_canonical_block_by_height(n)
                .ok()
                .flatten()
                .map(|h| (h, n)),
            StateTag::Hash(h) if h != head_hash => {
                match storage.blocks.get_header(&h).ok().flatten() {
                    Some(hd)
                        if hd.height < head_height
                            && storage
                                .blocks
                                .get_canonical_block_by_height(hd.height)
                                .ok()
                                .flatten()
                                == Some(h) =>
                    {
                        Some((h, hd.height))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some((hash, height)) = below {
            return Ok(StateRead::At { hash, height });
        }
    }
    require_executed_head_state(tag, storage, policy)?;
    Ok(StateRead::Head)
}

/// A historical read of `tag` failed with `err`. Apply the chain#425 rule to
/// the same tag: if it serves the tag (the operator's recent-tag window,
/// `[rpc] serve_recent_state_tags`), `Ok(())` and the caller reads the
/// executed head's state as before; otherwise the chain#425 refusal (its code,
/// message prefix and `executedHead` data) with the historical reason added.
pub fn fall_back_to_head_rule(
    err: jsonrpc_core::Error,
    tag: Option<&Value>,
    storage: &StorageManager,
    policy: StateTagPolicy,
) -> Result<(), jsonrpc_core::Error> {
    match require_executed_head_state(tag, storage, policy) {
        Ok(()) => Ok(()),
        Err(mut refusal) => {
            let reason = err
                .message
                .strip_prefix(HISTORICAL_STATE_MESSAGE)
                .map(|r| r.trim_start_matches(':').trim_start())
                .unwrap_or(err.message.as_str())
                .to_string();
            refusal.message = format!("{}; rebuilding it: {reason}", refusal.message);
            Err(refusal)
        }
    }
}

/// One checked step of the walk from the durable tip down to the target.
struct Walk<'a> {
    storage: &'a StorageManager,
    cursor: Hash,
    height: u64,
}

impl<'a> Walk<'a> {
    /// Start at the durable applied tip.
    fn from_tip(storage: &'a StorageManager) -> Result<Self, jsonrpc_core::Error> {
        let (cursor, height) = storage
            .blocks
            .get_applied_tip()
            .map_err(|e| internal(format!("applied tip: {e}")))?
            .ok_or_else(|| refuse("no block has executed on this node yet".into()))?;
        Ok(Self {
            storage,
            cursor,
            height,
        })
    }

    /// The checked undo record of the block the walk is on; then step to its
    /// selected parent.
    fn step(&mut self) -> Result<BlockUndo, jsonrpc_core::Error> {
        let height = self.height;
        let below = height
            .checked_sub(1)
            .ok_or_else(|| refuse("the walk passed genesis".into()))?;
        let record = self
            .storage
            .state
            .get_reorg_undo(height)
            .map_err(|e| {
                refuse(format!(
                    "the undo record at height {height} is unreadable ({e})"
                ))
            })?
            .ok_or_else(|| {
                refuse(format!(
                    "no undo record at height {height}: the block is below this node's undo \
                     window (spec 06 §4.2) or its record was not kept"
                ))
            })?;
        if record.hash != self.cursor || record.height != height {
            return Err(refuse(format!(
                "the undo record at height {height} names {} @ {}, not the applied block {}",
                hx(&record.hash),
                record.height,
                hx(&self.cursor)
            )));
        }
        let header = self
            .storage
            .blocks
            .get_header(&self.cursor)
            .map_err(|e| internal(format!("header {}: {e}", hx(&self.cursor))))?
            .ok_or_else(|| refuse(format!("header {} is not stored", hx(&self.cursor))))?;
        if header.height != height {
            return Err(refuse(format!(
                "header {} is at height {}, not {height}",
                hx(&self.cursor),
                header.height
            )));
        }
        if record.parent != Some((header.selected_parent_hash, below)) {
            return Err(refuse(format!(
                "the undo record at height {height} names another parent, or none"
            )));
        }
        self.cursor = header.selected_parent_hash;
        self.height = below;
        Ok(record)
    }
}

/// The value of one key after the target block, from the walk rule above.
enum Lookup<'k> {
    Account(&'k Address),
    Slot(&'k Address, &'k [u8]),
}

enum Found {
    Account(Option<AccountState>),
    Slot(Option<Vec<u8>>),
}

fn point_read(
    storage: &StorageManager,
    target: (Hash, u64),
    key: Lookup<'_>,
) -> Result<Found, jsonrpc_core::Error> {
    let mut walk = Walk::from_tip(storage)?;
    let tip = (walk.cursor, walk.height);
    if target.1 > walk.height {
        return Err(refuse(format!(
            "block {} at height {} is above the executed head {}",
            hx(&target.0),
            target.1,
            walk.height
        )));
    }
    // Lowest record wins: walking down, a later (lower) hit replaces an
    // earlier one.
    let mut hit: Option<Found> = None;
    while walk.height > target.1 {
        let record = walk.step()?;
        match key {
            Lookup::Account(a) => {
                if let Some((_, pre)) = record.accounts.iter().find(|(addr, _)| addr == a) {
                    hit = Some(Found::Account(pre.clone()));
                }
            }
            Lookup::Slot(a, k) => {
                if let Some((_, _, pre)) = record
                    .storage
                    .iter()
                    .find(|(addr, slot, _)| addr == a && slot.as_slice() == k)
                {
                    hit = Some(Found::Slot(pre.clone()));
                }
            }
        }
    }
    if walk.cursor != target.0 {
        return Err(refuse(format!(
            "the applied chain reaches {} at height {}, not the requested block {}",
            hx(&walk.cursor),
            target.1,
            hx(&target.0)
        )));
    }
    let found = match hit {
        Some(f) => f,
        None => match key {
            Lookup::Account(a) => Found::Account(
                storage
                    .state
                    .get_account(a)
                    .map_err(|e| internal(format!("account read: {e}")))?,
            ),
            Lookup::Slot(a, k) => Found::Slot(
                storage
                    .state
                    .get_storage(a, k)
                    .map_err(|e| internal(format!("storage read: {e}")))?,
            ),
        },
    };
    // The flat store moved while we read it (a block committed): the answer
    // may mix two states. Refuse; the caller retries.
    let now = storage
        .blocks
        .get_applied_tip()
        .map_err(|e| internal(format!("applied tip: {e}")))?;
    if now != Some(tip) {
        return Err(refuse(
            "the executed head moved during the read; retry the request".into(),
        ));
    }
    Ok(found)
}

/// The account after `target` (`None`: it did not exist).
pub fn account_at(
    storage: &StorageManager,
    target: (Hash, u64),
    address: &Address,
) -> Result<Option<AccountState>, jsonrpc_core::Error> {
    match point_read(storage, target, Lookup::Account(address))? {
        Found::Account(a) => Ok(a),
        Found::Slot(_) => Err(internal("account lookup returned a slot".into())),
    }
}

/// The raw stored value of a storage slot after `target` (`None`: unset).
pub fn storage_at(
    storage: &StorageManager,
    target: (Hash, u64),
    address: &Address,
    slot: &[u8],
) -> Result<Option<Vec<u8>>, jsonrpc_core::Error> {
    match point_read(storage, target, Lookup::Slot(address, slot))? {
        Found::Slot(v) => Ok(v),
        Found::Account(_) => Err(internal("slot lookup returned an account".into())),
    }
}

/// The contract code after `target` (empty for an account without code).
/// Code is content-addressed (`CF_CODE[code_hash]`), so the account's
/// historical code hash names it.
pub fn code_at(
    storage: &StorageManager,
    target: (Hash, u64),
    address: &Address,
) -> Result<Vec<u8>, jsonrpc_core::Error> {
    let Some(account) = account_at(storage, target, address)? else {
        return Ok(Vec::new());
    };
    if account.code_hash == Hash::default() {
        return Ok(Vec::new());
    }
    storage
        .state
        .get_code(&account.code_hash)
        .map_err(|e| internal(format!("code read: {e}")))?
        .ok_or_else(|| {
            refuse(format!(
                "code {} of the historical account is not stored",
                hx(&account.code_hash)
            ))
        })
}

/// A state store for a throwaway replay executor. It never writes to the
/// node: every write is discarded (the replay's state is dropped with the
/// executor). Reads:
///
/// - [`ReplayStore::code_only`] (a rebuilt historical state): code from the
///   node's content-addressed code store (`CF_CODE`); accounts and slots
///   answer "absent", because the replayed state is complete (it reproduced a
///   committed state root), so a key it lacks did not exist then.
/// - [`ReplayStore::head`] (the executed head's state): code, accounts and
///   slots from the node's flat store (`CF_CODE`, `CF_ACCOUNTS`,
///   `CF_STORAGE`), the same cold-cache fallback `eth_call` uses (PIL-13b).
pub struct ReplayStore {
    storage: Arc<StorageManager>,
    head_reads: bool,
}

impl ReplayStore {
    /// For a rebuilt historical state (see the type doc).
    pub fn code_only(storage: Arc<StorageManager>) -> Self {
        Self {
            storage,
            head_reads: false,
        }
    }

    /// For the executed head's state (see the type doc).
    pub fn head(storage: Arc<StorageManager>) -> Self {
        Self {
            storage,
            head_reads: true,
        }
    }
}

impl StateStoreTrait for ReplayStore {
    fn put_account(&self, _address: &Address, _account: &AccountState) -> anyhow::Result<()> {
        Ok(())
    }
    fn get_account(&self, address: &Address) -> anyhow::Result<Option<AccountState>> {
        if self.head_reads {
            return self.storage.state.get_account(address);
        }
        Ok(None)
    }
    fn put_code(&self, _code_hash: &Hash, _code: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn get_code(&self, code_hash: &Hash) -> anyhow::Result<Option<Vec<u8>>> {
        self.storage.state.get_code(code_hash)
    }
    fn put_storage(&self, _address: &Address, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn get_storage(&self, address: &Address, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        if self.head_reads {
            return self.storage.state.get_storage(address, key);
        }
        Ok(None)
    }
    fn delete_storage(&self, _address: &Address, _key: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn write_reorg_batch_sync(
        &self,
        _accounts: &[(Address, AccountState)],
        _storage: &[citrate_execution::executor::StateStorageChange],
        _account_dels: &[Address],
        _code: &[(Hash, Vec<u8>)],
        _applied_tip: Option<(Hash, u64)>,
        _index: &citrate_execution::executor::ReceiptIndexBatch,
        _undo: &[BlockUndo],
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The state root of `snap` as the node computes it at `height` (the same
/// fold as `canonical_apply::rooted`).
fn rooted(snap: StateSnapshot, height: u64) -> (Hash, StateSnapshot) {
    let scratch = citrate_execution::StateDB::new();
    scratch.restore(snap);
    scratch.set_root_height(height);
    let root = scratch.calculate_state_root();
    scratch.accounts.clear_dirty();
    let _ = scratch.take_dirty_storage();
    (root, scratch.snapshot())
}

/// A storage pre-image as a node restarted at the reverted height would have
/// hydrated it (below the storage-root hardening height only 32-byte slots),
/// as `canonical_apply::hydrated_pre_images` does.
fn hydrated_pre_images(storage: &[StoragePreImage], full: bool) -> Vec<StoragePreImage> {
    use citrate_storage::state::{legacy_hydration_view, StorageBytes};
    if full {
        return storage.to_vec();
    }
    storage
        .iter()
        .filter_map(|(addr, key, value)| match value {
            Some(v) => legacy_hydration_view(vec![(
                (*addr, StorageBytes(key.clone())),
                StorageBytes(v.clone()),
            )])
            .pop()
            .map(|((a, k), v)| (a, k.into_vec(), Some(v.into_vec()))),
            None => (key.len() == 32).then(|| (*addr, key.clone(), None)),
        })
        .collect()
}

/// Rebuilds, verifies and caches full historical states.
#[derive(Default)]
pub struct HistoricalStates {
    cache: Mutex<VecDeque<(Hash, StateSnapshot)>>,
}

impl HistoricalStates {
    pub fn new() -> Self {
        Self::default()
    }

    fn cached(&self, hash: &Hash) -> Option<StateSnapshot> {
        let g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        g.iter().find(|(h, _)| h == hash).map(|(_, s)| s.clone())
    }

    fn remember(&self, hash: Hash, snap: StateSnapshot) {
        let mut g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|(h, _)| *h != hash);
        g.push_back((hash, snap));
        while g.len() > HISTORICAL_STATE_CACHE {
            if g.pop_front().is_none() {
                break;
            }
        }
    }

    /// The full state after the applied block `target`, verified against the
    /// state root in its header. `target` may be the executed head itself
    /// (then the executor's state is checked against the head's root).
    pub fn state_at(
        &self,
        storage: &StorageManager,
        executor: &Executor,
        target: (Hash, u64),
    ) -> Result<StateSnapshot, jsonrpc_core::Error> {
        use citrate_execution::storage_root_hardening::{active_at, storage_root_hardening_height};
        if let Some(s) = self.cached(&target.0) {
            return Ok(s);
        }
        let target_block = storage
            .blocks
            .get_block(&target.0)
            .map_err(|e| internal(format!("block {}: {e}", hx(&target.0))))?
            .ok_or_else(|| refuse(format!("block {} is not stored", hx(&target.0))))?;
        if target_block.header.height != target.1 {
            return Err(refuse(format!(
                "block {} is at height {}, not {}",
                hx(&target.0),
                target_block.header.height,
                target.1
            )));
        }
        let mut walk = Walk::from_tip(storage)?;
        let tip = (walk.cursor, walk.height);
        if target.1 > tip.1 {
            return Err(refuse(format!(
                "block {} at height {} is above the executed head {}",
                hx(&target.0),
                target.1,
                tip.1
            )));
        }
        // The executor's state is taken first: if a block applies after this,
        // the tip check below or the root check refuses.
        let at_tip = executor.state_snapshot();
        let activation = storage_root_hardening_height();
        let full = active_at(activation, tip.1.saturating_add(1));
        let mut accounts: HashMap<Address, AccountPreImage> = HashMap::new();
        let mut slots: HashMap<(Address, Vec<u8>), StoragePreImage> = HashMap::new();
        let mut models = HashMap::new();
        let mut jobs = HashMap::new();
        while walk.height > target.1 {
            let height = walk.height;
            let record = walk.step()?;
            if active_at(activation, height) != full {
                return Err(refuse(format!(
                    "the storage-root hydration rule changes at height {height}"
                )));
            }
            let models_jobs = record.models_jobs.as_ref().ok_or_else(|| {
                refuse(format!(
                    "the undo record at height {height} has no model/job pre-images"
                ))
            })?;
            for pre in &record.accounts {
                accounts.insert(pre.0, pre.clone());
            }
            for pre in hydrated_pre_images(&record.storage, full) {
                slots.insert((pre.0, pre.1.clone()), pre);
            }
            for (id, m) in &models_jobs.models {
                models.insert(*id, m.clone());
            }
            for (id, j) in &models_jobs.jobs {
                jobs.insert(*id, j.clone());
            }
        }
        if walk.cursor != target.0 {
            return Err(refuse(format!(
                "the applied chain reaches {} at height {}, not the requested block {}",
                hx(&walk.cursor),
                target.1,
                hx(&target.0)
            )));
        }
        let accounts: Vec<AccountPreImage> = accounts.into_values().collect();
        let slots: Vec<StoragePreImage> = slots.into_values().collect();
        let models_jobs = citrate_execution::executor::ModelJobUndo {
            models: models.into_iter().collect(),
            jobs: jobs.into_iter().collect(),
        };
        let reverted = at_tip
            .with_pre_images(&accounts, &slots, target.1)
            .with_model_job_pre_images(&models_jobs);
        let (root, snap) = rooted(reverted, target.1);
        if root != target_block.state_root {
            let moved = storage.blocks.get_applied_tip().ok().flatten() != Some(tip);
            return Err(refuse(if moved {
                "the executed head moved during the read; retry the request".to_string()
            } else {
                format!(
                    "the state rebuilt for block {} does not reproduce its state root \
                     (rebuilt {}, header {})",
                    hx(&target.0),
                    hx(&root),
                    hx(&target_block.state_root)
                )
            }));
        }
        self.remember(target.0, snap.clone());
        Ok(snap)
    }

    /// A throwaway executor over the verified state after `target` (see
    /// `Executor::replay_executor`). Nothing it does reaches the node.
    pub fn executor_at(
        &self,
        storage: &Arc<StorageManager>,
        executor: &Executor,
        target: (Hash, u64),
    ) -> Result<Executor, jsonrpc_core::Error> {
        let snap = self.state_at(storage, executor, target)?;
        Ok(executor.replay_executor(
            snap,
            Some(Arc::new(ReplayStore::code_only(storage.clone()))),
        ))
    }
}

/// Where an account got the code it has at the executed head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// The block of the applied chain whose execution gave it that code.
    Block { hash: Hash, height: u64 },
    /// It already had code after genesis (a genesis allocation).
    Genesis,
}

/// The applied block at which `address` got the code it holds at the durable
/// tip: the highest block whose undo record shows the account without code
/// before it (the latest creation, if it was destroyed and created again).
///
/// Data source: the undo records, walked down from the durable tip and checked
/// as for every historical read. Refused when the walk reaches the bottom of
/// the undo window first (the creation is older than this node keeps).
pub fn creation_of(
    storage: &StorageManager,
    address: &Address,
) -> Result<Creation, jsonrpc_core::Error> {
    let mut walk = Walk::from_tip(storage)?;
    while walk.height > 0 {
        let (hash, height) = (walk.cursor, walk.height);
        let record = walk.step()?;
        if let Some((_, pre)) = record.accounts.iter().find(|(a, _)| a == address) {
            let had_code = pre
                .as_ref()
                .is_some_and(|acct| acct.code_hash != Hash::default());
            if !had_code {
                return Ok(Creation::Block { hash, height });
            }
        }
    }
    Ok(Creation::Genesis)
}

/// JSON `{ "number", "hash" }` of a resolved historical block, for error data.
pub fn block_json(hash: &Hash, height: u64) -> Value {
    json!({ "number": format!("0x{height:x}"), "hash": hx(hash) })
}
