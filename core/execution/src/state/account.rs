// citrate/core/execution/src/state/account.rs

// Account manager for handling account states
use crate::types::{AccountState, Address, ExecutionError, ModelId};
use citrate_consensus::types::Hash;
use dashmap::DashMap;
use primitive_types::U256;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// Account manager for handling account states
pub struct AccountManager {
    accounts: Arc<DashMap<Address, AccountState>>,
    dirty: Arc<DashMap<Address, bool>>,
    /// CV-14 (b): every address whose resident entry changed (by ANY path: a
    /// write, a non-dirtying load, a restore, a storage change) since the
    /// incremental MPT state root last folded it. Unlike `dirty` (what the store
    /// still has to persist), nothing clears it except that fold, so the
    /// incremental root never misses a change the way the dirty-only fold did
    /// before ADR-2026-07-21-state-root-purity. Invariant: for every address NOT
    /// in this set, the account trie's leaf equals the encoding of its resident
    /// entry (absent if it is absent or empty).
    root_touched: Arc<parking_lot::Mutex<HashSet<Address>>>,
}

impl AccountManager {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            dirty: Arc::new(DashMap::new()),
            root_touched: Arc::new(parking_lot::Mutex::new(HashSet::new())),
        }
    }

    /// The resident entry, or `None` if the address is not resident.
    pub fn get_resident(&self, address: &Address) -> Option<AccountState> {
        self.accounts.get(address).map(|a| a.clone())
    }

    /// Record that `address` must be re-folded into the incremental state root
    /// (its storage changed). Every account write records it already.
    pub fn mark_root_touched(&self, address: Address) {
        self.root_touched.lock().insert(address);
    }

    /// Take the addresses to re-fold (see `root_touched`), leaving none.
    pub fn take_root_touched(&self) -> HashSet<Address> {
        std::mem::take(&mut *self.root_touched.lock())
    }

    /// Mark every resident address for re-folding (the incremental trie is
    /// discarded and rebuilt from the resident state).
    pub fn mark_all_root_touched(&self) {
        let mut t = self.root_touched.lock();
        for e in self.accounts.iter() {
            t.insert(*e.key());
        }
    }

    /// Record the storage root the state root just folded for `address`, without
    /// marking it for re-folding (the fold and this value agree by construction).
    /// It is marked dirty, as any account write, so the store keeps the same value.
    pub(crate) fn set_folded_storage_root(&self, address: Address, storage_root: Hash) {
        if let Some(mut a) = self.accounts.get_mut(&address) {
            if a.storage_root != storage_root {
                a.storage_root = storage_root;
                self.dirty.insert(address, true);
            }
        }
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> AccountState {
        self.accounts
            .get(address)
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Set account state
    pub fn set_account(&self, address: Address, state: AccountState) {
        self.accounts.insert(address, state);
        self.dirty.insert(address, true);
        self.mark_root_touched(address);
    }

    /// Load account state without marking it dirty.
    ///
    /// This is used when hydrating executor memory from persisted storage or
    /// restoring snapshots. Plain reads must not create synthetic dirty state.
    pub fn load_account(&self, address: Address, state: AccountState) {
        self.accounts.insert(address, state);
        self.dirty.remove(&address);
        // Not dirty (the store has it), but the root must still see it.
        self.mark_root_touched(address);
    }

    /// Get balance
    pub fn get_balance(&self, address: &Address) -> U256 {
        self.get_account(address).balance
    }

    /// Set balance
    pub fn set_balance(&self, address: Address, balance: U256) {
        let mut account = self.get_account(&address);
        account.balance = balance;
        self.set_account(address, account);
    }

    /// Transfer value between accounts
    pub fn transfer(
        &self,
        from: &Address,
        to: &Address,
        value: U256,
    ) -> Result<(), ExecutionError> {
        if from == to {
            return Ok(());
        }

        let from_balance = self.get_balance(from);
        if from_balance < value {
            return Err(ExecutionError::InsufficientBalance {
                need: value,
                have: from_balance,
            });
        }

        // Compute the credit before writing anything, so an overflow writes nothing.
        let to_balance = self.get_balance(to);
        let new_to = to_balance
            .checked_add(value)
            .ok_or(ExecutionError::Overflow("recipient balance"))?;

        // Deduct from sender (guarded by the balance check above)
        self.set_balance(*from, from_balance.saturating_sub(value));

        // Add to receiver
        self.set_balance(*to, new_to);

        debug!("Transferred {} from {} to {}", value, from, to);
        Ok(())
    }

    /// Get nonce
    pub fn get_nonce(&self, address: &Address) -> u64 {
        self.get_account(address).nonce
    }

    /// Set nonce
    pub fn set_nonce(&self, address: Address, nonce: u64) {
        let mut account = self.get_account(&address);
        account.nonce = nonce;
        self.set_account(address, account);
    }

    /// Increment nonce
    pub fn increment_nonce(&self, address: &Address) {
        let mut account = self.get_account(address);
        account.nonce = account.nonce.saturating_add(1);
        self.set_account(*address, account);
    }

    /// Check nonce matches expected value (does NOT increment).
    /// Use this before EVM execution so revm sees the correct pre-tx nonce
    /// for CREATE address derivation.
    pub fn check_nonce(&self, address: &Address, expected: u64) -> Result<(), ExecutionError> {
        let current = self.get_nonce(address);
        if current != expected {
            return Err(ExecutionError::InvalidNonce {
                expected: current,
                got: expected,
            });
        }
        Ok(())
    }

    /// Check and increment nonce (legacy — use check_nonce + increment_nonce
    /// separately for EVM-compliant CREATE address derivation).
    pub fn check_and_increment_nonce(
        &self,
        address: &Address,
        expected: u64,
    ) -> Result<(), ExecutionError> {
        self.check_nonce(address, expected)?;
        self.increment_nonce(address);
        Ok(())
    }

    /// Get code hash
    pub fn get_code_hash(&self, address: &Address) -> Hash {
        self.get_account(address).code_hash
    }

    /// Set code hash
    pub fn set_code_hash(&self, address: Address, code_hash: Hash) {
        let mut account = self.get_account(&address);
        account.code_hash = code_hash;
        self.set_account(address, account);
    }

    /// Check if account exists
    pub fn exists(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    /// Create account if not exists
    pub fn create_account_if_not_exists(&self, address: Address) {
        if !self.exists(&address) {
            self.set_account(address, AccountState::default());
            info!("Created new account: {}", address);
        }
    }

    /// Add model permission
    pub fn add_model_permission(&self, address: Address, model_id: ModelId) {
        let mut account = self.get_account(&address);
        if !account.model_permissions.contains(&model_id) {
            account.model_permissions.push(model_id);
            self.set_account(address, account);
        }
    }

    /// Check model permission
    pub fn has_model_permission(&self, address: &Address, model_id: &ModelId) -> bool {
        self.get_account(address)
            .model_permissions
            .contains(model_id)
    }

    /// Get dirty accounts
    pub fn get_dirty_accounts(&self) -> Vec<Address> {
        self.dirty
            .iter()
            .filter(|e| *e.value())
            .map(|e| *e.key())
            .collect()
    }

    /// SRP (ADR-2026-07-21): every resident account — the authoritative committed set
    /// the state root is computed over. `calculate_state_root` folds THIS set (not the
    /// dirty diff), so the root is a pure function of committed state, independent of
    /// dirty/insertion history. The resident map is never evicted, so for a from-genesis
    /// node this is the complete account set; a restarted node must fully hydrate the
    /// resident map from the store BEFORE computing any root (WP-2.2).
    pub fn all_accounts(&self) -> Vec<(Address, AccountState)> {
        self.accounts
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }

    /// Clear dirty flags
    pub fn clear_dirty(&self) {
        self.dirty.clear();
    }

    /// Create snapshot for rollback
    pub fn snapshot(&self) -> AccountSnapshot {
        AccountSnapshot {
            accounts: self
                .accounts
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect(),
            dirty: self
                .dirty
                .iter()
                .filter(|e| *e.value())
                .map(|e| *e.key())
                .collect(),
            root_touched: self.root_touched.lock().iter().copied().collect(),
        }
    }

    /// Restore from snapshot. The root-touched set is the snapshot's: it is
    /// restored together with the account trie the snapshot holds
    /// (`StateSnapshot`), and the two were consistent when it was taken.
    pub fn restore(&self, snapshot: AccountSnapshot) {
        self.accounts.clear();
        for (addr, state) in snapshot.accounts {
            self.accounts.insert(addr, state);
        }
        self.dirty.clear();
        for addr in snapshot.dirty {
            self.dirty.insert(addr, true);
        }
        *self.root_touched.lock() = snapshot.root_touched.into_iter().collect();
    }
}

impl Default for AccountManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Account snapshot for rollback
#[derive(Clone)]
pub struct AccountSnapshot {
    accounts: Vec<(Address, AccountState)>,
    dirty: Vec<Address>,
    /// `AccountManager::root_touched` at snapshot time.
    root_touched: Vec<Address>,
}

impl AccountSnapshot {
    /// A snapshot holding exactly `accounts`, none of them dirty, with
    /// `root_touched` still to be folded into the snapshot's account trie.
    pub(crate) fn from_entries(
        accounts: Vec<(Address, AccountState)>,
        root_touched: Vec<Address>,
    ) -> Self {
        Self {
            accounts,
            dirty: Vec::new(),
            root_touched,
        }
    }

    /// The addresses still to be folded into the snapshot's account trie.
    pub(crate) fn root_touched(&self) -> &[Address] {
        &self.root_touched
    }

    /// All captured accounts (every account resident in the cache at snapshot
    /// time). Used by the reorg store-reconciliation to diff two snapshots.
    pub fn entries(&self) -> &[(Address, AccountState)] {
        &self.accounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let manager = AccountManager::new();
        let addr = Address([1; 20]);

        assert!(!manager.exists(&addr));

        manager.create_account_if_not_exists(addr);
        assert!(manager.exists(&addr));

        let account = manager.get_account(&addr);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.balance, U256::zero());
    }

    #[test]
    fn test_transfer() {
        let manager = AccountManager::new();
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        // Setup alice with balance
        manager.set_balance(alice, U256::from(1000));

        // Transfer
        manager.transfer(&alice, &bob, U256::from(300)).unwrap();

        assert_eq!(manager.get_balance(&alice), U256::from(700));
        assert_eq!(manager.get_balance(&bob), U256::from(300));
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: set_balance then get_balance returns the same value.
        #[test]
        fn prop_balance_roundtrip(
            addr_byte in any::<u8>(),
            balance_lo in any::<u64>(),
        ) {
            let manager = AccountManager::new();
            let mut addr_bytes = [0u8; 20];
            addr_bytes[0] = addr_byte;
            let addr = Address(addr_bytes);
            let balance = U256::from(balance_lo);
            manager.set_balance(addr, balance);
            prop_assert_eq!(manager.get_balance(&addr), balance,
                "get_balance must return the value set by set_balance");
        }

        /// Property: set_nonce then get_nonce returns the same value.
        #[test]
        fn prop_nonce_roundtrip(
            addr_byte in any::<u8>(),
            nonce in any::<u64>(),
        ) {
            let manager = AccountManager::new();
            let mut addr_bytes = [0u8; 20];
            addr_bytes[0] = addr_byte;
            let addr = Address(addr_bytes);
            manager.set_nonce(addr, nonce);
            prop_assert_eq!(manager.get_nonce(&addr), nonce,
                "get_nonce must return the value set by set_nonce");
        }
    }

    #[test]
    fn test_insufficient_balance() {
        let manager = AccountManager::new();
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        manager.set_balance(alice, U256::from(100));

        let result = manager.transfer(&alice, &bob, U256::from(200));
        assert!(matches!(
            result,
            Err(ExecutionError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_nonce_management() {
        let manager = AccountManager::new();
        let addr = Address([1; 20]);

        assert_eq!(manager.get_nonce(&addr), 0);

        manager.check_and_increment_nonce(&addr, 0).unwrap();
        assert_eq!(manager.get_nonce(&addr), 1);

        // Wrong nonce should fail
        let result = manager.check_and_increment_nonce(&addr, 0);
        assert!(matches!(result, Err(ExecutionError::InvalidNonce { .. })));
    }
}
