// citrate/core/api/src/filter.rs

use citrate_consensus::types::Hash;
use citrate_execution::types::Address;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Filter types supported by eth_newFilter and related methods
#[derive(Clone, Debug)]
pub enum FilterType {
    /// Log filter with address and topic criteria
    Log {
        from_block: Option<u64>,
        to_block: Option<u64>,
        addresses: Vec<Address>,
        topics: Vec<Option<Vec<Hash>>>,
    },
    /// Block filter - returns new block hashes
    Block,
    /// Pending transaction filter - returns new pending tx hashes
    PendingTransaction,
}

/// A registered filter with metadata
#[derive(Clone, Debug)]
pub struct Filter {
    pub filter_type: FilterType,
    pub last_poll_block: u64,
    pub created_at: Instant,
    pub last_polled_at: Instant,
}

/// CHAIN-B-D003: hard ceiling on the number of live filters. `eth_newFilter`
/// et al. are unauthenticated and each accepted filter is retained for the
/// process lifetime; without a cap an attacker loops filter creation until the
/// node OOMs. 10k is far above any honest indexer's working set.
pub const MAX_FILTERS: usize = 10_000;

/// Filter registry for managing eth_newFilter/eth_getFilterChanges state
pub struct FilterRegistry {
    filters: RwLock<HashMap<u64, Filter>>,
    /// Filters older than this are eligible for cleanup
    max_filter_age: Duration,
    /// CHAIN-B-D003: maximum number of concurrently-registered filters.
    max_filters: usize,
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterRegistry {
    /// Create a new filter registry
    pub fn new() -> Self {
        Self {
            filters: RwLock::new(HashMap::new()),
            max_filter_age: Duration::from_secs(5 * 60), // 5 minute timeout
            max_filters: MAX_FILTERS,
        }
    }

    /// CHAIN-B-D011: mint a filter ID from a CSPRNG rather than a sequential
    /// counter. Filters have no owner and the handlers reach no caller identity
    /// (a jsonrpc-core limitation, same root cause as CHAIN-B-D009), so
    /// sequential IDs let any client enumerate `0x1..0x1000` and uninstall or
    /// drain every other client's filter. Unguessable 64-bit IDs make that
    /// enumeration infeasible. Called while holding the `filters` write lock so
    /// the collision check is race-free.
    fn mint_id(filters: &HashMap<u64, Filter>) -> u64 {
        loop {
            let id = rand::random::<u64>();
            if id != 0 && !filters.contains_key(&id) {
                return id;
            }
        }
    }

    /// CHAIN-B-D003: opportunistically evict stale filters, then report whether
    /// there is room for one more. Called from every `new_*_filter` path so the
    /// cap holds even if the periodic sweeper is not running.
    fn has_capacity(&self, filters: &mut HashMap<u64, Filter>) -> bool {
        if filters.len() >= self.max_filters {
            let now = Instant::now();
            filters.retain(|_, f| now.duration_since(f.last_polled_at) < self.max_filter_age);
        }
        filters.len() < self.max_filters
    }

    /// Create a new log filter and return its ID
    pub fn new_log_filter(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
        addresses: Vec<Address>,
        topics: Vec<Option<Vec<Hash>>>,
        current_block: u64,
    ) -> Option<u64> {
        let now = Instant::now();
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        // CHAIN-B-D003: refuse creation past the cap.
        if !self.has_capacity(&mut filters) {
            return None;
        }
        let id = Self::mint_id(&filters);

        let filter = Filter {
            filter_type: FilterType::Log {
                from_block,
                to_block,
                addresses,
                topics,
            },
            last_poll_block: current_block,
            created_at: now,
            last_polled_at: now,
        };

        filters.insert(id, filter);
        Some(id)
    }

    /// Create a new block filter and return its ID
    pub fn new_block_filter(&self, current_block: u64) -> Option<u64> {
        let now = Instant::now();
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        if !self.has_capacity(&mut filters) {
            return None;
        }
        let id = Self::mint_id(&filters);

        let filter = Filter {
            filter_type: FilterType::Block,
            last_poll_block: current_block,
            created_at: now,
            last_polled_at: now,
        };

        filters.insert(id, filter);
        Some(id)
    }

    /// Create a new pending transaction filter and return its ID
    pub fn new_pending_transaction_filter(&self) -> Option<u64> {
        let now = Instant::now();
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        if !self.has_capacity(&mut filters) {
            return None;
        }
        let id = Self::mint_id(&filters);

        let filter = Filter {
            filter_type: FilterType::PendingTransaction,
            last_poll_block: 0,
            created_at: now,
            last_polled_at: now,
        };

        filters.insert(id, filter);
        Some(id)
    }

    /// Get a filter by ID and update its last polled time
    pub fn get_filter(&self, id: u64) -> Option<Filter> {
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        if let Some(filter) = filters.get_mut(&id) {
            filter.last_polled_at = Instant::now();
            Some(filter.clone())
        } else {
            None
        }
    }

    /// Update the last poll block for a filter
    pub fn update_last_poll_block(&self, id: u64, block: u64) {
        if let Some(filter) = self
            .filters
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&id)
        {
            filter.last_poll_block = block;
            filter.last_polled_at = Instant::now();
        }
    }

    /// Uninstall (remove) a filter
    pub fn uninstall_filter(&self, id: u64) -> bool {
        self.filters
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
            .is_some()
    }

    /// Clean up stale filters that haven't been polled recently
    pub fn cleanup_stale_filters(&self) {
        let now = Instant::now();
        let mut filters = self.filters.write().unwrap_or_else(|e| e.into_inner());
        filters.retain(|_, filter| now.duration_since(filter.last_polled_at) < self.max_filter_age);
    }

    /// Get the number of active filters
    pub fn filter_count(&self) -> usize {
        self.filters.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// CHAIN-B-D003: spawn a periodic sweeper that drives
    /// `cleanup_stale_filters()`. Before this, the sweeper had ZERO call sites,
    /// so `max_filter_age` was inert and filters accumulated for the process
    /// lifetime. `cleanup_stale_filters` is fully synchronous (std `RwLock`), so
    /// this runs on a plain OS thread and needs no ambient async runtime.
    pub fn spawn_cleanup(
        self: std::sync::Arc<Self>,
        interval: Duration,
    ) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("citrate-filter-gc".to_string())
            .spawn(move || loop {
                std::thread::sleep(interval);
                self.cleanup_stale_filters();
            })
            .expect("filter-gc thread should spawn")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_filter_creation() {
        let registry = FilterRegistry::new();
        let id = registry
            .new_log_filter(Some(0), Some(100), vec![], vec![], 50)
            .expect("under cap");
        assert!(id > 0);

        let filter = registry.get_filter(id);
        assert!(filter.is_some());

        if let Some(f) = filter {
            match f.filter_type {
                FilterType::Log {
                    from_block,
                    to_block,
                    ..
                } => {
                    assert_eq!(from_block, Some(0));
                    assert_eq!(to_block, Some(100));
                }
                _ => panic!("Expected Log filter type"),
            }
        }
    }

    #[test]
    fn test_block_filter_creation() {
        let registry = FilterRegistry::new();
        let id = registry.new_block_filter(100).expect("under cap");

        let filter = registry.get_filter(id);
        assert!(filter.is_some());
        assert!(matches!(filter.unwrap().filter_type, FilterType::Block));
    }

    #[test]
    fn test_filter_uninstall() {
        let registry = FilterRegistry::new();
        let id = registry.new_block_filter(100).expect("under cap");

        assert!(registry.get_filter(id).is_some());
        assert!(registry.uninstall_filter(id));
        assert!(registry.get_filter(id).is_none());
        assert!(!registry.uninstall_filter(id)); // Second uninstall should return false
    }

    #[test]
    fn test_filter_update() {
        let registry = FilterRegistry::new();
        let id = registry.new_block_filter(100).expect("under cap");

        registry.update_last_poll_block(id, 200);

        let filter = registry.get_filter(id);
        assert!(filter.is_some());
        assert_eq!(filter.unwrap().last_poll_block, 200);
    }

    /// CHAIN-B-D003 tripwire: the registry refuses filter creation past its
    /// cap so an unauthenticated flood of `eth_newFilter` cannot grow retained
    /// heap without bound. Pre-fix `new_*_filter` inserted unconditionally and
    /// `cleanup_stale_filters()` had zero callers. RED before the cap (all
    /// 10_001 accepted); GREEN after (the last one refused).
    #[test]
    fn d003_filter_registry_is_capped() {
        let registry = FilterRegistry::new();
        // Fill to exactly the cap. Freshly-polled, so the age sweep can't
        // reclaim any — the cap must hold on count alone.
        for _ in 0..MAX_FILTERS {
            assert!(
                registry.new_block_filter(1).is_some(),
                "creation must succeed under the cap"
            );
        }
        assert_eq!(registry.filter_count(), MAX_FILTERS);
        assert!(
            registry.new_block_filter(1).is_none(),
            "creation past the cap must be refused"
        );
        assert_eq!(
            registry.filter_count(),
            MAX_FILTERS,
            "a refused creation must not grow the registry"
        );
    }

    /// CHAIN-B-D003: `cleanup_stale_filters()` actually evicts (it exists but
    /// had no callers). With a zero max-age everything is stale.
    #[test]
    fn d003_cleanup_evicts_stale_filters() {
        let mut registry = FilterRegistry::new();
        registry.max_filter_age = Duration::from_secs(0);
        let id = registry.new_block_filter(1).expect("under cap");
        assert_eq!(registry.filter_count(), 1);
        std::thread::sleep(Duration::from_millis(1));
        registry.cleanup_stale_filters();
        assert_eq!(
            registry.filter_count(),
            0,
            "a stale filter must be swept, and the sweeper must have a caller"
        );
        let _ = id;
    }

    /// CHAIN-B-D011 tripwire: filter IDs must not be a sequential counter. Pre-fix
    /// `new_*_filter` minted `1, 2, 3, …` from an `AtomicU64`, so any client could
    /// enumerate `0x1..` and uninstall or drain another client's filter. Post-fix
    /// they are unguessable 64-bit CSPRNG values.
    #[test]
    fn d011_filter_ids_are_not_sequential() {
        let registry = FilterRegistry::new();
        let ids: Vec<u64> = (0..8)
            .map(|_| registry.new_block_filter(1).expect("under cap"))
            .collect();
        let sequential: Vec<u64> = (1..=8).collect();
        assert_ne!(ids, sequential, "filter ids must not be a sequential counter");
        assert!(
            ids.iter().all(|&id| id > 0xffff),
            "filter ids must be unguessable, not trivially-enumerable small integers"
        );
    }
}
