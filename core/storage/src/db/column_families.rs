// citrate/core/storage/src/db/column_families.rs

/// Column family definitions for RocksDB
pub const CF_DEFAULT: &str = "default";
pub const CF_BLOCKS: &str = "blocks";
pub const CF_HEADERS: &str = "headers";
pub const CF_TRANSACTIONS: &str = "transactions";
pub const CF_RECEIPTS: &str = "receipts";
pub const CF_STATE: &str = "state";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_STORAGE: &str = "storage";
pub const CF_CODE: &str = "code";
pub const CF_MODELS: &str = "models";
pub const CF_TRAINING: &str = "training";
pub const CF_METADATA: &str = "metadata";
pub const CF_BLUE_SET: &str = "blue_set";
pub const CF_DAG_RELATIONS: &str = "dag_relations";

// WP-S.1: Persistent DAG store column families
pub const CF_DAG_BLOCKS: &str = "dag_blocks";
pub const CF_DAG_CHILDREN: &str = "dag_children";
pub const CF_DAG_TIPS: &str = "dag_tips";
pub const CF_DAG_FINALIZED: &str = "dag_finalized";
pub const CF_DAG_HEIGHT_INDEX: &str = "dag_height_index";
pub const CF_DAG_METADATA: &str = "dag_metadata";
// WP-S.3: BFT checkpoint column family
pub const CF_CHECKPOINTS: &str = "checkpoints";

// Sprint P950-A-4 WP-A.4.3: persistent MVCC per-account version tracker.
// Key: 20-byte Address. Value: 8-byte big-endian u64 (ReadVersion inner).
// One-key slot for global version: [0xFF; 20] (all-ones address, not a
// valid account under EIP-55 / secp256k1 derivations).
pub const CF_ACCOUNT_VERSIONS: &str = "account_versions";

/// Get all column families
pub fn all_column_families() -> Vec<&'static str> {
    vec![
        CF_DEFAULT,
        CF_BLOCKS,
        CF_HEADERS,
        CF_TRANSACTIONS,
        CF_RECEIPTS,
        CF_STATE,
        CF_ACCOUNTS,
        CF_STORAGE,
        CF_CODE,
        CF_MODELS,
        CF_TRAINING,
        CF_METADATA,
        CF_BLUE_SET,
        CF_DAG_RELATIONS,
        CF_DAG_BLOCKS,
        CF_DAG_CHILDREN,
        CF_DAG_TIPS,
        CF_DAG_FINALIZED,
        CF_DAG_HEIGHT_INDEX,
        CF_DAG_METADATA,
        CF_CHECKPOINTS,
        CF_ACCOUNT_VERSIONS,
    ]
}
