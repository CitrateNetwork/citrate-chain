//! The r1007 genesis (ADR-2026-11-03 CV-2, S3-6; docs/consensus/R1007_GENESIS.md).
//!
//! Owner decisions: r1007 is a new-genesis rehearsal of chain 40204 from the SAME
//! validator set, with TODAY's contract set (the r1006 ceremony state), and grants
//! re-issued by script after genesis. Its block 0 is rooted under the MPT state root
//! rule (CV-14, active from 0, block 0 included).
//!
//! The MPT rule is process-wide, so every test here takes `RULE` first.

use citrate_economics::genesis::{initialize_shared_genesis_state, GenesisConfig};
use citrate_economics::{r1006, r1007};
use citrate_execution::executor::Executor;
use citrate_execution::StateDB;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

static RULE: Mutex<()> = Mutex::new(());

fn rule(activation: Option<u64>) -> MutexGuard<'static, ()> {
    let g = RULE.lock().unwrap_or_else(|p| p.into_inner());
    citrate_execution::mpt_state_root::set_mpt_state_root_height(activation);
    g
}

/// The ceremony step (STATE_ROOT_MPT.md §1 step 3): the rule on from 0, then the shared
/// genesis function, twice over, gives exactly the block 0 this release pins: the r1007
/// configuration built from the fresh-keys alloc (D-K3 done 2026-11-11), at the canonical
/// genesis timestamp. The ceremony stamps its own timestamp, which moves the hash again.
#[test]
fn r1007_genesis_hash_is_pinned_and_reproducible_under_the_mpt_rule() {
    let _g = rule(Some(0));
    let cfg = GenesisConfig::r1007().expect("r1007 builds from the fresh-keys alloc");
    let a = r1007::genesis_block_hash(&cfg).expect("block 0");
    let b = r1007::genesis_block_hash(&GenesisConfig::r1007().expect("r1007")).expect("block 0");
    assert_eq!(a, b, "two builds of the r1007 genesis differ");
    assert_eq!(
        a,
        citrate_consensus::hardening::R1007_GENESIS,
        "R1007_GENESIS is stale: the r1007 profile builds 0x{}",
        hex::encode(a)
    );
    assert_eq!(
        r1007::compute_genesis_hash_for_ceremony().expect("ceremony step"),
        a
    );
    assert_ne!(
        a,
        r1007::genesis_block_hash(
            &r1007::candidate_layout_with_r1006_role_keys().expect("r1006-keys layout")
        )
        .expect("candidate"),
        "the fresh keys move block 0"
    );
    assert_ne!(a, citrate_consensus::hardening::R1006_GENESIS);
    // Block 0's root is the standard MPT root of the genesis state (the from-scratch
    // reference), not the legacy encoding.
    let db = Arc::new(StateDB::new());
    let ex = Arc::new(Executor::with_chain_id(db.clone(), 40204));
    let root = initialize_shared_genesis_state(&ex, &cfg).expect("genesis state");
    assert_eq!(root, *db.reference_state_root().as_bytes());
}

/// A GUI or light node that forgets to publish the rule must not build a different
/// "r1007" block 0: the shared genesis function refuses instead (fail closed).
#[test]
fn r1007_genesis_state_refuses_to_build_without_the_mpt_rule() {
    for activation in [None, Some(1), Some(10)] {
        let _g = rule(activation);
        let cfg = r1007::candidate_layout_with_r1006_role_keys().expect("r1007 layout");
        let ex = Arc::new(Executor::with_chain_id(Arc::new(StateDB::new()), 40204));
        let e = initialize_shared_genesis_state(&ex, &cfg)
            .expect_err("the r1007 genesis builds only under the MPT rule from 0")
            .to_string();
        assert!(e.contains("MPT state root"), "{activation:?}: {e}");
    }
    // Other geneses are not affected by the guard (r1006 keeps the legacy root).
    let _g = rule(None);
    let ex = Arc::new(Executor::with_chain_id(Arc::new(StateDB::new()), 40204));
    initialize_shared_genesis_state(&ex, &GenesisConfig::r1006().expect("r1006"))
        .expect("r1006 builds without the MPT rule");
}

/// Same contract set and same validator set as r1006 (owner Q-3): in the r1006-keys
/// layout every r1006 block-0 account is in r1007 byte for byte, except the r1006 genesis
/// note, which r1007 replaces with its own note. So every block-0 contract address, the
/// SBT and the vault included, is the same on r1007 as on r1006. D-K3 (2026-11-10)
/// changes the role keys those contracts name, not their addresses.
#[test]
fn r1007_keeps_the_r1006_contract_and_validator_sets() {
    let _g = rule(None);
    let r6 = GenesisConfig::r1006().expect("r1006");
    let r7 = r1007::candidate_layout_with_r1006_role_keys().expect("r1007 layout");
    assert_eq!(r7.chain_id, 40204);
    for a in r6
        .accounts
        .iter()
        .filter(|a| a.address != r1006::GENESIS_NOTE_ADDRESS)
    {
        let b = r7
            .accounts
            .iter()
            .find(|x| x.address == a.address)
            .unwrap_or_else(|| panic!("0x{} missing from r1007", hex::encode(a.address.0)));
        assert_eq!(
            (&b.code, &b.storage, b.balance, b.nonce),
            (&a.code, &a.storage, a.balance, a.nonce),
            "0x{}",
            hex::encode(a.address.0)
        );
    }
    assert!(!r7
        .accounts
        .iter()
        .any(|a| a.address == r1006::GENESIS_NOTE_ADDRESS));
    let note = r7
        .accounts
        .iter()
        .find(|a| a.address == r1007::GENESIS_NOTE_ADDRESS)
        .expect("the r1007 note");
    assert_eq!(
        note.storage,
        r1006::solidity_string_slots(r1007::GENESIS_NOTE)
    );
    assert_eq!(r7.accounts.len(), r6.accounts.len());
    let mut seen = HashSet::new();
    assert!(r7.accounts.iter().all(|a| seen.insert(a.address.0)));
    assert_eq!(r7.treasury_address, r6.treasury_address);
    assert_eq!(r7.mining_pool_max, r6.mining_pool_max, "same supply split");
    r7.validate().expect("valid");

    // The producer set the genesis registers, and the registry binding a node enforces.
    assert_eq!(
        r1007::validator_set_binding().expect("binding"),
        r1006::validator_set_binding().expect("binding")
    );
    let (registry, activation) = r1007::validator_set_binding()
        .expect("binding")
        .expect("the r1006 producer set is final, so r1007 compiles the binding");
    assert_eq!(
        activation,
        citrate_consensus::genesis_params::R1007_CHAIN_PARAMS.validator_activation_height
    );
    assert!(r7
        .accounts
        .iter()
        .any(|a| a.address.0 == registry && a.code.as_ref().is_some_and(|c| !c.is_empty())));
    // The r1006 inputs it is laid out from are final; r1007 itself is pending (D-K3,
    // see r1007_genesis_refuses_while_the_rotated_r1006_keys_are_pending).
    assert!(r1006::readiness().expect("readiness").is_release_ready());
}

#[test]
fn the_r1007_note_is_its_own_and_names_r1007() {
    assert_eq!(
        hex::encode(r1007::GENESIS_NOTE_ADDRESS.0),
        "000000000000000000000000000000c17a7e1007"
    );
    // Owner decision 2026-11-09: the exact block-0 text.
    assert_eq!(
        r1007::GENESIS_NOTE,
        "Citrate r1007: rehearsal genesis for chain 40204"
    );
    assert_ne!(r1007::GENESIS_NOTE, r1006::GENESIS_NOTE);
}

/// Owner decision D-K3 (2026-11-10), keys generated 2026-11-11: the r1007 block 0 is built
/// from the fresh-keys alloc, names no rotated r1006 key, and is release-ready.
#[test]
fn r1007_genesis_builds_from_the_fresh_keys_alloc() {
    let _g = rule(Some(0));
    let cfg = GenesisConfig::r1007().expect("r1007 builds");
    assert!(
        r1007::rotated_key_locations(&cfg).is_empty(),
        "{:?}",
        r1007::rotated_key_locations(&cfg)
    );
    let r = r1007::readiness().expect("readiness");
    assert!(r.is_release_ready(), "{:?}", r.missing());
}

/// The fresh-keys alloc, read raw: no rotated r1006 address anywhere in it. Not as an
/// account, not in a storage value or code (at any byte offset), not as a mapping key
/// keccak256(pad32(addr) ++ slot) for any slot below 64, and not in its header fields.
#[test]
fn the_r1007_alloc_names_no_rotated_r1006_key() {
    use sha3::{Digest, Keccak256};
    let raw: serde_json::Value = serde_json::from_str(r1007::R1007_ALLOC_JSON).expect("json");
    assert_eq!(raw["profile"], "r1007");
    assert_eq!(raw["inputsStatus"], "final");
    let text = r1007::R1007_ALLOC_JSON.to_ascii_lowercase();
    for k in r1007::ROTATED_R1006_KEYS {
        let hex20 = hex::encode(k.r1006_address);
        assert!(
            !text.contains(&hex20),
            "{} (0x{hex20}) appears in the r1007 alloc",
            k.role
        );
        for slot in 0u64..64 {
            let mut pre = [0u8; 64];
            pre[12..32].copy_from_slice(&k.r1006_address);
            pre[56..64].copy_from_slice(&slot.to_be_bytes());
            let key = hex::encode(Keccak256::digest(pre));
            assert!(
                !text.contains(&key),
                "{}: a mapping key of the r1006 address at slot {slot} remains",
                k.role
            );
        }
    }
}

/// Every rotated role that the r1006 block 0 names is named by its fresh r1007 key the
/// same number of times (accounts and storage words), and its r1006 mapping keys are
/// replaced one for one. The RELAYER is in neither block 0 (it is off chain).
#[test]
fn every_rotated_role_has_its_r1007_key_where_r1006_had_the_old_one() {
    let _g = rule(Some(0));
    let r6 = r1007::candidate_layout_with_r1006_role_keys().expect("r1006-keys layout");
    let r7 = GenesisConfig::r1007().expect("r1007");
    let fresh = r1007::r1007_role_keys().expect("inputs.r1007.env");
    assert_eq!(fresh.len(), r1007::ROTATED_R1006_KEYS.len());
    let old: HashSet<[u8; 20]> = r1007::ROTATED_R1006_KEYS
        .iter()
        .map(|k| k.r1006_address)
        .collect();
    let count = |cfg: &GenesisConfig, addr: [u8; 20]| -> usize {
        cfg.accounts
            .iter()
            .map(|a| {
                usize::from(a.address.0 == addr)
                    + a.storage
                        .iter()
                        .filter(|(_, v)| v.windows(20).any(|w| w == addr))
                        .count()
            })
            .sum()
    };
    for k in r1007::ROTATED_R1006_KEYS {
        let new = fresh
            .iter()
            .find(|(role, _)| role == k.role)
            .unwrap_or_else(|| panic!("{} missing from inputs.r1007.env", k.role))
            .1;
        assert!(
            !old.contains(&new),
            "{}: the r1007 key is a retired r1006 key",
            k.role
        );
        assert_eq!(
            count(&r7, new),
            count(&r6, k.r1006_address),
            "{}: occurrences of the fresh key in r1007 vs the old key in r1006",
            k.role
        );
        if k.role == "RELAYER" {
            assert_eq!(
                count(&r6, k.r1006_address),
                0,
                "the relayer is not in block 0"
            );
        } else {
            assert!(
                count(&r7, new) > 0,
                "{} is present in the r1007 block 0",
                k.role
            );
        }
    }
    assert_eq!(
        r7.accounts.len(),
        r6.accounts.len(),
        "the same accounts, renamed"
    );
}

/// The rotated set is exactly the non-producer keys of the r1006 ceremony inputs (every
/// address in `inputs.r1006.env`) plus the deployer, and no producer staker key.
#[test]
fn the_rotated_keys_are_every_r1006_non_producer_key() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let env = std::fs::read_to_string(root.join("scripts/genesis/r1006/inputs.r1006.env"))
        .expect("r1006 inputs");
    let mut want: HashSet<String> = HashSet::new();
    for line in env.lines().filter(|l| !l.starts_with('#')) {
        let Some((_, v)) = line.split_once('=') else {
            continue;
        };
        for part in v.split(',') {
            let p = part.trim().to_ascii_lowercase();
            if p.len() == 42 && p.starts_with("0x") {
                want.insert(p);
            }
        }
    }
    let alloc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("core/economics/assets/r1006/alloc.json"))
            .expect("alloc"),
    )
    .expect("alloc json");
    want.insert(
        alloc["deployer"]
            .as_str()
            .expect("deployer")
            .to_ascii_lowercase(),
    );
    let got: HashSet<String> = r1007::ROTATED_R1006_KEYS
        .iter()
        .map(|k| format!("0x{}", hex::encode(k.r1006_address)))
        .collect();
    assert_eq!(got, want);
    assert_eq!(r1007::ROTATED_R1006_KEYS.len(), want.len(), "no duplicates");
    let validators: serde_json::Value =
        serde_json::from_str(citrate_economics::r1006::R1006_VALIDATORS_JSON).expect("json");
    for v in validators["validators"].as_array().expect("validators") {
        let staker = v["staker"].as_str().expect("staker").to_ascii_lowercase();
        assert!(!got.contains(&staker), "producer key {staker} stays");
    }
}

/// Where the r1006 layout names each rotated key: the spots a fresh-keys r1007 alloc
/// must replace (R1007_GENESIS.md §1.1). Plain occurrences only: an account's own
/// balance, or a storage word that holds the address. A key held only under a hashed
/// mapping slot is not visible here (the RELAYER is the one such key).
#[test]
fn the_r1006_layout_shows_where_r1007_must_replace_each_rotated_key() {
    let _g = rule(None);
    let cfg = r1007::candidate_layout_with_r1006_role_keys().expect("layout");
    let found = r1007::rotated_key_locations(&cfg);
    let at = |role: &str| -> HashSet<String> {
        found
            .iter()
            .filter(|l| l.role == role)
            .map(|l| format!("0x{}", hex::encode(l.account)))
            .collect()
    };
    let governance = "0x3975c796e3ca6825de3c8ac7dae0820a1c0b2c5c";
    let guardian = "0xc6ed3ed2a3a302f1ed2249fb43e94808c9fbaf1d";
    for r in [
        "GOV_OWNER_1",
        "GOV_OWNER_2",
        "GOV_OWNER_3",
        "GOV_OWNER_4",
        "GOV_OWNER_5",
    ] {
        assert!(at(r).contains(governance), "{r}: {:?}", at(r));
    }
    for r in ["GRD_OWNER_1", "GRD_OWNER_2", "GRD_OWNER_3"] {
        assert!(at(r).contains(guardian), "{r}: {:?}", at(r));
    }
    let institutional = "0x9fea5d6bcfa82fa5879a7061381b40647aa67938";
    for r in ["SIGNER_1", "SIGNER_2", "SIGNER_3"] {
        assert!(at(r).contains(institutional), "{r}");
    }
    let grantor = at("MEMBERSHIP_GRANTOR");
    assert!(
        grantor.contains("0x883165132776171fbcfde2d3c789ef5bdb0d060d"),
        "SBT"
    );
    assert!(
        grantor.contains("0xd6632ea2179d047d2460f1de90abcc519839555e"),
        "vault"
    );
    let treasury = at("TREASURY");
    assert!(
        treasury.contains("0xeb6082db09c5383489a0b75057c739818bf33440"),
        "funded"
    );
    assert!(
        treasury.len() >= 4,
        "funded + fee recipient in 3 contracts: {treasury:?}"
    );
    assert!(at("FAUCET").contains("0xd75b8b3776532ea38f7683fdddc94401d0719b59"));
    let team = at("TEAM");
    assert!(
        team.contains("0x2a60d582019e002dce914c8a24f28435605a47be"),
        "vesting"
    );
    assert!(
        at("CITRATE_AA_OWNER").len() >= 2,
        "paymaster and wallet factory"
    );
    assert!(!at("CITRATE_AA_IDENTITY_SIGNER").is_empty());
    assert!(!at("CITRATE_AA_SPONSOR_SIGNER").is_empty());
    assert!(at("DEPLOYER").contains("0xe40325ba1f4cf362b203d9fe2b8160312e926c11"));
    assert!(
        at("RELAYER").is_empty(),
        "held under a hashed slot, if at all"
    );
}
