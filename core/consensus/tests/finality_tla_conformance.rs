//! WP-S.3 Stage 2 — spec-to-code conformance between the Rust checkpoint
//! finality state machine and `specs/tla/consensus/CheckpointFinalitySafety.tla`
//! (+ `CheckpointVoteSafety.tla`), docs/consensus/CHECKPOINT_FINALITY_WIRING.md
//! §8.4.
//!
//! Two layers:
//!
//! 1. Static: the TLA+ module defines the actions and invariants this suite
//!    and the node adversarial suite (`node/src/finality_adversarial_tests.rs`) refer
//!    to, the gating TLC config checks them, and the constants the model uses
//!    (`MinCommittee`, the `Quorum` rule) and the vote message layout (69 bytes,
//!    domain-separated, chain id + height + hash) are the Rust ones.
//!
//! 2. Trace conformance: seeded random walks drive real `FinalityGadget`s
//!    (three honest validators with durable stores + one Byzantine key) through
//!    the TLA+ actions — `Propose`, `SignVote`, vote delivery (`Finalize` on
//!    quorum), `Reorg` (the node's canonical block at a height changes), and
//!    `Restart` (rebuild over the same store) — while a shadow of the TLA+
//!    state checks, after every step, the model's invariants on the Rust state
//!    (`NoConflictingFinality`, `HonestNoEquivocation`, `FinalizedHasQuorum`)
//!    and that `SignVote` is enabled in Rust exactly when the model's guard
//!    (durable record) allows it. `VerifyFloor` and the floor side of `Reorg`
//!    live in the node crate and are covered there.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use citrate_consensus::checkpoint::{
    canonical_vote_message, derived_quorum, sign_checkpoint_vote, CheckpointConfig,
    CheckpointManager, CheckpointStatus, CheckpointVote, CITRATE_VOTE_DOMAIN_SEPARATOR,
    DEFAULT_VOTE_DEPTH, MIN_FINALITY_COMMITTEE,
};
use citrate_consensus::checkpoint_gadget::{FinalityGadget, SignRefusal};
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::{DagStore, KvStore};
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey};
use citrate_consensus::vrf::VrfProposerSelector;

const SPEC: &str = include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety.tla");
const SPEC_CFG: &str = include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety.cfg");
const VOTE_SPEC: &str = include_str!("../../../specs/tla/consensus/CheckpointVoteSafety.tla");
const CI_SCRIPT: &str = include_str!("../../../scripts/ci/tla_finality.sh");

// ---------------------------------------------------------------------------
// 1. Static conformance
// ---------------------------------------------------------------------------

/// The value of a TLA+ definition `Name == <expr>` (single line).
fn definition<'a>(spec: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name} ==");
    spec.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .map(str::trim)
}

#[test]
fn spec_defines_every_action_the_code_maps_to() {
    for action in [
        "Propose(n, h) ==",
        "SignVote(n, h) ==",
        "Finalize(n, h) ==",
        "VerifyFloor(n) ==",
        "Reorg(n, h0, c) ==",
        "Restart(n) ==",
        "BootNoCertificate(n) ==",
        "SyncCert(n, m, h) ==",
    ] {
        assert!(SPEC.contains(action), "TLA+ action `{action}` missing");
    }
    // Every action is reachable from Next.
    let next = SPEC
        .split("Next ==")
        .nth(1)
        .and_then(|s| s.split("Spec ==").next())
        .expect("Next definition");
    for name in [
        "Propose(",
        "SignVote(",
        "Finalize(",
        "VerifyFloor(",
        "Reorg(",
        "Restart(",
        "BootNoCertificate(",
        "SyncCert(",
    ] {
        assert!(next.contains(name), "{name} not in Next");
    }
}

#[test]
fn gating_config_checks_s1_and_s2() {
    for inv in [
        "NoConflictingFinality",
        "HonestNoEquivocation",
        "FloorBlockIsFinalized",
        "FinalizedHasQuorum",
    ] {
        assert!(SPEC.contains(&format!("{inv} ==")), "{inv} not defined");
        assert!(
            SPEC_CFG.contains(&format!("INVARIANT {inv}")),
            "{inv} not checked by the gating config"
        );
    }
    for prop in ["HaltedSignsNothing", "FloorMonotone"] {
        assert!(SPEC_CFG.contains(&format!("PROPERTY {prop}")), "{prop}");
    }
    // The CI script runs the gating config and the mutation configs.
    for cfg in [
        "CheckpointVoteSafety.cfg",
        "CheckpointFinalitySafety.cfg",
        "CheckpointFinalitySafety_byz2.cfg",
        "CheckpointFinalitySafety_norecord.cfg",
        "CheckpointFinalitySafety_strict.cfg",
        "CheckpointFinalitySafety_committees.cfg",
        "CheckpointFinalitySafety_pollonly.cfg",
        "CheckpointFinalitySafety_restart.cfg",
        "CheckpointFinalitySafety_bootlimit.cfg",
        "CheckpointFinalitySafety_syncnoguard.cfg",
    ] {
        assert!(CI_SCRIPT.contains(cfg), "{cfg} not run by tla_finality.sh");
    }
}

/// S2 at finalization: the strict config checks §5 S2 as written with the
/// floor raised in the Finalize step (SyncFloor), and the poll-only mutation
/// keeps the counterexample alive.
#[test]
fn strict_s2_config_checks_the_floor_at_finalization() {
    const STRICT: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_strict.cfg");
    const POLL: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_pollonly.cfg");
    assert!(SPEC.contains("FinalizedNeverReverted =="));
    assert!(SPEC.contains("FinalizedStaysCanonical =="));
    assert!(STRICT.contains("SyncFloor = TRUE"));
    assert!(STRICT.contains("PROPERTY FinalizedNeverReverted"));
    assert!(STRICT.contains("INVARIANT FinalizedStaysCanonical"));
    assert!(POLL.contains("SyncFloor = FALSE"));
    assert!(SPEC_CFG.contains("SyncFloor = TRUE"));
    assert!(CI_SCRIPT
        .contains("expect_pass CheckpointFinalitySafety CheckpointFinalitySafety_strict.cfg"));
}

/// Stage 1b certificate sync (review of #332 @ 354908b): the gating and strict
/// configs run SyncCert with the guarded install (the code), and the unguarded
/// mutation keeps its counterexample alive.
#[test]
fn certificate_sync_configs_check_the_guarded_install() {
    const STRICT: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_strict.cfg");
    const NOGUARD: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_syncnoguard.cfg");
    assert!(SPEC.contains("SyncCert(n, m, h) =="));
    assert!(SPEC_CFG.contains("CertSync = \"guarded\""));
    assert!(STRICT.contains("CertSync = \"guarded\""));
    assert!(NOGUARD.contains("CertSync = \"unguarded\""));
    assert!(NOGUARD.contains("PROPERTY FinalizedNeverReverted"));
    assert!(CI_SCRIPT.contains(
        "expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_syncnoguard.cfg \
         FinalizedNeverReverted"
    ));
}

/// S2 across restarts (review of #335 @ 5236d2b): the boot check consults
/// every stored certificate (FloorVerifier::restore_certified_floor), so every
/// config sets BootRegLimit to at least its number of heights, the restart
/// config checks S2 over two heights with it, and the truncated mutation keeps
/// its counterexample alive.
#[test]
fn restart_s2_configs_check_the_boot_floor_restore() {
    const RESTART: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_restart.cfg");
    const BOOTLIMIT: &str =
        include_str!("../../../specs/tla/consensus/CheckpointFinalitySafety_bootlimit.cfg");
    assert!(SPEC.contains("BootFloor(n) =="));
    assert!(SPEC.contains("BootConsulted(n) =="));
    for cfg in [RESTART, BOOTLIMIT] {
        assert!(cfg.contains("Heights = {1, 2}"));
        assert!(cfg.contains("SyncFloor = TRUE"));
        assert!(cfg.contains("PROPERTY FinalizedNeverReverted"));
    }
    assert!(
        RESTART.contains("BootRegLimit = 2"),
        "every stored certificate"
    );
    assert!(
        BOOTLIMIT.contains("BootRegLimit = 1"),
        "truncated (mutation)"
    );
    assert!(SPEC_CFG.contains("BootRegLimit = 1") && SPEC_CFG.contains("Heights = {1}"));
    assert!(CI_SCRIPT
        .contains("expect_pass CheckpointFinalitySafety CheckpointFinalitySafety_restart.cfg"));
    assert!(CI_SCRIPT.contains(
        "expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_bootlimit.cfg \
         FinalizedNeverReverted"
    ));
}

#[test]
fn model_constants_are_the_rust_constants() {
    let min: usize = definition(SPEC, "MinCommittee")
        .expect("MinCommittee")
        .parse()
        .expect("number");
    assert_eq!(min, MIN_FINALITY_COMMITTEE);
    assert_eq!(
        definition(SPEC, "Quorum"),
        Some("(2 * CommitteeSize) \\div 3 + 1"),
        "the model's quorum rule is floor(2n/3)+1 over the candidate's committee"
    );
    // Committees are per candidate (committee_for seeds the selector with the
    // candidate block's VRF output): only committee members' votes count.
    assert_eq!(
        definition(SPEC, "Supporters(h, x)"),
        Some("{v \\in Committee(h, x) : <<v, h, x>> \\in AllVotes}")
    );
    // The gating config's committee is the whole 4-voter set, as the trace
    // walks below assume; the per-candidate case is the _committees finding.
    assert!(SPEC_CFG.contains("CommitteeSize = 4"));
    for n in 1usize..=1000 {
        assert_eq!(derived_quorum(n), (2 * n) / 3 + 1, "n = {n}");
    }
    // The gating model has 4 voters: quorum 3 (spec §3, D-2: 3 of 4).
    assert_eq!(derived_quorum(4), 3);
    // Spec §3 / FEATURE_REFERENCE.md: committee 100, quorum 67 = derived(100);
    // vote depth D = 3. (The interval default stays 50 pending D-1; §3's 2 is
    // a deployment parameter, not asserted here.)
    let d = CheckpointConfig::default();
    assert_eq!(d.committee_size, 100);
    assert_eq!(d.quorum_threshold, derived_quorum(100));
    assert_eq!(d.interval, 50);
    assert_eq!(DEFAULT_VOTE_DEPTH, 3);
    assert_eq!(d.vote_depth, DEFAULT_VOTE_DEPTH);
}

#[test]
fn vote_message_layout_matches_the_specs() {
    // CheckpointVoteSafety.tla H-02: (chain_id, height, block_hash) are bound
    // inside a domain-separated prefix.
    assert!(VOTE_SPEC.contains("CanonicalMessageBindsChain"));
    assert_eq!(CITRATE_VOTE_DOMAIN_SEPARATOR, b"CITRATE-CHECKPOINT-V1");
    let hash = Hash::new([0xAB; 32]);
    let m = canonical_vote_message(40204, 42, &hash);
    assert_eq!(m.len(), 69, "21 + 8 + 8 + 32");
    let (sep, rest) = m.split_at(21);
    let (chain, rest) = rest.split_at(8);
    let (height, h) = rest.split_at(8);
    assert_eq!(sep, CITRATE_VOTE_DOMAIN_SEPARATOR);
    assert_eq!(chain, 40204u64.to_le_bytes());
    assert_eq!(height, 42u64.to_le_bytes());
    assert_eq!(h, hash.as_bytes());
    assert_ne!(m, canonical_vote_message(1337, 42, &hash));
    assert_ne!(m, canonical_vote_message(40204, 44, &hash));
}

// ---------------------------------------------------------------------------
// 2. Trace conformance
// ---------------------------------------------------------------------------

const CHAIN: u64 = 40204;
const HEIGHTS: [u64; 2] = [2, 4];
const HONEST: usize = 3;

type KvKey = (String, Vec<u8>);

/// Durable store that survives a "restart" (shared by Arc).
struct MemKv(Mutex<HashMap<KvKey, Vec<u8>>>);

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let m = self.0.lock().map_err(|e| e.to_string())?;
        Ok(m.get(&(cf.to_string(), key.to_vec())).cloned())
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut m = self.0.lock().map_err(|e| e.to_string())?;
        m.insert((cf.to_string(), key.to_vec()), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        let mut m = self.0.lock().map_err(|e| e.to_string())?;
        m.remove(&(cf.to_string(), key.to_vec()));
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        let m = self.0.lock().map_err(|e| e.to_string())?;
        Ok(m.contains_key(&(cf.to_string(), key.to_vec())))
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let m = self.0.lock().map_err(|e| e.to_string())?;
        Ok(m.iter()
            .filter(|((c, _), _)| c == cf)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// Candidate block `x` (0 = a, 1 = b) at `height`: the model's `Hashes`.
fn block(height: u64, x: u8) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&height.to_le_bytes());
    b[31] = 0xA0 | x;
    Hash::new(b)
}

fn key(i: u8) -> Ed25519SigningKey {
    let mut s = [0u8; 32];
    s[0] = i;
    s[31] = 0x3C;
    Ed25519SigningKey::from_bytes(&s)
}

fn pk(k: &Ed25519SigningKey) -> PublicKey {
    PublicKey::new(k.verifying_key().to_bytes())
}

/// Deterministic xorshift (no dependency).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).expect("fits")).expect("fits")
    }
}

struct Honest {
    key: Ed25519SigningKey,
    kv: Arc<MemKv>,
    gadget: FinalityGadget,
    /// canon[h]: which candidate this node's chain holds at h (model `canon`).
    canon: HashMap<u64, u8>,
}

async fn dag() -> Arc<DagStore> {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    for h in HEIGHTS {
        for x in 0..2u8 {
            let b = BlockBuilder::new()
                .hash(block(h, x))
                .height(h)
                .parent(Hash::new([h as u8; 32]))
                .build_unhashed();
            dag.store_block(b).await.expect("store");
        }
    }
    dag
}

async fn gadget(kv: &Arc<MemKv>, set: &[(PublicKey, u128)]) -> FinalityGadget {
    let cfg = CheckpointConfig {
        interval: 2,
        committee_size: 100,
        quorum_threshold: 67,
        chain_id: CHAIN,
        vote_depth: 3,
    };
    let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
    sel.sync_active_set_at(1, set.to_vec(), 1).await;
    let store: Arc<dyn KvStore> = kv.clone();
    let mgr = Arc::new(CheckpointManager::with_persistence(cfg, dag().await, store));
    FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), true)
}

/// Shadow of the TLA+ state that the Rust run is checked against.
#[derive(Default)]
struct Shadow {
    /// `sent`: honest votes <<voter, h, x>>.
    sent: BTreeSet<(usize, u64, u8)>,
    /// Byzantine votes released so far (the model assumes all; we track which
    /// were actually delivered, a subset, so quorum checks are conservative).
    byz: BTreeSet<(u64, u8)>,
}

impl Shadow {
    fn supporters(&self, h: u64, x: u8) -> usize {
        let honest = self
            .sent
            .iter()
            .filter(|(_, hh, xx)| *hh == h && *xx == x)
            .count();
        honest + usize::from(self.byz.contains(&(h, x)))
    }
}

/// Model invariants evaluated on the Rust state.
async fn check_invariants(nodes: &[Honest], shadow: &Shadow, step: &str) {
    for h in HEIGHTS {
        let mut seen: Option<Hash> = None;
        for n in nodes {
            let Some(cp) = n.gadget.manager().get_checkpoint(h).await else {
                continue;
            };
            assert_eq!(cp.status, CheckpointStatus::Finalized);
            // NoConflictingFinality
            if let Some(prev) = seen {
                assert_eq!(
                    prev, cp.block_hash,
                    "NoConflictingFinality at {h} after {step}"
                );
            }
            seen = Some(cp.block_hash);
            // FinalizedHasQuorum: the certificate verifies, and the model's sent
            // votes support it with a quorum.
            assert!(cp.verify_certificate(CHAIN).is_ok(), "{step}");
            let x = u8::from(cp.block_hash == block(h, 1));
            assert!(
                shadow.supporters(h, x) >= derived_quorum(HONEST + 1),
                "FinalizedHasQuorum at {h} after {step}"
            );
        }
    }
    // HonestNoEquivocation
    for (v, h, x) in &shadow.sent {
        assert!(
            !shadow.sent.contains(&(*v, *h, 1 - *x)),
            "HonestNoEquivocation: voter {v} at {h} after {step}"
        );
    }
}

/// One random walk; returns how many own votes Rust refused as Conflicting
/// (the durable-record guard firing) and how many checkpoints finalized.
async fn walk(seed: u64, steps: usize) -> (usize, usize) {
    let mut rng = Rng(seed | 1);
    let keys: Vec<Ed25519SigningKey> = (0..=HONEST as u8).map(key).collect();
    let set: Vec<(PublicKey, u128)> = keys.iter().map(|k| (pk(k), 1000)).collect();
    let byz = keys.get(HONEST).expect("byzantine key");
    let mut nodes = Vec::new();
    for k in keys.iter().take(HONEST) {
        let kv = Arc::new(MemKv(Mutex::new(HashMap::new())));
        nodes.push(Honest {
            key: k.clone(),
            gadget: gadget(&kv, &set).await,
            kv,
            canon: HEIGHTS.iter().map(|h| (*h, 0u8)).collect(),
        });
    }
    let mut shadow = Shadow::default();
    // Votes in flight (sent, not yet delivered everywhere): (vote, receivers left).
    let mut inflight: Vec<(CheckpointVote, Vec<usize>)> = Vec::new();
    let mut refusals = 0usize;
    let seed_hash = Hash::new([9; 32]);

    for step in 0..steps {
        let n = rng.below(HONEST);
        let h = *HEIGHTS.get(rng.below(HEIGHTS.len())).expect("height");
        let action = rng.below(100);
        let label;
        if action < 20 {
            // Propose(n, h): the canonical block at h is buried (no signer).
            label = format!("Propose(n{n}, {h})");
            let node = nodes.get(n).expect("node");
            let x = *node.canon.get(&h).expect("canon");
            let _ = node
                .gadget
                .on_buried_checkpoint(h, block(h, x), &seed_hash, None)
                .await;
        } else if action < 40 {
            // SignVote(n, h): report again with the signer. Rust signs iff the
            // node has the pending checkpoint for its canonical block, has not
            // voted, and the durable record allows it (the model's guard).
            label = format!("SignVote(n{n}, {h})");
            let node = nodes.get(n).expect("node");
            let x = *node.canon.get(&h).expect("canon");
            let pending = node.gadget.manager().pending_hash(h).await;
            let finalized = node.gadget.manager().latest_finalized_height().await >= h;
            let had_vote = node
                .gadget
                .manager()
                .has_pending_vote(h, &pk(&node.key))
                .await;
            let out = node
                .gadget
                .on_buried_checkpoint(h, block(h, x), &seed_hash, Some(&node.key))
                .await;
            let model_guard = !shadow.sent.contains(&(n, h, 1 - x));
            if out.signed_own_vote {
                assert!(
                    model_guard,
                    "Rust signed where the model's guard forbids ({label})"
                );
                assert!(pending.is_none_or(|p| p == block(h, x)), "{label}");
                shadow.sent.insert((n, h, x));
            } else if let Some(SignRefusal::Conflicting { signed }) = &out.sign_refused {
                assert!(
                    !model_guard,
                    "Rust refused where the model allows ({label})"
                );
                assert_eq!(*signed, block(h, 1 - x));
                refusals += 1;
            } else if pending.is_none_or(|p| p == block(h, x)) && !finalized && !had_vote {
                // Nothing in Rust stood in the way, yet it neither signed nor
                // refused as Conflicting: the code and the model disagree.
                panic!("SignVote neither taken nor refused ({label}): {out:?}");
            }
            for v in out.outbound {
                inflight.push((v, (0..HONEST).filter(|i| *i != n).collect()));
            }
        } else if action < 75 && !inflight.is_empty() {
            // Deliver one in-flight vote to one receiver (Finalize on quorum).
            let i = rng.below(inflight.len());
            let (vote, r, drained) = {
                let (vote, left) = inflight.get_mut(i).expect("inflight");
                let r = left.remove(rng.below(left.len()));
                (vote.clone(), r, left.is_empty())
            };
            if drained {
                inflight.swap_remove(i);
            }
            label = format!("Deliver(n{r}, {})", vote.height);
            let out = nodes
                .get(r)
                .expect("node")
                .gadget
                .on_inbound_vote(vote)
                .await;
            if let Some(relay) = out.relay() {
                inflight.push((relay.clone(), (0..HONEST).filter(|j| *j != r).collect()));
            }
        } else if action < 85 {
            // Byzantine voter releases a vote for either candidate, to everyone.
            let x = u8::try_from(rng.below(2)).expect("0/1");
            label = format!("Byz({h}, {x})");
            shadow.byz.insert((h, x));
            inflight.push((
                sign_checkpoint_vote(CHAIN, h, block(h, x), byz),
                (0..HONEST).collect(),
            ));
        } else if action < 95 {
            // Reorg(n, h, c): fork choice moves node n to the other candidate
            // at h (the floor side of Reorg is the node crate's; here the
            // effect is on what the node proposes and would sign).
            label = format!("Reorg(n{n}, {h})");
            let node = nodes.get_mut(n).expect("node");
            let x = node.canon.get_mut(&h).expect("canon");
            *x = 1 - *x;
        } else {
            // Restart(n): memory lost, durable store kept.
            label = format!("Restart(n{n})");
            let node = nodes.get_mut(n).expect("node");
            node.gadget = gadget(&node.kv, &set).await;
            // Messages addressed to it while down are lost.
            for (_, left) in &mut inflight {
                left.retain(|j| *j != n);
            }
            inflight.retain(|(_, left)| !left.is_empty());
        }
        check_invariants(&nodes, &shadow, &format!("step {step}: {label}")).await;
    }
    let mut finalized = 0usize;
    for n in &nodes {
        for h in HEIGHTS {
            finalized += usize::from(n.gadget.manager().get_checkpoint(h).await.is_some());
        }
    }
    (refusals, finalized)
}

/// Seeded random walks over the TLA+ actions; every step is checked against
/// the model's invariants and the SignVote guard. The walks must also exercise
/// the guard (some Conflicting refusals) so the check is not vacuous.
#[tokio::test]
async fn rust_gadget_conforms_to_the_tla_actions_and_invariants() {
    let (mut refusals, mut finalized) = (0usize, 0usize);
    for seed in 1u64..=120 {
        let (r, f) = walk(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 80).await;
        refusals += r;
        finalized += f;
    }
    assert!(refusals > 0, "the durable-record guard was never exercised");
    assert!(
        finalized > 0,
        "no walk ever finalized: the invariants were vacuous"
    );
    eprintln!("conformance walks: {finalized} finalized checkpoints, {refusals} guarded refusals");
}
