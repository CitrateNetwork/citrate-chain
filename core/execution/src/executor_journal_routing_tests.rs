// Per-transaction journal routing of governance, model-registry, artifact-index
// and training-job writes, across the hardening activation height.
//
// From the activation height every state write a transaction makes lands in
// its journal, so the executor's two ways of not committing a transaction
// remove it completely:
//
//   * revert: the failure arm discards the journal's writes, then drains only
//     the gas burn and nonce bump;
//   * abort:  a commit attempt that loses its MVCC check drops the journal
//     undrained and re-executes from scratch.
//
// Below the height the legacy direct writes are kept so historical blocks
// replay to the roots they were produced with; those tests pin the legacy
// behaviour exactly.
//
// The activation height is process-wide. Every test here publishes the same
// value (`ACT`) and every other unit test in this crate runs at heights far
// below it, so the tests here never change what another test observes.

use super::*;
use crate::types::{JobId, JobStatus, ModelMetadata, TrainingJob};
use citrate_consensus::types::{BlockBuilder, PublicKey, Signature};
use sha3::{Digest, Keccak256};

const ACT: u64 = 1_000_000_000;
const LEGACY: u64 = 100;
const FUND: u128 = 1_000_000_000_000_000_000;

fn arm() {
    crate::supply_hardening::set_supply_hardening_height(Some(ACT));
}

fn block(h: u64) -> Block {
    BlockBuilder::new()
        .height(h)
        .timestamp(1_000_000)
        .build_unhashed()
}

fn pk(seed: u8) -> PublicKey {
    PublicKey::new([seed; 32])
}

fn addr_of(p: &PublicKey) -> Address {
    crate::address_utils::normalize_address(p)
}

/// A public key that normalises to the 20-byte EVM address `a`.
fn pk_for(a: Address) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&a.0);
    PublicKey::new(b)
}

fn tx(from: PublicKey, to: Option<PublicKey>, data: Vec<u8>, nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([0x5E; 32]),
        nonce,
        from,
        to,
        value: 0,
        gas_limit: 5_000_000,
        gas_price: 1,
        data,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn gov() -> Address {
    Executor::governance_precompile_address()
}

fn art() -> Address {
    Executor::artifact_precompile_address()
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn addr_word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

fn set_admin_data(new_admin: Address) -> Vec<u8> {
    let mut d = selector4(b"setAdmin(address)").to_vec();
    d.extend_from_slice(&addr_word(new_admin));
    d
}

fn queue_data(key: [u8; 32], value: &[u8], eta: u64) -> Vec<u8> {
    let mut d = selector4(b"queueSetParam(bytes32,bytes,uint64)").to_vec();
    d.extend_from_slice(&key);
    d.extend_from_slice(&word(96)); // offset of the bytes arg, relative to args
    d.extend_from_slice(&word(eta));
    d.extend_from_slice(&word(value.len() as u64));
    d.extend_from_slice(value);
    d
}

fn execute_param_data(key: [u8; 32]) -> Vec<u8> {
    let mut d = selector4(b"executeSetParam(bytes32)").to_vec();
    d.extend_from_slice(&key);
    d
}

fn register_data(model_hash: [u8; 32], cid: &[u8]) -> Vec<u8> {
    let mut d = selector4(b"registerModel(bytes32,string)").to_vec();
    d.extend_from_slice(&model_hash);
    d.extend_from_slice(&word(64));
    d.extend_from_slice(&word(cid.len() as u64));
    d.extend_from_slice(cid);
    d
}

fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.extend_from_slice(suffix);
    k
}

const PKEY: [u8; 32] = [0xC1; 32];
const MHASH: [u8; 32] = [0x4D; 32];
const CID: &[u8] = b"bafy-test-cid";

/// A fresh executor with a funded admin who already holds governance.
fn fixture() -> (Arc<StateDB>, Executor, PublicKey) {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone());
    let admin = pk(0xA1);
    state
        .accounts
        .set_balance(addr_of(&admin), U256::from(FUND));
    state.set_storage(gov(), b"ADMIN".to_vec(), addr_of(&admin).0.to_vec());
    (state, exec, admin)
}

fn model(owner: Address) -> ModelState {
    ModelState {
        owner,
        model_hash: Hash::new(MHASH),
        version: 1,
        metadata: ModelMetadata {
            name: "m".into(),
            ..Default::default()
        },
        access_policy: AccessPolicy::Public,
        usage_stats: crate::types::UsageStats::default(),
    }
}

fn job(id: JobId, participants: Vec<Address>, submitted: u32) -> TrainingJob {
    TrainingJob {
        id,
        owner: Address([9; 20]),
        model_id: ModelId(Hash::new([1; 32])),
        dataset_hash: Hash::new([2; 32]),
        participants,
        gradients_submitted: submitted,
        gradients_required: 2,
        reward_pool: U256::from(100u64),
        status: JobStatus::Active,
        created_at: 0,
        completed_at: None,
    }
}

/// Everything a write in this file can reach: the injective account/storage
/// fingerprint, the governance and artifact keys used here (those precompile
/// addresses hold no account, so the fingerprint does not fold them), every
/// registered model, and the jobs named in `jobs`.
fn world(state: &StateDB, jobs: &[JobId]) -> Hash {
    let mut h = Keccak256::new();
    h.update(state.full_state_fingerprint().as_bytes());
    let mh = MHASH;
    let keys: Vec<(Address, Vec<u8>)> = vec![
        (gov(), b"ADMIN".to_vec()),
        (gov(), key(b"PENDING:", &PKEY)),
        (gov(), key(b"PARAM:", &PKEY)),
        (art(), key(b"MODEL_CID:", &mh)),
        (art(), key(b"MODEL_ARTS:", &mh)),
        (art(), key(b"MODEL_PROOFS:", &mh)),
    ];
    for (a, k) in keys {
        match state.get_storage(&a, &k) {
            Some(v) => {
                h.update([1u8]);
                h.update((v.len() as u32).to_be_bytes());
                h.update(&v);
            }
            None => h.update([0u8]),
        }
    }
    let mut models = state.all_models();
    models.sort_by_key(|(id, _)| id.0);
    for (id, m) in models {
        h.update(id.0.as_bytes());
        h.update(serde_json::to_vec(&m).expect("model serializes"));
    }
    for id in jobs {
        match state.get_training_job(id) {
            Some(j) => h.update(serde_json::to_vec(&j).expect("job serializes")),
            None => h.update([0u8]),
        }
    }
    Hash::new(h.finalize().into())
}

/// How an executed attempt ends.
#[derive(Clone, Copy, Debug)]
enum End {
    /// Lost its MVCC commit check: the journal is dropped undrained.
    Abort,
    /// The failure arm: pending writes discarded, then the journal drained.
    Revert,
    /// Committed: the journal drained as recorded.
    Commit,
}

/// Run one transaction's dispatch into a fresh pinned journal at height `h`,
/// then end the attempt as `end`. Returns the dispatch result.
async fn dispatch(
    exec: &Executor,
    h: u64,
    from: PublicKey,
    tt: TransactionType,
    end: End,
) -> Result<(), ExecutionError> {
    let b = block(h);
    let t = tx(from, None, vec![], 0);
    let mut ctx = ExecutionContext::new(&b, &t);
    ctx.journal
        .lock()
        .pin_at(exec.commit_coordinator.current_version());
    let r = exec
        .execute_transaction_type(tt, &mut ctx, addr_of(&from))
        .await;
    match end {
        End::Abort => drop(ctx),
        End::Revert => {
            ctx.journal.lock().discard_writes();
            exec.drain_journal(&ctx.journal);
        }
        End::Commit => exec.drain_journal(&ctx.journal),
    }
    r
}

/// Run a full transaction (`execute_tx_into_journal`) and drop its journal
/// undrained: exactly the `CommitOutcome::Aborted` arm of `execute_transaction`.
async fn full_tx_aborted(exec: &Executor, h: u64, t: &Transaction) -> TransactionReceipt {
    let b = block(h);
    let mut ctx = ExecutionContext::new(&b, t);
    ctx.journal
        .lock()
        .pin_at(exec.commit_coordinator.current_version());
    let (receipt, _writes) = exec
        .execute_tx_into_journal(&b, t, &mut ctx)
        .await
        .expect("tx is valid");
    drop(ctx);
    receipt
}

fn call(to: Address, data: Vec<u8>) -> TransactionType {
    TransactionType::Call {
        to,
        data,
        value: U256::zero(),
    }
}

// ───────────────────────── governance precompile ─────────────────────────

#[tokio::test]
async fn governance_set_admin_is_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = fixture();
        let before = world(&state, &[]);
        let r = dispatch(
            &exec,
            ACT,
            admin,
            call(gov(), set_admin_data(Address([0xEE; 20]))),
            end,
        )
        .await;
        assert!(r.is_ok(), "{end:?}: setAdmin by the admin dispatches");
        assert_eq!(
            state.get_storage(&gov(), b"ADMIN"),
            Some(addr_of(&admin).0.to_vec()),
            "{end:?}: admin must be unchanged when the tx does not commit"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn governance_queue_param_is_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = fixture();
        let before = world(&state, &[]);
        dispatch(
            &exec,
            ACT,
            admin,
            call(gov(), queue_data(PKEY, b"v1", 5)),
            end,
        )
        .await
        .expect("queue dispatches");
        assert_eq!(
            state.get_storage(&gov(), &key(b"PENDING:", &PKEY)),
            None,
            "{end:?}: no pending param may survive"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn governance_execute_param_is_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = fixture();
        let mut stored = 0u64.to_le_bytes().to_vec();
        stored.extend_from_slice(b"v1");
        state.set_storage(gov(), key(b"PENDING:", &PKEY), stored.clone());
        let before = world(&state, &[]);
        dispatch(
            &exec,
            ACT,
            admin,
            call(gov(), execute_param_data(PKEY)),
            end,
        )
        .await
        .expect("execute dispatches");
        assert_eq!(
            state.get_storage(&gov(), &key(b"PARAM:", &PKEY)),
            None,
            "{end:?}: the param must not be set"
        );
        assert_eq!(
            state.get_storage(&gov(), &key(b"PENDING:", &PKEY)),
            Some(stored.clone()),
            "{end:?}: the pending entry must not be deleted"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn governance_writes_land_on_commit() {
    arm();
    let (state, exec, admin) = fixture();
    dispatch(
        &exec,
        ACT,
        admin,
        call(gov(), queue_data(PKEY, b"v1", 0)),
        End::Commit,
    )
    .await
    .expect("queue");
    let mut want = 0u64.to_le_bytes().to_vec();
    want.extend_from_slice(b"v1");
    assert_eq!(
        state.get_storage(&gov(), &key(b"PENDING:", &PKEY)),
        Some(want)
    );
    dispatch(
        &exec,
        ACT,
        admin,
        call(gov(), execute_param_data(PKEY)),
        End::Commit,
    )
    .await
    .expect("execute");
    assert_eq!(
        state.get_storage(&gov(), &key(b"PARAM:", &PKEY)),
        Some(b"v1".to_vec())
    );
    assert_eq!(
        state.get_storage(&gov(), &key(b"PENDING:", &PKEY)),
        None,
        "executing a param consumes its pending entry"
    );
    let new_admin = Address([0xEE; 20]);
    dispatch(
        &exec,
        ACT,
        admin,
        call(gov(), set_admin_data(new_admin)),
        End::Commit,
    )
    .await
    .expect("setAdmin");
    assert_eq!(
        state.get_storage(&gov(), b"ADMIN"),
        Some(new_admin.0.to_vec())
    );
}

/// A full transaction whose commit attempt is aborted, then retried: the
/// retry must see the pre-transaction state and succeed exactly once.
#[tokio::test]
async fn governance_execute_param_aborted_attempt_then_retry_commits_once() {
    arm();
    let (state, exec, admin) = fixture();
    let mut stored = 0u64.to_le_bytes().to_vec();
    stored.extend_from_slice(b"v1");
    state.set_storage(gov(), key(b"PENDING:", &PKEY), stored);
    let before = world(&state, &[]);
    let t = tx(admin, Some(pk_for(gov())), execute_param_data(PKEY), 0);

    let aborted = full_tx_aborted(&exec, ACT, &t).await;
    assert!(aborted.status, "the aborted attempt itself succeeded");
    assert_eq!(
        world(&state, &[]),
        before,
        "an aborted attempt leaves no trace"
    );

    let r = exec
        .execute_transaction(&block(ACT), &t)
        .await
        .expect("retry executes");
    assert!(
        r.status,
        "the retry must still find the pending param and succeed"
    );
    assert_eq!(
        state.get_storage(&gov(), &key(b"PARAM:", &PKEY)),
        Some(b"v1".to_vec())
    );
    assert_eq!(state.get_storage(&gov(), &key(b"PENDING:", &PKEY)), None);
}

// ─────────────────── model registry + artifact index ───────────────────

#[tokio::test]
async fn register_model_and_artifact_index_are_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = fixture();
        let before = world(&state, &[]);
        dispatch(
            &exec,
            ACT,
            admin,
            call(art_model(), register_data(MHASH, CID)),
            end,
        )
        .await
        .expect("register dispatches");
        assert!(
            state.get_model(&ModelId(Hash::new(MHASH))).is_none(),
            "{end:?}: the model must not be registered"
        );
        assert_eq!(
            state.get_storage(&art(), &key(b"MODEL_CID:", &MHASH)),
            None,
            "{end:?}: no model-CID index entry"
        );
        assert_eq!(
            state.get_storage(&art(), &key(b"MODEL_ARTS:", &MHASH)),
            None,
            "{end:?}: no artifact-list entry"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

fn art_model() -> Address {
    Executor::model_precompile_address()
}

#[tokio::test]
async fn register_model_aborted_attempt_then_retry_registers_once() {
    arm();
    let (state, exec, admin) = fixture();
    let before = world(&state, &[]);
    let t = tx(
        admin,
        Some(pk_for(art_model())),
        register_data(MHASH, CID),
        0,
    );

    full_tx_aborted(&exec, ACT, &t).await;
    assert_eq!(
        world(&state, &[]),
        before,
        "an aborted attempt leaves no trace"
    );

    let r = exec
        .execute_transaction(&block(ACT), &t)
        .await
        .expect("retry executes");
    assert!(
        r.status,
        "the retry must not find a model left behind by the aborted attempt"
    );
    let m = state
        .get_model(&ModelId(Hash::new(MHASH)))
        .expect("registered once");
    assert_eq!(m.owner, addr_of(&admin));
    assert_eq!(
        state.get_storage(&art(), &key(b"MODEL_CID:", &MHASH)),
        Some(CID.to_vec())
    );
    let list: Vec<String> = serde_json::from_slice(
        &state
            .get_storage(&art(), &key(b"MODEL_ARTS:", &MHASH))
            .expect("artifact list"),
    )
    .expect("json list");
    assert_eq!(list, vec![String::from_utf8_lossy(CID).to_string()]);
}

#[tokio::test]
async fn duplicate_registration_still_reverts_after_activation() {
    arm();
    let (state, exec, admin) = fixture();
    state
        .register_model(ModelId(Hash::new(MHASH)), model(Address([7; 20])))
        .expect("seed");
    let before = world(&state, &[]);
    let r = dispatch(
        &exec,
        ACT,
        admin,
        call(art_model(), register_data(MHASH, CID)),
        End::Revert,
    )
    .await;
    assert!(r.is_err(), "a second registration of one hash must fail");
    assert_eq!(world(&state, &[]), before);
}

#[tokio::test]
async fn update_model_and_artifact_index_are_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = fixture();
        let id = ModelId(Hash::new(MHASH));
        state
            .register_model(id, model(addr_of(&admin)))
            .expect("seed");
        let before = world(&state, &[]);
        dispatch(
            &exec,
            ACT,
            admin,
            TransactionType::UpdateModel {
                model_id: id,
                metadata: ModelMetadata {
                    name: "v2".into(),
                    ..Default::default()
                },
                artifact_cid: Some(String::from_utf8_lossy(CID).to_string()),
            },
            end,
        )
        .await
        .expect("update dispatches");
        let m = state.get_model(&id).expect("model");
        assert_eq!(m.version, 1, "{end:?}: version must not move");
        assert_eq!(m.metadata.name, "m", "{end:?}: metadata must not move");
        assert_eq!(
            state.get_storage(&art(), &key(b"MODEL_ARTS:", &MHASH)),
            None,
            "{end:?}: no artifact-list entry"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn update_model_lands_on_commit() {
    arm();
    let (state, exec, admin) = fixture();
    let id = ModelId(Hash::new(MHASH));
    state
        .register_model(id, model(addr_of(&admin)))
        .expect("seed");
    dispatch(
        &exec,
        ACT,
        admin,
        TransactionType::UpdateModel {
            model_id: id,
            metadata: ModelMetadata {
                name: "v2".into(),
                ..Default::default()
            },
            artifact_cid: Some(String::from_utf8_lossy(CID).to_string()),
        },
        End::Commit,
    )
    .await
    .expect("update");
    let m = state.get_model(&id).expect("model");
    assert_eq!(m.version, 2);
    assert_eq!(m.metadata.name, "v2");
    assert!(state
        .get_storage(&art(), &key(b"MODEL_ARTS:", &MHASH))
        .is_some());
}

// ───────────────────── inference usage + proof index ─────────────────────

struct ProofService;

#[async_trait::async_trait]
impl InferenceService for ProofService {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Ok((
            vec![0xAA],
            0,
            Address([0x0F; 20]),
            U256::zero(),
            Some(vec![9, 9]),
        ))
    }
}

struct Artifacts;

#[async_trait::async_trait]
impl ArtifactService for Artifacts {
    async fn pin(&self, _cid: &str, _replicas: usize) -> Result<(), ExecutionError> {
        Ok(())
    }
    async fn status(&self, _cid: &str) -> Result<String, ExecutionError> {
        Ok("pinned".into())
    }
    async fn add(&self, _data: &[u8]) -> Result<String, ExecutionError> {
        Ok("bafy-proof".into())
    }
}

fn inference_fixture() -> (Arc<StateDB>, Executor, PublicKey) {
    let (state, _, admin) = fixture();
    let exec = Executor::new(state.clone())
        .with_inference_service(Arc::new(ProofService))
        .with_artifact_service(Arc::new(Artifacts));
    state
        .register_model(ModelId(Hash::new(MHASH)), model(Address([7; 20])))
        .expect("seed");
    (state, exec, admin)
}

fn infer() -> TransactionType {
    TransactionType::InferenceRequest {
        model_id: ModelId(Hash::new(MHASH)),
        input_data: vec![1, 2, 3],
        max_gas: 5_000_000,
    }
}

#[tokio::test]
async fn inference_usage_stats_and_proof_index_are_undone_by_abort_and_revert() {
    arm();
    if crate::activation::pba_hardening_active(ACT) {
        // In-block inference reverts before any write on such a node.
        return;
    }
    for end in [End::Abort, End::Revert] {
        let (state, exec, admin) = inference_fixture();
        let before = world(&state, &[]);
        dispatch(&exec, ACT, admin, infer(), end)
            .await
            .expect("inference dispatches");
        let m = state.get_model(&ModelId(Hash::new(MHASH))).expect("model");
        assert_eq!(
            m.usage_stats.total_inferences, 0,
            "{end:?}: usage must not be counted"
        );
        assert_eq!(
            state.get_storage(&art(), &key(b"MODEL_PROOFS:", &MHASH)),
            None,
            "{end:?}: no proof-index entry"
        );
        assert_eq!(world(&state, &[]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn inference_usage_stats_and_proof_index_land_on_commit() {
    arm();
    if crate::activation::pba_hardening_active(ACT) {
        return;
    }
    let (state, exec, admin) = inference_fixture();
    dispatch(&exec, ACT, admin, infer(), End::Commit)
        .await
        .expect("inference");
    let m = state.get_model(&ModelId(Hash::new(MHASH))).expect("model");
    assert_eq!(m.usage_stats.total_inferences, 1);
    assert!(state
        .get_storage(&art(), &key(b"MODEL_PROOFS:", &MHASH))
        .is_some());
}

// ─────────────────────────── training jobs ───────────────────────────

fn gradient(job_id: JobId) -> TransactionType {
    TransactionType::SubmitGradient {
        job_id,
        gradient_data: vec![],
        proof: vec![],
    }
}

#[tokio::test]
async fn gradient_job_update_and_reward_credits_are_undone_by_abort_and_revert() {
    arm();
    for end in [End::Abort, End::Revert] {
        let (state, exec, _) = fixture();
        let id = JobId(Hash::new([0x44; 32]));
        let other = Address([4; 20]);
        state
            .create_training_job(job(id, vec![other], 1))
            .expect("seed");
        let submitter = pk(0xB2);
        let before = world(&state, &[id]);
        dispatch(&exec, ACT, submitter, gradient(id), end)
            .await
            .expect("gradient dispatches");
        let j = state.get_training_job(&id).expect("job");
        assert_eq!(j.gradients_submitted, 1, "{end:?}: submission not counted");
        assert_eq!(j.status, JobStatus::Active, "{end:?}: job not completed");
        assert_eq!(
            state.accounts.get_balance(&other),
            U256::zero(),
            "{end:?}: no reward may be credited"
        );
        assert_eq!(
            state.accounts.get_balance(&addr_of(&submitter)),
            U256::zero(),
            "{end:?}: no reward may be credited"
        );
        assert_eq!(world(&state, &[id]), before, "{end:?}: no state change");
    }
}

#[tokio::test]
async fn gradient_completion_lands_on_commit() {
    arm();
    let (state, exec, _) = fixture();
    let id = JobId(Hash::new([0x44; 32]));
    let other = Address([4; 20]);
    state
        .create_training_job(job(id, vec![other], 1))
        .expect("seed");
    let submitter = pk(0xB2);
    dispatch(&exec, ACT, submitter, gradient(id), End::Commit)
        .await
        .expect("gradient");
    let j = state.get_training_job(&id).expect("job");
    assert_eq!(j.status, JobStatus::Completed);
    assert_eq!(j.gradients_submitted, 2);
    assert_eq!(state.accounts.get_balance(&other), U256::from(50u64));
    assert_eq!(
        state.accounts.get_balance(&addr_of(&submitter)),
        U256::from(50u64)
    );
}

// ────────────────────── below the activation height ──────────────────────

/// Below the height each site is the legacy direct write, exactly as
/// historical blocks were produced with.
#[tokio::test]
async fn below_activation_the_legacy_direct_writes_are_kept() {
    arm();
    let (state, exec, admin) = fixture();
    dispatch(
        &exec,
        LEGACY,
        admin,
        call(gov(), queue_data(PKEY, b"v1", 5)),
        End::Abort,
    )
    .await
    .expect("queue");
    assert!(
        state
            .get_storage(&gov(), &key(b"PENDING:", &PKEY))
            .is_some(),
        "legacy: the governance write is direct"
    );
    dispatch(
        &exec,
        LEGACY,
        admin,
        call(art_model(), register_data(MHASH, CID)),
        End::Abort,
    )
    .await
    .expect("register");
    assert!(
        state.get_model(&ModelId(Hash::new(MHASH))).is_some(),
        "legacy: the model registration is direct"
    );
    assert!(state
        .get_storage(&art(), &key(b"MODEL_CID:", &MHASH))
        .is_some());
    let id = JobId(Hash::new([0x44; 32]));
    state
        .create_training_job(job(id, vec![Address([4; 20])], 1))
        .expect("seed");
    dispatch(&exec, LEGACY, pk(0xB2), gradient(id), End::Abort)
        .await
        .expect("gradient");
    assert_eq!(
        state.get_training_job(&id).expect("job").status,
        JobStatus::Completed,
        "legacy: the job update is direct"
    );
    assert_eq!(
        state.accounts.get_balance(&Address([4; 20])),
        U256::from(50u64),
        "legacy: the reward credit is direct"
    );
}

/// One scripted sequence of every site, committed below the height. Its world
/// digest was recorded on the code before the hardening and must not change:
/// pre-activation replay is byte-identical.
async fn legacy_sequence(state: &Arc<StateDB>, exec: &Executor, admin: PublicKey, h: u64) {
    let t = tx(admin, Some(pk_for(gov())), queue_data(PKEY, b"v1", 0), 0);
    assert!(
        exec.execute_transaction(&block(h), &t)
            .await
            .unwrap()
            .status
    );
    let t = tx(admin, Some(pk_for(gov())), execute_param_data(PKEY), 1);
    assert!(
        exec.execute_transaction(&block(h), &t)
            .await
            .unwrap()
            .status
    );
    let t = tx(
        admin,
        Some(pk_for(art_model())),
        register_data(MHASH, CID),
        2,
    );
    assert!(
        exec.execute_transaction(&block(h), &t)
            .await
            .unwrap()
            .status
    );
    let t = tx(
        admin,
        Some(pk_for(gov())),
        set_admin_data(Address([0xEE; 20])),
        3,
    );
    assert!(
        exec.execute_transaction(&block(h), &t)
            .await
            .unwrap()
            .status
    );
    let id = ModelId(Hash::new(MHASH));
    dispatch(
        exec,
        h,
        admin,
        TransactionType::UpdateModel {
            model_id: id,
            metadata: ModelMetadata {
                name: "v2".into(),
                ..Default::default()
            },
            artifact_cid: Some("bafy-second".into()),
        },
        End::Commit,
    )
    .await
    .expect("update");
    let job_id = JobId(Hash::new([0x44; 32]));
    state
        .create_training_job(job(job_id, vec![Address([4; 20])], 1))
        .expect("seed");
    dispatch(exec, h, pk(0xB2), gradient(job_id), End::Commit)
        .await
        .expect("gradient");
}

#[tokio::test]
async fn below_activation_committed_sequence_is_byte_identical_to_the_legacy_rule() {
    arm();
    let (state, exec, admin) = fixture();
    legacy_sequence(&state, &exec, admin, LEGACY).await;
    let got = world(&state, &[JobId(Hash::new([0x44; 32]))]);
    assert_eq!(
        hex::encode(got.as_bytes()),
        LEGACY_SEQUENCE_DIGEST,
        "the pre-activation result must not change"
    );
}

/// The same committed sequence lands the same state on both sides of the
/// height: routing through the journal changes what a non-committed attempt
/// leaves behind, not what a committed one writes.
#[tokio::test]
async fn committed_sequence_lands_the_same_state_on_both_sides_of_the_height() {
    arm();
    let (s1, e1, a1) = fixture();
    legacy_sequence(&s1, &e1, a1, LEGACY).await;
    let (s2, e2, a2) = fixture();
    legacy_sequence(&s2, &e2, a2, ACT).await;
    let jobs = [JobId(Hash::new([0x44; 32]))];
    assert_eq!(world(&s1, &jobs), world(&s2, &jobs));
}

/// Recorded on the pre-hardening executor (parent commit), see the module doc.
const LEGACY_SEQUENCE_DIGEST: &str =
    "d3d8e7e892e1a446b4f39e278de4624ceab7159c75ee11769829eed4b6dbc709";

// ───────────────────── concurrent attempts (MVCC) ─────────────────────

/// Two attempts pinned at the same version both dispatch `tt`; the first
/// commits. The second must lose its MVCC check, so its stale view of the
/// entry can never be drained over the first one's write.
async fn second_concurrent_attempt_aborts(
    exec: &Executor,
    from: PublicKey,
    tt: impl Fn() -> TransactionType,
) {
    use crate::mvcc::CommitOutcome;
    let b = block(ACT);
    let t = tx(from, None, vec![], 0);
    let pin = exec.commit_coordinator.current_version();
    let mut a = ExecutionContext::new(&b, &t);
    a.journal.lock().pin_at(pin);
    let mut c = ExecutionContext::new(&b, &t);
    c.journal.lock().pin_at(pin);

    exec.execute_transaction_type(tt(), &mut a, addr_of(&from))
        .await
        .expect("first attempt dispatches");
    // The first attempt has not committed, so the second must not see its
    // writes: it dispatches against the same pinned view and succeeds too.
    let second_dispatch = exec
        .execute_transaction_type(tt(), &mut c, addr_of(&from))
        .await;
    assert!(
        second_dispatch.is_ok(),
        "the second attempt saw the first one's uncommitted writes: {second_dispatch:?}"
    );

    let first = exec.commit_coordinator.try_commit(&a.journal.lock());
    assert!(matches!(first, CommitOutcome::Committed { .. }));
    exec.drain_journal(&a.journal);
    let second = exec.commit_coordinator.try_commit(&c.journal.lock());
    assert!(
        matches!(second, CommitOutcome::Aborted { .. }),
        "the second attempt read an entry the first one wrote: {second:?}"
    );
}

#[tokio::test]
async fn concurrent_registration_of_one_model_cannot_both_commit() {
    arm();
    let (state, exec, admin) = fixture();
    second_concurrent_attempt_aborts(&exec, admin, || {
        call(art_model(), register_data(MHASH, CID))
    })
    .await;
    assert_eq!(state.all_models().len(), 1);
}

#[tokio::test]
async fn concurrent_governance_execute_cannot_both_commit() {
    arm();
    let (state, exec, admin) = fixture();
    let mut stored = 0u64.to_le_bytes().to_vec();
    stored.extend_from_slice(b"v1");
    state.set_storage(gov(), key(b"PENDING:", &PKEY), stored);
    second_concurrent_attempt_aborts(&exec, admin, || call(gov(), execute_param_data(PKEY))).await;
    assert_eq!(state.get_storage(&gov(), &key(b"PENDING:", &PKEY)), None);
}

#[tokio::test]
async fn concurrent_inference_usage_updates_cannot_both_commit() {
    arm();
    if crate::activation::pba_hardening_active(ACT) {
        return;
    }
    let (state, exec, admin) = inference_fixture();
    second_concurrent_attempt_aborts(&exec, admin, infer).await;
    let m = state.get_model(&ModelId(Hash::new(MHASH))).expect("model");
    assert_eq!(m.usage_stats.total_inferences, 1);
}

#[tokio::test]
async fn concurrent_gradient_submissions_cannot_both_commit() {
    arm();
    let (state, exec, _) = fixture();
    let id = JobId(Hash::new([0x44; 32]));
    state.create_training_job(job(id, vec![], 0)).expect("seed");
    second_concurrent_attempt_aborts(&exec, pk(0xB2), || gradient(id)).await;
    assert_eq!(
        state
            .get_training_job(&id)
            .expect("job")
            .gradients_submitted,
        1
    );
}

/// Within one tx the journal-first view is used: a later read sees the
/// tx's own earlier delete, not the committed value.
#[tokio::test]
async fn in_tx_reads_see_the_tx_s_own_writes_and_deletes() {
    arm();
    let (state, exec, admin) = fixture();
    let mut stored = 0u64.to_le_bytes().to_vec();
    stored.extend_from_slice(b"v1");
    state.set_storage(gov(), key(b"PENDING:", &PKEY), stored);
    let b = block(ACT);
    let t = tx(admin, None, vec![], 0);
    let mut ctx = ExecutionContext::new(&b, &t);
    ctx.journal
        .lock()
        .pin_at(exec.commit_coordinator.current_version());
    let from = addr_of(&admin);
    exec.execute_transaction_type(call(gov(), execute_param_data(PKEY)), &mut ctx, from)
        .await
        .expect("execute");
    // The same tx executing it again must find no pending entry.
    let again = exec
        .execute_transaction_type(call(gov(), execute_param_data(PKEY)), &mut ctx, from)
        .await;
    assert!(
        matches!(&again, Err(ExecutionError::Reverted(m)) if m.contains("No such pending")),
        "{again:?}"
    );
    let mut get = selector4(b"getParam(bytes32)").to_vec();
    get.extend_from_slice(&PKEY);
    exec.execute_transaction_type(call(gov(), get), &mut ctx, from)
        .await
        .expect("getParam");
    assert_eq!(ctx.output, b"v1".to_vec(), "reads its own pending param");
    // Nothing reached state_db yet.
    assert_eq!(state.get_storage(&gov(), &key(b"PARAM:", &PKEY)), None);
}
