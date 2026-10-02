//! Independent replay of a federated LoRA round (HUP-S9.2).
//!
//! The coordinator (citrate-compute-pool `citrate-fl-round`) aggregates a round
//! by sending each chunk to a node's 0x0110 and commits the roots to
//! `FederatedRoundLedger`. This crate checks that work without trusting any of
//! it: it is a second implementation of `docs/fl/FL_ROUND_V1.md`, written
//! against the spec, sharing no code with the coordinator, and it runs the
//! precompile's own kernel (`citrate_execution::precompiles::q16::belnap`) in
//! process instead of asking a node.
//!
//! What a replay establishes, given the bundle, the participants' delta
//! artifacts and (optionally) the start and merged adapters:
//!
//! 1. the config hash and round id follow from the config;
//! 2. every participant is on the roster, in strictly ascending order, and its
//!    artifact hashes to the value it signed, re-derives the delta root it
//!    signed, and carries a signature that recovers to it;
//! 3. every chunk input rebuilt from those artifacts hashes to the committed
//!    leaf, and the kernel's output for it hashes to the committed output leaf;
//! 4. the three roots and the record digest follow;
//! 5. the merged adapter is exactly the start adapter plus the kernel's
//!    aggregate, and hashes to the committed adapter hash.
//!
//! Every disagreement is reported; nothing is fixed up.

use std::path::Path;

use serde::Deserialize;
use sha3::{Digest as _, Keccak256};

pub type B32 = [u8; 32];
pub type Addr = [u8; 20];

pub fn keccak(parts: &[&[u8]]) -> B32 {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha256(b: &[u8]) -> B32 {
    sha2::Sha256::digest(b).into()
}

pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn unhex<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let v = hex::decode(s.trim().trim_start_matches("0x"))?;
    v.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{s:?}: {} bytes, expected {N}", v.len()))
}

// ── the tree (FL_ROUND_V1 §4) ───────────────────────────────────────

pub fn leaf(i: u32, payload: &B32) -> B32 {
    keccak(&[&[0x00], &i.to_be_bytes(), payload])
}

pub fn root(payloads: &[B32]) -> B32 {
    if payloads.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<B32> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| leaf(i as u32, p))
        .collect();
    level.resize(payloads.len().next_power_of_two(), [0u8; 32]);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| keccak(&[&[0x01], &p[0], &p[1]]))
            .collect();
    }
    level[0]
}

// ── the bundle, as published ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Config {
    pub chain_id: u64,
    pub ledger: String,
    pub cluster_id: String,
    pub base_model_sha256: String,
    pub start_adapter_sha256: String,
    pub roster: Vec<String>,
    pub min_participants: u16,
    pub chunk_dim: u32,
    pub value_scale_log2: u8,
    pub threshold_pos: i64,
    pub threshold_neg: i64,
    pub confidence: String,
    pub weight: String,
    pub max_values: u64,
}

#[derive(Debug, Deserialize)]
pub struct WorkerResult {
    pub round_id: String,
    pub worker: String,
    pub delta_root: String,
    pub delta_sha256: String,
    pub n_values: u64,
    pub chunk_dim: u32,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct Participant {
    pub worker: String,
    pub delta_root: String,
    pub delta_sha256: String,
    pub result: WorkerResult,
}

#[derive(Debug, Deserialize)]
pub struct Bundle {
    pub ordinal: u64,
    pub round_id: String,
    pub config_hash: String,
    pub config: Config,
    pub participants: Vec<Participant>,
    pub n_values: u64,
    pub chunks: u32,
    pub input_hashes: Vec<String>,
    pub output_hashes: Vec<String>,
    pub participants_root: String,
    pub input_root: String,
    pub output_root: String,
    pub adapter_sha256: String,
    pub record_digest: String,
}

/// The on-chain view of the cluster's rules (from `getCluster`), when the
/// caller has it, so the replay can check the config agrees with the chain.
#[derive(Debug, Clone, Copy)]
pub struct ChainRules {
    pub min_participants: u16,
    pub chunk_dim: u32,
    pub value_scale_log2: u8,
    pub threshold_pos: i64,
    pub threshold_neg: i64,
}

// ── FL_ROUND_V1 §2-§3 ────────────────────────────────────────────────

fn rule_code(s: &str) -> anyhow::Result<u8> {
    match s {
        "nonzero" | "uniform" => Ok(1),
        other => anyhow::bail!("unknown rule {other:?}"),
    }
}

pub fn config_hash(c: &Config) -> anyhow::Result<B32> {
    let mut roster = Vec::new();
    for a in &c.roster {
        roster.extend_from_slice(&unhex::<20>(a)?);
    }
    Ok(keccak(&[
        b"citrate-fl-round-config/1",
        &c.chain_id.to_be_bytes(),
        &unhex::<20>(&c.ledger)?,
        &unhex::<32>(&c.cluster_id)?,
        &unhex::<32>(&c.base_model_sha256)?,
        &unhex::<32>(&c.start_adapter_sha256)?,
        &c.min_participants.to_be_bytes(),
        &c.chunk_dim.to_be_bytes(),
        &[c.value_scale_log2],
        &c.threshold_pos.to_be_bytes(),
        &c.threshold_neg.to_be_bytes(),
        &[rule_code(&c.confidence)?, rule_code(&c.weight)?],
        &c.max_values.to_be_bytes(),
        &(c.roster.len() as u32).to_be_bytes(),
        &roster,
    ]))
}

pub fn round_id(c: &Config, ordinal: u64) -> anyhow::Result<B32> {
    Ok(keccak(&[
        b"citrate-fl-round-key/1",
        &c.chain_id.to_be_bytes(),
        &unhex::<20>(&c.ledger)?,
        &unhex::<32>(&c.cluster_id)?,
        &ordinal.to_be_bytes(),
    ]))
}

pub fn delta_digest(
    round: &B32,
    worker: &Addr,
    delta_root: &B32,
    delta_sha: &B32,
    n: u64,
    chunk: u32,
) -> B32 {
    keccak(&[
        b"citrate-fl-delta/1",
        round,
        worker,
        delta_root,
        delta_sha,
        &n.to_be_bytes(),
        &chunk.to_be_bytes(),
    ])
}

/// Recover the address behind a 65-byte `r ‖ s ‖ v` signature over a digest.
pub fn recover(digest: &B32, sig: &[u8]) -> anyhow::Result<Addr> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    anyhow::ensure!(sig.len() == 65, "signature is {} bytes", sig.len());
    let s = Signature::from_slice(&sig[..64])?;
    let v = match sig[64] {
        27 | 28 => sig[64] - 27,
        v => v,
    };
    let id = RecoveryId::from_byte(v).ok_or_else(|| anyhow::anyhow!("bad recovery id {v}"))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &s, id)?;
    let point = vk.to_encoded_point(false);
    let h = keccak(&[&point.as_bytes()[1..]]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Ok(a)
}

/// A parsed `FLD1` delta artifact.
#[derive(Debug, Clone)]
pub struct Delta {
    pub scale: u8,
    pub round: B32,
    pub worker: Addr,
    pub start: B32,
    pub chunk_dim: u32,
    pub values: Vec<i64>,
}

pub fn parse_delta(b: &[u8], max_values: u64) -> anyhow::Result<Delta> {
    const H: usize = 168;
    anyhow::ensure!(b.len() >= H && &b[0..4] == b"FLD1", "not an FLD1 artifact");
    anyhow::ensure!(b[4..6] == [0, 1] && b[7] == 0, "unsupported FLD1 version");
    let n = u64::from_be_bytes(b[160..168].try_into()?);
    anyhow::ensure!(n <= max_values, "{n} values over the round limit");
    anyhow::ensure!(
        b.len() as u64 == H as u64 + 8 * n,
        "length does not match its count"
    );
    Ok(Delta {
        scale: b[6],
        round: b[8..40].try_into()?,
        worker: b[40..60].try_into()?,
        start: b[60..92].try_into()?,
        chunk_dim: u32::from_be_bytes(b[156..160].try_into()?),
        values: b[H..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| i64::from_be_bytes(*c))
            .collect(),
    })
}

fn row(v: &[i64], dim: usize, c: usize) -> &[i64] {
    let lo = (c * dim).min(v.len());
    &v[lo..(lo + dim).min(v.len())]
}

fn be(v: &[i64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_be_bytes()).collect()
}

/// The 0x0110 input for one chunk under the v1 rules (nonzero confidence,
/// uniform weight).
pub fn chunk_input(rows: &[&[i64]], tpos: i64, tneg: i64) -> Vec<u8> {
    let n = rows.len();
    let dim = rows.first().map_or(0, |r| r.len());
    let mut b = Vec::new();
    b.extend_from_slice(&(dim as u32).to_be_bytes());
    b.extend_from_slice(&(n as u32).to_be_bytes());
    for r in rows {
        b.extend_from_slice(&be(r));
    }
    for r in rows {
        for v in *r {
            let c: i64 = if *v == 0 { 0 } else { 65536 };
            b.extend_from_slice(&c.to_be_bytes());
        }
    }
    let w = 65536 / n.max(1) as i64;
    for _ in 0..n {
        b.extend_from_slice(&w.to_be_bytes());
    }
    b.extend_from_slice(&tpos.to_be_bytes());
    b.extend_from_slice(&tneg.to_be_bytes());
    b
}

/// The kernel 0x0110 runs, in process.
pub fn kernel(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    citrate_execution::precompiles::q16::belnap::aggregate(input)
        .map_err(|e| anyhow::anyhow!("0x0110 kernel refused the input: {e}"))
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

#[allow(clippy::too_many_arguments)]
pub fn record_digest(
    chain_id: u64,
    ledger: &Addr,
    round: &B32,
    config: &B32,
    parts: &B32,
    input: &B32,
    output: &B32,
    adapter: &B32,
    n_values: u64,
    chunks: u32,
    participants: u16,
) -> B32 {
    let mut l = [0u8; 32];
    l[12..].copy_from_slice(ledger);
    keccak(&[
        &word(chain_id),
        &l,
        round,
        config,
        parts,
        input,
        output,
        adapter,
        &word(n_values),
        &word(u64::from(chunks)),
        &word(u64::from(participants)),
    ])
}

// ── GGUF, just enough to check the merge ────────────────────────────

/// One tensor: name, GGML dims, values.
pub type Tensor = (String, Vec<u64>, Vec<f32>);

/// Every tensor of an F32 GGUF file, in file order (the merged adapter is F32).
pub fn gguf_tensors(b: &[u8]) -> anyhow::Result<Vec<Tensor>> {
    struct R<'a> {
        b: &'a [u8],
        p: usize,
    }
    impl R<'_> {
        fn take(&mut self, n: usize) -> anyhow::Result<&[u8]> {
            anyhow::ensure!(self.p + n <= self.b.len(), "gguf truncated");
            let s = &self.b[self.p..self.p + n];
            self.p += n;
            Ok(s)
        }
        fn u32(&mut self) -> anyhow::Result<u32> {
            Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
        }
        fn u64(&mut self) -> anyhow::Result<u64> {
            Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
        }
        fn s(&mut self) -> anyhow::Result<String> {
            let n = usize::try_from(self.u64()?)?;
            Ok(String::from_utf8(self.take(n)?.to_vec())?)
        }
        fn skip_value(&mut self, ty: u32) -> anyhow::Result<Option<u32>> {
            let fixed = match ty {
                0 | 1 | 7 => 1,
                2 | 3 => 2,
                4..=6 => 4,
                10..=12 => 8,
                8 => {
                    self.s()?;
                    return Ok(None);
                }
                9 => {
                    let et = self.u32()?;
                    let n = self.u64()?;
                    for _ in 0..n {
                        self.skip_value(et)?;
                    }
                    return Ok(None);
                }
                t => anyhow::bail!("gguf value type {t}"),
            };
            let v = self.take(fixed)?;
            Ok((ty == 4).then(|| u32::from_le_bytes([v[0], v[1], v[2], v[3]])))
        }
    }
    let mut r = R { b, p: 0 };
    anyhow::ensure!(r.take(4)? == b"GGUF", "not GGUF");
    r.u32()?;
    let nt = r.u64()?;
    let nkv = r.u64()?;
    let mut align = 32u64;
    for _ in 0..nkv {
        let k = r.s()?;
        let ty = r.u32()?;
        let v = r.skip_value(ty)?;
        if k == "general.alignment" {
            align = u64::from(v.ok_or_else(|| anyhow::anyhow!("bad alignment"))?);
        }
    }
    let mut infos = Vec::new();
    for _ in 0..nt {
        let name = r.s()?;
        let nd = r.u32()?;
        let mut dims = Vec::new();
        for _ in 0..nd {
            dims.push(r.u64()?);
        }
        let ty = r.u32()?;
        let off = r.u64()?;
        infos.push((name, dims, ty, off));
    }
    let data = (r.p as u64).div_ceil(align) * align;
    let mut out = Vec::new();
    for (name, dims, ty, off) in infos {
        let n = usize::try_from(dims.iter().product::<u64>())?;
        let start = usize::try_from(data + off)?;
        let vals = match ty {
            0 => b
                .get(start..start + 4 * n)
                .ok_or_else(|| anyhow::anyhow!("tensor {name} out of range"))?
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| f32::from_le_bytes(*c))
                .collect(),
            t => anyhow::bail!("tensor {name}: type {t} (the merge is written as F32)"),
        };
        out.push((name, dims, vals));
    }
    Ok(out)
}

// ── the replay ──────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize)]
pub struct Report {
    pub participants: usize,
    pub chunks: u32,
    pub config_hash: String,
    pub round_id: String,
    pub participants_root: String,
    pub input_root: String,
    pub output_root: String,
    pub record_digest: String,
    pub merged_adapter_checked: bool,
    pub mismatches: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.mismatches.is_empty()
    }
}

pub struct Inputs<'a> {
    pub bundle: &'a Bundle,
    pub deltas: &'a Path,
    pub start_adapter: Option<&'a [u8]>,
    pub merged_adapter: Option<&'a [u8]>,
    pub chain_rules: Option<ChainRules>,
}

pub fn replay(inp: &Inputs<'_>) -> anyhow::Result<Report> {
    let b = inp.bundle;
    let c = &b.config;
    let mut rep = Report::default();
    let mut mis: Vec<String> = Vec::new();

    let ch = config_hash(c)?;
    let rid = round_id(c, b.ordinal)?;
    if hex0x(&ch) != b.config_hash.to_lowercase() {
        mis.push("config hash does not follow from the config".into());
    }
    if hex0x(&rid) != b.round_id.to_lowercase() {
        mis.push("round id does not follow from the config and ordinal".into());
    }
    if let Some(r) = inp.chain_rules {
        if r.min_participants != c.min_participants
            || r.chunk_dim != c.chunk_dim
            || r.value_scale_log2 != c.value_scale_log2
            || r.threshold_pos != c.threshold_pos
            || r.threshold_neg != c.threshold_neg
        {
            mis.push("the config's rules differ from the cluster's rules on chain".into());
        }
    }
    let roster: Vec<Addr> = c
        .roster
        .iter()
        .map(|a| unhex::<20>(a))
        .collect::<Result<_, _>>()?;
    let start_sha = unhex::<32>(&c.start_adapter_sha256)?;
    if b.participants.len() < usize::from(c.min_participants) {
        mis.push(format!(
            "{} participants, below the minimum of {}",
            b.participants.len(),
            c.min_participants
        ));
    }

    let mut deltas: Vec<Delta> = Vec::new();
    let mut part_payloads = Vec::new();
    let mut prev: Option<Addr> = None;
    for (i, p) in b.participants.iter().enumerate() {
        let w = unhex::<20>(&p.worker)?;
        let dr = unhex::<32>(&p.delta_root)?;
        let ds = unhex::<32>(&p.delta_sha256)?;
        if let Some(prev) = prev {
            if w <= prev {
                mis.push(format!("participant {i} breaks strictly ascending order"));
            }
        }
        prev = Some(w);
        if !roster.contains(&w) {
            mis.push(format!("participant {i} is not on the roster"));
        }
        let r = &p.result;
        if unhex::<20>(&r.worker)? != w
            || unhex::<32>(&r.delta_root)? != dr
            || unhex::<32>(&r.delta_sha256)? != ds
            || unhex::<32>(&r.round_id)? != rid
        {
            mis.push(format!(
                "participant {i}: the signed result disagrees with the bundle"
            ));
        }
        let digest = delta_digest(&rid, &w, &dr, &ds, r.n_values, r.chunk_dim);
        match recover(&digest, &hex::decode(r.signature.trim_start_matches("0x"))?) {
            Ok(a) if a == w => {}
            _ => mis.push(format!(
                "participant {i}: signature does not recover to the worker"
            )),
        }
        let path = inp.deltas.join(format!("{}.fld", hex::encode(ds)));
        let bytes = std::fs::read(&path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        if sha256(&bytes) != ds {
            mis.push(format!(
                "participant {i}: artifact does not hash to the signed value"
            ));
        }
        let d = parse_delta(&bytes, c.max_values)?;
        if d.round != rid
            || d.worker != w
            || d.start != start_sha
            || d.chunk_dim != c.chunk_dim
            || d.scale != c.value_scale_log2
            || d.values.len() as u64 != b.n_values
            || r.n_values != b.n_values
            || r.chunk_dim != c.chunk_dim
        {
            mis.push(format!(
                "participant {i}: artifact header does not match the round"
            ));
        }
        let dim = c.chunk_dim as usize;
        let nchunks = d.values.len().div_ceil(dim.max(1));
        let rows: Vec<B32> = (0..nchunks)
            .map(|k| keccak(&[&be(row(&d.values, dim, k))]))
            .collect();
        if root(&rows) != dr {
            mis.push(format!(
                "participant {i}: artifact does not re-derive its delta root"
            ));
        }
        part_payloads.push(keccak(&[&w, &dr]));
        deltas.push(d);
    }

    let dim = c.chunk_dim as usize;
    let chunks = (b.n_values as usize).div_ceil(dim.max(1));
    if chunks as u64 != u64::from(b.chunks) {
        mis.push("chunk count does not follow from n_values and chunk_dim".into());
    }
    if b.input_hashes.len() != chunks || b.output_hashes.len() != chunks {
        mis.push("leaf lists are not one per chunk".into());
    }
    let mut ins = Vec::with_capacity(chunks);
    let mut outs = Vec::with_capacity(chunks);
    let mut agg: Vec<i64> = Vec::with_capacity(b.n_values as usize);
    for k in 0..chunks {
        let rows: Vec<&[i64]> = deltas.iter().map(|d| row(&d.values, dim, k)).collect();
        let input = chunk_input(&rows, c.threshold_pos, c.threshold_neg);
        let output = kernel(&input)?;
        let (ih, oh) = (keccak(&[&input]), keccak(&[&output]));
        if b.input_hashes.get(k).map(|s| s.to_lowercase()) != Some(hex0x(&ih)) {
            mis.push(format!(
                "chunk {k}: committed input leaf differs from the rebuilt input"
            ));
        }
        if b.output_hashes.get(k).map(|s| s.to_lowercase()) != Some(hex0x(&oh)) {
            mis.push(format!(
                "chunk {k}: committed output differs from the 0x0110 kernel's"
            ));
        }
        let w = rows.first().map_or(0, |r| r.len());
        agg.extend(
            output
                .get(..8 * w)
                .ok_or_else(|| anyhow::anyhow!("chunk {k}: kernel output too short"))?
                .as_chunks::<8>()
                .0
                .iter()
                .map(|x| i64::from_be_bytes(*x)),
        );
        ins.push(ih);
        outs.push(oh);
    }
    let (pr, ir, or) = (root(&part_payloads), root(&ins), root(&outs));
    for (name, got, want) in [
        ("participants", pr, &b.participants_root),
        ("input", ir, &b.input_root),
        ("output", or, &b.output_root),
    ] {
        if hex0x(&got) != want.to_lowercase() {
            mis.push(format!("{name} root differs from the replay"));
        }
    }
    let adapter = unhex::<32>(&b.adapter_sha256)?;
    let rd = record_digest(
        c.chain_id,
        &unhex::<20>(&c.ledger)?,
        &rid,
        &ch,
        &pr,
        &ir,
        &or,
        &adapter,
        b.n_values,
        b.chunks,
        b.participants.len() as u16,
    );
    if hex0x(&rd) != b.record_digest.to_lowercase() {
        mis.push("record digest differs from the replay".into());
    }

    if let (Some(start), Some(merged)) = (inp.start_adapter, inp.merged_adapter) {
        if sha256(start) != start_sha {
            mis.push("start adapter does not hash to the config".into());
        }
        if sha256(merged) != adapter {
            mis.push("merged adapter does not hash to the committed adapter hash".into());
        }
        let s = gguf_tensors(start)?;
        let m = gguf_tensors(merged)?;
        let mut order: Vec<usize> = (0..s.len()).collect();
        order.sort_by(|a, b| s[*a].0.cmp(&s[*b].0));
        let denom = 65536.0f64 * 2f64.powi(i32::from(c.value_scale_log2));
        let mut k = 0usize;
        let mut ok = s.len() == m.len();
        for fi in order {
            if !ok {
                break;
            }
            let (sn, sd, sv) = &s[fi];
            let (mn, md, mv) = &m[fi];
            if sn != mn || sd != md || sv.len() != mv.len() {
                ok = false;
                break;
            }
            for (a, got) in sv.iter().zip(mv.iter()) {
                let want = (f64::from(*a) + agg.get(k).copied().unwrap_or(0) as f64 / denom) as f32;
                if want.to_bits() != got.to_bits() {
                    ok = false;
                    break;
                }
                k += 1;
            }
        }
        if !ok || k != agg.len() {
            mis.push("merged adapter is not the start adapter plus the kernel's aggregate".into());
        }
        rep.merged_adapter_checked = true;
    }

    rep.participants = b.participants.len();
    rep.chunks = b.chunks;
    rep.config_hash = hex0x(&ch);
    rep.round_id = hex0x(&rid);
    rep.participants_root = hex0x(&pr);
    rep.input_root = hex0x(&ir);
    rep.output_root = hex0x(&or);
    rep.record_digest = hex0x(&rd);
    rep.mismatches = mis;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_pads_to_a_power_of_two_with_zero_words() {
        let p = |n: u8| [n; 32];
        let node = |l: &B32, r: &B32| keccak(&[&[0x01], l, r]);
        let want = node(
            &node(&leaf(0, &p(1)), &leaf(1, &p(2))),
            &node(&leaf(2, &p(3)), &[0u8; 32]),
        );
        assert_eq!(root(&[p(1), p(2), p(3)]), want);
        assert_eq!(root(&[p(9)]), leaf(0, &p(9)));
    }

    #[test]
    fn malformed_artifacts_are_refused() {
        let mut a = b"FLD1".to_vec();
        a.extend_from_slice(&[0, 1, 8, 0]);
        a.extend_from_slice(&[0u8; 148]);
        a.extend_from_slice(&[0, 0, 0, 4]); // chunk_dim
        a.extend_from_slice(&2u64.to_be_bytes()); // two values
        a.extend_from_slice(&5i64.to_be_bytes());
        a.extend_from_slice(&(-6i64).to_be_bytes());
        let d = parse_delta(&a, 10).expect("parse");
        assert_eq!(d.values, vec![5, -6]);
        assert_eq!(d.chunk_dim, 4);
        assert!(parse_delta(&a, 1).is_err(), "over the round limit");
        assert!(parse_delta(&a[..a.len() - 1], 10).is_err(), "short");
        let mut bad = a.clone();
        bad[0] = b'X';
        assert!(parse_delta(&bad, 10).is_err(), "magic");
        let mut bad = a;
        bad[7] = 1;
        assert!(parse_delta(&bad, 10).is_err(), "reserved byte");
    }

    #[test]
    fn signatures_recover_with_either_v_convention() {
        use k256::ecdsa::SigningKey;
        // A throwaway key built at run time.
        let mut seed = [0u8; 32];
        seed[31] = 0x42;
        let sk = SigningKey::from_bytes(&seed.into()).expect("key");
        let digest = keccak(&[b"citrate-fl-replay test"]);
        let (sig, id) = sk.sign_prehash_recoverable(&digest).expect("sign");
        let point = sk.verifying_key().to_encoded_point(false);
        let h = keccak(&[&point.as_bytes()[1..]]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&h[12..]);
        let mut raw = sig.to_bytes().to_vec();
        raw.push(id.to_byte());
        assert_eq!(recover(&digest, &raw).expect("recover"), addr);
        let last = raw.len() - 1;
        raw[last] += 27;
        assert_eq!(recover(&digest, &raw).expect("recover"), addr);
        assert!(recover(&digest, &raw[..64]).is_err());
    }

    #[test]
    fn the_chunk_input_follows_the_v1_rules() {
        let rows: [&[i64]; 3] = [&[0, 7], &[1, 0], &[-2, 3]];
        let b = chunk_input(&rows, 32768, -32768);
        assert_eq!(b.len(), 24 + 16 * 3 * 2 + 8 * 3);
        let word = |o: usize| i64::from_be_bytes(b[o..o + 8].try_into().expect("8"));
        // Confidence: 0 where the row is 0, else 1.0.
        assert_eq!(word(8 + 48), 0);
        assert_eq!(word(8 + 48 + 8), 65536);
        // Uniform weights floor(1/3).
        assert_eq!(word(8 + 96), 21845);
        assert_eq!(word(b.len() - 8), -32768);
    }
}
