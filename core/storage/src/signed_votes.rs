// citrate/core/storage/src/signed_votes.rs
//
// Carrying a voting validator's checkpoint signed-vote record across a
// replacement of its chain database .
//
// The record is the double-sign protection of checkpoint finality
// (`citrate_consensus::checkpoint_gadget`): `dag_metadata`
// `checkpoint_signed:<chain_id>:<height>` -> the 32-byte hash this node signed,
// and `checkpoint_signed_meta:<chain_id>` -> `floor || highest`. It lives in
// the chain database, so any procedure that replaces that database (a cold
// resync, a reseed from another node's snapshot) discards it unless it is
// carried over (docs/consensus/CHECKPOINT_FINALITY_WIRING.md, option (a)).
// A validator that keeps `proposer.key` without it can later sign a different
// hash at a height it already signed.
//
// Used by the node's cold resync (`node/src/cold_resync.rs`) and by the
// operator tool `examples/signed_vote_carry.rs` (first used for the r1007
// reseed of 2026-11-14).
//
// The carry is never less strict than either side: vote records are copied
// and a record that conflicts with one already in the target is refused; the
// watermarks are merged by taking the larger floor and the larger highest
// (every node writes a watermark, a non-signer too, because the floor follows
// finalization).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use citrate_consensus::checkpoint_gadget::{
    SignedVoteMeta, SIGNED_VOTE_KEY_PREFIX, SIGNED_VOTE_META_PREFIX,
};

use crate::db::column_families::CF_DAG_METADATA;
use crate::db::RocksDB;

/// One stored entry: key and value bytes.
pub type Record = (Vec<u8>, Vec<u8>);

/// What a record set holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Every entry (votes and watermarks).
    pub records: usize,
    /// Vote entries.
    pub votes: usize,
    /// Lowest and highest voted height.
    pub vote_heights: Option<(u64, u64)>,
    /// The watermarks, per chain id.
    pub meta: Vec<(String, SignedVoteMeta)>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} record(s), {} vote(s)", self.records, self.votes)?;
        if let Some((lo, hi)) = self.vote_heights {
            write!(f, " at heights {lo}..={hi}")?;
        }
        for (chain, m) in &self.meta {
            write!(
                f,
                "; chain {chain}: floor {} highest {}",
                m.floor, m.highest
            )?;
        }
        Ok(())
    }
}

fn is_meta(key: &[u8]) -> bool {
    key.starts_with(SIGNED_VOTE_META_PREFIX.as_bytes())
}

fn is_record(key: &[u8]) -> bool {
    is_meta(key) || key.starts_with(SIGNED_VOTE_KEY_PREFIX.as_bytes())
}

/// Every signed-vote entry in `db`, in key order. A read error or a value that
/// does not decrypt fails the export: a vote missing
/// from the carry is a height this validator could sign again.
pub fn export(db: &RocksDB) -> Result<Vec<Record>> {
    // Both prefixes start with "checkpoint_signed"; scan that, keep only the
    // two kinds (the finalized-certificate prefix is "checkpoint:").
    let common = SIGNED_VOTE_KEY_PREFIX.trim_end_matches(':').as_bytes();
    let mut out = Vec::new();
    for (k, v) in db.prefix_entries_strict_cf(CF_DAG_METADATA, common)? {
        if is_record(&k) {
            out.push((k.to_vec(), v.to_vec()));
        }
    }
    Ok(out)
}

/// Describe a record set.
pub fn summarize(recs: &[Record]) -> Result<Summary> {
    let mut s = Summary {
        records: recs.len(),
        ..Summary::default()
    };
    for (k, v) in recs {
        let key = std::str::from_utf8(k).context("signed-vote key is not UTF-8")?;
        if let Some(chain) = key.strip_prefix(SIGNED_VOTE_META_PREFIX) {
            let m = SignedVoteMeta::decode(v)
                .ok_or_else(|| anyhow!("watermark {key}: {} bytes, expected 16", v.len()))?;
            s.meta.push((chain.to_string(), m));
        } else if let Some(rest) = key.strip_prefix(SIGNED_VOTE_KEY_PREFIX) {
            let h: u64 = rest
                .rsplit(':')
                .next()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| anyhow!("vote key {key}: no height"))?;
            if v.len() != 32 {
                bail!("vote {key}: {} bytes, expected 32", v.len());
            }
            s.votes = s.votes.saturating_add(1);
            s.vote_heights = Some(match s.vote_heights {
                None => (h, h),
                Some((lo, hi)) => (lo.min(h), hi.max(h)),
            });
        }
    }
    Ok(s)
}

/// Union of two record sets, as [`import`] would leave them: votes must agree
/// where both have one (a conflict is an error), watermarks take the larger
/// floor and the larger highest.
pub fn merge(a: &[Record], b: &[Record]) -> Result<Vec<Record>> {
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (k, v) in a.iter().chain(b.iter()) {
        if !is_record(k) {
            bail!("not a signed-vote entry: {}", String::from_utf8_lossy(k));
        }
        match out.get(k) {
            None => {
                out.insert(k.clone(), v.clone());
            }
            Some(cur) if cur == v => {}
            Some(cur) if is_meta(k) => {
                let x =
                    SignedVoteMeta::decode(cur).ok_or_else(|| anyhow!("watermark: bad length"))?;
                let y =
                    SignedVoteMeta::decode(v).ok_or_else(|| anyhow!("watermark: bad length"))?;
                let m = SignedVoteMeta {
                    floor: x.floor.max(y.floor),
                    highest: x.highest.max(y.highest),
                };
                out.insert(k.clone(), m.encode());
            }
            Some(_) => bail!(
                "conflicting signed-vote records for {}: refusing (the two sides signed different \
                 hashes at that height)",
                String::from_utf8_lossy(k)
            ),
        }
    }
    Ok(out.into_iter().collect())
}

/// Write `recs` into `db`, merged with what it already holds (see [`merge`]),
/// in one synced batch, then read them back. Returns what `db` holds after.
pub fn import(db: &RocksDB, recs: &[Record]) -> Result<Vec<Record>> {
    let before = export(db)?;
    let merged = merge(&before, recs)?;
    let mut batch = db.batch();
    for (k, v) in &merged {
        db.batch_put_cf(&mut batch, CF_DAG_METADATA, k, v)?;
    }
    db.write_batch_sync(batch)?;
    db.flush()?;
    let after = export(db)?;
    if after != merged {
        bail!("signed-vote read-back after import does not match what was written");
    }
    Ok(after)
}

/// The body form: one `hex(key) hex(value)` line per record.
pub fn encode(recs: &[Record]) -> String {
    let mut s = String::new();
    for (k, v) in recs {
        s.push_str(&hex::encode(k));
        s.push(' ');
        s.push_str(&hex::encode(v));
        s.push('\n');
    }
    s
}

/// Parse [`encode`]'s form.
pub fn decode(text: &str) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(k), Some(v), None) = (it.next(), it.next(), it.next()) else {
            bail!(
                "line {}: expected `hex(key) hex(value)`",
                n.saturating_add(1)
            );
        };
        let rec = (hex::decode(k)?, hex::decode(v)?);
        if !is_record(&rec.0) {
            bail!("line {}: not a signed-vote entry", n.saturating_add(1));
        }
        out.push(rec);
    }
    Ok(out)
}

/// What a carry file is bound to: a record is only ever
/// imported into the same chain, genesis and validator it was exported from.
/// `None` fields are not bound (unknown where the file was written).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Binding {
    pub chain_id: Option<u64>,
    /// Hex of the genesis block hash.
    pub genesis: Option<String>,
    /// Hex of the validator's address (its coinbase / staker), lower case,
    /// no `0x`.
    pub validator: Option<String>,
}

impl Binding {
    /// Normalize an address or hash: lower-case hex without `0x`; empty and
    /// all-zero read as unbound.
    pub fn normalize(s: &str) -> Option<String> {
        let t = s.trim().trim_start_matches("0x").to_ascii_lowercase();
        (!t.is_empty() && t.chars().any(|c| c != '0')).then_some(t)
    }

    /// Every field bound in `expected` must be bound to the same value here.
    pub fn check(&self, expected: &Binding) -> Result<()> {
        fn field<T: PartialEq + std::fmt::Debug>(
            name: &str,
            have: &Option<T>,
            want: &Option<T>,
        ) -> Result<()> {
            match (have, want) {
                (_, None) => Ok(()),
                (Some(h), Some(w)) if h == w => Ok(()),
                (h, Some(w)) => bail!(
                    "signed-vote carry file is bound to {name} {h:?}, this node is {w:?}: refusing"
                ),
            }
        }
        field("chain id", &self.chain_id, &expected.chain_id)?;
        field("genesis", &self.genesis, &expected.genesis)?;
        field("validator", &self.validator, &expected.validator)
    }
}

const FILE_MAGIC: &str = "citrate-signed-votes 2";

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("-")
}

/// The carry file: a header binding it to its chain, genesis and validator,
/// the record count and a BLAKE3 checksum of the body, then the body.
pub fn encode_file(recs: &[Record], binding: &Binding) -> String {
    let body = encode(recs);
    let chain = binding
        .chain_id
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{FILE_MAGIC}\nchain_id {chain}\ngenesis {}\nvalidator {}\nrecords {}\nblake3 {}\n{body}",
        opt(&binding.genesis),
        opt(&binding.validator),
        recs.len(),
        blake3::hash(body.as_bytes()).to_hex()
    )
}

/// Parse and verify [`encode_file`]'s form: magic, checksum, record count.
/// Returns the binding it carries and its records.
pub fn decode_file(text: &str) -> Result<(Binding, Vec<Record>)> {
    let mut lines = text.splitn(7, '\n');
    let mut next = |what: &str| -> Result<String> {
        let l = lines
            .next()
            .ok_or_else(|| anyhow!("signed-vote carry file: missing {what}"))?;
        match what {
            "magic" => Ok(l.to_string()),
            _ => l
                .strip_prefix(what)
                .and_then(|r| r.strip_prefix(' '))
                .map(str::to_string)
                .ok_or_else(|| anyhow!("signed-vote carry file: bad {what} line")),
        }
    };
    if next("magic")? != FILE_MAGIC {
        bail!("not a signed-vote carry file (expected `{FILE_MAGIC}`)");
    }
    let chain = next("chain_id")?;
    let genesis = next("genesis")?;
    let validator = next("validator")?;
    let count: usize = next("records")?.parse().context("record count")?;
    let sum = next("blake3")?;
    let body = lines.next().unwrap_or_default();
    if blake3::hash(body.as_bytes()).to_hex().as_str() != sum {
        bail!("signed-vote carry file checksum mismatch: the file changed after it was written");
    }
    let recs = decode(body)?;
    if recs.len() != count {
        bail!(
            "signed-vote carry file holds {} record(s), its header says {count}",
            recs.len()
        );
    }
    let bound = |v: String| (v != "-").then_some(v);
    let binding = Binding {
        chain_id: bound(chain)
            .map(|c| c.parse())
            .transpose()
            .context("chain id")?,
        genesis: bound(genesis),
        validator: bound(validator),
    };
    Ok((binding, recs))
}

/// Write `recs` to `path` durably (temp file, fsync, rename, fsync dir),
/// bound to `binding`.
pub fn write_file_bound(path: &Path, recs: &[Record], binding: &Binding) -> Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(encode_file(recs, binding).as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// [`write_file_bound`] with nothing bound (the operator tool).
pub fn write_file(path: &Path, recs: &[Record]) -> Result<()> {
    write_file_bound(path, recs, &Binding::default())
}

/// Read and verify a carry file; every field bound in `expected` must match.
pub fn read_file_bound(path: &Path, expected: &Binding) -> Result<Vec<Record>> {
    let (binding, recs) = decode_file(&std::fs::read_to_string(path)?)?;
    binding.check(expected)?;
    Ok(recs)
}

/// [`read_file_bound`] checking only the file's own integrity.
pub fn read_file(path: &Path) -> Result<Vec<Record>> {
    read_file_bound(path, &Binding::default())
}

/// Refuse while another process holds `db_dir`'s RocksDB lock (a running
/// node): a read beside a live writer can miss a vote it is signing
///. RocksDB takes an fcntl write lock on `LOCK`.
pub fn ensure_unlocked(db_dir: &Path) -> Result<()> {
    let lock = db_dir.join("LOCK");
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    lock_holder(&f).map_or(Ok(()), |pid| {
        bail!(
            "{} is locked by process {pid}: stop the node before exporting its signed votes",
            db_dir.display()
        )
    })
}

/// The pid holding an fcntl lock on `f`, if another process holds one.
#[cfg(unix)]
// The lock constants are c_short on some targets and c_int on others.
#[allow(clippy::unnecessary_cast)]
fn lock_holder(f: &std::fs::File) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock` is plain data; F_GETLK only reads the file descriptor's
    // lock state into it.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as libc::c_short;
    fl.l_whence = libc::SEEK_SET as libc::c_short;
    // SAFETY: a valid open descriptor and a valid `flock` pointer.
    let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETLK, &mut fl) };
    let unlocked = i64::from(fl.l_type) == i64::from(libc::F_UNLCK);
    (rc == 0 && !unlocked).then_some(fl.l_pid)
}

#[cfg(not(unix))]
fn lock_holder(_f: &std::fs::File) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::checkpoint_gadget::{signed_vote_key, signed_vote_meta_key};
    use tempfile::TempDir;

    fn vote(h: u64, b: u8) -> Record {
        (signed_vote_key(40204, h), vec![b; 32])
    }

    fn meta(floor: u64, highest: u64) -> Record {
        (
            signed_vote_meta_key(40204),
            SignedVoteMeta { floor, highest }.encode(),
        )
    }

    fn db() -> (TempDir, RocksDB) {
        let dir = TempDir::new().expect("tempdir");
        let db = RocksDB::open(dir.path()).expect("open");
        (dir, db)
    }

    #[test]
    fn export_import_round_trip_and_ignore_other_keys() {
        let (_a, src) = db();
        let recs = vec![vote(93_050, 1), vote(95_350, 2), meta(93_000, 95_350)];
        import(&src, &recs).expect("seed");
        // A finalized certificate shares the "checkpoint" stem and must not be carried.
        src.put_cf(CF_DAG_METADATA, b"checkpoint:93000", b"cert")
            .expect("cert");
        let out = export(&src).expect("export");
        assert_eq!(out.len(), 3);
        let (_b, dst) = db();
        let after = import(&dst, &decode(&encode(&out)).expect("decode")).expect("import");
        assert_eq!(after, out);
        let s = summarize(&after).expect("summary");
        assert_eq!(s.votes, 2);
        assert_eq!(s.vote_heights, Some((93_050, 95_350)));
    }

    /// The reseed target already has a watermark (non-signers write one as the
    /// floor follows finalization): merged by max, never lowered.
    #[test]
    fn watermarks_merge_by_max() {
        let (_d, dst) = db();
        import(&dst, &[meta(104_150, 0)]).expect("target watermark");
        let after = import(&dst, &[vote(95_300, 3), meta(93_000, 95_300)]).expect("import");
        let s = summarize(&after).expect("summary");
        assert_eq!(
            s.meta,
            vec![(
                "40204".to_string(),
                SignedVoteMeta {
                    floor: 104_150,
                    highest: 95_300
                }
            )]
        );
    }

    /// Two different hashes signed at one height can never be merged.
    #[test]
    fn a_conflicting_vote_is_refused_and_nothing_is_written() {
        let (_d, dst) = db();
        import(&dst, &[vote(95_350, 1)]).expect("first");
        let err = import(&dst, &[vote(95_350, 2), vote(95_400, 2)]).expect_err("conflict");
        assert!(err.to_string().contains("conflicting"), "{err}");
        let s = summarize(&export(&dst).expect("export")).expect("summary");
        assert_eq!(s.votes, 1, "the batch was not partly applied");
    }

    /// a carry file that changed after it was written
    /// (one flipped byte in a vote's hash) must be refused, not imported.
    #[test]
    fn a_tampered_carry_file_is_refused() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("votes");
        write_file(&path, &[vote(95_350, 1)]).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        let tampered = text.replacen("0101", "0102", 1);
        assert_ne!(text, tampered, "fixture flips a byte");
        std::fs::write(&path, tampered).expect("tamper");
        assert!(
            read_file(&path).is_err(),
            "a tampered carry file was accepted"
        );
    }

    /// a carry file from another chain, genesis or
    /// validator is refused; one bound to this node is read.
    #[test]
    fn a_carry_file_is_bound_to_its_chain_genesis_and_validator() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("votes");
        let mine = Binding {
            chain_id: Some(40204),
            genesis: Binding::normalize("0xCF686345"),
            validator: Binding::normalize("0x96b82a070ca2615eef29d8c67b86c21fd0ba474b"),
        };
        write_file_bound(&path, &[vote(95_350, 1)], &mine).expect("write");
        assert_eq!(read_file_bound(&path, &mine).expect("same node").len(), 1);
        for other in [
            Binding {
                chain_id: Some(1),
                ..mine.clone()
            },
            Binding {
                genesis: Some("ab".into()),
                ..mine.clone()
            },
            Binding {
                validator: Some("fc0305a20a46c791ea40e72bbf80582fdd5fe0ab".into()),
                ..mine.clone()
            },
        ] {
            assert!(read_file_bound(&path, &other).is_err(), "{other:?}");
        }
    }

    /// the export refuses while another process (a
    /// running node) holds the database's RocksDB lock. The holder is this
    /// test binary re-run as a child that opens the database and waits.
    #[test]
    fn export_refuses_while_another_process_holds_the_lock() {
        const CHILD: &str = "CITRATE_SVC_LOCK_CHILD";
        if let Ok(dir) = std::env::var(CHILD) {
            let _db = RocksDB::open(&dir).expect("child open");
            std::thread::sleep(std::time::Duration::from_secs(20));
            return;
        }
        let dir = TempDir::new().expect("tempdir");
        drop(RocksDB::open(dir.path()).expect("create"));
        assert!(ensure_unlocked(dir.path()).is_ok(), "nobody holds it yet");
        let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([
                "signed_votes::tests::export_refuses_while_another_process_holds_the_lock",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, dir.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn holder");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut refused = false;
        while std::time::Instant::now() < deadline {
            if ensure_unlocked(dir.path()).is_err() {
                refused = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(refused, "the export did not notice the running holder");
    }

    #[test]
    fn decode_rejects_foreign_entries() {
        let line = format!("{} {}\n", hex::encode(b"checkpoint:1"), hex::encode(b"x"));
        assert!(decode(&line).is_err());
    }
}
