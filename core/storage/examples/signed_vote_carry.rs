//! Operator tool: carry a voting validator's checkpoint signed-vote record
//! from an old chain database into a new one (`citrate_storage::signed_votes`). First used for the r1007 reseed of 2026-11-14.
//!
//! ```text
//! signed_vote_carry show   <db_dir>              # read-only; node stopped
//! signed_vote_carry export <db_dir> <file>       # read-only open; node STOPPED (refused while its lock is held)
//! signed_vote_carry import <db_dir> <file>       # node STOPPED; merges, refuses conflicts, synced write + read-back
//! ```
//!
//! Plaintext databases only (fleet nodes); an encrypted one is refused at open.
use citrate_storage::db::RocksDB;
use citrate_storage::signed_votes;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage = || anyhow::anyhow!("usage: signed_vote_carry show|export|import <db_dir> [file]");
    let cmd = args.get(1).ok_or_else(usage)?;
    let dir = args.get(2).ok_or_else(usage)?;
    match cmd.as_str() {
        "show" => {
            signed_votes::ensure_unlocked(Path::new(dir))?;
            let db = RocksDB::open_read_only(dir)?;
            println!("{}", signed_votes::summarize(&signed_votes::export(&db)?)?);
        }
        "export" => {
            let file = args.get(3).ok_or_else(usage)?;
            // A read beside a running node can miss a vote it is signing.
            signed_votes::ensure_unlocked(Path::new(dir))?;
            let db = RocksDB::open_read_only(dir)?;
            let recs = signed_votes::export(&db)?;
            signed_votes::write_file(Path::new(file), &recs)?;
            println!("exported {}", signed_votes::summarize(&recs)?);
        }
        "import" => {
            let file = args.get(3).ok_or_else(usage)?;
            let recs = signed_votes::read_file(Path::new(file))?;
            let db = RocksDB::open(dir)?;
            println!(
                "target before: {}",
                signed_votes::summarize(&signed_votes::export(&db)?)?
            );
            let after = signed_votes::import(&db, &recs)?;
            println!("imported; now {}", signed_votes::summarize(&after)?);
        }
        _ => return Err(usage()),
    }
    Ok(())
}
