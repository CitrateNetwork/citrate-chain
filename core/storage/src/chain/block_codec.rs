//! The stored encodings of a [`Block`] in `CF_BLOCKS`.
//!
//! r1007 S3-3b (spec 06 §3.9) appended `accepted_root` to `Block`, its last
//! field. bincode writes a `Hash` as its 32 bytes with no length, so there are
//! exactly two encodings, told apart by length alone:
//! - [`StoredBlockEncoding::V013`]: every field up to `equivocation_vote`, as
//!   v0.1.3 and r1006 builds write it (no accepted root);
//! - [`StoredBlockEncoding::R1007`]: the V013 bytes followed by the 32-byte
//!   `accepted_root`, as this build writes every block.
//!
//! A V013 block decodes with `accepted_root` zero, which is what such a block
//! committed (a zero root is outside the block-hash preimage), so its hash is
//! unchanged. A store written by an r1006 build therefore still reads. Bytes
//! that are neither encoding are refused, never padded or truncated into one.

use anyhow::{anyhow, Result};
use citrate_consensus::types::{Block, Hash};

/// Which stored encoding a block value is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredBlockEncoding {
    /// v0.1.3 / r1006: no `accepted_root`.
    V013,
    /// r1007: `accepted_root` appended.
    R1007,
}

/// Length of the appended `accepted_root`.
const ACCEPTED_ROOT_LEN: usize = 32;

/// Decode a `CF_BLOCKS` value, and say which encoding it was in.
pub fn decode_stored_block(bytes: &[u8]) -> Result<(Block, StoredBlockEncoding)> {
    if let Ok(block) = decode_exact(bytes) {
        return Ok((block, StoredBlockEncoding::R1007));
    }
    let mut padded = Vec::with_capacity(bytes.len().saturating_add(ACCEPTED_ROOT_LEN));
    padded.extend_from_slice(bytes);
    padded.extend_from_slice(&[0u8; ACCEPTED_ROOT_LEN]);
    match decode_exact(&padded) {
        Ok(block) => Ok((block, StoredBlockEncoding::V013)),
        Err(e) => Err(anyhow!(
            "stored block is neither the r1007 nor the v0.1.3 encoding ({} bytes): {e}",
            bytes.len()
        )),
    }
}

/// The V013 encoding of `block`. Refused for a block with a non-zero
/// `accepted_root`: an r1007 accepting block has no v0.1.3 form.
pub fn encode_block_v013(block: &Block) -> Result<Vec<u8>> {
    if block.accepted_root != Hash::default() {
        return Err(anyhow!(
            "block {} commits an accepted_root (r1007); it has no v0.1.3 encoding",
            block.header.block_hash
        ));
    }
    let mut bytes = bincode::serialize(block)?;
    let keep = bytes
        .len()
        .checked_sub(ACCEPTED_ROOT_LEN)
        .ok_or_else(|| anyhow!("block encoding shorter than its accepted root"))?;
    bytes.truncate(keep);
    Ok(bytes)
}

/// bincode decode that consumes every byte (the storage writes with
/// `bincode::serialize`: fixed-width integers, little endian).
fn decode_exact(bytes: &[u8]) -> Result<Block> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}
