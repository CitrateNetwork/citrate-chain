// citrate/core/mcp/src/chunk_assembly.rs

//! Reassembly of chunked model weights from a `ChunkManifest`.
//!
//! The manifest is fetched by CID, so every size field in it is input data.
//! This module turns a manifest into a bounded assembly plan and reassembles
//! the fetched chunks while checking them against the declared sizes.

use citrate_storage::ipfs::chunking::ChunkManifest;
use thiserror::Error;

/// Largest assembled model accepted from a manifest (32 GiB).
pub const MAX_ASSEMBLED_MODEL_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Largest per-chunk size a manifest may declare (1 GiB).
pub const MAX_CHUNK_BYTES: u64 = 1024 * 1024 * 1024;
/// Most chunks a manifest may list.
pub const MAX_MODEL_CHUNKS: usize = 65_536;
/// Upper bound on the up-front reservation; the buffer grows with data that
/// has actually been fetched beyond this.
pub const MAX_INITIAL_RESERVE_BYTES: usize = 256 * 1024 * 1024;

/// Typed rejection reasons for a manifest or its fetched chunks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ManifestAssemblyError {
    #[error("manifest total_size {declared} exceeds maximum {max}")]
    TotalSizeTooLarge { declared: u64, max: u64 },
    #[error("manifest chunk_size {declared} is outside 1..={max}")]
    InvalidChunkSize { declared: u64, max: u64 },
    #[error("manifest lists {listed} chunks, maximum is {max}")]
    TooManyChunks { listed: usize, max: usize },
    #[error("manifest lists {listed} chunks but its sizes imply {expected}")]
    ChunkCountMismatch { listed: usize, expected: u64 },
    #[error("chunk {index} is {len} bytes, larger than declared chunk_size {chunk_size}")]
    ChunkTooLarge {
        index: usize,
        len: usize,
        chunk_size: u64,
    },
    #[error("assembled {actual} bytes but manifest declares {declared}")]
    SizeMismatch { declared: u64, actual: u64 },
}

/// Incremental, bounded reassembly of a chunked model.
#[derive(Debug)]
pub struct ChunkAssembler {
    declared_total: u64,
    chunk_size: u64,
    planned_capacity: usize,
    pushed: usize,
    buf: Vec<u8>,
}

impl ChunkAssembler {
    /// Validate `manifest` and build an assembler for it.
    ///
    /// Checks, in order: declared total against [`MAX_ASSEMBLED_MODEL_BYTES`],
    /// chunk size in `1..=MAX_CHUNK_BYTES`, listed chunk count against
    /// [`MAX_MODEL_CHUNKS`], and listed count against the count implied by
    /// the declared sizes. The up-front reservation is the declared total
    /// clamped to [`MAX_INITIAL_RESERVE_BYTES`].
    pub fn new(manifest: &ChunkManifest) -> Result<Self, ManifestAssemblyError> {
        let declared_total = manifest.total_size;
        if declared_total > MAX_ASSEMBLED_MODEL_BYTES {
            return Err(ManifestAssemblyError::TotalSizeTooLarge {
                declared: declared_total,
                max: MAX_ASSEMBLED_MODEL_BYTES,
            });
        }
        let chunk_size = u64::try_from(manifest.chunk_size).unwrap_or(u64::MAX);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_BYTES {
            return Err(ManifestAssemblyError::InvalidChunkSize {
                declared: chunk_size,
                max: MAX_CHUNK_BYTES,
            });
        }
        let listed = manifest.chunks.len();
        if listed > MAX_MODEL_CHUNKS {
            return Err(ManifestAssemblyError::TooManyChunks {
                listed,
                max: MAX_MODEL_CHUNKS,
            });
        }
        let expected = declared_total.div_ceil(chunk_size);
        if u64::try_from(listed).ok() != Some(expected) {
            return Err(ManifestAssemblyError::ChunkCountMismatch { listed, expected });
        }
        let planned_capacity = usize::try_from(declared_total)
            .unwrap_or(usize::MAX)
            .min(MAX_INITIAL_RESERVE_BYTES);
        Ok(Self {
            declared_total,
            chunk_size,
            planned_capacity,
            pushed: 0,
            buf: Vec::with_capacity(planned_capacity),
        })
    }

    /// Bytes the assembler reserved before any chunk was fetched.
    pub fn planned_capacity(&self) -> usize {
        self.planned_capacity
    }

    /// Append the next fetched chunk, rejecting it if it is larger than the
    /// declared chunk size or would take the payload past the declared total.
    pub fn push(&mut self, bytes: Vec<u8>) -> Result<(), ManifestAssemblyError> {
        let index = self.pushed;
        let len = bytes.len();
        if u64::try_from(len).map_or(true, |l| l > self.chunk_size) {
            return Err(ManifestAssemblyError::ChunkTooLarge {
                index,
                len,
                chunk_size: self.chunk_size,
            });
        }
        let new_total = self.assembled_len().saturating_add(len as u64);
        if new_total > self.declared_total {
            return Err(ManifestAssemblyError::SizeMismatch {
                declared: self.declared_total,
                actual: new_total,
            });
        }
        self.buf.extend(bytes);
        self.pushed = index.saturating_add(1);
        Ok(())
    }

    /// Finish assembly; the payload must match the declared total exactly.
    pub fn finish(self) -> Result<Vec<u8>, ManifestAssemblyError> {
        let actual = self.assembled_len();
        if actual != self.declared_total {
            return Err(ManifestAssemblyError::SizeMismatch {
                declared: self.declared_total,
                actual,
            });
        }
        Ok(self.buf)
    }

    fn assembled_len(&self) -> u64 {
        u64::try_from(self.buf.len()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_storage::ipfs::chunking::chunk_model;
    use citrate_storage::ipfs::{Cid, ModelFramework, ModelMetadata, ModelType};

    fn metadata() -> ModelMetadata {
        ModelMetadata {
            name: "m".into(),
            version: "1".into(),
            framework: ModelFramework::Custom("gguf".into()),
            model_type: ModelType::Language,
            size_bytes: 0,
            input_shape: vec![],
            output_shape: vec![],
            description: String::new(),
            author: String::new(),
            license: String::new(),
            created_at: 0,
        }
    }

    fn manifest(total_size: u64, chunk_size: usize, n_chunks: usize) -> ChunkManifest {
        ChunkManifest {
            chunks: (0..n_chunks).map(|i| Cid(format!("chunk-{i}"))).collect(),
            total_size,
            chunk_size,
            metadata: metadata(),
            metal_optimized: false,
            unified_memory_compatible: true,
        }
    }

    // Every test below inspects the plan or the pushed byte counts only; none
    // of them asks the allocator for the declared size, so a missing bound
    // shows up as an assertion failure rather than an abort.

    #[test]
    fn rejects_total_size_of_u64_max() {
        // A negative length encoded as unsigned (-1 as u64).
        let m = manifest(u64::MAX, 256 * 1024 * 1024, 1);
        let err = ChunkAssembler::new(&m).err();
        assert_eq!(
            err,
            Some(ManifestAssemblyError::TotalSizeTooLarge {
                declared: u64::MAX,
                max: MAX_ASSEMBLED_MODEL_BYTES
            })
        );
    }

    #[test]
    fn rejects_total_size_above_cap_even_when_chunk_count_is_consistent() {
        let chunk = MAX_CHUNK_BYTES as usize;
        let total = MAX_ASSEMBLED_MODEL_BYTES + MAX_CHUNK_BYTES;
        let n = (total / MAX_CHUNK_BYTES) as usize;
        let m = manifest(total, chunk, n);
        assert!(matches!(
            ChunkAssembler::new(&m),
            Err(ManifestAssemblyError::TotalSizeTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_zero_and_oversized_chunk_size() {
        let m = manifest(10, 0, 1);
        assert!(matches!(
            ChunkAssembler::new(&m),
            Err(ManifestAssemblyError::InvalidChunkSize { .. })
        ));
        let m = manifest(10, (MAX_CHUNK_BYTES + 1) as usize, 1);
        assert!(matches!(
            ChunkAssembler::new(&m),
            Err(ManifestAssemblyError::InvalidChunkSize { .. })
        ));
    }

    #[test]
    fn rejects_chunk_count_inconsistent_with_sizes() {
        // 10 bytes in 4-byte chunks needs 3 chunks, not 1 or 5.
        for listed in [0usize, 1, 2, 4, 5] {
            let m = manifest(10, 4, listed);
            assert_eq!(
                ChunkAssembler::new(&m).err(),
                Some(ManifestAssemblyError::ChunkCountMismatch {
                    listed,
                    expected: 3
                }),
                "listed={listed}"
            );
        }
    }

    #[test]
    fn rejects_too_many_chunks() {
        let m = manifest((MAX_MODEL_CHUNKS as u64) + 1, 1, MAX_MODEL_CHUNKS + 1);
        assert!(matches!(
            ChunkAssembler::new(&m),
            Err(ManifestAssemblyError::TooManyChunks { .. })
        ));
    }

    #[test]
    fn valid_large_manifest_reserves_at_most_the_initial_cap() {
        // 8 GiB in 256 MiB chunks: a legitimate manifest, but the up-front
        // reservation must not follow the declared size.
        let chunk = 256 * 1024 * 1024usize;
        let total = 8 * 1024 * 1024 * 1024u64;
        let m = manifest(total, chunk, (total / chunk as u64) as usize);
        let a = ChunkAssembler::new(&m).expect("valid manifest");
        assert!(
            a.planned_capacity() <= MAX_INITIAL_RESERVE_BYTES,
            "planned {} > cap {}",
            a.planned_capacity(),
            MAX_INITIAL_RESERVE_BYTES
        );
    }

    #[test]
    fn small_manifest_reserves_exactly_its_size() {
        let m = manifest(10, 4, 3);
        let a = ChunkAssembler::new(&m).expect("valid manifest");
        assert_eq!(a.planned_capacity(), 10);
    }

    #[test]
    fn rejects_chunk_larger_than_declared_chunk_size() {
        let m = manifest(10, 4, 3);
        let mut a = ChunkAssembler::new(&m).expect("valid manifest");
        assert_eq!(
            a.push(vec![0u8; 5]),
            Err(ManifestAssemblyError::ChunkTooLarge {
                index: 0,
                len: 5,
                chunk_size: 4
            })
        );
    }

    #[test]
    fn rejects_payload_longer_than_declared_total() {
        // Three full 4-byte chunks = 12 bytes against a declared 10.
        let m = manifest(10, 4, 3);
        let mut a = ChunkAssembler::new(&m).expect("valid manifest");
        assert_eq!(a.push(vec![1u8; 4]), Ok(()));
        assert_eq!(a.push(vec![2u8; 4]), Ok(()));
        assert_eq!(
            a.push(vec![3u8; 4]),
            Err(ManifestAssemblyError::SizeMismatch {
                declared: 10,
                actual: 12
            })
        );
    }

    #[test]
    fn rejects_payload_shorter_than_declared_total() {
        let m = manifest(10, 4, 3);
        let mut a = ChunkAssembler::new(&m).expect("valid manifest");
        assert_eq!(a.push(vec![1u8; 4]), Ok(()));
        assert_eq!(a.push(vec![2u8; 4]), Ok(()));
        assert_eq!(a.push(vec![3u8; 1]), Ok(()));
        assert_eq!(
            a.finish(),
            Err(ManifestAssemblyError::SizeMismatch {
                declared: 10,
                actual: 9
            })
        );
    }

    #[test]
    fn round_trips_a_real_chunked_payload() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let chunks = chunk_model(&data, 64).expect("chunk");
        let m = manifest(data.len() as u64, 64, chunks.len());
        let mut a = ChunkAssembler::new(&m).expect("valid manifest");
        for c in chunks {
            a.push(c.data).expect("push");
        }
        assert_eq!(a.finish().expect("finish"), data);
    }

    #[test]
    fn empty_manifest_assembles_to_empty_payload() {
        let m = manifest(0, 4, 0);
        let a = ChunkAssembler::new(&m).expect("valid manifest");
        assert_eq!(a.planned_capacity(), 0);
        assert_eq!(a.finish().expect("finish"), Vec::<u8>::new());
    }
}
