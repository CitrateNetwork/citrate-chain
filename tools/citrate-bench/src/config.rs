//! Benchmark config (`bench.toml`) loading and offline validation.
//!
//! Offline validation — everything that can be checked without RPC —
//! runs here and in unit tests. Network validation (chain id match,
//! RPC reachability, balance checks) happens at runtime in `main.rs`
//! before a real run, and is intentionally NOT part of this module.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: TargetConfig,
    pub run: RunConfig,
    pub workload: WorkloadConfig,
    pub signers: SignersConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    /// Hex sha256 of the ceremony proof bundle. Accepts the optional
    /// `sha256:` prefix for legibility.
    pub ceremony_bundle_sha256: String,
    pub address_table_path: PathBuf,
    pub manifest_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub duration_secs: u64,
    pub target_tps: u64,
    pub concurrency_cap: usize,
    #[serde(default)]
    pub warmup_secs: u64,
    #[serde(default)]
    pub cooldown_secs: u64,
    pub report_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    pub mix: Vec<WorkloadClassWeight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadClassWeight {
    pub class: String,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignersConfig {
    pub keystore_dir: PathBuf,
    pub accounts: Vec<String>,
    /// String rather than integer to preserve full u256 range.
    pub funding_floor_wei: String,
    pub per_signer_max_inflight: usize,
}

/// Read and parse a `bench.toml` from disk.
pub fn load(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&contents)?;
    Ok(cfg)
}

impl Config {
    /// Everything checkable without RPC.
    ///
    /// Performs:
    /// - Non-zero run parameters
    /// - Non-empty signer + workload lists
    /// - Positive weight sum
    /// - `funding_floor_wei` parseable as u128 (u256 support is a later phase)
    /// - `address_table_path` and `manifest_path` exist on disk
    /// - `ceremony_bundle_sha256` is 64 hex chars
    pub fn validate_offline(&self) -> Result<()> {
        if self.run.duration_secs == 0 {
            return Err(Error::Config("run.duration_secs must be > 0".into()));
        }
        if self.run.target_tps == 0 {
            return Err(Error::Config("run.target_tps must be > 0".into()));
        }
        if self.run.concurrency_cap == 0 {
            return Err(Error::Config("run.concurrency_cap must be > 0".into()));
        }
        if self.signers.accounts.is_empty() {
            return Err(Error::Config("signers.accounts must be non-empty".into()));
        }
        if self.signers.per_signer_max_inflight == 0 {
            return Err(Error::Config(
                "signers.per_signer_max_inflight must be > 0".into(),
            ));
        }
        if self.workload.mix.is_empty() {
            return Err(Error::Config("workload.mix must be non-empty".into()));
        }
        let total_weight: u32 = self.workload.mix.iter().map(|w| w.weight).sum();
        if total_weight == 0 {
            return Err(Error::Config("workload.mix weights sum to 0".into()));
        }
        self.funding_floor_u128()?;

        if !self.target.address_table_path.exists() {
            return Err(Error::Config(format!(
                "address_table_path not found: {}",
                self.target.address_table_path.display()
            )));
        }
        if !self.target.manifest_path.exists() {
            return Err(Error::Config(format!(
                "manifest_path not found: {}",
                self.target.manifest_path.display()
            )));
        }
        validate_sha256_prefix(&self.target.ceremony_bundle_sha256)?;
        Ok(())
    }

    /// Parse `funding_floor_wei` into a `u128`. Values that exceed `u128`
    /// range are rejected; a later phase can add a `U256` variant if the
    /// floor ever needs to exceed ~3.4e38 wei.
    pub fn funding_floor_u128(&self) -> Result<u128> {
        let raw = self.signers.funding_floor_wei.trim();
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            return u128::from_str_radix(hex, 16)
                .map_err(|e| Error::Config(format!("funding_floor_wei hex: {e}")));
        }
        raw.parse::<u128>()
            .map_err(|e| Error::Config(format!("funding_floor_wei decimal: {e}")))
    }

    /// Normalized workload mix as `(class_name, share)` where shares
    /// sum to 1.0 (rounding aside). Empty mix returns an empty vec.
    pub fn normalized_mix(&self) -> Vec<(String, f64)> {
        let total: u32 = self.workload.mix.iter().map(|w| w.weight).sum();
        if total == 0 {
            return Vec::new();
        }
        let total_f = total as f64;
        self.workload
            .mix
            .iter()
            .map(|w| (w.class.clone(), w.weight as f64 / total_f))
            .collect()
    }
}

fn validate_sha256_prefix(s: &str) -> Result<()> {
    let stripped = s.strip_prefix("sha256:").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(Error::Config(format!(
            "ceremony_bundle_sha256 must be 64 hex chars (optionally prefixed 'sha256:'), got {}",
            stripped.len()
        )));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Config(
            "ceremony_bundle_sha256 contains non-hex characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_config() -> Config {
        Config {
            target: TargetConfig {
                rpc_url: "https://rpc.citrate.ai".into(),
                chain_id: 40204,
                ceremony_bundle_sha256:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                        .into(),
                address_table_path: PathBuf::from("/tmp/__nonexistent_addr_table__"),
                manifest_path: PathBuf::from("/tmp/__nonexistent_manifest__"),
            },
            run: RunConfig {
                duration_secs: 60,
                target_tps: 1000,
                concurrency_cap: 500,
                warmup_secs: 0,
                cooldown_secs: 0,
                report_dir: PathBuf::from("/tmp/benchmarks"),
            },
            workload: WorkloadConfig {
                mix: vec![
                    WorkloadClassWeight {
                        class: "simple_transfer".into(),
                        weight: 50,
                    },
                    WorkloadClassWeight {
                        class: "wrapped_salt".into(),
                        weight: 50,
                    },
                ],
            },
            signers: SignersConfig {
                keystore_dir: PathBuf::from("/tmp/keystores"),
                accounts: vec!["bench-01".into(), "bench-02".into()],
                funding_floor_wei: "1000000000000000000".into(),
                per_signer_max_inflight: 100,
            },
        }
    }

    #[test]
    fn funding_floor_decimal() {
        let cfg = ok_config();
        assert_eq!(cfg.funding_floor_u128().expect("parse"), 1_000_000_000_000_000_000u128);
    }

    #[test]
    fn funding_floor_hex() {
        let mut cfg = ok_config();
        cfg.signers.funding_floor_wei = "0xde0b6b3a7640000".into();
        assert_eq!(cfg.funding_floor_u128().expect("parse"), 1_000_000_000_000_000_000u128);
    }

    #[test]
    fn funding_floor_rejects_garbage() {
        let mut cfg = ok_config();
        cfg.signers.funding_floor_wei = "not-a-number".into();
        assert!(cfg.funding_floor_u128().is_err());
    }

    #[test]
    fn rejects_zero_duration() {
        let mut cfg = ok_config();
        cfg.run.duration_secs = 0;
        assert!(cfg.validate_offline().is_err());
    }

    #[test]
    fn rejects_zero_tps() {
        let mut cfg = ok_config();
        cfg.run.target_tps = 0;
        assert!(cfg.validate_offline().is_err());
    }

    #[test]
    fn rejects_empty_signers() {
        let mut cfg = ok_config();
        cfg.signers.accounts.clear();
        assert!(cfg.validate_offline().is_err());
    }

    #[test]
    fn rejects_empty_mix() {
        let mut cfg = ok_config();
        cfg.workload.mix.clear();
        assert!(cfg.validate_offline().is_err());
    }

    #[test]
    fn rejects_zero_weight_sum() {
        let mut cfg = ok_config();
        for w in &mut cfg.workload.mix {
            w.weight = 0;
        }
        assert!(cfg.validate_offline().is_err());
    }

    #[test]
    fn sha256_shape_accepts_prefixed() {
        validate_sha256_prefix(
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .expect("accept");
    }

    #[test]
    fn sha256_shape_accepts_bare() {
        validate_sha256_prefix(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .expect("accept");
    }

    #[test]
    fn sha256_shape_rejects_wrong_length() {
        assert!(validate_sha256_prefix("deadbeef").is_err());
    }

    #[test]
    fn sha256_shape_rejects_non_hex() {
        assert!(validate_sha256_prefix(
            "zzzzef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        .is_err());
    }

    #[test]
    fn normalized_mix_sums_to_one() {
        let cfg = ok_config();
        let mix = cfg.normalized_mix();
        let sum: f64 = mix.iter().map(|(_, w)| w).sum();
        assert!((sum - 1.0).abs() < 1e-9, "sum = {sum}");
    }
}
