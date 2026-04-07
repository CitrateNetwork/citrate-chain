//! Loader for the ceremony's `30_address_table.json` artifact.
//!
//! The schema is permissive on input (contract entries may carry
//! additional fields this crate does not yet use) and strict on the
//! minimum shape: a `chainId` and a list of contracts each with at least
//! `name` and `address`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTable {
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(default)]
    pub deployer: Option<String>,
    #[serde(rename = "contractCount", default)]
    pub contract_count: Option<u64>,
    #[serde(default)]
    pub contracts: Vec<ContractEntry>,
    /// Catch-all for forward-compatible fields the ceremony emits but
    /// this crate has not formalized yet (receipt summaries, gas
    /// metadata, signatures, etc.).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEntry {
    pub name: String,
    pub address: String,
    #[serde(rename = "deploymentTxHash", default)]
    pub deployment_tx_hash: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub deployer: Option<String>,
    #[serde(rename = "constructorArgs", default)]
    pub constructor_args: Option<serde_json::Value>,
    #[serde(rename = "codeSizeBytes", default)]
    pub code_size_bytes: Option<u64>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Load and minimally validate an address table from disk.
pub fn load(path: &Path) -> Result<AddressTable> {
    let contents = std::fs::read_to_string(path)?;
    let table: AddressTable = serde_json::from_str(&contents)?;
    table.validate_shape()?;
    Ok(table)
}

/// Compute the sha256 of the address table file contents. Used when
/// the runner wants to fingerprint a run against an exact artifact.
pub fn sha256_of_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

impl AddressTable {
    pub fn validate_shape(&self) -> Result<()> {
        if self.contracts.is_empty() {
            return Err(Error::AddressTable("no contracts in address table".into()));
        }
        if let Some(reported) = self.contract_count {
            if reported != self.contracts.len() as u64 {
                return Err(Error::AddressTable(format!(
                    "contractCount ({}) does not match contracts array length ({})",
                    reported,
                    self.contracts.len()
                )));
            }
        }
        for c in &self.contracts {
            if c.name.trim().is_empty() {
                return Err(Error::AddressTable("contract with empty name".into()));
            }
            validate_eth_address(&c.address).map_err(|e| {
                Error::AddressTable(format!("{} has invalid address: {e}", c.name))
            })?;
        }
        Ok(())
    }

    /// Lookup a contract by name (case-sensitive).
    pub fn find(&self, name: &str) -> Option<&ContractEntry> {
        self.contracts.iter().find(|c| c.name == name)
    }

    /// Names of all contracts in deployment order.
    pub fn names(&self) -> Vec<&str> {
        self.contracts.iter().map(|c| c.name.as_str()).collect()
    }
}

fn validate_eth_address(s: &str) -> Result<()> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        return Err(Error::AddressTable(format!(
            "address must be 20 bytes (40 hex chars, optional 0x prefix), got {} chars",
            stripped.len()
        )));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::AddressTable(
            "address contains non-hex characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn parses_minimal_table() {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "WrappedSALT", "address": "0x0000000000000000000000000000000000000001" },
            { "name": "ModelRegistry", "address": "0x0000000000000000000000000000000000000002" }
          ]
        }"#;
        let f = write_tmp(json);
        let tbl = load(f.path()).expect("load");
        assert_eq!(tbl.chain_id, 40204);
        assert_eq!(tbl.contracts.len(), 2);
        assert_eq!(tbl.contracts[0].name, "WrappedSALT");
    }

    #[test]
    fn lookups_by_name() {
        let json = r#"{
          "chainId": 1,
          "contracts": [
            { "name": "A", "address": "0x0000000000000000000000000000000000000001" }
          ]
        }"#;
        let f = write_tmp(json);
        let tbl = load(f.path()).expect("load");
        assert_eq!(tbl.find("A").expect("A exists").address,
                   "0x0000000000000000000000000000000000000001");
        assert!(tbl.find("B").is_none());
    }

    #[test]
    fn rejects_empty_contracts() {
        let json = r#"{ "chainId": 1, "contracts": [] }"#;
        let f = write_tmp(json);
        assert!(load(f.path()).is_err());
    }

    #[test]
    fn rejects_mismatched_count() {
        let json = r#"{
          "chainId": 1,
          "contractCount": 2,
          "contracts": [
            { "name": "A", "address": "0x0000000000000000000000000000000000000001" }
          ]
        }"#;
        let f = write_tmp(json);
        assert!(load(f.path()).is_err());
    }

    #[test]
    fn rejects_bad_address() {
        let json = r#"{
          "chainId": 1,
          "contracts": [
            { "name": "A", "address": "not-an-address" }
          ]
        }"#;
        let f = write_tmp(json);
        assert!(load(f.path()).is_err());
    }

    #[test]
    fn accepts_bare_hex_address() {
        let json = r#"{
          "chainId": 1,
          "contracts": [
            { "name": "A", "address": "0000000000000000000000000000000000000001" }
          ]
        }"#;
        let f = write_tmp(json);
        load(f.path()).expect("bare hex address is accepted");
    }

    #[test]
    fn preserves_unknown_fields() {
        let json = r#"{
          "chainId": 1,
          "ceremonyTimestamp": "2026-04-07T10:00:00Z",
          "contracts": [
            { "name": "A", "address": "0x0000000000000000000000000000000000000001",
              "gasUsed": 123456 }
          ]
        }"#;
        let f = write_tmp(json);
        let tbl = load(f.path()).expect("load");
        assert!(tbl.extra.contains_key("ceremonyTimestamp"));
        assert!(tbl.contracts[0].extra.contains_key("gasUsed"));
    }

    #[test]
    fn sha256_is_deterministic() {
        let json = r#"{
          "chainId": 1,
          "contracts": [
            { "name": "A", "address": "0x0000000000000000000000000000000000000001" }
          ]
        }"#;
        let f = write_tmp(json);
        let a = sha256_of_file(f.path()).expect("a");
        let b = sha256_of_file(f.path()).expect("b");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
