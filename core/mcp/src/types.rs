// citrate/core/mcp/src/types.rs

// Types for representing models, providers, and requests
use citrate_execution::{Address, Hash};
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Model identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelId(pub [u8; 32]);

impl ModelId {
    pub fn from_hash(hash: &Hash) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub id: ModelId,
    pub owner: Address,
    pub name: String,
    pub version: String,
    pub hash: Hash,
    pub size: u64,
    /// Model architecture descriptor (e.g. GGUF header bytes, layer config).
    /// Empty for legacy records; populated on model load from GGUF or metadata.
    #[serde(default)]
    pub architecture: Vec<u8>,
    pub compute_requirements: ComputeRequirements,
    pub pricing: PricingModel,
}

/// Compute requirements for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeRequirements {
    pub min_memory: u64,    // Minimum RAM in bytes
    pub min_compute: u64,   // Minimum compute units
    pub gpu_required: bool, // Whether GPU is required
    pub supported_hardware: Vec<HardwareType>,
}

/// Hardware types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareType {
    CPU,
    GPU(String),    // GPU model (e.g., "NVIDIA A100")
    TPU(String),    // TPU version
    Custom(String), // Custom accelerator
}

/// Pricing model for compute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingModel {
    pub base_price: U256,       // Base price per inference
    pub per_token_price: U256,  // Price per token (for LLMs)
    pub per_second_price: U256, // Price per second of compute
    pub currency: Currency,
}

/// Supported currencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Currency {
    SALT,  // Native Citrate token
    ETH,   // Ethereum
    USDC,  // USD Coin
}

/// Provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub address: Address,
    pub name: String,
    pub endpoint: String,
    pub capacity: ComputeCapacity,
    pub reputation: u64,
    pub total_executions: u64,
}

/// Compute capacity of a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCapacity {
    pub total_memory: u64,
    pub available_memory: u64,
    pub total_compute: u64,
    pub available_compute: u64,
    pub hardware: Vec<HardwareType>,
}

/// Execution request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub id: RequestId,
    pub model_id: ModelId,
    pub input_hash: Hash,
    pub requester: Address,
    pub provider: Address,
    pub max_price: U256,
    pub status: RequestStatus,
    pub created_at: u64,
}

/// Request identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub [u8; 32]);

/// Request status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestStatus {
    Pending,
    Assigned(Address), // Assigned to provider
    Executing,
    Completed(Hash), // Result hash
    Failed(String),  // Error message
    Cancelled,
}

/// Execution proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProof {
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub io_commitment: Hash,
    pub statement: Vec<u8>,
    pub proof_data: Vec<u8>,
    pub timestamp: u64,
    pub provider: Address,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_id_from_hash() {
        let hash = Hash::new([42u8; 32]);
        let model_id = ModelId::from_hash(&hash);
        assert_eq!(model_id.0, [42u8; 32]);
    }

    #[test]
    fn test_model_id_as_bytes() {
        let model_id = ModelId([1u8; 32]);
        let bytes = model_id.as_bytes();
        assert_eq!(bytes, &[1u8; 32]);
    }

    #[test]
    fn test_model_id_equality() {
        let id1 = ModelId([1u8; 32]);
        let id2 = ModelId([1u8; 32]);
        let id3 = ModelId([2u8; 32]);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_model_id_hash_trait() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ModelId([1u8; 32]));
        set.insert(ModelId([2u8; 32]));
        set.insert(ModelId([1u8; 32])); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_request_id_equality() {
        let id1 = RequestId([1u8; 32]);
        let id2 = RequestId([1u8; 32]);
        let id3 = RequestId([2u8; 32]);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_hardware_type_variants() {
        let cpu = HardwareType::CPU;
        let gpu = HardwareType::GPU("NVIDIA A100".to_string());
        let tpu = HardwareType::TPU("v4".to_string());
        let custom = HardwareType::Custom("FPGA".to_string());

        // Just test they can be created and debug-printed
        assert!(format!("{:?}", cpu).contains("CPU"));
        assert!(format!("{:?}", gpu).contains("NVIDIA"));
        assert!(format!("{:?}", tpu).contains("v4"));
        assert!(format!("{:?}", custom).contains("FPGA"));
    }

    #[test]
    fn test_currency_variants() {
        let salt = Currency::SALT;
        let eth = Currency::ETH;
        let usdc = Currency::USDC;

        assert!(format!("{:?}", salt).contains("SALT"));
        assert!(format!("{:?}", eth).contains("ETH"));
        assert!(format!("{:?}", usdc).contains("USDC"));
    }

    #[test]
    fn test_request_status_variants() {
        let pending = RequestStatus::Pending;
        let assigned = RequestStatus::Assigned(Address([0u8; 20]));
        let executing = RequestStatus::Executing;
        let completed = RequestStatus::Completed(Hash::default());
        let failed = RequestStatus::Failed("error".to_string());
        let cancelled = RequestStatus::Cancelled;

        assert!(format!("{:?}", pending).contains("Pending"));
        assert!(format!("{:?}", assigned).contains("Assigned"));
        assert!(format!("{:?}", executing).contains("Executing"));
        assert!(format!("{:?}", completed).contains("Completed"));
        assert!(format!("{:?}", failed).contains("error"));
        assert!(format!("{:?}", cancelled).contains("Cancelled"));
    }

    #[test]
    fn test_compute_requirements_serialization() {
        let req = ComputeRequirements {
            min_memory: 1024 * 1024 * 1024, // 1GB
            min_compute: 100,
            gpu_required: true,
            supported_hardware: vec![HardwareType::GPU("RTX 4090".to_string())],
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ComputeRequirements = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.min_memory, req.min_memory);
        assert_eq!(deserialized.gpu_required, true);
    }

    #[test]
    fn test_pricing_model_serialization() {
        let pricing = PricingModel {
            base_price: U256::from(100),
            per_token_price: U256::from(1),
            per_second_price: U256::from(10),
            currency: Currency::SALT,
        };

        let json = serde_json::to_string(&pricing).unwrap();
        let deserialized: PricingModel = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.base_price, U256::from(100));
    }

    #[test]
    fn test_model_metadata_creation() {
        let metadata = ModelMetadata {
            id: ModelId([0u8; 32]),
            owner: Address([1u8; 20]),
            name: "test-model".to_string(),
            version: "1.0.0".to_string(),
            hash: Hash::default(),
            size: 1000,
            architecture: vec![0x47, 0x47, 0x55, 0x46], // "GGUF" magic
            compute_requirements: ComputeRequirements {
                min_memory: 1000,
                min_compute: 10,
                gpu_required: false,
                supported_hardware: vec![HardwareType::CPU],
            },
            pricing: PricingModel {
                base_price: U256::from(100),
                per_token_price: U256::from(1),
                per_second_price: U256::from(10),
                currency: Currency::SALT,
            },
        };

        assert_eq!(metadata.name, "test-model");
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.size, 1000);
    }
}
