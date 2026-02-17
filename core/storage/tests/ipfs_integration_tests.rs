// citrate/core/storage/tests/ipfs_integration_tests.rs

//! Integration tests for IPFS daemon management
//!
//! These tests verify the IPFS daemon lifecycle, auto-download,
//! and integration with the storage layer.

use citrate_storage::ipfs::{
    DaemonConfig, DaemonStatus, IpfsDaemon, IPFSService, ModelMetadata,
    ModelFramework, ModelType, Cid,
};
use std::path::PathBuf;
use tempfile::TempDir;

/// Test daemon configuration
fn test_config(temp_dir: &TempDir) -> DaemonConfig {
    DaemonConfig {
        binary_path: None,
        repo_path: temp_dir.path().join("ipfs"),
        api_addr: "/ip4/127.0.0.1/tcp/15001".to_string(), // Use non-standard port for testing
        gateway_addr: "/ip4/127.0.0.1/tcp/18080".to_string(),
        swarm_addrs: vec!["/ip4/0.0.0.0/tcp/14001".to_string()],
        auto_start: false, // Manual control in tests
        auto_download: false, // Don't auto-download in unit tests
        enable_pubsub: false,
        low_power: true,
        storage_max: "1GB".to_string(),
    }
}

#[tokio::test]
async fn test_daemon_config_defaults() {
    let config = DaemonConfig::default();

    assert!(config.auto_start);
    assert!(config.auto_download);
    assert!(config.enable_pubsub);
    assert!(!config.low_power);
    assert_eq!(config.storage_max, "100GB");

    // Check repo path is in home directory
    let home = dirs::home_dir().unwrap();
    assert_eq!(config.repo_path, home.join(".ipfs"));
}

#[tokio::test]
async fn test_daemon_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);

    let daemon = IpfsDaemon::new(config.clone());

    // Verify API URL is correctly constructed
    assert_eq!(daemon.api_url(), "http://127.0.0.1:15001");

    // Verify repo is not initialized
    assert!(!daemon.is_repo_initialized());
}

#[tokio::test]
async fn test_daemon_status_when_not_running() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);

    let daemon = IpfsDaemon::new(config);

    // Should report not installed or stopped
    let status = daemon.status().await;
    assert!(matches!(status, DaemonStatus::NotInstalled | DaemonStatus::Stopped));
}

#[tokio::test]
async fn test_ipfs_service_creation() {
    let service = IPFSService::new("http://localhost:5001".to_string());

    // Should have empty pinned models initially
    let pinned = service.list_pinned_models();
    assert!(pinned.is_empty());
}

#[tokio::test]
async fn test_model_metadata_creation() {
    let metadata = ModelMetadata {
        name: "test-model".to_string(),
        version: "1.0.0".to_string(),
        framework: ModelFramework::ONNX,
        model_type: ModelType::Language,
        size_bytes: 1024 * 1024 * 100, // 100MB
        input_shape: vec![1, 512],
        output_shape: vec![1, 50257],
        description: "A test language model".to_string(),
        author: "Citrate Team".to_string(),
        license: "MIT".to_string(),
        created_at: 1700000000,
    };

    assert_eq!(metadata.name, "test-model");
    assert_eq!(metadata.size_bytes, 104857600);
}

#[tokio::test]
async fn test_cid_operations() {
    let cid1 = Cid("QmTest123".to_string());
    let cid2 = Cid("QmTest123".to_string());
    let cid3 = Cid("QmTest456".to_string());

    // Test equality
    assert_eq!(cid1, cid2);
    assert_ne!(cid1, cid3);

    // Test hashing
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(cid1.clone());
    set.insert(cid2);
    assert_eq!(set.len(), 1);

    set.insert(cid3);
    assert_eq!(set.len(), 2);
}

#[tokio::test]
async fn test_pinning_rewards_calculation() {
    let mut service = IPFSService::new("http://localhost:5001".to_string());

    let cid = Cid("QmTest".to_string());
    let metadata = ModelMetadata {
        name: "Vision Model".to_string(),
        version: "1.0".to_string(),
        framework: ModelFramework::PyTorch,
        model_type: ModelType::Vision, // 3x multiplier
        size_bytes: 1024 * 1024 * 1024, // 1GB
        input_shape: vec![1, 3, 224, 224],
        output_shape: vec![1, 1000],
        description: "Test vision model".to_string(),
        author: "Test".to_string(),
        license: "Apache-2.0".to_string(),
        created_at: 0,
    };

    // Record external pin
    let reward = service.record_external_pin(
        cid.clone(),
        "provider-1".to_string(),
        metadata.clone(),
        metadata.size_bytes,
    );

    assert_eq!(reward.reward, 3); // 1GB * 3x multiplier
    assert_eq!(reward.total_replicas, 1);

    // Get pinning summary
    let summary = service.pinning_summary(&cid).unwrap();
    assert_eq!(summary.total_replicas, 1);
    assert_eq!(summary.total_pinned_bytes, 1024 * 1024 * 1024);
}

#[tokio::test]
async fn test_model_type_multipliers() {
    let mut service = IPFSService::new("http://localhost:5001".to_string());

    let test_cases = vec![
        (ModelType::Language, 2),     // 2x
        (ModelType::Vision, 3),       // 3x
        (ModelType::Audio, 2),        // 2x
        (ModelType::Multimodal, 4),   // 4x
        (ModelType::Reinforcement, 3), // 3x
    ];

    for (model_type, expected_multiplier) in test_cases {
        let cid = Cid(format!("QmTest_{:?}", model_type));
        let metadata = ModelMetadata {
            name: format!("{:?} Model", model_type),
            version: "1.0".to_string(),
            framework: ModelFramework::ONNX,
            model_type,
            size_bytes: 1024 * 1024 * 1024, // 1GB
            input_shape: vec![1, 512],
            output_shape: vec![1, 512],
            description: "Test".to_string(),
            author: "Test".to_string(),
            license: "MIT".to_string(),
            created_at: 0,
        };

        let reward = service.record_external_pin(
            cid,
            "provider".to_string(),
            metadata.clone(),
            metadata.size_bytes,
        );

        assert_eq!(
            reward.reward, expected_multiplier,
            "Expected {}x multiplier for {:?}",
            expected_multiplier, metadata.model_type
        );
    }
}

/// Test that verifies daemon can detect when IPFS is not installed
#[tokio::test]
#[ignore = "Environment-dependent: fails when IPFS is installed on system PATH"]
async fn test_daemon_binary_detection_failure() {
    let temp_dir = TempDir::new().unwrap();
    let config = DaemonConfig {
        binary_path: Some(PathBuf::from("/definitely/not/a/real/path/ipfs")),
        auto_download: false,
        ..test_config(&temp_dir)
    };

    let daemon = IpfsDaemon::new(config);
    let result = daemon.find_ipfs_binary().await;

    assert!(result.is_err());
}

/// Test daemon health check when not running
#[tokio::test]
async fn test_daemon_health_check_not_running() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);

    let daemon = IpfsDaemon::new(config);
    let health = daemon.health_check().await.unwrap();

    assert!(!health.healthy);
    assert_eq!(health.peer_count, 0);
    assert_eq!(health.repo_size, 0);
    assert!(health.error.is_some());
}

/// Test that daemon correctly reports running status
#[tokio::test]
async fn test_daemon_is_running_false() {
    let temp_dir = TempDir::new().unwrap();
    let config = test_config(&temp_dir);

    let daemon = IpfsDaemon::new(config);

    // Should not be running
    assert!(!daemon.is_running().await);
}

/// Test serialization of daemon status
#[tokio::test]
async fn test_daemon_status_serialization() {
    // Test all status variants serialize correctly
    let statuses = vec![
        DaemonStatus::NotInstalled,
        DaemonStatus::Stopped,
        DaemonStatus::Starting,
        DaemonStatus::Running,
        DaemonStatus::Error("test error".to_string()),
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: DaemonStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }
}

/// Test multiaddr parsing
#[tokio::test]
async fn test_api_url_parsing() {
    let test_cases = vec![
        ("/ip4/127.0.0.1/tcp/5001", "http://127.0.0.1:5001"),
        ("/ip4/0.0.0.0/tcp/5001", "http://0.0.0.0:5001"),
        ("/ip6/::1/tcp/5001", "http://::1:5001"),
    ];

    for (multiaddr, expected_url) in test_cases {
        let temp_dir = TempDir::new().unwrap();
        let config = DaemonConfig {
            api_addr: multiaddr.to_string(),
            ..test_config(&temp_dir)
        };

        let daemon = IpfsDaemon::new(config);
        assert_eq!(daemon.api_url(), expected_url);
    }
}
