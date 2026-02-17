// citrate/core/storage/src/ipfs/daemon.rs

//! IPFS Daemon Management
//!
//! This module handles automatic downloading, installation, and lifecycle
//! management of the IPFS daemon (kubo). It ensures IPFS is available
//! and running when the Citrate node starts.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// IPFS (kubo) version to download if not installed
pub const KUBO_VERSION: &str = "0.32.1";

/// Default IPFS API port
pub const DEFAULT_API_PORT: u16 = 5001;

/// Default IPFS gateway port
pub const DEFAULT_GATEWAY_PORT: u16 = 8080;

/// Default IPFS swarm port
pub const DEFAULT_SWARM_PORT: u16 = 4001;

/// IPFS daemon status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DaemonStatus {
    /// Daemon is not installed
    NotInstalled,
    /// Daemon is installed but not running
    Stopped,
    /// Daemon is starting up
    Starting,
    /// Daemon is running and healthy
    Running,
    /// Daemon encountered an error
    Error(String),
}

/// IPFS daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to IPFS binary
    pub binary_path: Option<PathBuf>,
    /// IPFS repository path
    pub repo_path: PathBuf,
    /// API listen address
    pub api_addr: String,
    /// Gateway listen address
    pub gateway_addr: String,
    /// Swarm listen addresses
    pub swarm_addrs: Vec<String>,
    /// Auto-start daemon when node starts
    pub auto_start: bool,
    /// Auto-download if not installed
    pub auto_download: bool,
    /// Enable pubsub
    pub enable_pubsub: bool,
    /// Low-power profile for resource-constrained systems
    pub low_power: bool,
    /// Maximum storage size (e.g., "100GB")
    pub storage_max: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            binary_path: None,
            repo_path: home.join(".ipfs"),
            api_addr: format!("/ip4/127.0.0.1/tcp/{}", DEFAULT_API_PORT),
            gateway_addr: format!("/ip4/127.0.0.1/tcp/{}", DEFAULT_GATEWAY_PORT),
            swarm_addrs: vec![
                format!("/ip4/0.0.0.0/tcp/{}", DEFAULT_SWARM_PORT),
                format!("/ip6/::/tcp/{}", DEFAULT_SWARM_PORT),
                format!("/ip4/0.0.0.0/udp/{}/quic-v1", DEFAULT_SWARM_PORT),
                format!("/ip6/::/udp/{}/quic-v1", DEFAULT_SWARM_PORT),
            ],
            auto_start: true,
            auto_download: true,
            enable_pubsub: true,
            low_power: false,
            storage_max: "100GB".to_string(),
        }
    }
}

/// IPFS node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub peer_id: String,
    pub agent_version: String,
    pub protocol_version: String,
    pub addresses: Vec<String>,
}

/// IPFS daemon manager
pub struct IpfsDaemon {
    config: DaemonConfig,
    status: Arc<RwLock<DaemonStatus>>,
    child_process: Arc<RwLock<Option<Child>>>,
    http_client: Client,
    shutdown: Arc<AtomicBool>,
}

impl IpfsDaemon {
    /// Create a new IPFS daemon manager
    pub fn new(config: DaemonConfig) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            status: Arc::new(RwLock::new(DaemonStatus::NotInstalled)),
            child_process: Arc::new(RwLock::new(None)),
            http_client,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initialize and start the IPFS daemon
    ///
    /// This method will:
    /// 1. Check if IPFS is installed, download if not (and auto_download is true)
    /// 2. Initialize the IPFS repository if needed
    /// 3. Start the daemon if auto_start is true
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing IPFS daemon...");

        // Find or download IPFS binary
        let binary_path = match self.find_ipfs_binary().await {
            Ok(path) => {
                info!("Found IPFS binary at: {:?}", path);
                path
            }
            Err(_) if self.config.auto_download => {
                info!("IPFS not found, downloading...");
                self.download_ipfs().await?
            }
            Err(e) => return Err(e),
        };

        // Initialize repository if needed
        if !self.is_repo_initialized() {
            info!("Initializing IPFS repository...");
            self.init_repo(&binary_path).await?;
        }

        // Configure IPFS
        self.configure_ipfs(&binary_path).await?;

        // Start daemon if auto_start is enabled
        if self.config.auto_start {
            self.start(&binary_path).await?;
        } else {
            *self.status.write().await = DaemonStatus::Stopped;
        }

        Ok(())
    }

    /// Find the IPFS binary in common locations
    pub async fn find_ipfs_binary(&self) -> Result<PathBuf> {
        // Check configured path first
        if let Some(ref path) = self.config.binary_path {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        // Common installation paths
        let search_paths = [
            "/usr/local/bin/ipfs",
            "/usr/bin/ipfs",
            "/opt/homebrew/bin/ipfs",
            &format!(
                "{}/.local/bin/ipfs",
                dirs::home_dir().unwrap_or_default().display()
            ),
            &format!(
                "{}/.citrate/bin/ipfs",
                dirs::home_dir().unwrap_or_default().display()
            ),
        ];

        for path_str in &search_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                // Verify it's actually IPFS
                if let Ok(output) = Command::new(&path).arg("--version").output() {
                    if output.status.success() {
                        let version = String::from_utf8_lossy(&output.stdout);
                        if version.contains("ipfs") || version.contains("kubo") {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        // Try PATH
        if let Ok(output) = Command::new("which").arg("ipfs").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = PathBuf::from(path_str.trim());
                if path.exists() {
                    return Ok(path);
                }
            }
        }

        Err(anyhow!("IPFS binary not found"))
    }

    /// Download and install IPFS (kubo)
    pub async fn download_ipfs(&self) -> Result<PathBuf> {
        let (os, arch) = Self::detect_platform()?;
        let archive_ext = if os == "windows" { "zip" } else { "tar.gz" };

        let download_url = format!(
            "https://dist.ipfs.tech/kubo/v{}/kubo_v{}_{}-{}.{}",
            KUBO_VERSION, KUBO_VERSION, os, arch, archive_ext
        );

        info!("Downloading IPFS from: {}", download_url);
        *self.status.write().await = DaemonStatus::Starting;

        // Create install directory
        let install_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory"))?
            .join(".citrate")
            .join("bin");

        tokio::fs::create_dir_all(&install_dir).await?;

        // Download archive
        let response = self.http_client
            .get(&download_url)
            .send()
            .await
            .context("Failed to download IPFS")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download IPFS: HTTP {}",
                response.status()
            ));
        }

        let archive_bytes = response.bytes().await?;
        info!("Downloaded {} bytes", archive_bytes.len());

        // Extract archive
        let binary_path = self.extract_archive(&archive_bytes, &install_dir, os).await?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&binary_path).await?.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&binary_path, perms).await?;
        }

        // Verify installation
        let output = Command::new(&binary_path)
            .arg("--version")
            .output()
            .context("Failed to verify IPFS installation")?;

        if !output.status.success() {
            return Err(anyhow!("IPFS installation verification failed"));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        info!("Successfully installed IPFS: {}", version.trim());

        Ok(binary_path)
    }

    /// Detect the current platform (os, arch)
    fn detect_platform() -> Result<(&'static str, &'static str)> {
        let os = match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "darwin",
            "windows" => "windows",
            "freebsd" => "freebsd",
            other => return Err(anyhow!("Unsupported OS: {}", other)),
        };

        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "arm" => "arm",
            "x86" => "386",
            other => return Err(anyhow!("Unsupported architecture: {}", other)),
        };

        Ok((os, arch))
    }

    /// Extract the downloaded archive
    async fn extract_archive(
        &self,
        archive_bytes: &[u8],
        install_dir: &PathBuf,
        os: &str,
    ) -> Result<PathBuf> {
        use std::io::Cursor;

        let binary_name = if os == "windows" { "ipfs.exe" } else { "ipfs" };
        let binary_path = install_dir.join(binary_name);

        if os == "windows" {
            // Extract ZIP
            let cursor = Cursor::new(archive_bytes);
            let mut archive = zip::ZipArchive::new(cursor)
                .context("Failed to open ZIP archive")?;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.ends_with(binary_name) || name.ends_with("/ipfs") {
                    let mut outfile = std::fs::File::create(&binary_path)?;
                    std::io::copy(&mut file, &mut outfile)?;
                    break;
                }
            }
        } else {
            // Extract tar.gz
            let cursor = Cursor::new(archive_bytes);
            let gz = flate2::read::GzDecoder::new(cursor);
            let mut archive = tar::Archive::new(gz);

            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;
                let path_str = path.to_string_lossy();

                if path_str.ends_with("/ipfs") || path_str == "kubo/ipfs" {
                    entry.unpack(&binary_path)?;
                    break;
                }
            }
        }

        if !binary_path.exists() {
            return Err(anyhow!("Failed to extract IPFS binary"));
        }

        Ok(binary_path)
    }

    /// Check if the IPFS repository is initialized
    pub fn is_repo_initialized(&self) -> bool {
        self.config.repo_path.join("config").exists()
    }

    /// Initialize the IPFS repository
    async fn init_repo(&self, binary_path: &PathBuf) -> Result<()> {
        let profile = if self.config.low_power {
            "lowpower"
        } else {
            "server"
        };

        let output = Command::new(binary_path)
            .env("IPFS_PATH", &self.config.repo_path)
            .args(["init", "--profile", profile])
            .output()
            .context("Failed to initialize IPFS repository")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already initialized" errors
            if !stderr.contains("already") {
                return Err(anyhow!("Failed to init IPFS repo: {}", stderr));
            }
        }

        info!("IPFS repository initialized at {:?}", self.config.repo_path);
        Ok(())
    }

    /// Configure IPFS settings
    async fn configure_ipfs(&self, binary_path: &PathBuf) -> Result<()> {
        let configs = [
            // API address
            ("Addresses.API", &self.config.api_addr),
            // Gateway address
            ("Addresses.Gateway", &self.config.gateway_addr),
            // Storage max
            ("Datastore.StorageMax", &self.config.storage_max),
        ];

        for (key, value) in configs {
            let _ = Command::new(binary_path)
                .env("IPFS_PATH", &self.config.repo_path)
                .args(["config", key, value])
                .output();
        }

        // Enable pubsub if configured
        if self.config.enable_pubsub {
            let _ = Command::new(binary_path)
                .env("IPFS_PATH", &self.config.repo_path)
                .args(["config", "--json", "Pubsub.Enabled", "true"])
                .output();
        }

        // Configure CORS for API access
        let cors_configs = [
            ("API.HTTPHeaders.Access-Control-Allow-Origin", r#"["*"]"#),
            ("API.HTTPHeaders.Access-Control-Allow-Methods", r#"["PUT", "POST", "GET"]"#),
        ];

        for (key, value) in cors_configs {
            let _ = Command::new(binary_path)
                .env("IPFS_PATH", &self.config.repo_path)
                .args(["config", "--json", key, value])
                .output();
        }

        info!("IPFS configured successfully");
        Ok(())
    }

    /// Start the IPFS daemon
    pub async fn start(&self, binary_path: &PathBuf) -> Result<()> {
        // Check if already running
        if self.is_running().await {
            info!("IPFS daemon is already running");
            *self.status.write().await = DaemonStatus::Running;
            return Ok(());
        }

        info!("Starting IPFS daemon...");
        *self.status.write().await = DaemonStatus::Starting;

        // Build command
        let mut cmd = Command::new(binary_path);
        cmd.env("IPFS_PATH", &self.config.repo_path)
            .args(["daemon", "--migrate=true"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if self.config.enable_pubsub {
            cmd.arg("--enable-pubsub-experiment");
        }

        // Spawn the daemon
        let child = cmd.spawn().context("Failed to start IPFS daemon")?;

        *self.child_process.write().await = Some(child);

        // Wait for daemon to be ready
        self.wait_for_ready().await?;

        *self.status.write().await = DaemonStatus::Running;
        info!("IPFS daemon started successfully");

        Ok(())
    }

    /// Wait for the daemon to be ready
    async fn wait_for_ready(&self) -> Result<()> {
        let api_url = self.api_url();
        let max_attempts = 60; // 30 seconds with 500ms intervals

        for attempt in 1..=max_attempts {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(anyhow!("Shutdown requested during startup"));
            }

            match self.http_client
                .post(format!("{}/api/v0/id", api_url))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    debug!("IPFS daemon ready after {} attempts", attempt);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("Waiting for IPFS daemon (attempt {}): {}", attempt, e);
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(anyhow!("IPFS daemon failed to start within timeout"))
    }

    /// Check if the daemon is running
    pub async fn is_running(&self) -> bool {
        let api_url = self.api_url();

        match self.http_client
            .post(format!("{}/api/v0/id", api_url))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Get current daemon status
    pub async fn status(&self) -> DaemonStatus {
        if self.is_running().await {
            DaemonStatus::Running
        } else {
            let status = self.status.read().await;
            match *status {
                DaemonStatus::Starting => DaemonStatus::Starting,
                DaemonStatus::Error(ref e) => DaemonStatus::Error(e.clone()),
                _ => {
                    if self.find_ipfs_binary().await.is_ok() {
                        DaemonStatus::Stopped
                    } else {
                        DaemonStatus::NotInstalled
                    }
                }
            }
        }
    }

    /// Get node information
    pub async fn node_info(&self) -> Result<NodeInfo> {
        let api_url = self.api_url();

        #[derive(Deserialize)]
        struct IdResponse {
            #[serde(rename = "ID")]
            id: String,
            #[serde(rename = "AgentVersion")]
            agent_version: String,
            #[serde(rename = "ProtocolVersion")]
            protocol_version: String,
            #[serde(rename = "Addresses")]
            addresses: Vec<String>,
        }

        let response = self.http_client
            .post(format!("{}/api/v0/id", api_url))
            .send()
            .await?;

        let info: IdResponse = response.json().await?;

        Ok(NodeInfo {
            peer_id: info.id,
            agent_version: info.agent_version,
            protocol_version: info.protocol_version,
            addresses: info.addresses,
        })
    }

    /// Stop the IPFS daemon
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping IPFS daemon...");
        self.shutdown.store(true, Ordering::Relaxed);

        // Try graceful shutdown via API
        let api_url = self.api_url();
        let shutdown_result = self.http_client
            .post(format!("{}/api/v0/shutdown", api_url))
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        // If API shutdown failed, try killing the process
        if shutdown_result.is_err() {
            if let Some(mut child) = self.child_process.write().await.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Wait for process to exit
        tokio::time::sleep(Duration::from_millis(500)).await;

        *self.status.write().await = DaemonStatus::Stopped;
        info!("IPFS daemon stopped");

        Ok(())
    }

    /// Get the API URL
    pub fn api_url(&self) -> String {
        // Convert multiaddr format to HTTP URL
        // /ip4/127.0.0.1/tcp/5001 -> http://127.0.0.1:5001
        let addr = &self.config.api_addr;

        if let Some(captures) = parse_multiaddr(addr) {
            format!("http://{}:{}", captures.0, captures.1)
        } else {
            format!("http://127.0.0.1:{}", DEFAULT_API_PORT)
        }
    }

    /// Health check
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let is_running = self.is_running().await;

        if !is_running {
            return Ok(HealthStatus {
                healthy: false,
                peer_count: 0,
                repo_size: 0,
                error: Some("Daemon not running".to_string()),
            });
        }

        // Get peer count
        let peer_count = self.get_peer_count().await.unwrap_or(0);

        // Get repo stats
        let repo_size = self.get_repo_size().await.unwrap_or(0);

        Ok(HealthStatus {
            healthy: true,
            peer_count,
            repo_size,
            error: None,
        })
    }

    /// Get connected peer count
    async fn get_peer_count(&self) -> Result<usize> {
        let api_url = self.api_url();

        #[derive(Deserialize)]
        struct SwarmPeersResponse {
            #[serde(rename = "Peers")]
            peers: Option<Vec<serde_json::Value>>,
        }

        let response = self.http_client
            .post(format!("{}/api/v0/swarm/peers", api_url))
            .send()
            .await?;

        let result: SwarmPeersResponse = response.json().await?;
        Ok(result.peers.map(|p| p.len()).unwrap_or(0))
    }

    /// Get repository size
    async fn get_repo_size(&self) -> Result<u64> {
        let api_url = self.api_url();

        #[derive(Deserialize)]
        struct RepoStatResponse {
            #[serde(rename = "RepoSize")]
            repo_size: u64,
        }

        let response = self.http_client
            .post(format!("{}/api/v0/repo/stat", api_url))
            .send()
            .await?;

        let result: RepoStatResponse = response.json().await?;
        Ok(result.repo_size)
    }
}

impl Drop for IpfsDaemon {
    fn drop(&mut self) {
        // Try to stop daemon on drop
        // Use try_write to avoid blocking in destructor
        if let Ok(mut guard) = self.child_process.try_write() {
            if let Some(mut child) = guard.take() {
                // Kill the child process
                match child.kill() {
                    Ok(_) => {
                        // Wait for process to exit
                        let _ = child.wait();
                    }
                    Err(_) => {
                        // Process may have already exited
                    }
                }
            }
        }
    }
}

/// Health status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub peer_count: usize,
    pub repo_size: u64,
    pub error: Option<String>,
}

/// Parse multiaddr format to (ip, port)
fn parse_multiaddr(addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr.split('/').collect();

    // /ip4/127.0.0.1/tcp/5001
    if parts.len() >= 5 && (parts[1] == "ip4" || parts[1] == "ip6") && parts[3] == "tcp" {
        let ip = parts[2].to_string();
        let port = parts[4].parse().ok()?;
        return Some((ip, port));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DaemonConfig::default();
        assert!(config.auto_start);
        assert!(config.auto_download);
        assert!(config.enable_pubsub);
        assert_eq!(config.storage_max, "100GB");
    }

    #[test]
    fn test_parse_multiaddr() {
        let addr = "/ip4/127.0.0.1/tcp/5001";
        let result = parse_multiaddr(addr);
        assert_eq!(result, Some(("127.0.0.1".to_string(), 5001)));

        let addr = "/ip6/::1/tcp/5001";
        let result = parse_multiaddr(addr);
        assert_eq!(result, Some(("::1".to_string(), 5001)));

        let invalid = "http://localhost:5001";
        let result = parse_multiaddr(invalid);
        assert_eq!(result, None);
    }

    #[test]
    fn test_detect_platform() {
        let result = IpfsDaemon::detect_platform();
        assert!(result.is_ok());

        let (os, arch) = result.unwrap();
        assert!(!os.is_empty());
        assert!(!arch.is_empty());
    }

    #[test]
    fn test_api_url() {
        let config = DaemonConfig {
            api_addr: "/ip4/127.0.0.1/tcp/5001".to_string(),
            ..Default::default()
        };
        let daemon = IpfsDaemon::new(config);
        assert_eq!(daemon.api_url(), "http://127.0.0.1:5001");
    }

    #[test]
    fn test_daemon_status_serialization() {
        let status = DaemonStatus::Running;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Running\"");

        let status = DaemonStatus::Error("test error".to_string());
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("test error"));
    }

    #[tokio::test]
    async fn test_is_repo_initialized_false() {
        let config = DaemonConfig {
            repo_path: PathBuf::from("/nonexistent/path"),
            ..Default::default()
        };
        let daemon = IpfsDaemon::new(config);
        assert!(!daemon.is_repo_initialized());
    }

    #[tokio::test]
    #[ignore = "Environment-dependent: fails when IPFS is installed on system PATH"]
    async fn test_find_ipfs_binary_with_custom_path() {
        let config = DaemonConfig {
            binary_path: Some(PathBuf::from("/nonexistent/ipfs")),
            ..Default::default()
        };
        let daemon = IpfsDaemon::new(config);

        // Should fail since path doesn't exist
        let result = daemon.find_ipfs_binary().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "Environment-dependent: fails when IPFS daemon is running on system"]
    async fn test_status_not_installed() {
        let config = DaemonConfig {
            binary_path: Some(PathBuf::from("/nonexistent/ipfs")),
            auto_download: false,
            ..Default::default()
        };
        let daemon = IpfsDaemon::new(config);

        let status = daemon.status().await;
        assert_eq!(status, DaemonStatus::NotInstalled);
    }
}
