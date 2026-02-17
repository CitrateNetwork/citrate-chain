use async_trait::async_trait;
use citrate_execution::executor::ArtifactService;
use citrate_execution::ExecutionError;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Duration;

/// Simple IPFS HTTP client-backed artifact service.
/// Probes IPFS availability at construction time to avoid blocking RPC.
pub struct NodeArtifactService {
    client: reqwest::Client,
    apis: Vec<String>,
    ipfs_available: AtomicBool,
}

impl NodeArtifactService {
    pub fn new(api_base: Option<String>) -> Self {
        let apis = if let Ok(list) = std::env::var("CITRATE_IPFS_PROVIDERS") {
            list.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![api_base.unwrap_or_else(|| "http://127.0.0.1:5001".to_string())]
        };
        // Synchronously probe IPFS at startup
        let available = Self::probe_ipfs_sync(&apis);
        if !available {
            eprintln!("[artifact] IPFS not reachable at startup; artifact operations will return errors");
        }
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_millis(1500))
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            apis,
            ipfs_available: AtomicBool::new(available),
        }
    }

    pub fn new_with_providers(providers: Vec<String>) -> Self {
        let apis = if providers.is_empty() {
            vec!["http://127.0.0.1:5001".to_string()]
        } else {
            providers
        };
        let available = Self::probe_ipfs_sync(&apis);
        if !available {
            eprintln!("[artifact] IPFS not reachable at startup; artifact operations will return errors");
        }
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_millis(1500))
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            apis,
            ipfs_available: AtomicBool::new(available),
        }
    }

    /// Synchronous TCP probe to check if any IPFS provider is reachable
    fn probe_ipfs_sync(apis: &[String]) -> bool {
        for base in apis {
            // Extract host:port from URL like "http://127.0.0.1:5001"
            let stripped = base
                .strip_prefix("http://")
                .or_else(|| base.strip_prefix("https://"))
                .unwrap_or(base);
            let addr_str = if stripped.contains(':') {
                stripped.split('/').next().unwrap_or("127.0.0.1:5001").to_string()
            } else {
                format!("{}:5001", stripped.split('/').next().unwrap_or("127.0.0.1"))
            };
            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                if std::net::TcpStream::connect_timeout(
                    &addr,
                    std::time::Duration::from_secs(1),
                ).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    fn check_available(&self) -> Result<(), ExecutionError> {
        if !self.ipfs_available.load(Ordering::Relaxed) {
            // Re-probe: IPFS may have started since last check
            if Self::probe_ipfs_sync(&self.apis) {
                self.ipfs_available.store(true, Ordering::Relaxed);
                eprintln!("[artifact] IPFS now reachable — re-enabled artifact operations");
            } else {
                return Err(ExecutionError::Reverted(
                    "IPFS daemon not available".into(),
                ));
            }
        }
        Ok(())
    }

    fn mark_unavailable(&self) {
        self.ipfs_available.store(false, Ordering::Relaxed);
    }
}

#[async_trait]
impl ArtifactService for NodeArtifactService {
    async fn pin(&self, cid: &str, replicas: usize) -> Result<(), ExecutionError> {
        self.check_available()?;

        let needed = replicas.max(1);
        let mut successes = 0usize;
        let mut last_err: Option<String> = None;
        for base in &self.apis {
            let url = format!("{}/api/v0/pin/add?arg={}&timeout=5s", base, cid);
            match self.client.post(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    successes += 1;
                }
                Ok(resp) => {
                    last_err = Some(format!("{}: status {}", base, resp.status()));
                }
                Err(e) => {
                    if e.is_connect() {
                        self.mark_unavailable();
                    }
                    last_err = Some(format!("{}: {}", base, e));
                }
            }
            if successes >= needed {
                return Ok(());
            }
        }
        Err(ExecutionError::Reverted(
            last_err.unwrap_or_else(|| "pin failed: no IPFS providers available".into()),
        ))
    }

    async fn status(&self, cid: &str) -> Result<String, ExecutionError> {
        self.check_available()?;

        let mut arr = Vec::new();
        for base in &self.apis {
            let url = format!("{}/api/v0/pin/ls?arg={}", base, cid);
            let status = match self.client.post(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(body) => {
                        if body.contains(cid) {
                            "pinned"
                        } else {
                            "unpinned"
                        }
                    }
                    Err(_) => "unknown",
                },
                Ok(_) => "unknown",
                Err(e) => {
                    if e.is_connect() {
                        self.mark_unavailable();
                    }
                    "unknown"
                }
            };
            arr.push(serde_json::json!({ "provider": base, "status": status }));
        }
        Ok(serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into()))
    }

    async fn add(&self, data: &[u8]) -> Result<String, ExecutionError> {
        self.check_available()?;

        let base = self
            .apis
            .first()
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:5001".to_string());
        let url = format!("{}/api/v0/add?pin=true", base);
        let part = reqwest::multipart::Part::bytes(data.to_vec()).file_name("artifact.bin");
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    self.mark_unavailable();
                }
                ExecutionError::Reverted(format!("ipfs add error: {}", e))
            })?;
        if !resp.status().is_success() {
            return Err(ExecutionError::Reverted(format!(
                "ipfs add status: {}",
                resp.status()
            )));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ExecutionError::Reverted(format!("ipfs add parse error: {}", e)))?;
        let cid = json["Hash"].as_str().unwrap_or("").to_string();
        if cid.is_empty() {
            return Err(ExecutionError::Reverted(
                "ipfs add returned empty cid".into(),
            ));
        }
        Ok(cid)
    }
}
