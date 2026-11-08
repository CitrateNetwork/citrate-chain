//citrate/cli/src/commands/verify.rs
//
// Client for CitrateScan source verification (`citrate contract verify`).
//
// Data source: the explorer's Etherscan-compatible API (`GET|POST <explorer>/api`,
// `module=contract`, actions `verifysourcecode`, `checkverifystatus`, `getsourcecode`).
// The request shape is the one forge 1.5.1 (`--verifier custom`) and hardhat-verify 2.1.3
// send; `cli/tests/fixtures/verify/*/…-requests.jsonl` holds their recorded requests and the
// tests compare this client against them.
//
// The standard JSON input is built from a compiler build-info file (forge
// `out/build-info/*.json` written with `--build-info`, hardhat `artifacts/build-info/*.json`,
// or a hardhat contract artifact, which names its build-info in the sibling `.dbg.json`).
// Like forge and hardhat-verify, only the sources the contract's metadata lists are sent.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Default Etherscan-compatible endpoint of CitrateScan.
pub const DEFAULT_EXPLORER_URL: &str = "https://explorer.citrate.ai/api";
/// Explorer limit on the submitted source (docs/VERIFY.md, "Limits").
pub const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
/// Explorer limit on the number of source files.
pub const MAX_SOURCE_FILES: usize = 64;
/// Etherscan accepts at most ten `libraryname<n>` / `libraryaddress<n>` pairs.
pub const MAX_SINGLE_FILE_LIBRARIES: usize = 10;

const CODEFORMAT_STANDARD_JSON: &str = "solidity-standard-json-input";
const CODEFORMAT_SINGLE_FILE: &str = "solidity-single-file";

// ---------------------------------------------------------------------------
// Build-info parsing
// ---------------------------------------------------------------------------

/// Which file a compilation input was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildArtifactKind {
    /// forge `out/build-info/<id>.json` (`_format: ethers-rs-sol-build-info-1`).
    ForgeBuildInfo,
    /// hardhat `artifacts/build-info/<id>.json` (`_format: hh-sol-build-info-1`).
    HardhatBuildInfo,
    /// hardhat `artifacts/<path>/<Name>.json`, resolved through `<Name>.dbg.json`.
    HardhatArtifact,
    /// A bare solc standard JSON input (`{language, sources, settings}`).
    StandardJsonInput,
}

/// A solc standard JSON input plus whatever compiler output came with it.
#[derive(Debug, Clone)]
pub struct CompilationInput {
    pub kind: BuildArtifactKind,
    /// The standard JSON input (`language`, `sources`, `settings`, possibly tool extras).
    pub input: Value,
    /// The compiler output, when the file carries it (build-info files do).
    pub output: Option<Value>,
    /// `solcLongVersion` from the build-info, if any. forge 1.5.1 writes `0.8.26` here
    /// without the commit, so the contract metadata is preferred.
    pub solc_long_version: Option<String>,
    /// The contract a hardhat artifact names (`sourceName:contractName`).
    pub default_contract: Option<String>,
}

/// Read a build-info file, a hardhat contract artifact or a standard JSON input.
pub fn load_compilation_input(path: &Path) -> Result<CompilationInput> {
    let value = read_json(path)?;
    if value.get("_format").and_then(Value::as_str) == Some("hh-sol-artifact-1") {
        return load_hardhat_artifact(path, &value);
    }
    parse_compilation_input(value)
}

/// Classify an already-parsed JSON document. Hardhat contract artifacts need the file
/// system (their build-info is a separate file); use [`load_compilation_input`] for those.
pub fn parse_compilation_input(value: Value) -> Result<CompilationInput> {
    let format = value
        .get("_format")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if format.as_deref() == Some("hh-sol-artifact-1") {
        bail!("a hardhat contract artifact names its build-info in the sibling .dbg.json; pass the artifact's path");
    }
    if let Some(input) = value.get("input") {
        if !input.is_object() {
            bail!("build-info `input` is not an object");
        }
        let kind = match format.as_deref() {
            Some(f) if f.starts_with("hh-sol-build-info") => BuildArtifactKind::HardhatBuildInfo,
            _ => BuildArtifactKind::ForgeBuildInfo,
        };
        return Ok(CompilationInput {
            kind,
            input: input.clone(),
            output: value.get("output").cloned(),
            solc_long_version: value
                .get("solcLongVersion")
                .and_then(Value::as_str)
                .map(str::to_owned),
            default_contract: None,
        });
    }
    if value.get("source_id_to_path").is_some() {
        bail!(
            "this forge build-info has no compiler input (forge writes the full file only with \
             --build-info). Rebuild with `forge build --build-info` or set `build_info = true` \
             in foundry.toml, then pass out/build-info/<id>.json"
        );
    }
    if value.get("sources").is_some() && value.get("language").is_some() {
        return Ok(CompilationInput {
            kind: BuildArtifactKind::StandardJsonInput,
            input: value,
            output: None,
            solc_long_version: None,
            default_contract: None,
        });
    }
    bail!("not a forge or hardhat build-info, a hardhat artifact, or a standard JSON input")
}

fn load_hardhat_artifact(path: &Path, artifact: &Value) -> Result<CompilationInput> {
    let source_name = artifact
        .get("sourceName")
        .and_then(Value::as_str)
        .context("hardhat artifact has no sourceName")?;
    let contract_name = artifact
        .get("contractName")
        .and_then(Value::as_str)
        .context("hardhat artifact has no contractName")?;
    let dbg_path = dbg_path_for(path)?;
    let dbg = read_json(&dbg_path).with_context(|| {
        format!(
            "hardhat artifact needs its debug file {} (run `npx hardhat compile`)",
            dbg_path.display()
        )
    })?;
    let rel = dbg
        .get("buildInfo")
        .and_then(Value::as_str)
        .with_context(|| format!("{} has no buildInfo path", dbg_path.display()))?;
    let base = dbg_path.parent().unwrap_or_else(|| Path::new("."));
    let build_info_path = base.join(rel);
    let mut ci = parse_compilation_input(read_json(&build_info_path)?)
        .with_context(|| format!("reading {}", build_info_path.display()))?;
    ci.kind = BuildArtifactKind::HardhatArtifact;
    ci.default_contract = Some(format!("{source_name}:{contract_name}"));
    Ok(ci)
}

fn dbg_path_for(artifact_path: &Path) -> Result<PathBuf> {
    let stem = artifact_path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("artifact path has no file name")?;
    Ok(artifact_path.with_file_name(format!("{stem}.dbg.json")))
}

fn read_json(path: &Path) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))
}

// ---------------------------------------------------------------------------
// Standard JSON submission
// ---------------------------------------------------------------------------

/// What `verifysourcecode` needs for `codeformat=solidity-standard-json-input`.
#[derive(Debug, Clone, PartialEq)]
pub struct StandardJsonSubmission {
    pub standard_json: Value,
    /// Fully qualified name, `path/To.sol:Name`.
    pub contract_name: String,
    /// solc long version with the `v` prefix, e.g. `v0.8.26+commit.8a97fa7a`.
    pub compiler_version: String,
}

/// Build the submission for one contract of a compilation.
///
/// `contract` is `path:Name` or a bare `Name` (resolved when unique). `compiler` overrides the
/// version read from the contract metadata.
pub fn prepare_standard_json(
    ci: &CompilationInput,
    contract: Option<&str>,
    compiler: Option<&str>,
) -> Result<StandardJsonSubmission> {
    let wanted = contract
        .map(str::to_owned)
        .or_else(|| ci.default_contract.clone());
    let (path, name) = resolve_contract(ci, wanted.as_deref())?;
    let metadata = contract_metadata(ci, &path, &name)?;

    let compiler_version = match compiler {
        Some(v) => normalize_compiler_version(v)?,
        None => {
            let from_metadata = metadata
                .as_ref()
                .and_then(|m| m.get("compiler"))
                .and_then(|c| c.get("version"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let found = from_metadata
                .or_else(|| ci.solc_long_version.clone())
                .context(
                    "no compiler version in the build-info; pass --compiler v0.8.x+commit.<hash>",
                )?;
            normalize_compiler_version(&found)?
        }
    };

    let sources_in = ci
        .input
        .get("sources")
        .and_then(Value::as_object)
        .context("standard JSON input has no sources")?;
    // Only the files the contract was compiled from, as forge and hardhat-verify send.
    let keep: Vec<String> = match metadata
        .as_ref()
        .and_then(|m| m.get("sources"))
        .and_then(Value::as_object)
    {
        Some(meta_sources) => meta_sources.keys().cloned().collect(),
        None => sources_in.keys().cloned().collect(),
    };
    let mut sources = Map::new();
    for key in keep {
        let entry = sources_in.get(&key).with_context(|| {
            format!("source {key} is listed in the metadata but missing from the input")
        })?;
        if entry.get("content").and_then(Value::as_str).is_none() {
            bail!("source {key} has no inline content (the explorer does not fetch `urls`)");
        }
        sources.insert(key, entry.clone());
    }
    if sources.len() > MAX_SOURCE_FILES {
        bail!(
            "{} source files; the explorer accepts at most {MAX_SOURCE_FILES}",
            sources.len()
        );
    }

    let mut settings = ci
        .input
        .get("settings")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(sel) = settings.get("outputSelection").and_then(Value::as_object) {
        if !sel.contains_key("*") {
            // forge keys outputSelection by file; the pruned input uses one "*" entry.
            if let Some(first) = sel.values().next() {
                let mut star = Map::new();
                star.insert("*".to_owned(), first.clone());
                settings.insert("outputSelection".to_owned(), Value::Object(star));
            }
        }
    }
    if !settings.contains_key("libraries") {
        settings.insert("libraries".to_owned(), Value::Object(Map::new()));
    }

    let language = ci
        .input
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("Solidity")
        .to_owned();
    let mut std_json = Map::new();
    std_json.insert("language".to_owned(), Value::String(language));
    std_json.insert("sources".to_owned(), Value::Object(sources));
    std_json.insert("settings".to_owned(), Value::Object(settings));
    let standard_json = Value::Object(std_json);

    let size = serde_json::to_string(&standard_json)?.len();
    if size > MAX_SOURCE_BYTES {
        bail!(
            "standard JSON input is {size} bytes; the explorer accepts at most {MAX_SOURCE_BYTES}"
        );
    }

    Ok(StandardJsonSubmission {
        standard_json,
        contract_name: format!("{path}:{name}"),
        compiler_version,
    })
}

fn resolve_contract(ci: &CompilationInput, wanted: Option<&str>) -> Result<(String, String)> {
    let contracts = ci
        .output
        .as_ref()
        .and_then(|o| o.get("contracts"))
        .and_then(Value::as_object);
    match (wanted, contracts) {
        (Some(fq), _) if fq.contains(':') => {
            let (path, name) = fq.rsplit_once(':').context("contract name")?;
            if let Some(all) = contracts {
                let present = all.get(path).and_then(|f| f.get(name)).is_some();
                if !present {
                    bail!("contract {fq} is not in this build-info");
                }
            }
            Ok((path.to_owned(), name.to_owned()))
        }
        (wanted, Some(all)) => {
            let mut hits = Vec::new();
            for (path, file) in all {
                if let Some(file) = file.as_object() {
                    for name in file.keys() {
                        if wanted.is_none_or(|w| w == name) {
                            hits.push((path.clone(), name.clone()));
                        }
                    }
                }
            }
            match hits.len() {
                1 => hits.pop().context("one match"),
                0 => bail!(
                    "contract {} is not in this build-info",
                    wanted.unwrap_or("(none given)")
                ),
                _ => bail!(
                    "several contracts match; pass --contract <path>:<Name>, one of: {}",
                    hits.iter()
                        .map(|(p, n)| format!("{p}:{n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        (_, None) => {
            bail!("a standard JSON input carries no contract list; pass --contract <path>:<Name>")
        }
    }
}

fn contract_metadata(ci: &CompilationInput, path: &str, name: &str) -> Result<Option<Value>> {
    let raw = ci
        .output
        .as_ref()
        .and_then(|o| o.get("contracts"))
        .and_then(|c| c.get(path))
        .and_then(|f| f.get(name))
        .and_then(|c| c.get("metadata"));
    match raw {
        Some(Value::String(s)) => Ok(Some(
            serde_json::from_str(s).with_context(|| format!("metadata of {path}:{name}"))?,
        )),
        Some(v @ Value::Object(_)) => Ok(Some(v.clone())),
        _ => Ok(None),
    }
}

/// `0.8.26+commit.8a97fa7a` or `v0.8.26+commit.8a97fa7a` → `v0.8.26+commit.8a97fa7a`.
/// The explorer resolves only full release versions, so a version without the commit is refused.
pub fn normalize_compiler_version(v: &str) -> Result<String> {
    let t = v.trim();
    let t = t.strip_prefix('v').unwrap_or(t);
    if !t.contains("+commit.") {
        bail!("compiler version {v:?} lacks the commit; use the long form, e.g. v0.8.26+commit.8a97fa7a");
    }
    Ok(format!("v{t}"))
}

/// Validate hex constructor arguments and return them lowercase without `0x`.
pub fn normalize_constructor_args(args: &str) -> Result<String> {
    let t = args.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if !t.len().is_multiple_of(2) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("constructor args must be ABI-encoded hex (e.g. from `cast abi-encode`)");
    }
    Ok(t.to_ascii_lowercase())
}

fn validate_address(a: &str) -> Result<()> {
    let h = a
        .strip_prefix("0x")
        .or_else(|| a.strip_prefix("0X"))
        .with_context(|| format!("address {a:?} must start with 0x"))?;
    if h.len() != 40 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("address {a:?} is not 20 bytes of hex");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Etherscan `verifysourcecode` request
// ---------------------------------------------------------------------------

/// The source half of a submission.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceSubmission {
    StandardJson(StandardJsonSubmission),
    SingleFile {
        source: String,
        contract_name: String,
        compiler_version: String,
        optimization_used: bool,
        runs: u32,
        evm_version: Option<String>,
        /// (library name, address), at most ten.
        libraries: Vec<(String, String)>,
    },
}

/// One `module=contract&action=verifysourcecode` submission.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyRequest {
    pub address: String,
    pub source: SourceSubmission,
    /// ABI-encoded constructor arguments, hex. Optional: the explorer reads them from the
    /// creation transaction.
    pub constructor_args: Option<String>,
    pub creation_tx_hash: Option<String>,
    /// Etherscan v2 `chainid`. The explorer accepts it when it is 40204.
    pub chain_id: Option<u64>,
}

impl VerifyRequest {
    /// The form fields, in the order forge sends them. `apikey` is added by the client.
    pub fn form_fields(&self) -> Result<Vec<(String, String)>> {
        validate_address(&self.address)?;
        let mut f: Vec<(String, String)> = Vec::new();
        let mut push = |k: &str, v: String| f.push((k.to_owned(), v));
        if let Some(id) = self.chain_id {
            push("chainid", id.to_string());
        }
        push("module", "contract".to_owned());
        push("action", "verifysourcecode".to_owned());
        push("contractaddress", self.address.clone());
        match &self.source {
            SourceSubmission::StandardJson(s) => {
                push("sourceCode", serde_json::to_string(&s.standard_json)?);
                push("codeformat", CODEFORMAT_STANDARD_JSON.to_owned());
                push("contractname", s.contract_name.clone());
                push(
                    "compilerversion",
                    normalize_compiler_version(&s.compiler_version)?,
                );
            }
            SourceSubmission::SingleFile {
                source,
                contract_name,
                compiler_version,
                optimization_used,
                runs,
                evm_version,
                libraries,
            } => {
                if source.len() > MAX_SOURCE_BYTES {
                    bail!(
                        "source is {} bytes; the explorer accepts at most {MAX_SOURCE_BYTES}",
                        source.len()
                    );
                }
                if libraries.len() > MAX_SINGLE_FILE_LIBRARIES {
                    bail!("at most {MAX_SINGLE_FILE_LIBRARIES} libraries in single-file mode");
                }
                push("sourceCode", source.clone());
                push("codeformat", CODEFORMAT_SINGLE_FILE.to_owned());
                push("contractname", contract_name.clone());
                push(
                    "compilerversion",
                    normalize_compiler_version(compiler_version)?,
                );
                push(
                    "optimizationUsed",
                    if *optimization_used { "1" } else { "0" }.to_owned(),
                );
                push("runs", runs.to_string());
                if let Some(evm) = evm_version {
                    push("evmversion", evm.clone());
                }
                for (i, (lib, addr)) in libraries.iter().enumerate() {
                    validate_address(addr)?;
                    let n = i.saturating_add(1);
                    push(&format!("libraryname{n}"), lib.clone());
                    push(&format!("libraryaddress{n}"), addr.clone());
                }
            }
        }
        if let Some(args) = &self.constructor_args {
            let hex = normalize_constructor_args(args)?;
            // Etherscan's historical spelling, plus the corrected one, as forge sends both.
            push("constructorArguements", hex.clone());
            push("constructorArguments", hex);
        }
        if let Some(tx) = &self.creation_tx_hash {
            push("creationtxhash", tx.clone());
        }
        Ok(f)
    }
}

/// Parse `Name:0xAddress` (the `--library` flag).
pub fn parse_library(spec: &str) -> Result<(String, String)> {
    let (name, addr) = spec
        .rsplit_once(':')
        .with_context(|| format!("library {spec:?} must be Name:0xAddress"))?;
    validate_address(addr)?;
    Ok((name.to_owned(), addr.to_owned()))
}

// ---------------------------------------------------------------------------
// Explorer client
// ---------------------------------------------------------------------------

/// Status of a verification job (`checkverifystatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Pending(String),
    Verified(String),
    Failed(String),
}

impl VerifyStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, VerifyStatus::Pending(_))
    }
}

/// Why a submission or poll did not produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The explorer already holds a verified record for this address.
    AlreadyVerified(String),
    /// The explorer refused the submission (Etherscan's `result` string).
    Rejected(String),
    /// `Max rate limit reached`, after the configured retries.
    RateLimited(String),
    /// The job did not reach a verdict before the deadline.
    Timeout { guid: String, last: String },
    /// Non-2xx answer without an Etherscan envelope.
    Http { status: u16, body: String },
    /// The answer was not the documented envelope.
    Protocol(String),
    /// Connection-level failure.
    Transport(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::AlreadyVerified(m) => write!(f, "already verified: {m}"),
            VerifyError::Rejected(m) => write!(f, "explorer refused the submission: {m}"),
            VerifyError::RateLimited(m) => write!(f, "rate limited: {m}"),
            VerifyError::Timeout { guid, last } => {
                write!(
                    f,
                    "no verdict for {guid} before the deadline (last status: {last})"
                )
            }
            VerifyError::Http { status, body } => {
                write!(f, "explorer answered HTTP {status}: {body}")
            }
            VerifyError::Protocol(m) => write!(f, "unexpected explorer answer: {m}"),
            VerifyError::Transport(m) => write!(f, "could not reach the explorer: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl VerifyError {
    /// Worth retrying later: a transport failure (connection refused or reset, timeout) or an
    /// HTTP 5xx or 429 answer. `--watch` rides these out until its deadline; the SDKs do the
    /// same.
    pub fn is_transient(&self) -> bool {
        match self {
            VerifyError::Transport(_) => true,
            VerifyError::Http { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

/// Etherscan's `{status, message, result}`.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub ok: bool,
    pub message: String,
    pub result: Value,
}

impl Envelope {
    pub fn parse(body: &Value) -> Option<Envelope> {
        let status = match body.get("status")? {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => return None,
        };
        Some(Envelope {
            ok: status == "1",
            message: body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            result: body.get("result").cloned().unwrap_or(Value::Null),
        })
    }

    fn result_text(&self) -> String {
        match &self.result {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
}

fn is_rate_limited(text: &str) -> bool {
    text.to_ascii_lowercase().contains("rate limit")
}

/// Classify a `checkverifystatus` envelope.
pub fn classify_status(env: &Envelope) -> VerifyStatus {
    let text = env.result_text();
    let lower = text.to_ascii_lowercase();
    if env.ok || lower.contains("already verified") {
        VerifyStatus::Verified(text)
    } else if lower.starts_with("pending") || is_rate_limited(&text) {
        VerifyStatus::Pending(text)
    } else {
        VerifyStatus::Failed(text)
    }
}

/// Polling and retry knobs.
#[derive(Debug, Clone, Copy)]
pub struct PollConfig {
    pub interval: Duration,
    pub timeout: Duration,
    /// Extra submission attempts after `Max rate limit reached`.
    pub rate_limit_retries: u32,
    pub rate_limit_backoff: Duration,
    /// While polling, a transient error is retried after a backoff that starts at `interval`,
    /// doubles per consecutive error and is capped here, all within `timeout`.
    pub transient_backoff_max: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3),
            // Compiles may take 120 s (docs/VERIFY.md, "Limits") plus queue time.
            timeout: Duration::from_secs(300),
            rate_limit_retries: 3,
            // One submission per 5 s per IP.
            rate_limit_backoff: Duration::from_secs(5),
            transient_backoff_max: Duration::from_secs(30),
        }
    }
}

/// HTTP client for the explorer's Etherscan-compatible API.
#[derive(Clone)]
pub struct ExplorerClient {
    base_url: String,
    api_key: Option<String>,
    /// Etherscan v2 `chainid`, sent on status and read calls when set.
    chain_id: Option<u64>,
    http: reqwest::Client,
}

impl fmt::Debug for ExplorerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExplorerClient")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

/// The key as it can appear in a URL query, raw and percent-encoded.
fn key_spellings(key: &str) -> Vec<String> {
    let mut out = vec![key.to_owned()];
    let encoded: String = reqwest::Url::parse_with_params("http://x/", [("k", key)])
        .ok()
        .and_then(|u| {
            u.query()
                .and_then(|q| q.strip_prefix("k="))
                .map(str::to_owned)
        })
        .unwrap_or_default();
    if !encoded.is_empty() && encoded != key {
        out.push(encoded);
    }
    out
}

impl ExplorerClient {
    /// A transport failure as `VerifyError::Transport`. reqwest's `Display` includes the
    /// request URL, and status and read calls carry `apikey` in the query string, so the URL
    /// is dropped and the key is scrubbed from the whole source chain before anything is
    /// formatted for the user.
    fn transport_error(&self, e: reqwest::Error) -> VerifyError {
        let e = e.without_url();
        let mut msg = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            msg.push_str(": ");
            msg.push_str(&cause.to_string());
            source = cause.source();
        }
        if let Some(key) = &self.api_key {
            for spelling in key_spellings(key) {
                msg = msg.replace(&spelling, "<redacted>");
            }
        }
        VerifyError::Transport(msg)
    }

    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self> {
        let parsed = reqwest::Url::parse(base_url)
            .with_context(|| format!("explorer URL {base_url:?} is not a URL"))?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            bail!("explorer URL must be http(s)");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("citrate-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| anyhow!("http client: {e}"))?;
        Ok(Self {
            base_url: base_url.to_owned(),
            api_key: api_key.filter(|k| !k.is_empty()),
            chain_id: None,
            http,
        })
    }

    /// Send Etherscan v2 `chainid` on `checkverifystatus` and `getsourcecode`. `None` (the
    /// default) sends nothing, so a local devnet with another chain id still works.
    pub fn with_chain_id(mut self, chain_id: Option<u64>) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Envelope, VerifyError> {
        let resp = req.send().await.map_err(|e| self.transport_error(e))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| self.transport_error(e))?;
        let parsed: Option<Value> = serde_json::from_str(&text).ok();
        match parsed.as_ref().and_then(Envelope::parse) {
            Some(env) => Ok(env),
            None if !status.is_success() => Err(VerifyError::Http {
                status: status.as_u16(),
                body: text.chars().take(512).collect(),
            }),
            None => Err(VerifyError::Protocol(text.chars().take(512).collect())),
        }
    }

    /// Submit once. Returns the guid.
    pub async fn submit_once(&self, req: &VerifyRequest) -> Result<String, VerifyError> {
        let mut fields = req
            .form_fields()
            .map_err(|e| VerifyError::Rejected(format!("invalid request: {e:#}")))?;
        if let Some(k) = &self.api_key {
            fields.insert(0, ("apikey".to_owned(), k.clone()));
        }
        let env = self
            .send(self.http.post(&self.base_url).form(&fields))
            .await?;
        let text = env.result_text();
        if env.ok {
            if text.is_empty() {
                return Err(VerifyError::Protocol("empty guid".to_owned()));
            }
            return Ok(text);
        }
        if text.to_ascii_lowercase().contains("already verified") {
            Err(VerifyError::AlreadyVerified(text))
        } else if is_rate_limited(&text) {
            Err(VerifyError::RateLimited(text))
        } else {
            Err(VerifyError::Rejected(text))
        }
    }

    /// Submit, retrying after `Max rate limit reached`.
    pub async fn submit(
        &self,
        req: &VerifyRequest,
        cfg: &PollConfig,
    ) -> Result<String, VerifyError> {
        let mut attempt: u32 = 0;
        loop {
            match self.submit_once(req).await {
                Err(VerifyError::RateLimited(m)) => {
                    if attempt >= cfg.rate_limit_retries {
                        return Err(VerifyError::RateLimited(m));
                    }
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(cfg.rate_limit_backoff).await;
                }
                other => return other,
            }
        }
    }

    fn query(&self, pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut q: Vec<(String, String)> = Vec::new();
        if let Some(k) = &self.api_key {
            q.push(("apikey".to_owned(), k.clone()));
        }
        if let Some(id) = self.chain_id {
            q.push(("chainid".to_owned(), id.to_string()));
        }
        q.extend(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        q
    }

    /// One `checkverifystatus` call.
    pub async fn check_status(&self, guid: &str) -> Result<VerifyStatus, VerifyError> {
        let q = self.query(&[
            ("module", "contract"),
            ("action", "checkverifystatus"),
            ("guid", guid),
        ]);
        let env = self.send(self.http.get(&self.base_url).query(&q)).await?;
        Ok(classify_status(&env))
    }

    /// Poll `checkverifystatus` until a verdict or the deadline. Transient errors (see
    /// [`VerifyError::is_transient`]) are retried with bounded backoff inside the deadline;
    /// any other error ends the wait.
    pub async fn wait(&self, guid: &str, cfg: &PollConfig) -> Result<VerifyStatus, VerifyError> {
        let deadline = Instant::now().checked_add(cfg.timeout);
        let mut transient_errors: u32 = 0;
        loop {
            let mut delay = cfg.interval;
            let last = match self.check_status(guid).await {
                Ok(status) if status.is_terminal() => return Ok(status),
                Ok(status) => {
                    transient_errors = 0;
                    match status {
                        VerifyStatus::Pending(m) => m,
                        _ => String::new(),
                    }
                }
                Err(e) if e.is_transient() => {
                    transient_errors = transient_errors.saturating_add(1);
                    let factor = 2u32.saturating_pow(transient_errors.saturating_sub(1));
                    delay = cfg
                        .interval
                        .saturating_mul(factor)
                        .min(cfg.transient_backoff_max.max(cfg.interval));
                    e.to_string()
                }
                Err(e) => return Err(e),
            };
            if deadline.is_some_and(|d| Instant::now().checked_add(delay).is_none_or(|n| n > d)) {
                return Err(VerifyError::Timeout {
                    guid: guid.to_owned(),
                    last,
                });
            }
            tokio::time::sleep(delay).await;
        }
    }

    /// `getsourcecode` for one address: the first (only) entry of Etherscan's result list.
    pub async fn get_source_code(&self, address: &str) -> Result<Value, VerifyError> {
        validate_address(address).map_err(|e| VerifyError::Rejected(e.to_string()))?;
        let q = self.query(&[
            ("module", "contract"),
            ("action", "getsourcecode"),
            ("address", address),
        ]);
        let env = self.send(self.http.get(&self.base_url).query(&q)).await?;
        if !env.ok {
            return Err(VerifyError::Rejected(env.result_text()));
        }
        env.result
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .ok_or_else(|| VerifyError::Protocol("getsourcecode result is not a list".to_owned()))
    }
}
