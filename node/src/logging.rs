//! Structured Logging Module
//!
//! Provides structured JSON logging with trace ID propagation for request correlation.
//! This enables efficient log aggregation and debugging in production environments.
//!
//! # Features
//! - JSON formatted output for log aggregation
//! - Trace ID generation and propagation
//! - Configurable log levels per module
//! - Optional additive file output
//! - Environment-based configuration
//!
//! # Usage
//! ```rust
//! use citrate_node::logging::{init_logging, LogConfig};
//!
//! let config = LogConfig::from_env();
//! let _logging_guard = init_logging(&config)?;
//!
//! tracing::info!(trace_id = %TraceId::new(), "Request received");
//! ```

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::Dispatch;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    field::RecordFields,
    fmt::{
        format::{DefaultFields, FmtSpan, FormatFields, JsonFields, PrettyFields, Writer},
        writer::MakeWriter,
    },
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Counter for generating unique trace IDs
static TRACE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique identifier for correlating logs across a request lifecycle
#[derive(Clone, Copy, Debug)]
pub struct TraceId {
    /// Timestamp component (ms since epoch)
    timestamp: u64,
    /// Sequential counter component
    counter: u64,
    /// Random component for uniqueness
    random: u16,
}

impl TraceId {
    /// Generate a new unique trace ID
    pub fn new() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let counter = TRACE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let random = rand::random::<u16>();

        Self {
            timestamp,
            counter,
            random,
        }
    }

    /// Create trace ID from string (for propagation)
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        let [timestamp, counter, random] = parts.as_slice() else {
            return None;
        };

        Some(Self {
            timestamp: u64::from_str_radix(timestamp, 16).ok()?,
            counter: u64::from_str_radix(counter, 16).ok()?,
            random: u16::from_str_radix(random, 16).ok()?,
        })
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x}-{:x}-{:04x}",
            self.timestamp, self.counter, self.random
        )
    }
}

/// Log level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable format
    Pretty,
    /// JSON format for log aggregation
    Json,
    /// Compact single-line format
    Compact,
}

impl LogFormat {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => LogFormat::Json,
            "compact" => LogFormat::Compact,
            _ => LogFormat::Pretty,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Default log level
    pub level: LogLevel,
    /// Output format (json, pretty, compact)
    pub format: LogFormat,
    /// Enable ANSI colors (for terminal output)
    pub ansi_colors: bool,
    /// Log to file path (optional)
    pub log_file: Option<PathBuf>,
    /// Enable span events (enter/exit)
    pub span_events: bool,
    /// Module-specific log levels
    pub module_levels: Vec<(String, LogLevel)>,
    /// Include target in logs
    pub include_target: bool,
    /// Include file location in logs
    pub include_location: bool,
    /// Include thread ID in logs
    pub include_thread_id: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            ansi_colors: true,
            log_file: None,
            span_events: false,
            module_levels: Vec::new(),
            include_target: true,
            include_location: false,
            include_thread_id: false,
        }
    }
}

impl LogConfig {
    /// Create configuration from environment variables
    ///
    /// Environment variables:
    /// - RUST_LOG: Log level filter (e.g., "info,citrate_api=debug")
    /// - LOG_FORMAT: Output format (json, pretty, compact)
    /// - LOG_FILE: Path to log file
    /// - LOG_ANSI: Enable ANSI colors (true/false)
    pub fn from_env() -> Self {
        let rust_log = std::env::var("RUST_LOG").ok();
        let format = std::env::var("LOG_FORMAT").ok();
        let log_file = std::env::var_os("LOG_FILE");
        let ansi = std::env::var("LOG_ANSI").ok();

        Self::resolve(
            rust_log.as_deref(),
            format.as_deref(),
            log_file.as_deref(),
            ansi.as_deref(),
        )
    }

    fn resolve(
        rust_log: Option<&str>,
        format: Option<&str>,
        log_file: Option<&OsStr>,
        ansi: Option<&str>,
    ) -> Self {
        let parsed_format = format.map(LogFormat::parse);
        let mut config = if parsed_format == Some(LogFormat::Json) {
            Self::production()
        } else {
            Self::default()
        };

        if let Some(rust_log) = rust_log {
            let level_str = rust_log.split(',').next().unwrap_or("info");
            config.level = LogLevel::parse(level_str);
        }
        if let Some(format) = parsed_format {
            config.format = format;
        }
        config.log_file = log_file.filter(|path| !path.is_empty()).map(PathBuf::from);
        if let Some(ansi) = ansi {
            config.ansi_colors = ansi.to_lowercase() == "true";
        }

        config
    }

    /// Create JSON logging configuration for production
    pub fn production() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            ansi_colors: false,
            log_file: None,
            span_events: true,
            module_levels: vec![
                ("citrate_api".to_string(), LogLevel::Info),
                ("citrate_consensus".to_string(), LogLevel::Info),
                ("citrate_network".to_string(), LogLevel::Warn),
                ("hyper".to_string(), LogLevel::Warn),
                ("tower".to_string(), LogLevel::Warn),
            ],
            include_target: true,
            include_location: true,
            include_thread_id: true,
        }
    }

    /// Create verbose configuration for development
    pub fn development() -> Self {
        Self {
            level: LogLevel::Debug,
            format: LogFormat::Pretty,
            ansi_colors: true,
            log_file: None,
            span_events: true,
            module_levels: vec![
                ("citrate".to_string(), LogLevel::Debug),
                ("hyper".to_string(), LogLevel::Info),
            ],
            include_target: true,
            include_location: true,
            include_thread_id: false,
        }
    }

    /// Build the env filter string
    fn build_filter(&self) -> String {
        let mut filter = self.level.as_str().to_string();

        for (module, level) in &self.module_levels {
            filter.push_str(&format!(",{}={}", module, level.as_str()));
        }

        filter
    }
}

/// Keeps the nonblocking file writer alive and flushes it when dropped.
#[must_use = "keep this guard alive to flush nonblocking file logs"]
#[derive(Debug)]
pub struct LoggingGuard {
    _file_worker: Option<WorkerGuard>,
}

struct FileFields<F>(F);

impl<'writer, F> FormatFields<'writer> for FileFields<F>
where
    F: FormatFields<'writer>,
{
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        self.0.format_fields(writer, fields)
    }
}

#[allow(deprecated)]
fn ansi_free_pretty_fields() -> FileFields<PrettyFields> {
    FileFields(PrettyFields::new().with_ansi(false))
}

fn file_writer(
    configured_path: &Path,
) -> anyhow::Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    let parent = configured_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if parent != Path::new(".") {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to initialize log file '{}': could not create parent directory '{}': {}",
                configured_path.display(),
                parent.display(),
                error
            )
        })?;
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(configured_path)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to initialize log file '{}': could not open for append: {}",
                configured_path.display(),
                error
            )
        })?;

    Ok(tracing_appender::non_blocking(file))
}

fn build_dispatch<W>(
    config: &LogConfig,
    console_writer: W,
) -> anyhow::Result<(Dispatch, LoggingGuard)>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    // Build filter from config or RUST_LOG env
    let filter = if let Ok(rust_log) = std::env::var("RUST_LOG") {
        EnvFilter::new(rust_log)
    } else {
        EnvFilter::new(config.build_filter())
    };

    // Determine span events
    let span_events = if config.span_events {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    let (file_writer, file_worker) = match config
        .log_file
        .as_deref()
        .filter(|path| !path.as_os_str().is_empty())
    {
        Some(path) => {
            let (writer, guard) = file_writer(path)?;
            (Some(writer), Some(guard))
        }
        None => (None, None),
    };

    let dispatch = match config.format {
        LogFormat::Json => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events.clone())
                        .with_ansi(false)
                        .with_writer(console_writer),
                )
                .with(file_writer.map(|writer| {
                    tracing_subscriber::fmt::layer()
                        .json()
                        .fmt_fields(FileFields(JsonFields::new()))
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events.clone())
                        .with_ansi(false)
                        .with_writer(writer)
                }));
            Dispatch::new(subscriber)
        }
        LogFormat::Pretty => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events.clone())
                        .with_ansi(config.ansi_colors)
                        .with_writer(console_writer),
                )
                .with(file_writer.map(|writer| {
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .fmt_fields(ansi_free_pretty_fields())
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events)
                        .with_ansi(false)
                        .with_writer(writer)
                }));
            Dispatch::new(subscriber)
        }
        LogFormat::Compact => {
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events.clone())
                        .with_ansi(config.ansi_colors)
                        .with_writer(console_writer),
                )
                .with(file_writer.map(|writer| {
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .fmt_fields(FileFields(DefaultFields::new()))
                        .with_target(config.include_target)
                        .with_file(config.include_location)
                        .with_line_number(config.include_location)
                        .with_thread_ids(config.include_thread_id)
                        .with_span_events(span_events)
                        .with_ansi(false)
                        .with_writer(writer)
                }));
            Dispatch::new(subscriber)
        }
    };

    Ok((
        dispatch,
        LoggingGuard {
            _file_worker: file_worker,
        },
    ))
}

/// Initialize the logging system with the given configuration.
pub fn init_logging(config: &LogConfig) -> anyhow::Result<LoggingGuard> {
    let (dispatch, guard) = build_dispatch(config, std::io::stdout)?;
    dispatch
        .try_init()
        .map_err(|error| anyhow::anyhow!("Failed to init logging: {}", error))?;
    Ok(guard)
}

/// Initialize logging with defaults (for quick setup)
pub fn init_default_logging() -> anyhow::Result<LoggingGuard> {
    let config = LogConfig::from_env();
    init_logging(&config)
}

/// Macro for creating a span with trace ID
#[macro_export]
macro_rules! traced_span {
    ($level:ident, $name:expr $(, $($field:tt)*)?) => {
        tracing::span!(
            tracing::Level::$level,
            $name,
            trace_id = %$crate::logging::TraceId::new()
            $(, $($field)*)?
        )
    };
}

/// Log formats for common operations
pub mod formats {
    use super::TraceId;

    /// Format for RPC request logging
    pub fn rpc_request(trace_id: &TraceId, method: &str, params_size: usize) -> String {
        format!(
            "trace_id={} method={} params_size={}",
            trace_id, method, params_size
        )
    }

    /// Format for RPC response logging
    pub fn rpc_response(
        trace_id: &TraceId,
        method: &str,
        duration_ms: u64,
        success: bool,
    ) -> String {
        format!(
            "trace_id={} method={} duration_ms={} success={}",
            trace_id, method, duration_ms, success
        )
    }

    /// Format for block production logging
    pub fn block_produced(
        trace_id: &TraceId,
        height: u64,
        tx_count: usize,
        build_time_ms: u64,
    ) -> String {
        format!(
            "trace_id={} height={} tx_count={} build_time_ms={}",
            trace_id, height, tx_count, build_time_ms
        )
    }

    /// Format for transaction logging
    pub fn transaction(trace_id: &TraceId, tx_hash: &str, from: &str, to: &str) -> String {
        format!(
            "trace_id={} tx_hash={} from={} to={}",
            trace_id, tx_hash, from, to
        )
    }

    /// Format for peer connection logging
    pub fn peer_connection(trace_id: &TraceId, peer_id: &str, action: &str) -> String {
        format!(
            "trace_id={} peer_id={} action={}",
            trace_id, peer_id, action
        )
    }

    /// Format for AI inference logging
    pub fn ai_inference(
        trace_id: &TraceId,
        model_id: &str,
        latency_ms: u64,
        tokens: usize,
    ) -> String {
        format!(
            "trace_id={} model_id={} latency_ms={} tokens={}",
            trace_id, model_id, latency_ms, tokens
        )
    }

    /// Format for IPFS operation logging
    pub fn ipfs_operation(trace_id: &TraceId, operation: &str, cid: &str, size: usize) -> String {
        format!(
            "trace_id={} operation={} cid={} size={}",
            trace_id, operation, cid, size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for Buffer {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    impl Buffer {
        fn text(&self) -> String {
            let bytes = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            String::from_utf8(bytes).expect("logging output is UTF-8")
        }
    }

    struct EnvGuard {
        key: &'static str,
        old: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&OsStr>) -> Self {
            let old = std::env::var_os(key);
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.old.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn scoped_logging(config: &LogConfig, console: Buffer, emit: impl FnOnce()) -> LoggingGuard {
        let (dispatch, guard) = build_dispatch(config, console).expect("build logging dispatch");
        tracing::dispatcher::with_default(&dispatch, emit);
        drop(dispatch);
        guard
    }

    #[test]
    fn test_trace_id_generation() {
        let id1 = TraceId::new();
        let id2 = TraceId::new();

        // IDs should be unique
        assert_ne!(id1.to_string(), id2.to_string());
    }

    #[test]
    fn test_trace_id_parsing() {
        let id = TraceId::new();
        let id_str = id.to_string();

        let parsed = TraceId::parse(&id_str);
        assert!(parsed.is_some());

        let parsed = parsed.unwrap();
        assert_eq!(id.timestamp, parsed.timestamp);
        assert_eq!(id.counter, parsed.counter);
        assert_eq!(id.random, parsed.random);
    }

    #[test]
    fn test_log_config_from_env() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", Some(OsStr::new("debug")));
        let _format = EnvGuard::set("LOG_FORMAT", Some(OsStr::new("JsOn")));
        let _log_file = EnvGuard::set("LOG_FILE", Some(OsStr::new("logs/custom node.log")));

        let config = LogConfig::from_env();
        assert_eq!(config.level, LogLevel::Debug);
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.log_file, Some(PathBuf::from("logs/custom node.log")));
        assert!(config.span_events);
        assert!(config.include_location);
        assert!(config.include_thread_id);
    }

    #[test]
    fn empty_log_file_is_unset_and_json_has_no_implicit_path() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let _format = EnvGuard::set("LOG_FORMAT", Some(OsStr::new("json")));
        let _log_file = EnvGuard::set("LOG_FILE", Some(OsStr::new("")));

        let config = LogConfig::from_env();

        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.log_file, None);
        assert!(config.span_events);
        assert!(config.include_location);
        assert!(config.include_thread_id);
        assert_eq!(LogConfig::production().log_file, None);
    }

    #[test]
    fn nested_unicode_path_receives_additive_ansi_free_output() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let temp = tempfile::tempdir().expect("temp directory");
        let path = temp
            .path()
            .join("nested logs")
            .join("unicode-日志")
            .join("node output.log");
        let console = Buffer::default();
        let config = LogConfig {
            format: LogFormat::Compact,
            ansi_colors: true,
            log_file: Some(path.clone()),
            ..Default::default()
        };

        let guard = scoped_logging(&config, console.clone(), || {
            tracing::info!("additive-file-sentinel");
        });
        drop(guard);

        let file_output = std::fs::read_to_string(&path).expect("read log file");
        assert_eq!(console.text().matches("additive-file-sentinel").count(), 1);
        assert_eq!(file_output.matches("additive-file-sentinel").count(), 1);
        assert!(!file_output.contains('\u{1b}'));
    }

    #[test]
    fn json_file_contains_parseable_message() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let temp = tempfile::tempdir().expect("temp directory");
        let path = temp.path().join("node.json.log");
        let config = LogConfig {
            format: LogFormat::Json,
            log_file: Some(path.clone()),
            ..LogConfig::production()
        };

        let guard = scoped_logging(&config, Buffer::default(), || {
            tracing::info!("json-file-sentinel");
        });
        drop(guard);

        let output = std::fs::read_to_string(path).expect("read JSON log");
        let record: serde_json::Value =
            serde_json::from_str(output.trim()).expect("parse JSON log record");
        assert_eq!(record["fields"]["message"], "json-file-sentinel");
    }

    #[test]
    fn existing_file_is_appended_without_truncation() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let temp = tempfile::tempdir().expect("temp directory");
        let path = temp.path().join("append.log");
        std::fs::write(&path, "existing-content\n").expect("seed log file");
        let config = LogConfig {
            format: LogFormat::Compact,
            log_file: Some(path.clone()),
            ..Default::default()
        };

        let guard = scoped_logging(&config, Buffer::default(), || {
            tracing::info!("appended-sentinel");
        });
        drop(guard);

        let output = std::fs::read_to_string(path).expect("read appended log");
        assert!(output.starts_with("existing-content\n"));
        assert!(output.contains("appended-sentinel"));
    }

    #[test]
    fn invalid_parent_error_includes_configured_path_and_cause() {
        let temp = tempfile::tempdir().expect("temp directory");
        let blocked = temp.path().join("blocked-parent");
        std::fs::write(&blocked, "file").expect("create blocking file");
        let path = blocked.join("node.log");

        let error = file_writer(&path).expect_err("invalid parent must fail");
        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()));
        assert!(message.contains("could not create parent directory"));
        assert!(message.contains("blocked-parent"));
    }

    #[test]
    fn dropping_guard_flushes_nonblocking_output() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let temp = tempfile::tempdir().expect("temp directory");
        let path = temp.path().join("flush.log");
        let config = LogConfig {
            log_file: Some(path.clone()),
            ..Default::default()
        };

        let guard = scoped_logging(&config, Buffer::default(), || {
            tracing::info!("shutdown-flush-sentinel");
        });
        drop(guard);

        let output = std::fs::read_to_string(path).expect("read flushed log");
        assert_eq!(output.matches("shutdown-flush-sentinel").count(), 1);
    }

    fn assert_span_fields_are_ansi_free(format: LogFormat, file_name: &str) {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _rust_log = EnvGuard::set("RUST_LOG", None);
        let temp = tempfile::tempdir().expect("temp directory");
        let path = temp.path().join(file_name);
        let console = Buffer::default();
        let config = LogConfig {
            format,
            ansi_colors: true,
            log_file: Some(path.clone()),
            ..Default::default()
        };

        let guard = scoped_logging(&config, console.clone(), || {
            let span = tracing::info_span!("field_bearing_span", span_field = "span-value");
            let _entered = span.enter();
            tracing::info!("span-field-sentinel");
        });
        drop(guard);

        let console_output = console.text();
        assert!(console_output.contains("span-value"));
        assert!(console_output.contains('\u{1b}'));

        let output = std::fs::read(path).expect("read span log file");
        assert!(output
            .windows(b"span-value".len())
            .any(|bytes| bytes == b"span-value"));
        assert!(!output.contains(&0x1b));
    }

    #[test]
    fn pretty_file_span_fields_are_ansi_free() {
        assert_span_fields_are_ansi_free(LogFormat::Pretty, "pretty.log");
    }

    #[test]
    fn compact_file_span_fields_are_ansi_free() {
        assert_span_fields_are_ansi_free(LogFormat::Compact, "compact.log");
    }

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(LogLevel::parse("trace"), LogLevel::Trace);
        assert_eq!(LogLevel::parse("DEBUG"), LogLevel::Debug);
        assert_eq!(LogLevel::parse("Info"), LogLevel::Info);
        assert_eq!(LogLevel::parse("WARN"), LogLevel::Warn);
        assert_eq!(LogLevel::parse("error"), LogLevel::Error);
        assert_eq!(LogLevel::parse("invalid"), LogLevel::Info);
    }

    #[test]
    fn test_build_filter() {
        let config = LogConfig {
            level: LogLevel::Info,
            module_levels: vec![
                ("citrate_api".to_string(), LogLevel::Debug),
                ("hyper".to_string(), LogLevel::Warn),
            ],
            ..Default::default()
        };

        let filter = config.build_filter();
        assert!(filter.contains("info"));
        assert!(filter.contains("citrate_api=debug"));
        assert!(filter.contains("hyper=warn"));
    }

    #[test]
    fn test_format_helpers() {
        let trace_id = TraceId::new();

        let rpc_log = formats::rpc_request(&trace_id, "eth_blockNumber", 0);
        assert!(rpc_log.contains("eth_blockNumber"));

        let block_log = formats::block_produced(&trace_id, 100, 5, 50);
        assert!(block_log.contains("height=100"));
        assert!(block_log.contains("tx_count=5"));
    }
}
