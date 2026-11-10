//! The node's panic hook: every panic, in any thread or task, leaves one
//! timestamped `PANIC` line in the node log (thread, location, payload) before
//! the default hook prints its own report.
//!
//! Without it a panic in a spawned task reaches stderr only, untimestamped, and
//! the log the operator reads (stdout, the journal) does not show that it
//! happened (lead decision, 2026-11-10).
//!
//! The hook does not abort. Three paths in this build catch panics on purpose
//! and must keep working:
//! - `Executor::execute_tx_into_journal` (EXEC-02): a transaction that panics
//!   inside dispatch becomes a reverted receipt, not a chain halt;
//! - the end-of-block system call (CHAIN-B-B019): a panic there undoes the
//!   transient minter funding;
//! - the producer's supervised round (`producer::run_supervised` and the
//!   `PanicBreaker`): a round that panics is retried and a culprit
//!   transaction quarantined.
//!
//! An aborting hook runs before any of those barriers can catch the panic, so
//! one panicking transaction would abort every node that executes it. Whether
//! to abort on the panics no barrier catches is an open decision.

use std::panic::PanicHookInfo;

/// The text of a panic payload (`&str` or `String`), or a placeholder.
pub fn payload_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// The one log line for a panic (without the logger's timestamp and level).
pub fn panic_line(thread: &str, info: &PanicHookInfo<'_>) -> String {
    let location = info.location().map_or_else(
        || "<unknown location>".to_string(),
        |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
    );
    format!(
        "PANIC in thread '{thread}' at {location}: {}",
        payload_text(info.payload())
    )
}

/// Install the hook. Call it once, before the async runtime starts, so it
/// covers every worker thread and spawned task.
pub fn install() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let current = std::thread::current();
        let thread = current.name().unwrap_or("<unnamed>");
        tracing::error!("{}", panic_line(thread, info));
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHILD: &str = "CITRATE_PANIC_HOOK_CHILD";

    /// `main` installs the hook before it builds the async runtime, so every
    /// worker thread and spawned task is covered.
    #[test]
    fn main_installs_the_hook_before_the_runtime_starts() {
        let main = include_str!("main.rs");
        let install = main
            .find("panic_hook::install();")
            .expect("main.rs installs the panic hook");
        let runtime = main
            .find("tokio::runtime::Builder::new_multi_thread()")
            .expect("main.rs builds the runtime itself");
        assert!(install < runtime, "the hook is installed first");
        assert!(
            !main.contains("#[tokio::main]"),
            "a #[tokio::main] entry point starts the runtime before any statement of main"
        );
    }

    /// A task spawned on the multi-thread runtime panics; the node log (the
    /// node's own logging, as `main` initializes it) carries exactly one
    /// timestamped PANIC line with the panic's file and line. The logger is
    /// process-wide, so this runs in a child process.
    #[test]
    fn a_panicking_task_leaves_one_timestamped_panic_line_in_the_log() {
        if std::env::var(CHILD).is_ok() {
            let _guard = crate::logging::init_logging(&crate::logging::LogConfig::from_env())
                .expect("node logging");
            install();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let joined = rt.block_on(async {
                tokio::spawn(async {
                    panic!("panic-hook-probe");
                })
                .await
            });
            assert!(joined.is_err_and(|e| e.is_panic()));
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([
                "panic_hook::tests::a_panicking_task_leaves_one_timestamped_panic_line_in_the_log",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env_remove("RUST_LOG")
            // One line per event, no colour codes: the shape the PANIC line is
            // checked in (the default pretty format carries the same text).
            .env("LOG_FORMAT", "compact")
            .env("LOG_ANSI", "false")
            .output()
            .expect("spawn child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
        let lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains("PANIC in thread"))
            .collect();
        assert_eq!(lines.len(), 1, "one PANIC line in the log:\n{stdout}");
        let line = lines[0];
        assert!(line.contains("panic-hook-probe"), "{line}");
        assert!(line.contains("node/src/panic_hook.rs:"), "location: {line}");
        assert!(line.contains("ERROR"), "level: {line}");
        // The logger's RFC 3339 timestamp leads the line: 20YY-MM-DDTHH:MM:SS.
        let ts = line
            .split_whitespace()
            .find(|w| w.len() >= 19 && w.as_bytes().get(4) == Some(&b'-'))
            .unwrap_or("");
        assert!(
            ts.starts_with("20") && ts.as_bytes().get(10) == Some(&b'T'),
            "timestamp: {line}"
        );
    }
}
