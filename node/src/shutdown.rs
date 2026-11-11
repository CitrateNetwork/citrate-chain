//! The node's shutdown signal: SIGINT (Ctrl-C) or SIGTERM.
//!
//! CORE-053: the node waited for SIGINT only. systemd stops a unit with
//! SIGTERM, whose default action ends the process at once, so every
//! `systemctl stop` and every host shutdown skipped the shutdown path (the RPC
//! server close and join, "Shutting down..."). Both signals now run the same
//! path.

#[cfg(test)]
mod tests {
    use super::*;

    const CHILD: &str = "CITRATE_SHUTDOWN_SIGNAL_CHILD";

    /// main and the RPC task wait on `shutdown_signal`, never on SIGINT alone.
    #[test]
    fn main_waits_for_sigint_or_sigterm() {
        let main = include_str!("main.rs");
        assert!(
            !main.contains("tokio::signal::ctrl_c()"),
            "main.rs waits for SIGINT alone somewhere"
        );
        assert!(
            main.matches("shutdown::shutdown_signal().await").count() >= 2,
            "the node and its RPC task wait on shutdown_signal"
        );
    }

    /// A process waiting on `shutdown_signal` that receives SIGTERM runs the
    /// code after the wait and exits 0, instead of being ended by the signal.
    #[cfg(unix)]
    #[test]
    fn sigterm_runs_the_shutdown_path() {
        if std::env::var(CHILD).is_ok() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let got = rt.block_on(async {
                let signal = ShutdownSignal::register().expect("signal handler");
                println!("SHUTDOWN-PROBE waiting");
                signal.wait().await.expect("signal")
            });
            println!("SHUTDOWN-PROBE graceful shutdown on {got}");
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([
                "shutdown::tests::sigterm_runs_the_shutdown_path",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn child");
        let mut stdout = child.stdout.take().expect("stdout");
        // Wait until the child is waiting on the signal, then send SIGTERM.
        let mut seen = String::new();
        let mut buf = [0u8; 256];
        while !seen.contains("SHUTDOWN-PROBE waiting") {
            let n = std::io::Read::read(&mut stdout, &mut buf).expect("read child");
            assert!(n > 0, "child exited early: {seen}");
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        // The SIGTERM handler is registered before the line is printed.
        let status = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut rest).expect("read rest");
        let exit = child.wait().expect("wait");
        assert!(exit.success(), "ended by the signal ({exit:?}):\n{seen}{rest}");
        assert!(
            rest.contains("SHUTDOWN-PROBE graceful shutdown on SIGTERM"),
            "{seen}{rest}"
        );
    }
}
