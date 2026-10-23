// Fixture (signal-synthetic-pid, positive): every marked line sends a real signal to a pid
// the test made up. Each must be flagged.
#[test]
fn stop_path_kills_a_recorded_pid() {
    unsafe { libc::kill(4242, libc::SIGKILL) }; // FLAG
    signal_pid(u32::MAX, libc::SIGTERM); // FLAG: wraps to -1
    signal_pid(i32::MAX as u32 + 1, libc::SIGKILL); // FLAG: wraps negative
    unsafe { libc::kill(0, libc::SIGTERM) }; // FLAG: our own process group
    nix::sys::signal::kill(Pid::from_raw(31337), Signal::SIGKILL).ok(); // FLAG
    kill_now(99_999); // FLAG
}
