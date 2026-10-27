// Fixture (signal-synthetic-pid, negative): real pids the test spawned, and probes that
// deliver no signal. Nothing here may be flagged.
#[test]
fn stop_path_kills_the_child_it_spawned() {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn");
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) };
    signal_pid(st.pid.expect("running"), libc::SIGKILL);
    assert!(
        !signal_pid(u32::MAX, 0),
        "probe only: signal 0 delivers nothing"
    );
    assert!(!signal_pid(0, 0));
    // libc::kill(4242, libc::SIGKILL) in a comment is not a call
}
