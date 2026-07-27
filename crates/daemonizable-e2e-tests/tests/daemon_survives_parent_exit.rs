//! Parent-exit survival of the **raw** spawn machinery
//! (`start_background_process_with_exe`): the daemon keeps running after the
//! process that spawned it exits.
//!
//! Launches the `daemonizable-test-spawn-then-exit` helper *process* (see its
//! doc for why a separate process rather than an in-test `fork()`), which
//! spawns the `daemonizable-test-background` helper in `sentinel_loop` mode
//! (ignores RPC, writes a tick counter to a file forever) and exits
//! immediately. The test then verifies the daemon is in its own session and
//! still updating the sentinel. Cleans up via `DaemonGuard`.
//!
//! Note: the `setsid` this test observes is one the helper binary performs
//! itself — the raw path deliberately bypasses the framework's daemon-stage
//! arms. The framework's own `setsid`/second fork is covered by
//! `framework_e2e.rs`, and the framework-path counterpart of THIS test is
//! `framework_daemon_survives_parent_exit.rs`.

use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use daemonizable_e2e_tests::{DaemonGuard, read_pid_file};
use nix::unistd::getsid;

/// The `daemonizable-test-background` helper, run as the daemon (in
/// `sentinel_loop` mode) by the spawner process.
fn background_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

/// The `daemonizable-test-spawn-then-exit` helper: stands in for the parent CLI
/// that launches the daemon and then exits.
fn spawner_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-spawn-then-exit"))
}

#[test]
fn daemon_survives_parent_exit() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-daemon-survive-test")
        .tempdir()
        .unwrap();
    let sentinel_path = tmp.path().join("sentinel");
    let pid_path = tmp.path().join("daemon.pid");

    // Run the spawner: it launches the daemon and exits immediately,
    // simulating a parent CLI that daemonizes and returns. The daemon paths
    // ride the environment — set on the spawner's `Command`, inherited by the
    // daemon across the spawn — so this test process never mutates its own
    // environment (no `set_var`, hence no cross-thread env race).
    let status = Command::new(spawner_exe())
        .env("DAEMONIZABLE_TEST_DAEMON_EXE", background_exe())
        .env("DAEMONIZABLE_TEST_SENTINEL", &sentinel_path)
        .env("DAEMONIZABLE_TEST_PID", &pid_path)
        .status()
        .expect("failed to run spawner process");
    assert!(
        status.success(),
        "spawner process did not exit cleanly: {status:?}",
    );

    // The daemon is not our child; discover its PID through the file it
    // writes on startup (content-polled — see `read_pid_file`).
    let daemon_pid = read_pid_file(&pid_path, Duration::from_secs(5));
    // Installed *before* any assertion below, so the daemon gets killed even if
    // a check panics.
    let _guard = DaemonGuard(daemon_pid);

    // setsid moved the daemon into its own session. Without this, the daemon
    // would die on SIGHUP when the parent's controlling terminal closes (e.g.
    // when the user closes the shell).
    let daemon_sid = getsid(Some(daemon_pid)).expect("getsid(daemon)");
    let test_sid = getsid(None).expect("getsid(test)");
    assert_ne!(
        daemon_sid, test_sid,
        "daemon and test share a session — setsid did not take effect",
    );

    // Daemon must keep writing the sentinel even though its spawner (the
    // sub-process) has exited. Wait for the file to appear, then poll until its
    // contents change. Daemon writes every 50 ms, so observing a change normally
    // takes <100 ms; 5 s is a generous ceiling that fails fast if the daemon has
    // actually stopped.
    let sentinel_appear_deadline = Instant::now() + Duration::from_secs(5);
    while !sentinel_path.exists() {
        assert!(
            Instant::now() < sentinel_appear_deadline,
            "daemon did not create sentinel file within 5s",
        );
        thread::sleep(Duration::from_millis(20));
    }
    let first = std::fs::read_to_string(&sentinel_path).expect("read sentinel");
    let change_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        thread::sleep(Duration::from_millis(20));
        let next = std::fs::read_to_string(&sentinel_path).expect("read sentinel");
        if next != first {
            break; // observed a change → daemon is alive
        }
        assert!(
            Instant::now() < change_deadline,
            "daemon stopped writing sentinel after parent exited (no change in 5s)",
        );
    }

    // Cleanup happens via DaemonGuard's Drop.
}
