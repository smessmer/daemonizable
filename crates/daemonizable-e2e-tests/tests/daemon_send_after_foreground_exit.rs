//! The daemon-side half of dead-peer communication: the daemon sends a
//! response after the foreground process that spawned it has ALREADY EXITED,
//! and must observe a clean `BrokenPipe` error — not a false success, not a
//! hang. (The mirror scenario — the foreground sending to an exited daemon —
//! is `test_child_send_request_after_daemon_exited` in
//! `daemon_child_lifecycle.rs`; the in-process channel primitive is covered by
//! the `dropped_recver` unit test in `ipc/channel`.)
//!
//! Mechanics: like `daemon_survives_parent_exit.rs`, the test launches the
//! `daemonizable-test-spawn-then-exit` helper, which stands in for a
//! foreground CLI — it spawns the `daemonizable-test-background` helper as
//! the daemon (here in `send_after_parent_exit` mode) and exits immediately.
//! The daemon waits until the spawner is fully gone, attempts
//! `send_response`, and publishes the classified outcome to a file this test
//! asserts on.
//!
//! Every synchronization point is an observed event, never a delay:
//!   - The daemon detects the spawner's death by polling for its `getppid()`
//!     to change away from the spawner's pid (passed down via the
//!     environment). The kernel reparents the daemon only during the
//!     spawner's teardown, after the spawner's fds are closed — so once the
//!     reparent is visible, the channel has no reader left and the
//!     send outcome is deterministic.
//!   - The daemon publishes the outcome file atomically (write + rename), so
//!     the test's existence poll can never read a partial result.

use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use daemonizable_e2e_tests::DaemonGuard;
use nix::unistd::Pid;

/// The `daemonizable-test-background` helper, run as the daemon (in
/// `send_after_parent_exit` mode) by the spawner process.
fn background_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

/// The `daemonizable-test-spawn-then-exit` helper: stands in for the parent
/// CLI that launches the daemon and then exits.
fn spawner_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-spawn-then-exit"))
}

#[test]
fn daemon_send_response_after_foreground_exited() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-daemon-send-after-exit")
        .tempdir()
        .unwrap();
    let outcome_path = tmp.path().join("outcome");
    let pid_path = tmp.path().join("daemon.pid");

    // Run the spawner (the stand-in foreground CLI): it launches the daemon
    // and exits. `status()` reaps it, so once this returns the foreground
    // process is gone — though the daemon does not rely on that ordering; it
    // detects the death itself via its reparenting.
    let status = Command::new(spawner_exe())
        .env("DAEMONIZABLE_TEST_DAEMON_EXE", background_exe())
        .env("DAEMONIZABLE_TEST_BEHAVIOR", "send_after_parent_exit")
        .env("DAEMONIZABLE_TEST_OUTFILE", &outcome_path)
        .env("DAEMONIZABLE_TEST_PID", &pid_path)
        .status()
        .expect("failed to run spawner process");
    assert!(
        status.success(),
        "spawner process did not exit cleanly: {status:?}",
    );

    // The daemon writes its pid on startup; discover it so cleanup can kill
    // the daemon if an assertion below fails before it exits on its own.
    // Poll on parseable content, not existence (`std::fs::write` creates the
    // file before writing, so an existence check can win the race and read
    // an empty file).
    let pid_deadline = Instant::now() + Duration::from_secs(5);
    let daemon_pid = loop {
        if let Ok(contents) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                break Pid::from_raw(pid);
            }
        }
        assert!(
            Instant::now() < pid_deadline,
            "daemon did not publish a parseable PID within 5s",
        );
        thread::sleep(Duration::from_millis(20));
    };
    let _guard = DaemonGuard(daemon_pid);

    // Wait for the daemon to publish its verdict. The rename-based publish
    // makes existence sufficient: once the file is there, it is complete.
    // 10s is a failure ceiling, not a synchronization point — the daemon
    // publishes as soon as it has observed the spawner's death.
    let outcome_deadline = Instant::now() + Duration::from_secs(10);
    while !outcome_path.exists() {
        assert!(
            Instant::now() < outcome_deadline,
            "daemon did not publish a send outcome within 10s",
        );
        thread::sleep(Duration::from_millis(20));
    }
    let outcome = std::fs::read_to_string(&outcome_path).expect("read outcome file");
    assert_eq!(
        outcome, "send:broken_pipe",
        "daemon's send_response after the foreground exited did not fail with BrokenPipe",
    );

    // Cleanup happens via DaemonGuard's Drop (normally a no-op: the daemon
    // exits by itself right after publishing the outcome).
}
