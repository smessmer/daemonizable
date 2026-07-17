//! Regression test for daemon detachment.
//!
//! Launches a dedicated helper *process* (`daemonizable-test-spawn-then-exit`)
//! via `std::process::Command`. That helper calls
//! `start_background_process_with_exe` to spawn the `daemonizable-test-background`
//! helper in `sentinel_loop` mode (ignores RPC, writes a tick counter to a file
//! forever), then exits immediately. The main test waits for the spawner process
//! to reap, verifies the daemon is in its own session (setsid took effect), and
//! that it's still updating the sentinel. Cleans up via SIGTERM.
//!
//! Covers parent-exit survival of the **raw** spawn machinery
//! (`start_background_process_with_exe`): the daemon keeps running after the
//! process that spawned it exits. Using a separate spawner process launched with
//! `Command` (rather than an in-test `fork()`) exercises the identical survival
//! guarantee while keeping the test free of the fork-in-a-multithreaded-process
//! hazard — libtest runs each test on a worker thread, so a `fork()` here would
//! run in a multithreaded process and the (non-async-signal-safe) child could
//! deadlock. The spawner is also a more faithful stand-in for the real cryfs
//! parent CLI: a genuine separate process image, not a snapshot of the harness.
//!
//! Note: the `setsid` this test observes via `getsid()` is one the HELPER
//! BINARY performs itself (daemonizable_test_background.rs `sentinel_loop`),
//! not the framework's `setsid`/second fork in its daemon-stage arms
//! (`run_as_daemon_stage1`) — the raw
//! path deliberately bypasses the framework's child arm. The framework's own
//! `setsid` (and that the daemon is not a session leader) is covered by
//! `framework_e2e.rs`, which asserts the daemon's session differs from the test
//! process's AND from the daemon's own pid.

use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, getsid};

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

/// RAII handle that kills the daemon on drop, so an assertion failure in the
/// test doesn't leak the (init- or subreaper-parented, detached) daemon
/// process. SIGTERM first; SIGKILL after a 2 s grace period. Never panics from
/// Drop.
struct DaemonGuard(Pid);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = kill(self.0, Signal::SIGTERM);
        let term_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match kill(self.0, None) {
                Ok(()) if Instant::now() >= term_deadline => {
                    eprintln!(
                        "daemon {} did not exit on SIGTERM within 2s; sending SIGKILL",
                        self.0,
                    );
                    let _ = kill(self.0, Signal::SIGKILL);
                    break;
                }
                Ok(()) => thread::sleep(Duration::from_millis(20)),
                // ESRCH: gone already. Anything else: stop probing — we're
                // in Drop and can't usefully react.
                Err(_) => break,
            }
        }
    }
}

#[test]
fn daemon_survives_parent_exit() {
    let tmp = tempfile::Builder::new()
        .prefix("cryfs-daemon-survive-test")
        .tempdir()
        .unwrap();
    let sentinel_path = tmp.path().join("sentinel");
    let pid_path = tmp.path().join("daemon.pid");

    // Run the spawner as a separate process: it launches the daemon (the
    // `daemonizable-test-background` helper in `sentinel_loop` mode) and exits
    // immediately, simulating a parent CLI that daemonizes and returns. The
    // daemon paths are handed over the environment — passed to the spawner's
    // `Command` here, then inherited by the daemon across the spawn — so we
    // never mutate this test process's own environment (no `set_var`, hence no
    // cross-thread env race). `exit(0)` in the spawner skips destructors, just
    // like the real cryfs parent CLI after a successful mount.
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

    // Daemon is a grandchild of this test; discover its PID through the file it
    // writes on startup.
    //
    // Poll on parseable content rather than just file existence: `std::fs::write`
    // (used by the daemon) creates the file before it writes, so a naive
    // `pid_path.exists()` check can win the race and read an empty file. macOS
    // exposes this race more often than Linux.
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
