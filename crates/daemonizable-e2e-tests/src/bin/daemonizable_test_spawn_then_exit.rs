//! Helper for `tests/daemon_survives_parent_exit.rs` and
//! `tests/daemon_send_after_foreground_exit.rs`. Simulates a parent CLI
//! that daemonizes and then returns: it launches a background daemon via the
//! raw `start_background_process_with_exe` path and exits immediately, so a
//! test can verify what happens on the daemon's side after the process that
//! spawned it is gone (that it keeps running; that its sends fail cleanly).
//!
//! This is launched by the test via `std::process::Command` (a fresh process
//! image), NOT by forking the multithreaded libtest harness, so it carries none
//! of the fork-in-a-multithreaded-process hazard the previous in-test `fork()`
//! did — while exercising the identical "daemon survives its spawner's exit"
//! guarantee.
//!
//! Inputs (from the environment, set by the test on our `Command`):
//!   - `DAEMONIZABLE_TEST_DAEMON_EXE`: path to the `daemonizable-test-background`
//!     helper binary to launch as the daemon.
//!   - `DAEMONIZABLE_TEST_BEHAVIOR` (optional): the behavior to run the daemon
//!     in; defaults to `sentinel_loop`. Forwarded explicitly because our
//!     `extra_env` would otherwise override what the test set.
//!   - Behavior-specific paths (`DAEMONIZABLE_TEST_SENTINEL`,
//!     `DAEMONIZABLE_TEST_PID`, `DAEMONIZABLE_TEST_OUTFILE`): where the daemon
//!     writes. We don't read these ourselves; the daemon inherits them from
//!     our environment across the spawn.
//!
//! We additionally pass the daemon our own pid as
//! `DAEMONIZABLE_TEST_SPAWNER_PID`, so behaviors that must wait for this
//! process to be fully gone can detect that as an observed event (their
//! `getppid()` changing away from this pid on reparent) instead of guessing
//! with timing.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use daemonizable::start_background_process_with_exe;

fn main() {
    // The daemon binary to launch (the `daemonizable-test-background` helper),
    // handed to us by the test through the environment.
    let daemon_exe = PathBuf::from(
        std::env::var_os("DAEMONIZABLE_TEST_DAEMON_EXE")
            .expect("DAEMONIZABLE_TEST_DAEMON_EXE not set"),
    );

    // The behavior to run the daemon in (the test sets it on our Command;
    // default matches the original single-purpose version of this helper).
    // Behavior-specific paths ride the inherited environment untouched.
    let behavior =
        std::env::var_os("DAEMONIZABLE_TEST_BEHAVIOR").unwrap_or_else(|| "sentinel_loop".into());
    let spawner_pid: OsString = std::process::id().to_string().into();
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            behavior.as_os_str(),
        ),
        (
            OsStr::new("DAEMONIZABLE_TEST_SPAWNER_PID"),
            spawner_pid.as_os_str(),
        ),
    ];
    let _client = start_background_process_with_exe::<(), ()>(&daemon_exe, &env)
        .expect("start_background_process_with_exe failed in spawner");

    // Exit immediately, like a CLI that has launched its daemon and is done.
    // `exit(0)` skips destructors (dropping `_client` is unnecessary — the OS
    // closes our channel end on exit, and the daemon must survive regardless),
    // matching the real cryfs parent CLI after a successful mount.
    std::process::exit(0);
}
