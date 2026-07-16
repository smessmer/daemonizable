//! Helper for `tests/daemon_survives_parent_exit.rs`. Simulates a parent CLI
//! that daemonizes and then returns: it launches a background daemon via the
//! raw `start_background_process_with_exe` path and exits immediately, so the
//! test can verify the daemon keeps running after the process that spawned it
//! is gone.
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
//!   - `DAEMONIZABLE_TEST_SENTINEL` / `DAEMONIZABLE_TEST_PID`: where the daemon
//!     writes its sentinel/pid. We don't read these ourselves; the daemon
//!     inherits them from our environment across the spawn.

use std::ffi::OsStr;
use std::path::PathBuf;

use daemonizable::start_background_process_with_exe;

fn main() {
    // The daemon binary to launch (the `daemonizable-test-background` helper),
    // handed to us by the test through the environment.
    let daemon_exe = PathBuf::from(
        std::env::var_os("DAEMONIZABLE_TEST_DAEMON_EXE")
            .expect("DAEMONIZABLE_TEST_DAEMON_EXE not set"),
    );

    // Run the daemon in `sentinel_loop` mode; it reads `DAEMONIZABLE_TEST_SENTINEL`
    // / `DAEMONIZABLE_TEST_PID` from its environment (inherited from ours across
    // the spawn) to know where to write.
    let env: [(&OsStr, &OsStr); 1] = [(
        OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
        OsStr::new("sentinel_loop"),
    )];
    let _client = start_background_process_with_exe::<(), ()>(&daemon_exe, &env)
        .expect("start_background_process_with_exe failed in spawner");

    // Exit immediately, like a CLI that has launched its daemon and is done.
    // `exit(0)` skips destructors (dropping `_client` is unnecessary — the OS
    // closes our pipe ends on exit, and the daemon must survive regardless),
    // matching the real cryfs parent CLI after a successful mount.
    std::process::exit(0);
}
