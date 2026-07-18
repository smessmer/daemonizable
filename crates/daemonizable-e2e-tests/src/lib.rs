//! Support code shared by this crate's integration tests. The crate exists
//! for those tests and the helper binaries they spawn (see the crate-level
//! comment in `Cargo.toml`); this lib target hosts the few pieces the test
//! files share, and doubles as the target tools that expect a lib (e.g.
//! trybuild's generated test project) can depend on.

use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// RAII handle that kills a detached daemon process on drop, so an assertion
/// failure in a test doesn't leak the (init- or subreaper-parented, detached)
/// daemon process. SIGTERM first; SIGKILL after a 2 s grace period. Never
/// panics from Drop.
///
/// Shared by the parent-exit survival tests (`daemon_survives_parent_exit`,
/// `framework_daemon_survives_parent_exit`): their daemons outlive the
/// process that spawned them by design, so there is no `Child` handle to kill
/// through — cleanup has to go by pid.
pub struct DaemonGuard(pub Pid);

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
