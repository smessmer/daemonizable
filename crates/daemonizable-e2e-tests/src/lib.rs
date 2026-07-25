//! Support code shared by this crate's integration tests. The crate exists
//! for those tests and the helper binaries they spawn (see the crate-level
//! comment in `Cargo.toml`); this lib target hosts the few pieces the test
//! files share, and doubles as the target tools that expect a lib (e.g.
//! trybuild's generated test project) can depend on.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

/// The path of the `daemonizable-test-background` helper binary.
///
/// A macro rather than a lib function because `CARGO_BIN_EXE_*` is only set
/// by Cargo when compiling this package's integration tests — `env!` in the
/// lib target itself would not compile. The macro expands at the test's own
/// compile site, where the variable exists.
#[macro_export]
macro_rules! background_helper_exe {
    () => {
        ::std::path::PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
    };
}

/// Poll `path` until it holds a parseable pid, up to `timeout`; panics (with
/// the path) on expiry.
///
/// Poll on parseable CONTENT, not existence: the helpers publish their pid
/// with `std::fs::write`, which creates the file before it writes, so a naive
/// `path.exists()` check can win the race and read an empty file — macOS CI
/// exposes this race more often than Linux. (A helper that publishes via the
/// rename-into-place trick doesn't need this, but content-polling is correct
/// for every publisher.)
pub fn read_pid_file(path: &Path, timeout: Duration) -> Pid {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(pid) = contents.trim().parse::<i32>()
        {
            return Pid::from_raw(pid);
        }
        assert!(
            Instant::now() < deadline,
            "no parseable pid file appeared at {path:?} within {timeout:?}",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// RAII handle that kills a detached daemon process on drop, so an assertion
/// failure in a test doesn't leak the (init- or subreaper-parented, detached)
/// daemon process. SIGTERM first; SIGKILL after a 2 s grace period. Never
/// panics from Drop.
///
/// Shared by the parent-exit survival tests (`daemon_survives_parent_exit`,
/// `framework_daemon_survives_parent_exit`): their daemons outlive the
/// process that spawned them by design, so there is no `Child` handle to kill
/// through — cleanup has to go by pid. **Does not reap**: these daemons are
/// not our children. For a daemon that IS the test's direct child, use
/// [`ChildDaemonGuard`] — probing a zombie child with `kill(pid, 0)` reports
/// it alive, so this guard would always hit its SIGTERM timeout there.
#[derive(Debug)]
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

/// RAII handle that kills **and reaps** a daemon that is the test's *direct
/// child*, so an assertion failure doesn't leak it. SIGTERM first; SIGKILL
/// after a 2 s grace period. Never panics from Drop.
///
/// The reap/no-reap choice is load-bearing: a direct child must be reaped via
/// `waitpid` (used here to detect exit — `kill(pid, 0)` reports a zombie
/// child as "still alive", so [`DaemonGuard`]'s probe loop would always hit
/// its SIGTERM timeout on one). Used by the raw helper-spawn tests, whose
/// daemons never go through the framework's second fork (e.g.
/// `spawn_fd_isolation`).
#[derive(Debug)]
pub struct ChildDaemonGuard(pub Pid);

impl Drop for ChildDaemonGuard {
    fn drop(&mut self) {
        // A stale or invalid pid yields ESRCH/EPERM (discarded). Runs in the
        // parent during Drop, so async-signal-safety does not apply.
        let _ = kill(self.0, Signal::SIGTERM);
        let term_deadline = Instant::now() + Duration::from_secs(2);
        // Poll until the child is reaped — any non-`StillAlive` result (reaped,
        // or gone / not ours) ends the loop. If it outlasts the SIGTERM grace
        // period, escalate to SIGKILL and a blocking reap.
        while let Ok(WaitStatus::StillAlive) = waitpid(self.0, Some(WaitPidFlag::WNOHANG)) {
            if Instant::now() >= term_deadline {
                eprintln!(
                    "daemon {} did not exit on SIGTERM within 2s; sending SIGKILL",
                    self.0,
                );
                let _ = kill(self.0, Signal::SIGKILL);
                // Block-wait to reap; SIGKILL is unblockable.
                let _ = waitpid(self.0, None);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
