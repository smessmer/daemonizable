//! Regression test for FD_CLOEXEC restoration on the daemon's inherited RPC fds.
//!
//! When the parent spawns the daemon, the two RPC pipe ends are `dup2`'d onto
//! fixed fds 3 and 4, which clears their FD_CLOEXEC (that's how they survive the
//! `execve` into the daemon). `rpc_server_from_inherited_fds` re-sets the flag
//! so the daemon's *own* subprocesses don't inherit those fds. Without that,
//! a daemon-spawned child inherits the response pipe's write end (fd 4) across
//! its own fork+exec; because EOF only fires once every write end is closed,
//! such a child outliving the daemon suppresses the EOF the parent waits on —
//! so `recv_response` would hang on a long-dead daemon.
//!
//! This test spawns the `daemonizable-test-background` helper as a daemon in a
//! mode where it fork+execs a long-lived `sleep` grandchild and then exits. With
//! CLOEXEC restored, the grandchild does not hold fd 4, so the parent's receive
//! returns `SenderClosed` (EOF) as soon as the daemon exits. If the fds leaked,
//! no EOF arrives and the receive times out instead — which this test reports
//! as a failure.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use daemonizable::{PipeRecvError, start_background_process_with_exe};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

/// Cleans up the processes this test leaves behind, even on assertion failure:
/// the reparented `sleep` grandchild (killed by the pid it recorded) and the
/// daemon zombie (our direct child, already exited — reaped via `waitpid`).
struct Cleanup {
    sleeper_pid_file: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(contents) = std::fs::read_to_string(&self.sleeper_pid_file) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                // A stale or reused pid at cleanup time is a benign correctness
                // issue (defined ESRCH/EPERM behavior); the result is discarded.
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
        // Reap the daemon (our direct child; the raw helper-spawn path does not
        // go through the framework's second fork, so it stays our child). It has
        // already exited, so a non-blocking reap suffices; retry briefly in case
        // cleanup races its exit.
        for _ in 0..100 {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                // Not reaped yet; retry briefly in case cleanup races the exit.
                Ok(WaitStatus::StillAlive) => thread::sleep(Duration::from_millis(10)),
                // Reaped our only direct child, or ECHILD (nothing to reap) —
                // either way we're done.
                Ok(_) | Err(_) => break,
            }
        }
    }
}

#[test]
fn rpc_fds_do_not_leak_into_daemon_spawned_child() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-daemon-fd-cloexec")
        .tempdir()
        .unwrap();
    let sleeper_pid_file = tmp.path().join("sleeper.pid");

    let pid_param: OsString = sleeper_pid_file.clone().into_os_string();
    // SAFETY: `set_var` races with concurrent env reads on other threads. This
    // integration test is its own binary with a single `#[test]`, so no sibling
    // test thread reads env concurrently. The value is inherited through
    // fork + execve into the helper daemon.
    unsafe {
        std::env::set_var("DAEMONIZABLE_TEST_PID", &pid_param);
    }

    let env: [(&OsStr, &OsStr); 1] = [(
        OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
        OsStr::new("spawn_child_holding_fds_then_exit"),
    )];
    let mut client =
        start_background_process_with_exe::<(), ()>(&helper_exe(), &env).expect("spawn daemon");

    // Installed before the assertion so the daemon/grandchild are cleaned up
    // even if it fails or panics.
    let _cleanup = Cleanup {
        sleeper_pid_file: sleeper_pid_file.clone(),
    };

    // The daemon fork+execs a `sleep` grandchild and exits. With FD_CLOEXEC
    // restored on the inherited fds, the grandchild does not hold the response
    // pipe's write end, so once the daemon exits the parent's receive returns
    // EOF (SenderClosed) well within the timeout. If the fds leaked, the
    // grandchild keeps fd 4 open for its full sleep and this times out.
    let result = client.recv_response(Duration::from_secs(5));

    assert!(
        matches!(result, Err(PipeRecvError::SenderClosed)),
        "expected SenderClosed (EOF) once the daemon exited, got {result:?}; the RPC \
         fds leaked into the daemon-spawned child, keeping the response pipe's write \
         end open past the daemon's exit"
    );
}
