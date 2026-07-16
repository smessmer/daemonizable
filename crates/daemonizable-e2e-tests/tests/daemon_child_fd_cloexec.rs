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
                // SAFETY: `libc::kill` takes two integer scalars and no pointers, so
                // it has no memory-safety precondition and cannot invoke UB for any
                // argument. `pid` is the `i32` parsed just above and `SIGKILL` is a
                // valid signal constant; a stale or reused pid at cleanup time is a
                // benign correctness issue (defined ESRCH/EPERM behavior), and the
                // result is discarded.
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        // Reap the daemon (our direct child; the raw helper-spawn path does not
        // go through the framework's second fork, so it stays our child). It has
        // already exited, so a non-blocking reap suffices; retry briefly in case
        // cleanup races its exit.
        let mut status = 0;
        for _ in 0..100 {
            // SAFETY: `libc::waitpid`'s only pointer argument is `&mut status`,
            // which points to the live, initialized, correctly aligned stack `i32`
            // declared just above (`let mut status = 0;`, inferred as `c_int` from
            // the signature). `c_int` matches `i32` on Linux, so the status write is
            // in bounds and to writable storage. `pid = -1` and `WNOHANG` are plain
            // integers, and a missing child merely returns -1 (ECHILD), handled by
            // the `rc < 0` branch below — not UB. `waitpid` has no
            // async-signal-safety / single-threaded requirement, so thread context
            // is irrelevant.
            let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if rc > 0 {
                break; // reaped it (our only direct child)
            }
            if rc < 0 {
                break; // ECHILD — nothing to reap
            }
            thread::sleep(Duration::from_millis(10));
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
