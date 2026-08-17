//! Regression test for FD_CLOEXEC restoration on the daemon's inherited channel fd.
//!
//! When the parent spawns the daemon, the channel socket end is `dup2`'d onto
//! fixed fd 3, which clears its FD_CLOEXEC (that's how it survives the `execve`
//! into the daemon). `rpc_server_from_inherited_fd` re-sets the flag so the
//! daemon's *own* subprocesses don't inherit it. Without that, a daemon-spawned
//! child inherits the channel end (fd 3) across its own fork+exec; because EOF
//! only fires once every copy of an end is closed, such a child outliving the
//! daemon suppresses the EOF the parent waits on — so `recv_response` would hang
//! on a long-dead daemon.
//!
//! This test spawns the `daemonizable-test-background` helper as a daemon in a
//! mode where it fork+execs a long-lived `sleep` grandchild and then exits. With
//! CLOEXEC restored, the grandchild does not hold fd 3, so the parent's receive
//! returns `SenderClosed` (EOF) as soon as the daemon exits. If the fd leaked,
//! no EOF arrives and the receive times out instead — which this test reports
//! as a failure.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use daemonizable::{ChannelRecvError, start_background_process_with_exe};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

fn helper_exe() -> PathBuf {
    daemonizable_e2e_tests::background_helper_exe!()
}

/// Cleans up the processes this test leaves behind, even on assertion failure:
/// the reparented `sleep` grandchild (killed by the pid it recorded) and the
/// daemon zombie (our direct child, already exited — reaped via `waitpid`).
struct Cleanup {
    sleeper_pid_file: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(contents) = std::fs::read_to_string(&self.sleeper_pid_file)
            && let Ok(pid) = contents.trim().parse::<i32>()
        {
            // A stale or reused pid at cleanup time is a benign correctness
            // issue (defined ESRCH/EPERM behavior); the result is discarded.
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        // The raw helper-spawn path skips the framework's second fork, so the
        // daemon stays our direct child and must be reaped.
        for _ in 0..100 {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                // Not reaped yet; retry briefly in case cleanup races the exit.
                Ok(WaitStatus::StillAlive) => thread::sleep(Duration::from_millis(10)),
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
    // `extra_env` rather than `std::env::set_var`: mutating our own environment
    // is `unsafe`, racy against the libtest controller's own reads.
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("spawn_child_holding_fds_then_exit"),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_param.as_os_str()),
    ];
    let mut client =
        start_background_process_with_exe::<(), ()>(&helper_exe(), &env).expect("spawn daemon");

    // Before the assertion, so both are cleaned up even if it panics.
    let _cleanup = Cleanup {
        sleeper_pid_file: sleeper_pid_file.clone(),
    };

    // The daemon fork+execs a `sleep` grandchild and exits. If fd 3 leaked, that
    // grandchild would hold the channel end open for its full sleep and this
    // would time out instead of seeing EOF.
    let result = client.recv_response(Duration::from_secs(5));

    assert!(
        matches!(result, Err(ChannelRecvError::SenderClosed)),
        "expected SenderClosed (EOF) once the daemon exited, got {result:?}; the channel \
         fd leaked into the daemon-spawned child, keeping the channel end open past the \
         daemon's exit"
    );
}
