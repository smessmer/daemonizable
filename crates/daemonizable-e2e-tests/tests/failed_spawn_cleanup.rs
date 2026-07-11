//! Coverage for the documented failed-spawn cleanup contract: when the
//! handshake fails, `spawn_daemon` must kill and reap the child so a failed
//! spawn leaves no orphan and no unreapable zombie behind.
//!
//! This path can't be tested through `spawn_daemon` itself (it always re-execs
//! `/proc/self/exe`, unusable from a libtest binary), so we drive the exact
//! same cleanup via the `testutils`-gated `spawn_daemon_process_with_exe`
//! against the `daemonizable-test-background` helper. The helper writes its pid
//! to a file so we can assert, after the call returns, that the library already
//! reaped it (`waitpid` → `ECHILD`) and that it is gone (`kill(pid, 0)` →
//! `ESRCH`).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use daemonizable::{
    HandshakeError, PipeRecvError, SpawnDaemonError, spawn_daemon_process_with_exe,
};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::sys::wait::{WaitPidFlag, waitpid};
use nix::unistd::Pid;

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

/// Poll the pid file the helper writes until it has parseable content. The
/// helper writes it before it does anything the parent can observe, so it is
/// always present by the time the spawn call returns — but poll defensively.
fn read_helper_pid(pid_path: &PathBuf) -> Pid {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(pid_path) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                return Pid::from_raw(pid);
            }
        }
        assert!(
            Instant::now() < deadline,
            "helper never wrote a parseable pid file",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Assert the library already reaped the helper (so it is not a zombie child of
/// this test process) and that the process is gone. `waitpid(WNOHANG)` →
/// `ECHILD` is the load-bearing check: `kill(pid, 0)` alone succeeds against a
/// zombie, so it cannot prove reaping on its own.
fn assert_reaped_and_gone(pid: Pid) {
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Err(Errno::ECHILD) => { /* already reaped by the library — correct */ }
        other => panic!(
            "helper {pid} was not reaped by the failed-spawn cleanup: waitpid returned {other:?} \
             (expected ECHILD)"
        ),
    }
    // The reap is synchronous with the SIGKILL, so the process is already gone;
    // poll briefly only to absorb scheduler skew on loaded CI.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match kill(pid, None) {
            Err(Errno::ESRCH) => break, // gone — correct
            Ok(()) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(()) => panic!("helper {pid} still exists after failed-spawn cleanup"),
            Err(err) => panic!("unexpected kill(pid, 0) error probing helper {pid}: {err}"),
        }
    }
}

/// Poll until `pid` — which is NOT our child (the double-fork reparented it
/// away, so we cannot `waitpid` it) — is gone or a zombie. Either proves the
/// group SIGKILL reached it; a still-running state after the deadline fails.
/// Linux-only (reads `/proc`).
#[cfg(target_os = "linux")]
fn assert_killed_reparented(pid: Pid) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::read_to_string(format!("/proc/{}/status", pid.as_raw())) {
            Err(_) => return, // gone — killed and already reaped by init/subreaper
            Ok(status) => {
                let state = status
                    .lines()
                    .find_map(|l| l.strip_prefix("State:"))
                    .map(|s| s.trim_start());
                if state.is_some_and(|s| s.starts_with('Z')) {
                    return; // zombie — killed, the reaper just hasn't collected it yet
                }
                assert!(
                    Instant::now() < deadline,
                    "grandchild {pid} still running 5s after the group-kill: State={state:?}",
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[test]
fn failed_spawn_kills_and_reaps_a_live_child_on_handshake_mismatch() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-failed-spawn")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let pid_param: OsString = pid_file.clone().into_os_string();
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("wrong_handshake_then_idle"),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_param.as_os_str()),
    ];

    let result = spawn_daemon_process_with_exe::<(), ()>(
        &helper_exe(),
        "the-build-id-the-parent-expects",
        &env,
    );

    let err = result.err().expect("spawn must fail on handshake mismatch");
    assert!(
        matches!(
            err,
            SpawnDaemonError::Handshake(HandshakeError::Mismatch { .. })
        ),
        "expected Handshake(Mismatch), got: {err:?}"
    );

    // The helper wrote its pid, sent the wrong handshake, then idled — so the
    // cleanup had a LIVE child to SIGKILL and reap.
    let pid = read_helper_pid(&pid_file);
    assert_reaped_and_gone(pid);
}

#[test]
fn failed_spawn_reaps_a_child_that_died_before_the_handshake() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-failed-spawn")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let pid_param: OsString = pid_file.clone().into_os_string();
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("write_pid_then_exit"),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_param.as_os_str()),
    ];

    let result = spawn_daemon_process_with_exe::<(), ()>(
        &helper_exe(),
        "the-build-id-the-parent-expects",
        &env,
    );

    let err = result
        .err()
        .expect("spawn must fail when the child exits early");
    assert!(
        matches!(
            err,
            SpawnDaemonError::Handshake(HandshakeError::Recv(PipeRecvError::SenderClosed))
        ),
        "expected Handshake(Recv(SenderClosed)), got: {err:?}"
    );

    // The child exited before the handshake; the cleanup's wait() must have
    // reaped the resulting zombie.
    let pid = read_helper_pid(&pid_file);
    assert_reaped_and_gone(pid);
}

/// The real production topology: the helper double-forks like the framework
/// child arm (setsid → fork → intermediate `_exit(0)`), and the surviving
/// grandchild — the actual daemon — sends a wrong handshake and idles. The
/// failed-spawn cleanup's `kill(-child_pid, SIGKILL)` must reach that grandchild
/// (a plain `child.kill()` would only hit the already-dead intermediate). The
/// grandchild is reparented away, so we prove death via `/proc` rather than
/// `waitpid`. Linux-only.
#[cfg(target_os = "linux")]
#[test]
fn failed_spawn_group_kill_reaches_the_grandchild() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-failed-spawn")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let pid_param: OsString = pid_file.clone().into_os_string();
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("double_fork_wrong_handshake_then_idle"),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_param.as_os_str()),
    ];

    let result = spawn_daemon_process_with_exe::<(), ()>(
        &helper_exe(),
        "the-build-id-the-parent-expects",
        &env,
    );

    let err = result.err().expect("spawn must fail on handshake mismatch");
    assert!(
        matches!(
            err,
            SpawnDaemonError::Handshake(HandshakeError::Mismatch { .. })
        ),
        "expected Handshake(Mismatch), got: {err:?}"
    );

    // The pid file holds the GRANDCHILD's pid (written after the second fork).
    // The group-kill must have reached it even though it is not our direct child.
    let grandchild = read_helper_pid(&pid_file);
    assert_killed_reparented(grandchild);
}
