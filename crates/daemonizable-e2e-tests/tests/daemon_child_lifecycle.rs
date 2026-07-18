//! Integration version of the daemonize `test_child_*` lifecycle tests.
//!
//! These previously lived as unit tests in `ipc/daemonize.rs` and forked an
//! in-process fn pointer. That spawn shape suffered an ~5% flake rate in
//! parallel `cargo test` runs: sibling tests' pipe fds were inherited into
//! each others' daemonized children, preventing EOF/EPIPE delivery on the
//! rightful pipe owners.
//!
//! Reworked here to spawn a dedicated helper binary via fork+exec, so:
//! - The daemon child is a clean single-threaded process image (no inherited
//!   libtest threads or mutexes).
//! - Inherited fds are limited to the two we explicitly `dup2` onto fds 3 and
//!   4 — everything else dies under `FD_CLOEXEC` during `execve`.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use daemonizable::{
    ChannelRecvError, ChannelSendError, RpcClient, start_background_process_with_exe,
};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Request {
    request: i32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Response {
    response: i32,
}

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

fn spawn_daemon(behavior: &str) -> RpcClient<Request, Response> {
    let env: [(&OsStr, &OsStr); 1] = [(
        OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
        OsStr::new(behavior),
    )];
    start_background_process_with_exe(&helper_exe(), &env)
        .expect("start_background_process_with_exe failed")
}

#[test]
fn test_child_echo_roundtrip() {
    let mut rpc = spawn_daemon("echo");
    rpc.send_request(&Request { request: 42 }).unwrap();
    let response = rpc.recv_response(Duration::from_secs(2)).unwrap();
    assert_eq!(response, Response { response: 43 });
}

#[test]
fn test_child_panicking_after_request() {
    let mut rpc = spawn_daemon("panic_after_request");
    rpc.send_request(&Request { request: 42 }).unwrap();
    let response = rpc.recv_response(Duration::from_secs(2)).unwrap_err();
    assert!(
        matches!(response, ChannelRecvError::SenderClosed),
        "expected SenderClosed, got: {response:?}"
    );
}

#[test]
fn test_child_panicking_before_request() {
    let mut rpc = spawn_daemon("panic_before_request");
    let response = rpc.recv_response(Duration::from_secs(2)).unwrap_err();
    assert!(
        matches!(response, ChannelRecvError::SenderClosed),
        "expected SenderClosed, got: {response:?}"
    );
}

#[test]
fn test_child_exiting_after_request() {
    let mut rpc = spawn_daemon("exit_after_request");
    rpc.send_request(&Request { request: 42 }).unwrap();
    let response = rpc.recv_response(Duration::from_secs(2)).unwrap_err();
    assert!(
        matches!(response, ChannelRecvError::SenderClosed),
        "expected SenderClosed, got: {response:?}"
    );
}

#[test]
fn test_child_exiting_before_request() {
    let mut rpc = spawn_daemon("exit_before_request");
    let response = rpc.recv_response(Duration::from_secs(2)).unwrap_err();
    assert!(
        matches!(response, ChannelRecvError::SenderClosed),
        "expected SenderClosed, got: {response:?}"
    );
}

#[test]
fn test_child_send_request_after_daemon_exited() {
    // The SEND direction against a dead daemon (the tests above cover the
    // receive direction): once the daemon has exited, `send_request` must
    // fail with `BrokenPipe` — not succeed into a buffer no one will read,
    // and not hang. Every synchronization point is an observed event, never
    // a delay:
    //   1. EOF on the channel (`SenderClosed`) proves the daemon
    //      reached its exit path and closed its channel end.
    //   2. `waitpid` reaps the daemon (our direct child on this raw spawn
    //      path); once it returns, the process is fully gone, so every fd it
    //      held — including the request direction — is closed and the
    //      send outcome below is deterministic.
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let pid_param: OsString = pid_file.clone().into_os_string();
    let env: [(&OsStr, &OsStr); 2] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("write_pid_then_exit"),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_param.as_os_str()),
    ];
    let mut rpc: RpcClient<Request, Response> =
        start_background_process_with_exe(&helper_exe(), &env)
            .expect("start_background_process_with_exe failed");

    let err = rpc.recv_response(Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(err, ChannelRecvError::SenderClosed),
        "expected SenderClosed, got: {err:?}"
    );

    // The daemon wrote its pid file before touching its channel end
    // (`write_pid_then_exit`), so after the EOF above the file is guaranteed
    // present and complete — read it directly, no existence polling. The
    // blocking reap returns promptly for the same reason: EOF is only
    // observable once the daemon is already on its exit path.
    let daemon_pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("read pid file")
        .trim()
        .parse()
        .expect("parse pid");
    let status = waitpid(Pid::from_raw(daemon_pid), None).expect("waitpid(daemon)");
    assert!(
        matches!(status, WaitStatus::Exited(_, 0)),
        "daemon did not exit cleanly: {status:?}"
    );

    let err = rpc.send_request(&Request { request: 1 }).unwrap_err();
    assert!(
        matches!(&err, ChannelSendError::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe),
        "expected Io(BrokenPipe) when sending to an exited daemon, got: {err:?}"
    );
}
