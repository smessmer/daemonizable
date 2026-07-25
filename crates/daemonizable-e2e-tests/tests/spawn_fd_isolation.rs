//! Regression test for inherited-fd isolation across `start_background_process`.
//!
//! Before the fork+exec switch, `start_background_process` did a bare `fork()`
//! via the `daemonize` crate. Pipes created without CLOEXEC meant the daemon
//! child inherited every fd open in the parent at fork time — including pipes
//! belonging to sibling tests running in parallel. The original ~5% flake
//! rate on `cargo test` came from that.
//!
//! This test opens a "sentinel" pipe in the parent, then spawns the
//! `daemonizable-test-background` helper binary as a daemon, asking it to
//! write to the sentinel's *fd number*. Under fork+exec + `FD_CLOEXEC` on
//! every pipe, the sentinel fd is closed by the kernel during `execve` in
//! the daemon, so the write fails and the parent never receives anything on
//! its read end. The test asserts EOF.
//!
//! On the previous fork-only daemonize path this test would have observed
//! the sentinel byte in the parent — i.e. it was the canary for the bug.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::time::Duration;

use daemonizable::start_background_process_with_exe;
use daemonizable_e2e_tests::{ChildDaemonGuard, read_pid_file};
use nix::fcntl::OFlag;
use nix::unistd::pipe2;

#[test]
fn pipes_do_not_leak_into_daemon() {
    // Sentinel pipe — its fds should not be inherited by the daemon. Created
    // CLOEXEC (atomically, via pipe2(O_CLOEXEC)) the way a real application's
    // own pipes typically are, so the test isolates the *daemon spawn* layer
    // rather than relying on a coincidental inheritance default.
    let (sentinel_recver, sentinel_sender) = pipe2(OFlag::O_CLOEXEC).expect("create sentinel pipe");
    let sentinel_write_fd = sentinel_sender.as_raw_fd();

    // Tell the helper daemon (via env) which fd to attempt a write on.
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-spawn-fd-isolation")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let sentinel_param: OsString = sentinel_write_fd.to_string().into();

    // All three variables ride `extra_env` (`Command::env`, applied in the
    // spawned child) rather than `std::env::set_var` on this process: mutating
    // our own environment is `unsafe` (racy with any concurrently-reading
    // thread, e.g. the libtest controller), and the helper only reads these
    // from its own environment anyway.
    let env: [(&OsStr, &OsStr); 3] = [
        (
            OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
            OsStr::new("write_to_fd_then_idle"),
        ),
        (
            OsStr::new("DAEMONIZABLE_TEST_LEAK_FD"),
            sentinel_param.as_os_str(),
        ),
        (OsStr::new("DAEMONIZABLE_TEST_PID"), pid_file.as_os_str()),
    ];
    let _client = start_background_process_with_exe::<(), ()>(
        &daemonizable_e2e_tests::background_helper_exe!(),
        &env,
    )
    .expect("spawn daemon");

    // Drop our own copy of the sentinel sender so the only writer left
    // *would* be the daemon's inherited copy — if it had one. The recver
    // will go to EOF only after every writer is closed.
    drop(sentinel_sender);

    // Wait for the daemon to publish its PID, so we know it's reached its
    // main and (if the fd leaked) has had a chance to write. Content-polled,
    // not existence-polled — see `read_pid_file`.
    let daemon_pid = read_pid_file(&pid_file, Duration::from_secs(5));
    // Installed *before* the EOF assertion below, so the daemon gets killed
    // even if it panics. The reaping guard: this raw helper-spawn daemon is
    // our DIRECT child (no framework second fork), so it must be waitpid'd.
    let _guard = ChildDaemonGuard(daemon_pid);

    // No wait is needed before the check below: the helper attempts its leak
    // write BEFORE publishing the pid file (see `write_to_fd_then_idle`), so
    // having observed the pid file above already proves the write attempt
    // happened — ordering by observed events, not by timing.

    // Read from the sentinel pipe with a non-blocking read. Expect EOF (no
    // data) because the daemon's inherited copy of the fd was closed by
    // execve. If the fd had leaked, the daemon's write would have succeeded
    // and we'd see the bytes here.
    nix::fcntl::fcntl(
        &sentinel_recver,
        nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
    )
    .expect("set sentinel read end non-blocking");
    let mut recver = std::fs::File::from(sentinel_recver);
    let mut buf = [0u8; 16];
    match recver.read(&mut buf) {
        Ok(0) => { /* EOF — no writers left. Correct. */ }
        Ok(n) => panic!(
            "fd leaked into daemon: read {n} bytes from sentinel pipe: {:?}",
            &buf[..n]
        ),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            panic!(
                "fd leaked into daemon: sentinel pipe still has open writers \
                 (read would block instead of returning EOF)"
            );
        }
        Err(e) => panic!("unexpected read error: {e}"),
    }

    // Cleanup happens via ChildDaemonGuard's Drop.
}
