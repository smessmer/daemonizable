//! Regression test for inherited-fd isolation across the daemon spawn: fds the
//! parent holds (e.g. pipes belonging to sibling tests in a parallel
//! `cargo test` run) must not leak into the daemon — a fork-only daemonizer
//! would inherit them all, while fork+exec + `FD_CLOEXEC` closes them during
//! `execve`.
//!
//! The test opens a "sentinel" pipe in the parent, then spawns the
//! `daemonizable-test-background` helper binary as a daemon, asking it to
//! write to the sentinel's *fd number*. The daemon's copy of that fd must
//! already be closed, so the write fails and the parent's read end sees EOF
//! instead of the sentinel byte.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::time::Duration;

use daemonizable::start_background_process_with_exe;
use daemonizable_e2e_tests::{ChildDaemonGuard, read_pid_file};
use nix::fcntl::OFlag;

#[test]
fn pipes_do_not_leak_into_daemon() {
    // std's anonymous-pipe API sets CLOEXEC like every other std fd, the way a
    // real application's own pipes typically are, so this isolates the daemon
    // spawn layer rather than a coincidental inheritance default. Not
    // nix::unistd::pipe2: macOS has no pipe2, and this test runs on macOS CI.
    let (mut sentinel_recver, sentinel_sender) = std::io::pipe().expect("create sentinel pipe");
    let sentinel_write_fd = sentinel_sender.as_raw_fd();

    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-spawn-fd-isolation")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let sentinel_param: OsString = sentinel_write_fd.to_string().into();

    // `extra_env` rather than `std::env::set_var`: mutating our own environment
    // is `unsafe`, racy against the libtest controller's own reads.
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

    // Dropped so the only writer left would be the daemon's inherited copy, if
    // it had one — the recver reaches EOF only once every writer is closed.
    drop(sentinel_sender);

    // Content-polled, not existence-polled — see `read_pid_file`.
    let daemon_pid = read_pid_file(&pid_file, Duration::from_secs(5));
    // Before the EOF assertion below, so the daemon gets killed even if it
    // panics. This raw helper-spawn daemon is our direct child (no framework
    // second fork), so it must be waitpid'd.
    let _guard = ChildDaemonGuard(daemon_pid);

    // No wait is needed: the helper attempts its leak write before publishing
    // the pid file, so observing that file already proves the attempt happened.
    // EOF here means execve closed the daemon's inherited copy of the fd; a leak
    // would show up as the sentinel bytes instead.
    nix::fcntl::fcntl(
        &sentinel_recver,
        nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
    )
    .expect("set sentinel read end non-blocking");
    let mut buf = [0u8; 16];
    match sentinel_recver.read(&mut buf) {
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
}
