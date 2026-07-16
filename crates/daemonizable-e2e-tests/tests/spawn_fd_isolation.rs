//! Regression test for inherited-fd isolation across `start_background_process`.
//!
//! Before the fork+exec switch, `start_background_process` did a bare `fork()`
//! via the `daemonize` crate. Pipes created by `interprocess` weren't
//! CLOEXEC, so the daemon child inherited every fd open in the parent at
//! fork time — including pipes belonging to sibling tests running in
//! parallel. The original ~5% flake rate on `cargo test` came from that.
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
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use daemonizable::start_background_process_with_exe;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

fn helper_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daemonizable-test-background"))
}

/// RAII handle that kills and reaps the daemon on drop, so an assertion
/// failure in the test doesn't leak the daemon. SIGTERM first; SIGKILL after
/// a 2 s grace period. Never panics from Drop.
///
/// Unlike `daemon_survives_parent_exit`, here the daemon is our *direct
/// child*: this raw helper-spawn path does not go through the framework's
/// child arm (`run_as_daemon_child`), and hence not through its second fork —
/// so we must `waitpid` to reap it. `kill(pid, 0)` would report a zombie child
/// as "still alive", so polling with that would always hit the SIGTERM
/// timeout.
struct DaemonGuard(i32);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // A stale or invalid pid yields ESRCH/EPERM (discarded). Runs in the
        // parent during Drop, so async-signal-safety does not apply.
        let _ = kill(Pid::from_raw(self.0), Signal::SIGTERM);
        let term_deadline = Instant::now() + Duration::from_secs(2);
        // Poll until the child is reaped — any non-`StillAlive` result (reaped,
        // or gone / not ours) ends the loop. If it outlasts the SIGTERM grace
        // period, escalate to SIGKILL and a blocking reap.
        while let Ok(WaitStatus::StillAlive) =
            waitpid(Pid::from_raw(self.0), Some(WaitPidFlag::WNOHANG))
        {
            if Instant::now() >= term_deadline {
                eprintln!(
                    "daemon {} did not exit on SIGTERM within 2s; sending SIGKILL",
                    self.0,
                );
                let _ = kill(Pid::from_raw(self.0), Signal::SIGKILL);
                // Block-wait to reap; SIGKILL is unblockable.
                let _ = waitpid(Pid::from_raw(self.0), None);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn pipes_do_not_leak_into_daemon() {
    // Sentinel pipe — its fds should not be inherited by the daemon.
    let (sentinel_sender, sentinel_recver) =
        interprocess::unnamed_pipe::pipe().expect("create sentinel pipe");
    // We want the sentinel pipe to be CLOEXEC the same way cryfs's own
    // pipes are, so the test isolates the *daemon spawn* layer rather than
    // a coincidental CLOEXEC default.
    for fd in [sentinel_recver.as_raw_fd(), sentinel_sender.as_raw_fd()] {
        // SAFETY: FFI call to fcntl(2) with cmd F_GETFD, which takes no variadic
        // third argument (none is passed) and no pointer argument, so there are
        // no memory-validity preconditions. `fd` is a plain c_int borrowed via
        // as_raw_fd() from the live `sentinel_recver`/`sentinel_sender` pipes
        // (still owned in this scope); F_GETFD only reads the descriptor's flags
        // and never takes ownership, so a stale fd would merely return EBADF
        // (checked below), never cause UB.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        // SAFETY: FFI call to fcntl(2). Setting F_SETFD requires exactly one int
        // variadic arg, and `flags | FD_CLOEXEC` is that int (`flags` is the
        // c_int returned by the F_GETFD call above). No pointer args are passed.
        // `fd` is borrowed via AsRawFd from the still-live sentinel pipe halves;
        // F_SETFD only sets the close-on-exec flag and neither transfers nor
        // closes fd ownership, so there is no aliasing or double-close hazard. A
        // stale fd would only yield EBADF, not UB.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        assert!(rc >= 0);
    }
    let sentinel_write_fd = sentinel_sender.as_raw_fd();

    // Tell the helper daemon (via env) which fd to attempt a write on.
    let tmp = tempfile::Builder::new()
        .prefix("cryfs-spawn-fd-isolation")
        .tempdir()
        .unwrap();
    let pid_file = tmp.path().join("daemon.pid");
    let sentinel_param: OsString = sentinel_write_fd.to_string().into();
    // SAFETY: `set_var` is unsafe because it races with concurrent env reads
    // on other threads. This integration test is its own binary with a single
    // `#[test]`, so no sibling test thread is reading env at the same time.
    // The values are inherited through fork + execve into the helper daemon.
    unsafe {
        std::env::set_var("DAEMONIZABLE_TEST_LEAK_FD", &sentinel_param);
        std::env::set_var("DAEMONIZABLE_TEST_PID", &pid_file);
    }

    let env: [(&OsStr, &OsStr); 1] = [(
        OsStr::new("DAEMONIZABLE_TEST_BEHAVIOR"),
        OsStr::new("write_to_fd_then_idle"),
    )];
    let _client =
        start_background_process_with_exe::<(), ()>(&helper_exe(), &env).expect("spawn daemon");

    // Drop our own copy of the sentinel sender so the only writer left
    // *would* be the daemon's inherited copy — if it had one. The recver
    // will go to EOF only after every writer is closed.
    drop(sentinel_sender);

    // Wait for the daemon to publish its PID, so we know it's reached its
    // main and (if the fd leaked) has had a chance to write.
    let pid_deadline = Instant::now() + Duration::from_secs(5);
    while !pid_file.exists() {
        assert!(Instant::now() < pid_deadline, "daemon never wrote pid file",);
        thread::sleep(Duration::from_millis(10));
    }
    let daemon_pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("read pid file")
        .trim()
        .parse()
        .expect("parse pid");
    // Installed *before* the EOF assertion below, so the daemon gets killed
    // even if it panics.
    let _guard = DaemonGuard(daemon_pid);

    // Give the daemon a touch more time to actually run its write attempt.
    thread::sleep(Duration::from_millis(100));

    // Read from the sentinel pipe with a short deadline. Expect EOF (no
    // data) because the daemon's inherited copy of the fd was closed by
    // execve. If the fd had leaked, the daemon's write would have succeeded
    // and we'd see the bytes here.
    let mut recver = sentinel_recver;
    interprocess::os::unix::unnamed_pipe::UnnamedPipeExt::set_nonblocking(&recver, true)
        .expect("set_nonblocking");
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

    // Cleanup happens via DaemonGuard's Drop.
}
