//! Regression test for [`daemonizable::detach_stdio`]'s handling of a standard
//! fd that was already closed on entry.
//!
//! If stdin/stdout/stderr is closed when `detach_stdio` runs, `open("/dev/null")`
//! can return that same low fd number. A naive implementation then `dup2(fd, fd)`s
//! it onto itself (a no-op that doesn't close) and, when the temporary
//! `/dev/null` descriptor drops at end of scope, closes the very std fd it meant
//! to redirect — silently leaving it closed while returning `Ok`. The fix
//! relocates `/dev/null` above the std range before the `dup2`s.
//!
//! We can't exercise this in-process: it requires closing a real std fd, which
//! would corrupt the multithreaded libtest runner. So we spawn a dedicated
//! helper (`daemonizable-test-detach-stdio-preclosed`) that closes one std fd,
//! calls `detach_stdio`, and reports via its exit code whether all three std
//! fds end up open and pointing at `/dev/null`. Exit 0 = fixed; a non-zero exit
//! (notably 4 = "fd still closed") is the bug.

use std::process::Command;

fn preclosed_helper_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-detach-stdio-preclosed")
}

#[test]
fn detach_stdio_redirects_a_preclosed_std_fd_to_dev_null() {
    for fd in [0, 1, 2] {
        let status = Command::new(preclosed_helper_exe())
            .arg(fd.to_string())
            // Inherit real stdio so the helper starts with 0/1/2 open and then
            // closes exactly the one under test.
            .status()
            .expect("spawn the pre-closed detach_stdio helper");
        assert!(
            status.success(),
            "helper for pre-closed fd {fd} exited with {status:?}: detach_stdio must leave \
             all std fds open and pointing at /dev/null. Exit codes: 3 = detach_stdio \
             returned an error; 4 = a std fd was left closed (the bug this guards against); \
             5 = a std fd is open but not /dev/null; 6 = test setup failed to normalize the \
             inherited std fds"
        );
    }
}
