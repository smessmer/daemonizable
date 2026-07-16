//! Helper binary for `tests/detach_stdio_reopens_preclosed_fd.rs`.
//!
//! Regression coverage for [`daemonizable::detach_stdio`] when a standard fd
//! is already closed on entry. In that case `open("/dev/null")` can hand back
//! that very low fd number; a naive `dup2(fd, fd)` self-copy is a POSIX no-op
//! that doesn't close, so dropping the `/dev/null` descriptor afterwards would
//! close the std fd we meant to redirect — silently leaving it closed. The fix
//! relocates `/dev/null` above the std range first; this helper proves the
//! std fd ends up open and pointing at `/dev/null`.
//!
//! Usage: `argv[1]` is the std fd to pre-close (`0`, `1`, or `2`). The helper
//! closes it, calls `detach_stdio`, then checks that *every* std fd (0/1/2) is
//! open and is a character device (as `/dev/null` is), not closed.
//!
//! It reports only through its exit code — it must not write to stdout/stderr,
//! since one of those may be the fd under test:
//!   0  success: all std fds open and char devices after detach
//!   2  bad arguments
//!   3  `detach_stdio` itself returned an error
//!   4  a std fd is still closed after detach (the bug this guards against)
//!   5  a std fd is open but not a character device (unexpected)

fn main() {
    let Some(arg) = std::env::args().nth(1) else {
        std::process::exit(2);
    };
    let to_close: i32 = match arg.parse() {
        Ok(n @ 0..=2) => n,
        _ => std::process::exit(2),
    };

    // Pre-close the chosen std fd, so `/dev/null` will reopen onto that low
    // number inside `detach_stdio`.
    // SAFETY: closing a raw fd is always safe; a bad fd just returns EBADF.
    unsafe { libc::close(to_close) };

    if daemonizable::detach_stdio().is_err() {
        std::process::exit(3);
    }

    // After detaching, all three std fds must be open and point at /dev/null
    // (a character device). A closed fd (fstat → EBADF) is the bug.
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            // Not open — detach left it closed.
            std::process::exit(4);
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFCHR {
            std::process::exit(5);
        }
    }

    std::process::exit(0);
}
