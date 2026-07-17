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
//! Usage: `argv[1]` is the std fd to pre-close (`0`, `1`, or `2`). Because
//! `open` hands back the lowest-numbered *closed* descriptor, the helper first
//! makes sure every std fd *below* the target is open (whatever stdio the test
//! harness happened to inherit), so `/dev/null` deterministically reopens onto
//! the target fd rather than some lower hole. It then closes the target, calls
//! `detach_stdio`, and checks that *every* std fd (0/1/2) ends up open and is
//! specifically `/dev/null` — a character device whose `st_rdev` matches the
//! `/dev/null` device node — not closed and not some other stream.
//!
//! It reports only through its exit code — it must not write to stdout/stderr,
//! since one of those may be the fd under test:
//!   0  success: all std fds reopened onto /dev/null after detach
//!   2  bad arguments
//!   3  `detach_stdio` itself returned an error
//!   4  a std fd is still closed after detach (the bug this guards against)
//!   5  a std fd is open but is not /dev/null (unexpected)
//!   6  test setup failed to normalize the inherited std fds

use std::os::unix::fs::MetadataExt;

fn main() {
    let Some(arg) = std::env::args().nth(1) else {
        std::process::exit(2);
    };
    let to_close: i32 = match arg.parse() {
        Ok(n @ 0..=2) => n,
        _ => std::process::exit(2),
    };

    // The device identity of `/dev/null`, read before we disturb any std fd.
    // Each fd's `st_rdev` is compared against this so "open" specifically means
    // "reopened onto /dev/null", not merely "some character device" (an
    // inherited terminal is also a char device). Probed at runtime rather than
    // hard-coded, since the (major, minor) of /dev/null differs across OSes.
    let Some(devnull_rdev) = devnull_rdev() else {
        std::process::exit(6);
    };

    // `open` returns the lowest-numbered *closed* fd, so `/dev/null` only lands
    // on `to_close` inside `detach_stdio` if every lower std fd is already open.
    // Normalize that here, independent of whatever stdio the harness inherited,
    // so each iteration truly exercises its intended loop position.
    for fd in 0..to_close {
        if !ensure_open(fd) {
            std::process::exit(6);
        }
    }

    // Pre-close the chosen std fd, so `/dev/null` will reopen onto that low
    // number inside `detach_stdio`.
    // SAFETY: `close` takes a bare fd int; a bad fd is EBADF, not UB. `to_close`
    // is a std fd (0/1/2, per the `0..=2` match above) held as a raw number, not
    // owned by any `OwnedFd`/`File`, so closing it sets up no double-close, and
    // the single-threaded process has no concurrent reopen to race it. Closing
    // a std fd additionally obligates us to keep std from observing the hole:
    // this binary never materializes a `Stdin`/`Stdout`/`Stderr` handle or a
    // `BorrowedFd` over 0-2 (it reports via exit codes only, per the module
    // docs), the only fd allocation inside the closed window is
    // `detach_stdio`'s own `open`, which deliberately re-occupies the number,
    // and a panic in the window would write its message to a closed fd 2 as a
    // swallowed EBADF rather than into a stolen descriptor.
    unsafe { libc::close(to_close) };

    if daemonizable::detach_stdio().is_err() {
        std::process::exit(3);
    }

    // After detaching, all three std fds must be open and point at /dev/null.
    // A closed fd (fstat → EBADF) is the bug; a live fd with a different
    // identity means detach redirected it somewhere other than /dev/null.
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `libc::stat` is a `repr(C)` struct of only integer fields (no
        // references/NonZero/bool/enums), so an all-zero bit pattern is a valid,
        // fully-initialized value; it serves purely as the out-param `fstat` fills.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstat` reads into a valid out-param; a closed fd is EBADF.
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            // Not open — detach left it closed.
            std::process::exit(4);
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFCHR || st.st_rdev != devnull_rdev {
            std::process::exit(5);
        }
    }

    std::process::exit(0);
}

/// `st_rdev` of the `/dev/null` device node, or `None` if it can't be stat'd.
/// The probe fd is opened and dropped within this call, so it never perturbs
/// the std fds the rest of the helper manages.
fn devnull_rdev() -> Option<libc::dev_t> {
    let devnull = std::fs::File::open("/dev/null").ok()?;
    // Safe fstat via std — `metadata()` stats the live `File`. (The raw-libc
    // `fstat` in `main` cannot be replaced the same way: it probes possibly
    // *closed* fd numbers, which no safe `AsFd`-based API may wrap.)
    let meta = devnull.metadata().ok()?;
    // `MetadataExt::rdev` widens `st_rdev` to `u64`; cast back to the
    // platform's `dev_t` (a lossless round-trip of the kernel value) so the
    // comparison against the raw `libc::stat` in `main` stays exact.
    Some(meta.rdev() as libc::dev_t)
}

/// Ensure std fd `fd` is open, parking `/dev/null` on it if the harness left it
/// closed. Returns `false` on an unexpected failure. The parked descriptor is
/// intentionally left as a bare fd number (like the std fds themselves) — this
/// short-lived helper never owns or closes it.
fn ensure_open(fd: i32) -> bool {
    // SAFETY: `F_GETFD` only reads the descriptor flags (EBADF if closed).
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
        return true; // already open
    }
    // Closed — open /dev/null and move it onto `fd` if it didn't land there.
    // SAFETY: `open` takes a valid NUL-terminated path (a C string literal
    // that outlives the call) and creates a fresh descriptor; it reads no
    // other memory.
    let opened = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if opened < 0 {
        return false;
    }
    if opened == fd {
        return true;
    }
    // SAFETY: `dup2` takes two bare fd ints and dereferences nothing. `opened`
    // is the live fd returned by `open` above; `fd` is a std fd number (0..=2)
    // owned by no `OwnedFd`/`File`, so clobbering it in place breaks no other
    // owner. A bad fd yields EBADF, not UB.
    let moved = unsafe { libc::dup2(opened, fd) };
    // SAFETY: `opened` is the raw fd returned by `open` above; it is a live,
    // exclusively-owned descriptor (never wrapped in an `OwnedFd`/`File`, so no
    // other owner closes it) and is distinct from `fd` (the `opened == fd` case
    // returned early). `dup2` does not consume its source, so `opened` is still
    // open here; closing it releases the temporary `/dev/null` fd.
    unsafe { libc::close(opened) };
    moved >= 0
}
