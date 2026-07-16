//! Shared helper for setting `FD_CLOEXEC` on a raw file descriptor.
//!
//! Two call sites need this: the macOS pipe-creation fallback (platforms
//! without `pipe2(O_CLOEXEC)`), and the daemon child restoring the flag on the
//! RPC fds it inherited across `execve` (the spawn's `dup2` onto fds 3/4 clears
//! it). Keeping the fcntl pair in one place avoids duplicating the `unsafe`.

use std::os::fd::RawFd;

/// Set `FD_CLOEXEC` on `fd`, preserving any other descriptor flags. On failure
/// returns the `fcntl` operation that failed (`"F_GETFD"` or `"F_SETFD"`) and
/// the OS error, so each caller can fold it into its own error type.
pub(crate) fn set_cloexec(fd: RawFd) -> Result<(), (&'static str, std::io::Error)> {
    // SAFETY: FFI call into libc `fcntl`. `F_GETFD` takes no variadic third
    // argument and no pointers — just the `fd` and command ints — so there is
    // no type-mismatch or pointer-validity hazard, and it has no side effects
    // beyond returning the current flags. `fd` is a borrowed `RawFd` passed by
    // value: this function never wraps it in an owning `OwnedFd`, and F_GETFD
    // neither closes nor takes ownership of it, so there is no aliasing/
    // double-close risk. An invalid/closed `fd` yields a defined `EBADF` error
    // (return -1, checked below), not UB.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(("F_GETFD", std::io::Error::last_os_error()));
    }
    // SAFETY: FFI call into libc `fcntl`. For the `F_SETFD` command the variadic
    // third argument must be an `int`: `flags` is the c_int returned by F_GETFD
    // above and `FD_CLOEXEC` is a c_int, so `flags | FD_CLOEXEC` is a c_int, and
    // no pointers are passed. F_SETFD only ORs FD_CLOEXEC into the descriptor
    // flags, leaving the underlying file/pipe untouched. As above, `fd` is
    // borrowed by value (no ownership/aliasing hazard) and a bad fd yields EBADF,
    // handled below, not UB.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(("F_SETFD", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn sets_cloexec_on_a_fd_that_lacks_it() {
        // A raw interprocess pipe end does not have CLOEXEC set by default.
        let (sender, _recver) = interprocess::unnamed_pipe::pipe().unwrap();
        let fd = sender.as_raw_fd();

        // Precondition: clear the flag so we can observe set_cloexec setting it.
        // SAFETY: FFI call to fcntl(F_GETFD), which takes only the two integer
        // arguments — no variadic third argument and no pointers. `fd` comes
        // from `sender.as_raw_fd()`, an open pipe end whose owner (`sender`) is
        // alive for the whole test; `as_raw_fd` transfers no ownership, so there
        // is no aliasing/double-close hazard, and a bad fd could at worst yield
        // EBADF, never UB.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            // SAFETY: FFI call into libc fcntl(2). For F_SETFD the variadic third
            // arg must be an int, and `flags & !libc::FD_CLOEXEC` is a c_int (the
            // flags returned by the F_GETFD above with the CLOEXEC bit cleared),
            // so the variadic type matches; no pointers are passed. `fd` is
            // borrowed from the still-live `sender` (no ownership/aliasing
            // hazard) and a stale fd would only yield EBADF, not UB.
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        assert_eq!(
            // SAFETY: `fd` is the raw descriptor of the still-live `sender` pipe
            // end, so it is open for this call. F_GETFD takes no variadic third
            // argument and no pointers, has no side effects, and only reads the
            // descriptor flags; `as_raw_fd` transfers no ownership, so there is
            // no aliasing or double-close risk.
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "precondition: CLOEXEC should be clear before the call"
        );

        set_cloexec(fd).expect("set_cloexec should succeed on a valid open fd");

        assert_ne!(
            // SAFETY: FFI call to fcntl(F_GETFD), which takes no pointer or
            // variadic argument — only the int fd and cmd. `fd` is the raw
            // descriptor of the live `sender` pipe end (still in scope), so it is
            // open; even a bad fd would yield EBADF, not UB. F_GETFD is a
            // side-effect-free read of the descriptor flags and creates no owning
            // fd wrapper, so borrowing `fd` here is sound.
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "set_cloexec must leave FD_CLOEXEC set"
        );
    }

    #[test]
    fn errors_on_a_closed_fd() {
        // -1 is never a valid fd; fcntl(F_GETFD) fails with EBADF.
        let err = set_cloexec(-1).expect_err("a bad fd must error");
        assert_eq!(err.0, "F_GETFD");
    }
}
