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
    // SAFETY: `fd` is an open descriptor valid for the duration of both calls.
    // F_GETFD has no side effects beyond returning the current flags; F_SETFD
    // only ORs in FD_CLOEXEC, leaving the underlying file/pipe untouched.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(("F_GETFD", std::io::Error::last_os_error()));
    }
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
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "precondition: CLOEXEC should be clear before the call"
        );

        set_cloexec(fd).expect("set_cloexec should succeed on a valid open fd");

        assert_ne!(
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
