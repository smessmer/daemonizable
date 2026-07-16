//! Shared helper for setting `FD_CLOEXEC` on a file descriptor.
//!
//! Two call sites need this: the macOS pipe-creation fallback (platforms
//! without `pipe2(O_CLOEXEC)`), and the daemon child restoring the flag on the
//! RPC fds it inherited across `execve` (the spawn's `dup2` onto fds 3/4 clears
//! it). Keeping the flag-preserving read-modify-write in one place means each
//! caller just hands over a `BorrowedFd` it already holds.

use std::os::fd::BorrowedFd;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

/// Set `FD_CLOEXEC` on `fd`, preserving any other descriptor flags. On failure
/// returns the `fcntl` operation that failed (`"F_GETFD"` or `"F_SETFD"`) and
/// the OS error, so each caller can fold it into its own error type.
///
/// Takes a [`BorrowedFd`], so the caller has already established (once, where it
/// wraps the raw fd) that the descriptor is valid — the two `fcntl` calls here
/// go through `nix` and need no `unsafe`.
pub(crate) fn set_cloexec(fd: BorrowedFd<'_>) -> Result<(), (&'static str, std::io::Error)> {
    let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(|e| ("F_GETFD", e.into()))?;
    // Preserve any other descriptor flags; only add FD_CLOEXEC.
    let flags = FdFlag::from_bits_retain(flags | libc::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(|e| ("F_SETFD", e.into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn sets_cloexec_on_a_fd_that_lacks_it() {
        // A raw interprocess pipe end does not have CLOEXEC set by default.
        let (sender, _recver) = interprocess::unnamed_pipe::pipe().unwrap();
        let fd = sender.as_fd();

        // Precondition: clear the flag so we can observe set_cloexec setting it.
        let flags = fcntl(fd, FcntlArg::F_GETFD).unwrap();
        fcntl(
            fd,
            FcntlArg::F_SETFD(FdFlag::from_bits_retain(flags) & !FdFlag::FD_CLOEXEC),
        )
        .unwrap();
        assert!(
            !FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC),
            "precondition: CLOEXEC should be clear before the call"
        );

        set_cloexec(fd).expect("set_cloexec should succeed on a valid open fd");

        assert!(
            FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC),
            "set_cloexec must leave FD_CLOEXEC set"
        );
    }
}
