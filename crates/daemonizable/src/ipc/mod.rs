mod cloexec;
mod error;
mod pipe;
mod rpc;
mod spawn;

pub use error::{
    DetachStdioError, HandshakeError, InheritedFdsError, PipeCreateError, PipeRecvError,
    PipeSendError, SpawnDaemonError,
};
pub use rpc::{RpcClient, RpcConnection, RpcServer};
#[cfg(any(test, feature = "testutils"))]
pub use spawn::spawn_daemon_process_with_exe;
pub(crate) use spawn::{DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR, spawn_daemon_process};
pub use spawn::{rpc_server_from_inherited_fds, send_handshake, start_background_process_with_exe};

/// Replace the calling process's stdin/stdout/stderr with `/dev/null` via
/// `dup2`. The daemon calls this at its post-startup boundary — typically
/// right after the first successful operation completes — so inherited stdio
/// (still bound to the user's shell at this point) doesn't leak
/// background-daemon output to the terminal.
///
/// Call exactly once. Idempotent in practice (a second `dup2` is harmless)
/// but the intent is one-shot at the post-startup boundary.
///
/// We `dup2` rather than `close` to keep fd numbers 0/1/2 valid — a later
/// allocation that re-grabs those numbers would otherwise produce garbage in
/// unrelated files. The temp `/dev/null` fd is dropped after the dup2s; the
/// targets keep their duplicated descriptors.
///
/// One subtlety this guards against: if a standard fd was already *closed* when
/// this is called, `open("/dev/null")` can hand back that very low number (0, 1,
/// or 2). Then `dup2(fd, fd)` is a POSIX no-op that does **not** close, and
/// dropping the `/dev/null` fd at the end of scope would close the std fd we
/// meant to redirect — silently leaving it closed while returning `Ok`. To avoid
/// that, we first relocate the `/dev/null` descriptor above the std range (via
/// `fcntl(F_DUPFD_CLOEXEC)`) whenever it lands on 0/1/2, so the source fd is
/// never one of the `dup2` targets.
///
/// # Errors
/// Returns [`DetachStdioError`] if `/dev/null` can't be opened, the relocation
/// off the std-fd range fails, or a `dup2` fails. Detaching is best-effort — a
/// failure leaves stdio bound to whatever it was inherited from (possibly
/// partially redirected; see the error variants). The caller decides whether
/// that's fatal; the daemon otherwise keeps running.
pub fn detach_stdio() -> Result<(), DetachStdioError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(DetachStdioError::OpenDevNull)?;
    let mut source = OwnedFd::from(devnull);

    // If `/dev/null` opened onto one of the std fds (only reachable when that fd
    // was already closed on entry), move it above the range first — otherwise
    // the `dup2(fd, fd)` self-copy below is a no-op and the end-of-scope drop
    // would close the std fd we just "redirected". See the doc comment.
    if source.as_raw_fd() <= libc::STDERR_FILENO {
        // SAFETY: `source` is a live, open descriptor and the variadic third
        // argument is a valid `c_int` minimum fd. `F_DUPFD_CLOEXEC` only
        // duplicates the descriptor (or fails with a plain errno); it has no
        // memory effects. Ownership of the returned fd is taken below.
        let relocated = unsafe {
            libc::fcntl(
                source.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                libc::STDERR_FILENO + 1,
            )
        };
        if relocated < 0 {
            return Err(DetachStdioError::Relocate(std::io::Error::last_os_error()));
        }
        // Reassigning `source` drops the old (low) fd, closing it, and takes
        // ownership of the relocated one, which is guaranteed to be > 2.
        // SAFETY: `relocated` is a fresh, exclusively-owned fd from the fcntl.
        source = unsafe { OwnedFd::from_raw_fd(relocated) };
    }

    let fd = source.as_raw_fd();
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(fd, target) } < 0 {
            return Err(DetachStdioError::Dup2 {
                target,
                source: std::io::Error::last_os_error(),
            });
        }
    }
    // `source` (now guaranteed > 2) drops at end of scope, closing the temp fd;
    // the three targets keep their duplicated descriptors.
    Ok(())
}
