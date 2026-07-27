//! The app-facing daemon-lifecycle stdio utility: [`detach_stdio`] and its
//! error type. Not IPC — it touches only `/dev/null`, `fcntl`, and `dup2` —
//! which is why it lives in its own module rather than under `ipc`.

use thiserror::Error;

/// Detaching the daemon's inherited stdio to `/dev/null` failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DetachStdioError {
    /// Opening `/dev/null` failed, so there was nothing to redirect stdio to.
    /// The inherited stdio is left untouched.
    #[error("Failed to open /dev/null while detaching daemon stdio: {0}")]
    OpenDevNull(#[source] std::io::Error),

    /// Relocating the `/dev/null` descriptor off the std-fd range (0/1/2)
    /// failed. This only arises when `/dev/null` opened *onto* one of those
    /// numbers — i.e. that std fd was already closed when `detach_stdio` was
    /// called — and the `fcntl(F_DUPFD_CLOEXEC)` used to move it above the
    /// range failed. The inherited stdio is left untouched.
    #[error(
        "fcntl(F_DUPFD_CLOEXEC) failed relocating /dev/null off the std-fd range while detaching daemon stdio: {0}"
    )]
    Relocate(#[source] std::io::Error),

    /// `dup2(/dev/null, target)` failed for one of stdin/stdout/stderr. Any
    /// earlier targets in the stdin→stdout→stderr order were already
    /// redirected before this one failed.
    #[error("dup2(/dev/null, {target}) failed while detaching daemon stdio: {source}")]
    Dup2 {
        /// The standard fd (0/1/2) the redirect targeted.
        target: i32,
        #[source]
        source: std::io::Error,
    },
}

/// Replace the calling process's stdin/stdout/stderr with `/dev/null` via
/// `dup2`. The daemon calls this at its post-startup boundary — typically
/// right after the first successful operation completes — so inherited stdio
/// (still bound to the user's shell at this point) doesn't leak
/// background-daemon output to the terminal.
///
/// Call exactly once. Idempotent in practice (a second `dup2` is harmless)
/// but the intent is one-shot at the post-startup boundary.
///
/// Concurrency: prefer calling while no other thread is creating file
/// descriptors. Any std fd still *closed* when this is called is a hole a
/// concurrently-allocated descriptor can land in, after which the redirect
/// silently clobbers whatever landed there. (The function doesn't widen that
/// window internally: once the `open` fills the lowest hole, it never reopens
/// — see the relocation below.)
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
/// never one of the `dup2` targets. The old low descriptor is deliberately
/// leaked, not closed: it stays parked on `/dev/null` until the matching
/// `dup2` overwrites it in place, so the std-fd hole never reopens mid-flight.
///
/// # Errors
/// Returns [`DetachStdioError`] if `/dev/null` can't be opened, the relocation
/// off the std-fd range fails, or a `dup2` fails. Detaching is best-effort — a
/// failure leaves stdio bound to whatever it was inherited from (possibly
/// partially redirected; see the error variants). The caller decides whether
/// that's fatal; the daemon otherwise keeps running.
pub fn detach_stdio() -> Result<(), DetachStdioError> {
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    use nix::fcntl::{FcntlArg, fcntl};
    use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout};

    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(DetachStdioError::OpenDevNull)?;
    let mut source = OwnedFd::from(devnull);

    // If `/dev/null` opened onto one of the std fds (only reachable when that fd
    // was already closed on entry), move it above the range first — see the
    // relocation subtlety in the doc comment.
    if source.as_raw_fd() <= libc::STDERR_FILENO {
        let relocated = fcntl(
            source.as_fd(),
            FcntlArg::F_DUPFD_CLOEXEC(libc::STDERR_FILENO + 1),
        )
        .map_err(|errno| DetachStdioError::Relocate(errno.into()))?;
        // SAFETY: `relocated` is a fresh, exclusively-owned fd just returned by
        // `F_DUPFD_CLOEXEC` (guaranteed > 2 by the min-fd argument); nothing
        // else owns it, so adopting it into an `OwnedFd` (which closes it on
        // drop) is sound.
        let relocated = unsafe { OwnedFd::from_raw_fd(relocated) };
        // Deliberately LEAK the old low fd (`into_raw_fd`, not drop): closing
        // would reopen the std-fd hole for a moment, and a descriptor another
        // thread allocates in that window would be silently clobbered by the
        // dup2s below. Leaked, it stays parked on /dev/null until its matching
        // dup2 replaces it in place; on a dup2 error return it stays open on
        // /dev/null — a strictly better failure state than a closed std fd.
        let _ = std::mem::replace(&mut source, relocated).into_raw_fd();
    }

    // Redirect stdin/stdout/stderr onto `source`. `dup2_std*` are safe wrappers
    // around `dup2(source, 0/1/2)`; the relocation above guarantees `source > 2`,
    // so none of these is a self-copy no-op that would fail to replace the target.
    dup2_stdin(source.as_fd()).map_err(|errno| DetachStdioError::Dup2 {
        target: libc::STDIN_FILENO,
        source: errno.into(),
    })?;
    dup2_stdout(source.as_fd()).map_err(|errno| DetachStdioError::Dup2 {
        target: libc::STDOUT_FILENO,
        source: errno.into(),
    })?;
    dup2_stderr(source.as_fd()).map_err(|errno| DetachStdioError::Dup2 {
        target: libc::STDERR_FILENO,
        source: errno.into(),
    })?;
    // `source` (now guaranteed > 2) drops at end of scope, closing the temp fd;
    // the three targets keep their duplicated descriptors.
    Ok(())
}
