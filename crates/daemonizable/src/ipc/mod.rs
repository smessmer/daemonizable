mod channel;
mod cloexec;
mod error;
mod rpc;
mod spawn;

pub use error::{
    ChannelCreateError, ChannelRecvError, ChannelSendError, DetachStdioError, HandshakeError,
    SpawnDaemonError,
};
pub use rpc::{RpcClient, RpcConnection, RpcServer};
#[cfg(any(test, feature = "testutils"))]
pub(crate) use spawn::stage_token;
pub(crate) use spawn::{
    StageDispatch, channel_has_stage2_token, daemon_exe_path, dispatch_from_channel,
    spawn_daemon_process, verify_channel_peer_creds,
};
// `send_handshake` / `rpc_server_from_inherited_fds` are also used internally by
// the daemon-child arm (`app::daemon_child`), so they stay crate-visible here
// regardless of features; only their crate-root re-export in `lib.rs` is
// `testutils`-gated.
pub use spawn::{rpc_server_from_inherited_fds, send_handshake};

// Test-only surface, gated so it never ships in the default published API
// (mirrored by the `testutils`-gated crate-root re-exports in `lib.rs`).
// `InheritedFdsError` is produced only by the fd-claim helper — internal code
// names it via the `error` submodule directly, so this re-export exists purely
// for the crate-root one — and the `*_with_exe` spawn helpers exist only for
// the e2e tests.
#[cfg(any(test, feature = "testutils"))]
pub use error::InheritedFdsError;
#[cfg(any(test, feature = "testutils"))]
pub use spawn::{spawn_daemon_process_with_exe, start_background_process_with_exe};

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
/// concurrently-allocated descriptor can land in — from entry until the
/// `open` fills the lowest hole and the matching `dup2`s fill the rest —
/// after which the redirect silently clobbers whatever landed there. (The
/// function doesn't widen that window internally: once the `open` fills the
/// lowest hole, the relocation deliberately leaks rather than closes the low
/// fd, so that hole never reopens mid-flight — see the relocation comments.)
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
    // was already closed on entry), move it above the range first — otherwise
    // the `dup2(fd, fd)` self-copy below is a no-op and the end-of-scope drop
    // would close the std fd we just "redirected". See the doc comment.
    if source.as_raw_fd() <= libc::STDERR_FILENO {
        // Duplicate `source` above the std range with CLOEXEC in one `fcntl`.
        // Safe: it borrows `source` and only reads/duplicates the descriptor.
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
        // Deliberately LEAK the old low fd instead of dropping (closing) it:
        // closing would reopen the std-fd hole for a moment, and in a
        // multithreaded process a descriptor another thread allocates in that
        // window would land on the hole only to be silently clobbered by the
        // dup2s below. Leaked, the low number stays parked on /dev/null until
        // its matching dup2 atomically replaces it in place (every fd <= 2 is
        // a dup2 target below); on a dup2 error return it stays open on
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
