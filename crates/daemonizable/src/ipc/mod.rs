mod error;
mod pipe;
mod rpc;
mod spawn;

pub use error::{
    HandshakeError, InheritedFdsError, PipeCreateError, PipeRecvError, PipeSendError,
    SpawnDaemonError,
};
pub use rpc::{RpcClient, RpcConnection, RpcServer};
#[cfg(any(test, feature = "testutils"))]
pub use spawn::spawn_daemon_process_with_exe;
pub(crate) use spawn::{
    BOOTSTRAP_TIMEOUT, DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR, spawn_daemon_process,
};
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
pub fn detach_stdio() {
    let devnull = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        Ok(f) => f,
        Err(err) => {
            log::warn!("failed to open /dev/null while detaching daemon stdio: {err}");
            return;
        }
    };
    let fd = std::os::fd::AsRawFd::as_raw_fd(&devnull);
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(fd, target) } < 0 {
            log::warn!(
                "dup2(/dev/null, {target}) failed while detaching daemon stdio: {}",
                std::io::Error::last_os_error(),
            );
        }
    }
}
