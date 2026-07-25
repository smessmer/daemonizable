//! Typed errors for the IPC layer.
//!
//! Library-crate policy: detailed `thiserror` enums instead of `anyhow`, so
//! callers can match on failure modes (e.g. distinguish a peer that closed
//! the channel from a timeout) and the public API stays dependency-light.
//!
//! Every public enum here is `#[non_exhaustive]`: the crate's roadmap (the
//! batteries TODO in `app::daemon_child`) plans new failure modes — e.g.
//! `SpawnDaemonError` growing `AlreadyRunning` / privilege-drop variants — and
//! the match-on-failure-modes policy above is exactly the usage pattern that
//! would otherwise turn each addition into a breaking change. Callers keep a
//! wildcard arm; new variants land as minor releases.

use thiserror::Error;

/// Creating an IPC channel pair failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChannelCreateError {
    /// The underlying `socketpair(2)` call failed. `UnixStream::pair` sets
    /// `FD_CLOEXEC` on the created fds itself (atomically via `SOCK_CLOEXEC`
    /// where available), so a cloexec-setting failure folds into this same
    /// `io::Error` rather than a separate variant.
    #[error("Failed to create channel: {0}")]
    CreateSocket(#[source] std::io::Error),
}

/// Sending a message over an IPC channel failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChannelSendError {
    /// The message exceeds the wire format's maximum size. Nothing was
    /// written, so the channel remains usable.
    #[error("Message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// Serializing the message failed. Nothing was written, so the channel
    /// remains usable.
    #[error("Failed to encode message: {0}")]
    Encode(#[from] postcard::Error),

    /// Writing to the channel failed. A receiver that closed its end surfaces
    /// here as [`std::io::ErrorKind::BrokenPipe`].
    ///
    /// Treat as terminal: a frame may have been partially written, so the
    /// sender is poisoned and every later send fails with
    /// [`Desynchronized`](Self::Desynchronized) — retrying is never safe (a
    /// fresh length prefix would be consumed as leftover payload bytes by the
    /// peer).
    #[error("Failed to write to channel: {0}")]
    Io(#[from] std::io::Error),

    /// The sender is poisoned: a previous send failed after (possibly
    /// partially) writing a frame, so the wire is desynchronized on the send
    /// side. Every send on a poisoned sender fails with this without touching
    /// the channel. Abandon the connection. Mirrors
    /// [`ChannelRecvError::Desynchronized`] on the receive side.
    #[error("Sender desynchronized by a prior failed send; connection must be abandoned")]
    Desynchronized,
}

/// Receiving a message from an IPC channel failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChannelRecvError {
    /// The timeout expired before a full message arrived.
    #[error("Timeout waiting for a message on the channel")]
    Timeout,

    /// The sender closed its end of the channel (EOF), before or in the middle
    /// of a message. Normalized across blocking and timeout-bounded receives:
    /// EOF always surfaces as this variant, never as
    /// [`Io`](Self::Io)`(UnexpectedEof)`.
    #[error("Sender closed the channel")]
    SenderClosed,

    /// The message's length prefix exceeds the wire format's maximum size.
    #[error("Message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// The receiver is poisoned: a previous receive consumed part of a message
    /// frame and then failed — a mid-frame [`Timeout`](Self::Timeout), a
    /// mid-frame [`Io`](Self::Io) error, or a
    /// [`MessageTooLarge`](Self::MessageTooLarge) whose declared payload was
    /// left unread — so the stream is desynchronized. Every receive on a
    /// poisoned `Receiver` fails with this without touching the channel; a further
    /// read would misinterpret leftover payload bytes as a new length prefix.
    /// Abandon the connection. A clean idle timeout (nothing consumed), a
    /// [`Decode`](Self::Decode) failure of a fully-read frame, and EOF
    /// ([`SenderClosed`](Self::SenderClosed), terminal on its own) do *not*
    /// poison.
    #[error("Receiver desynchronized by a prior partial receive; connection must be abandoned")]
    Desynchronized,

    /// Deserializing the message failed.
    #[error("Failed to decode message: {0}")]
    Decode(#[from] postcard::Error),

    /// Reading from the channel failed. If the failure struck after part of a
    /// frame was consumed, the receiver is also poisoned — every later receive
    /// then reports [`Desynchronized`](Self::Desynchronized); do not retry.
    #[error("Failed to read from channel: {0}")]
    Io(#[from] std::io::Error),
}

/// The build-id handshake between parent and daemon failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// Receiving the handshake bytes failed (EOF, timeout, or I/O error) —
    /// e.g. the spawned binary exited or hangs without writing a handshake.
    #[error("Failed to receive build-id handshake from daemon: {0}")]
    Recv(#[source] ChannelRecvError),

    /// The daemon sent bytes that aren't valid UTF-8 — almost certainly a
    /// wrong binary writing unrelated data to the handshake fd.
    #[error("Daemon sent a build-id that isn't valid UTF-8")]
    InvalidUtf8(#[source] std::str::Utf8Error),

    /// The daemon's build id doesn't match what the parent expected.
    #[error(
        "Parent and daemon binaries don't match (parent={expected}, daemon={received}). Refusing to start."
    )]
    Mismatch { expected: String, received: String },
}

/// Spawning the daemon child process failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpawnDaemonError {
    /// Creating the parent↔child IPC channel failed.
    #[error("Failed to create IPC channel: {0}")]
    CreateChannel(#[from] ChannelCreateError),

    /// The path to re-exec could not be determined. On non-Linux this is a
    /// failed `std::env::current_exe`. On Linux (where `/proc/self/exe` is
    /// normally used and this never arises) it carries one of two synthesized
    /// errors, distinguishable by [`std::io::Error::kind`] as a documented
    /// contract:
    ///
    /// * [`PermissionDenied`](std::io::ErrorKind::PermissionDenied) — `/proc`
    ///   is not mounted and this is a secure-execution (setuid/setgid/
    ///   file-caps, `AT_SECURE`) process, so the `AT_EXECFN` / `argv[0]`
    ///   fallbacks were deliberately **refused unconsulted**: both are picked
    ///   by the unprivileged invoker, and re-exec'ing them would let the
    ///   invoker steer which binary runs with the elevated credentials.
    /// * [`NotFound`](std::io::ErrorKind::NotFound) — `/proc` is not mounted
    ///   and every fallback (`AT_EXECFN`, then `argv[0]`) was consulted but
    ///   failed to yield an executable path.
    #[error("Failed to determine the executable path to re-exec: {0}")]
    ExePath(#[source] std::io::Error),

    /// The spawn of the child process itself failed.
    #[error("Failed to spawn daemon binary at {}: {source}", path.display())]
    Spawn {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The spawned child failed the build-id handshake.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

/// The daemon child couldn't claim the IPC channel fd inherited from its parent.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InheritedFdError {
    /// The channel fd was already claimed by an earlier call. It is a process
    /// singleton (like stdio): a second claim would alias owning `OwnedFd`s
    /// and risk a use-after-close.
    ///
    /// Also returned when an earlier claim *attempt* failed validation: the
    /// claim guard never rolls back, so a failed first call permanently
    /// poisons the process even though no fd was adopted (see
    /// [`rpc_server_from_inherited_fd`](crate::rpc_server_from_inherited_fd)).
    #[error(
        "the inherited daemon channel fd ({channel_fd}) has already been claimed; rpc_server_from_inherited_fd must be called at most once per process"
    )]
    AlreadyClaimed { channel_fd: i32 },

    /// The fd isn't open — almost always a user invoking the daemon entry
    /// point manually from a shell.
    #[error(
        "fd {fd} (daemon channel) is not open. This entry point is internal to this binary; do not invoke it directly. ({source})"
    )]
    NotOpen {
        fd: i32,
        #[source]
        source: std::io::Error,
    },

    /// The fd is open but not a socket — whatever happened to be open on that
    /// fd number is not the parent's IPC channel.
    #[error(
        "fd {fd} (daemon channel) is not a socket (st_mode={st_mode:#o}). This entry point is internal to this binary; do not invoke it directly."
    )]
    NotASocket {
        fd: i32,
        /// The fd's `st_mode` as reported by `fstat`, widened to `u32` so no
        /// libc type (platform-varying `mode_t`: u32 on Linux, u16 on Apple)
        /// leaks into the public API.
        st_mode: u32,
    },

    /// Restoring `FD_CLOEXEC` on the claimed fd failed. The spawn's `dup2`
    /// cleared the flag so the fd would survive `execve`; it must be re-set so
    /// the daemon's own subprocesses don't inherit the channel end and suppress
    /// the EOF the parent relies on for liveness.
    #[error("fcntl({operation}) failed restoring FD_CLOEXEC on fd {fd} (daemon channel): {source}")]
    SetCloexec {
        fd: i32,
        /// Which fcntl operation failed (`"F_GETFD"` or `"F_SETFD"`).
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Cloning the claimed channel fd into the server's send/recv halves failed
    /// (`dup` → EMFILE/ENFILE). The adopted fd is closed on this error.
    #[error("failed to clone the daemon channel fd into its send/recv halves: {source}")]
    CloneFd {
        #[source]
        source: std::io::Error,
    },
}
