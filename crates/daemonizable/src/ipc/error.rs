//! Typed errors for the IPC layer.
//!
//! Library-crate policy: detailed `thiserror` enums instead of `anyhow`, so
//! callers can match on failure modes (e.g. distinguish a peer that closed
//! the pipe from a timeout) and the public API stays dependency-light.

use thiserror::Error;

/// Creating an IPC pipe pair failed.
#[derive(Debug, Error)]
pub enum PipeCreateError {
    /// The underlying `pipe(2)` call failed.
    #[error("Failed to create pipe: {0}")]
    CreatePipe(#[source] std::io::Error),

    /// Setting `FD_CLOEXEC` on a freshly created pipe end failed. The flag is
    /// required so pipe fds don't leak into fork+exec'd children.
    #[error("fcntl({operation}) failed while setting FD_CLOEXEC: {source}")]
    SetCloexec {
        /// Which fcntl operation failed (`"F_GETFD"` or `"F_SETFD"`).
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// Sending a message over an IPC pipe failed.
#[derive(Debug, Error)]
pub enum PipeSendError {
    /// The message exceeds the wire format's maximum size.
    #[error("Message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// Serializing the message failed.
    #[error("Failed to encode message: {0}")]
    Encode(#[from] postcard::Error),

    /// Writing to the pipe failed. A receiver that closed its end surfaces
    /// here as [`std::io::ErrorKind::BrokenPipe`].
    #[error("Failed to write to pipe: {0}")]
    Io(#[from] std::io::Error),
}

/// Receiving a message from an IPC pipe failed.
#[derive(Debug, Error)]
pub enum PipeRecvError {
    /// The timeout expired before a full message arrived.
    #[error("Timeout waiting for a message on the pipe")]
    Timeout,

    /// The sender closed its end of the pipe (EOF), before or in the middle
    /// of a message. Normalized across blocking and timeout-bounded receives:
    /// EOF always surfaces as this variant, never as
    /// [`Io`](Self::Io)`(UnexpectedEof)`.
    #[error("Sender closed the pipe")]
    SenderClosed,

    /// The message's length prefix exceeds the wire format's maximum size.
    #[error("Message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// Deserializing the message failed.
    #[error("Failed to decode message: {0}")]
    Decode(#[from] postcard::Error),

    /// Reading from the pipe failed.
    #[error("Failed to read from pipe: {0}")]
    Io(#[from] std::io::Error),
}

/// The build-id handshake between parent and daemon failed.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Receiving the handshake bytes failed (EOF, timeout, or I/O error) —
    /// e.g. the spawned binary exited or hangs without writing a handshake.
    #[error("Failed to receive build-id handshake from daemon: {0}")]
    Recv(#[source] PipeRecvError),

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
pub enum SpawnDaemonError {
    /// Creating the parent↔child IPC pipes failed.
    #[error("Failed to create IPC pipes: {0}")]
    CreatePipes(#[from] PipeCreateError),

    /// The path to re-exec could not be determined (only possible on
    /// platforms where we fall back to `std::env::current_exe`).
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

    /// Serializing the bootstrap payload failed.
    #[error("Failed to encode bootstrap payload: {0}")]
    EncodePayload(#[source] postcard::Error),

    /// Shipping the bootstrap payload to the daemon failed.
    #[error("Failed to send bootstrap payload to daemon: {0}")]
    SendPayload(#[source] PipeSendError),

    /// Receiving the daemon's bootstrap ack failed (timeout, EOF because the
    /// daemon died, or an I/O error).
    #[error("Failed to receive bootstrap ack from daemon: {0}")]
    RecvAck(#[source] PipeRecvError),

    /// The daemon acked with a non-empty payload — a protocol violation.
    #[error("Bootstrap ack carried {len} bytes; expected empty payload")]
    MalformedAck { len: usize },
}

/// The daemon child couldn't claim the IPC fds inherited from its parent.
#[derive(Debug, Error)]
pub enum InheritedFdsError {
    /// The fds were already claimed by an earlier call. They are a process
    /// singleton (like stdio): a second claim would alias owning `OwnedFd`s
    /// and risk a use-after-close.
    #[error(
        "the inherited daemon fds ({request_recv_fd}/{response_send_fd}) have already been claimed; rpc_server_from_inherited_fds must be called at most once per process"
    )]
    AlreadyClaimed {
        request_recv_fd: i32,
        response_send_fd: i32,
    },

    /// The fd isn't open — almost always a user invoking the daemon entry
    /// point manually from a shell.
    #[error(
        "fd {fd} ({label}) is not open. This entry point is internal to this binary; do not invoke it directly. ({source})"
    )]
    NotOpen {
        fd: i32,
        label: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// The fd is open but not a pipe — whatever happened to be open on that
    /// fd number is not the parent's IPC channel.
    #[error(
        "fd {fd} ({label}) is not a pipe (st_mode={st_mode:#o}). This entry point is internal to this binary; do not invoke it directly."
    )]
    NotAPipe {
        fd: i32,
        label: &'static str,
        st_mode: libc::mode_t,
    },
}

/// Receiving the daemon's bootstrap ack failed.
#[derive(Debug, Error)]
pub(crate) enum BootstrapAckError {
    /// The daemon sent a non-empty payload where the empty ack marker was
    /// expected — a protocol violation.
    #[error("Bootstrap ack carried {len} bytes; expected empty payload")]
    NonEmptyAck { len: usize },

    /// Receiving the ack failed (timeout, EOF, or I/O error).
    #[error(transparent)]
    Recv(#[from] PipeRecvError),
}
