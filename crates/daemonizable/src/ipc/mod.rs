//! The inter-process machinery behind the app-facing API, split by
//! responsibility:
//!
//! - [`mod@channel`] — the typed, length-prefixed framing over one `AF_UNIX`
//!   socket (`Sender`/`Receiver`, timeout + poison state machines).
//! - [`mod@rpc`] — the request/response endpoints built on it (`RpcClient`,
//!   `RpcServer`, and the channel-owning `RpcConnection`).
//! - [`mod@spawn`] — the fork+exec daemon spawn, stage-identity tokens,
//!   peer-credential check, fd claim, and build-id handshake.
//! - [`mod@error`] — the typed error enums for all of the above.
//! - [`mod@cloexec`] — the shared `FD_CLOEXEC` set helper.
//!
//! (The app-facing stdio utility `detach_stdio` is deliberately NOT here — it
//! is not IPC; see `crate::stdio`.)

mod channel;
mod cloexec;
mod error;
mod rpc;
mod spawn;

pub use error::{
    ChannelCreateError, ChannelRecvError, ChannelSendError, HandshakeError, SpawnDaemonError,
};
pub use rpc::{RpcClient, RpcConnection, RpcServer};
#[cfg(any(test, feature = "testutils"))]
pub(crate) use spawn::stage_token;
pub(crate) use spawn::{
    StageDispatch, channel_has_stage2_token, daemon_exe_path, dispatch_from_channel,
    spawn_daemon_process, verify_channel_peer_creds,
};
// `send_handshake` / `rpc_server_from_inherited_fd` are also used internally by
// the daemon-child arm (`app::daemon_child`), so they stay crate-visible here
// regardless of features; only their crate-root re-export in `lib.rs` is
// `testutils`-gated.
pub use spawn::{rpc_server_from_inherited_fd, send_handshake};

// Test-only surface, gated so it never ships in the default published API
// (mirrored by the `testutils`-gated crate-root re-exports in `lib.rs`).
// `InheritedFdError` is produced only by the fd-claim helper — internal code
// names it via the `error` submodule directly, so this re-export exists purely
// for the crate-root one — and the `*_with_exe` spawn helpers exist only for
// the e2e tests.
#[cfg(any(test, feature = "testutils"))]
pub use error::InheritedFdError;
#[cfg(any(test, feature = "testutils"))]
pub use spawn::{
    spawn_daemon_process_with_exe, spawn_daemon_process_with_exe_and_timeout,
    start_background_process_with_exe,
};
