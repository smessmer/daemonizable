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
//!
//! (The app-facing stdio utility `detach_stdio` is deliberately NOT here — it
//! is not IPC; see `crate::stdio`.)

mod channel;
mod error;
mod rpc;
mod spawn;

pub use error::{
    ChannelCreateError, ChannelRecvError, ChannelSendError, HandshakeError, SpawnDaemonError,
};
pub use rpc::{RpcClient, RpcServer};
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
// Internal code doesn't use these re-exports — it names the submodules
// directly — so they exist purely to feed the crate-root ones.
#[cfg(any(test, feature = "testutils"))]
pub use error::InheritedFdError;
// `in_process_rpc_pair`, not `RpcConnection`: downstream tests only ever want
// the connected pair, and keeping the connection type out of the re-export
// chain is what makes `new_channel` / `into_server_and_client` internal.
#[cfg(any(test, feature = "testutils"))]
pub use rpc::in_process_rpc_pair;
#[cfg(any(test, feature = "testutils"))]
pub use spawn::{
    spawn_daemon_process_with_exe, spawn_daemon_process_with_exe_and_timeout, stage_token_bytes,
    start_background_process_with_exe,
};
