//! Fork+exec daemon spawn and the pieces of the parent↔daemon startup
//! protocol.
//!
//! The moving parts are split by responsibility:
//! - [`mod@process`] — the fork+exec machinery on the parent side
//!   ([`spawn_daemon_process`], [`start_background_process_with_exe`]) and the
//!   bootstrap shipping that follows a validated handshake.
//! - [`mod@handshake`] — the build-id handshake both sides exchange
//!   ([`send_handshake`] on the daemon side, validation on the parent side).
//! - [`mod@inherited`] — the daemon child's one-time claim of the pipe fds it
//!   inherited across `execve` ([`rpc_server_from_inherited_fds`]).
//!
//! The fd numbers and environment marker shared across those modules live here.

mod handshake;
mod inherited;
mod process;

pub use handshake::send_handshake;
pub use inherited::rpc_server_from_inherited_fds;
pub(crate) use process::spawn_daemon_process;
pub use process::start_background_process_with_exe;

/// Fd numbers the fork+exec child receives its inherited pipe ends on.
/// Matches `sd_listen_fds(3)`-style convention (parent-provided fds start at 3).
const CHILD_REQUEST_RECV_FD: i32 = 3;
const CHILD_RESPONSE_SEND_FD: i32 = 4;

/// Environment marker identifying a re-exec'd binary as the daemon child.
/// An env var rather than an argv flag so applications aren't forced onto
/// any particular argument parser (the child's argv stays `[argv0]`). Set
/// child-only via `Command::env` during the spawn; the child removes it
/// again before entering the app's daemon entry point so its own children
/// aren't misdetected.
pub(crate) const DAEMON_CHILD_ENV_VAR: &str = "DAEMONIZABLE_DAEMON_CHILD";

/// The exact value `spawn_daemon_process` sets [`DAEMON_CHILD_ENV_VAR`] to.
/// Dispatch matches this value exactly; anything else is not a daemon child.
pub(crate) const DAEMON_CHILD_ENV_VALUE: &str = "1";

/// How long the daemon child waits for the parent's bootstrap payload after
/// sending its build-id handshake, and how long the parent waits for the
/// child's ack after shipping the payload. Sub-millisecond on any healthy
/// system (each side only serializes/acks a small message); generous bound
/// so a slow CI doesn't flake.
pub(crate) const BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
