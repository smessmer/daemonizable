//! Fork+exec daemon spawn and the pieces of the parent↔daemon startup
//! protocol.
//!
//! The moving parts are split by responsibility:
//! - [`mod@process`] — the fork+exec machinery on the parent side
//!   ([`spawn_daemon_process`], plus the `testutils`-gated
//!   `start_background_process_with_exe`) and the build-id handshake
//!   validation that completes a spawn.
//! - [`mod@handshake`] — the build-id handshake both sides exchange
//!   ([`send_handshake`] on the daemon side, validation on the parent side).
//! - [`mod@inherited`] — the daemon child's one-time claim of the channel fd it
//!   inherited across `execve` ([`rpc_server_from_inherited_fds`]).
//!
//! The channel fd number and stage-sentinel argv tokens shared across those
//! modules live here.

mod handshake;
mod inherited;
mod process;

pub use handshake::send_handshake;
pub use inherited::rpc_server_from_inherited_fds;
pub(crate) use inherited::validate_inherited_fds;
pub(crate) use process::{daemon_exe_path, spawn_daemon_process};
// Test-only spawn helpers: gated so they don't ship in the default published
// surface (their crate-root re-exports in `lib.rs` are `testutils`-gated too).
#[cfg(any(test, feature = "testutils"))]
pub use process::{spawn_daemon_process_with_exe, start_background_process_with_exe};

/// Fd number the fork+exec child receives its inherited full-duplex channel on.
/// Matches `sd_listen_fds(3)`-style convention (parent-provided fds start at 3).
/// Exactly ONE fd crosses the exec boundary now: the channel is a single
/// full-duplex `AF_UNIX` socket rather than a pair of one-way pipes on 3+4. (The
/// daemon's `RpcServer` dups this fd at runtime — via `endpoint_from_stream` — so
/// it can read and write independently; that runtime clone lands on whatever fd
/// the OS assigns, typically 4, and is CLOEXEC so it never leaks to children.)
const DAEMON_CHANNEL_FD: i32 = 3;

/// The argv[1] sentinel identifying a re-exec'd binary as stage 1 of the
/// daemon-child startup (set by the parent's spawn as the child's only
/// argument). See [`DAEMON_STAGE2_ARGV`] for why stage identity rides argv
/// rather than the environment.
pub(crate) const DAEMON_STAGE1_ARGV: &str = "__daemonizable-stage1";

/// The argv[1] sentinel identifying a re-exec'd binary as stage 2 — the final
/// daemon image (set by stage 1's re-exec as the image's only argument).
///
/// Stage identity rides argv, not the environment, for two structural
/// reasons. First, argv is not inherited by child processes: nothing ever
/// needs scrubbing before the daemon spawns children of its own, which is
/// what lets this crate avoid `env::remove_var` (and its no-concurrent-
/// env-readers contract) entirely. Second, with no environment marker to
/// filter out, stage 1 can re-exec with the inherited environment untouched
/// (`execv`), so the daemon's environment is byte-identical to the
/// foreground's and stage 1 never has to walk `environ` — which would race a
/// C-level `setenv` from any constructor-spawned thread.
///
/// The names are namespaced/ugly on purpose. Dispatch in [`crate::run`]
/// checks argv[1] against them before any app code runs, so an application
/// *flag* can never collide; these are, however, reserved tokens — a process
/// whose first argument is exactly one of them (hand-invocation, or argument
/// passthrough of hostile data) is routed to the corresponding daemon stage,
/// where the fd validation rejects anything the framework didn't plumb (see
/// the stage functions in `app::daemon_child` for what a hand-run observes).
pub(crate) const DAEMON_STAGE2_ARGV: &str = "__daemonizable-daemon";
