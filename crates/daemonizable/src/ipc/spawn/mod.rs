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
//! The channel fd number and the in-band stage-identity tokens shared across
//! those modules live here.

mod handshake;
mod inherited;
mod process;
mod token;

pub use handshake::send_handshake;
pub use inherited::rpc_server_from_inherited_fds;
pub(crate) use process::{daemon_exe_path, spawn_daemon_process};
pub(crate) use token::{
    StageDispatch, channel_has_stage2_token, dispatch_from_channel, verify_channel_peer_uid,
};
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

/// Length of a stage-identity token: the 32-byte [`TOKEN_MAGIC`] prefix plus a
/// one-byte stage tag.
pub(crate) const TOKEN_LEN: usize = TOKEN_MAGIC.len() + 1;

/// Stage-identity tag bytes appended to [`TOKEN_MAGIC`] to form the two tokens.
pub(crate) const TOKEN_STAGE1: u8 = 1;
pub(crate) const TOKEN_STAGE2: u8 = 2;

/// Fixed 32-byte magic prefixing each in-band stage-identity token.
///
/// # How stage identity is carried
///
/// The parent pre-queues two tokens — `TOKEN_MAGIC ‖ TOKEN_STAGE1` then
/// `TOKEN_MAGIC ‖ TOKEN_STAGE2` — into the channel socket ([`DAEMON_CHANNEL_FD`])
/// before spawning. Dispatch in [`crate::run`] peeks the head of that fd with
/// `recv(MSG_PEEK|MSG_DONTWAIT)`: a leading `TOKEN_MAGIC ‖ TOKEN_STAGE1`
/// routes to stage 1 (consuming those [`TOKEN_LEN`] bytes), a leading
/// `TOKEN_MAGIC ‖ TOKEN_STAGE2` routes to stage 2, and everything else —
/// closed fd, non-socket (a make jobserver FIFO), an empty or foreign socket,
/// wrong bytes — falls through to the foreground arm having consumed nothing.
/// Stage 1 and stage 2 are separate processes that share the inherited fd, so
/// they consume their tokens in order: stage 1's dispatch eats token 1, stage
/// 2's (in the re-exec'd image) eats token 2, then the framed RPC begins.
///
/// Why in-band on the channel fd rather than argv or the environment: the
/// daemon's argv stays empty (`run_daemon` sees no injected argument) and its
/// environment is byte-identical to the foreground's, and there is nothing to
/// scrub before the daemon spawns children of its own — the tokens live only
/// in the socket buffer and are consumed before any of them.
///
/// # Threat model — an accident authenticator, NOT a forgery defense
///
/// `TOKEN_MAGIC` is a FIXED, PUBLIC constant (as public as the old argv
/// sentinel strings were). Its sole job is to make a *coincidental* match with
/// unrelated inherited data astronomically unlikely (2⁻²⁵⁶), so a foreign fd
/// on number 3 — a systemd socket-activation socket, a make jobserver FIFO —
/// is not mistaken for a framework channel. It does NOT stop a deliberate
/// forger: anyone who can plant a socket on fd 3 can also write these public
/// bytes into it.
///
/// The real defense against a forged channel is downstream, in
/// [`run_as_daemon_stage2`](crate::run) (all applied *before* any application
/// code runs):
/// - a **peer-credential check** (`SO_PEERCRED` / `getpeereid`): the fd-3
///   peer's effective uid must equal ours, which rejects the load-bearing case —
///   a lower-privileged principal trying to drive a setuid/file-cap daemon
///   image into `run_daemon` over an attacker-controlled channel;
/// - the **session/group-leader guard**: a genuine daemon is a non-leader
///   grandchild (`sid == pgid == stage 1's pid ≠ own pid`), so a hand-run from
///   a shell or a setsid-wrapped launcher is refused.
///
/// A same-uid local process that plants a crafted channel can still reach
/// `run_daemon` (it could equally `ptrace` us), so — exactly as with the old
/// argv sentinel — applications must not treat `run_daemon`'s RPC input as
/// authenticated-by-provenance. See `run`'s docs for the `AT_SECURE` note.
pub(crate) const TOKEN_MAGIC: [u8; 32] = [
    0x54, 0x97, 0x91, 0xf3, 0xcc, 0x75, 0xa4, 0x5c, 0x7c, 0x42, 0x9c, 0xbd, 0x37, 0x14, 0x89, 0xb1,
    0x67, 0x7b, 0x6b, 0xf3, 0xf3, 0x38, 0x49, 0x44, 0x05, 0x0a, 0x7f, 0x6d, 0xfa, 0x9c, 0xbe, 0x94,
];

/// Build the `TOKEN_LEN`-byte stage token `TOKEN_MAGIC ‖ stage`.
pub(crate) fn stage_token(stage: u8) -> [u8; TOKEN_LEN] {
    let mut token = [0u8; TOKEN_LEN];
    token[..TOKEN_MAGIC.len()].copy_from_slice(&TOKEN_MAGIC);
    token[TOKEN_MAGIC.len()] = stage;
    token
}
