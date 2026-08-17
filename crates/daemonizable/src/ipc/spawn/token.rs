//! In-band stage-identity tokens on the channel fd.
//!
//! Stage identity rides the head of [`DAEMON_CHANNEL_FD`] (see [`TOKEN_MAGIC`]'s
//! doc for the protocol and threat model). This module owns the parent's token
//! bytes, the dispatch-time probe (`recv(MSG_PEEK|MSG_DONTWAIT)` + a pure
//! classifier) and the token consume. The stage-2 peer-credential check that
//! authenticates a genuine channel lives in its own module,
//! [`mod@super::peercred`].
//!
//! The tokens and the probe are part of the daemonization protocol; the
//! public step-by-step reference is [`crate::protocol`] — keep that page in
//! sync when changing behavior here.

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, recv};

use super::{DAEMON_CHANNEL_FD, TOKEN_LEN, TOKEN_MAGIC, TOKEN_STAGE1, TOKEN_STAGE2};

/// Which arm dispatch on the channel fd selects.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum StageDispatch {
    /// Not a framework channel (or no token queued) — run the app's foreground.
    Foreground,
    /// The channel head is `TOKEN_MAGIC ‖ TOKEN_STAGE1`.
    DaemonStage1,
    /// The channel head is `TOKEN_MAGIC ‖ TOKEN_STAGE2`.
    DaemonStage2,
}

/// Pure classifier for a `MSG_PEEK` result on the channel fd: given what
/// `recv(MSG_PEEK|MSG_DONTWAIT)` returned — either the peeked bytes or the
/// errno — decide which arm to take. **Never consumes anything**, so any
/// outcome but an exact token match leaves the fd untouched.
///
/// The mapping is a catch-all, not an errno allowlist: `EAGAIN`/`EWOULDBLOCK`
/// (connected socket, nothing queued), `EINVAL` (Linux `AF_UNIX` listening
/// socket), `ENOTCONN` (macOS/BSD listening socket), `EBADF` (closed fd),
/// `ENOTSOCK` (a FIFO / regular file / tty), `ECONNRESET`, and every other
/// errno all mean "not a token to route on" → [`Foreground`](StageDispatch::Foreground).
/// A `recv` of `0` (peer closed, nothing queued) and any short read
/// (`< TOKEN_LEN` bytes, so not a full token yet) do too.
fn classify(peeked: Result<&[u8], Errno>) -> StageDispatch {
    let Ok(bytes) = peeked else {
        return StageDispatch::Foreground;
    };
    if bytes.len() < TOKEN_LEN || bytes[..TOKEN_MAGIC.len()] != TOKEN_MAGIC {
        return StageDispatch::Foreground;
    }
    match bytes[TOKEN_MAGIC.len()] {
        TOKEN_STAGE1 => StageDispatch::DaemonStage1,
        TOKEN_STAGE2 => StageDispatch::DaemonStage2,
        // A future or garbage token: consume nothing, the boring safe choice.
        _ => StageDispatch::Foreground,
    }
}

/// Non-consuming peek of up to `TOKEN_LEN` bytes at the head of the channel fd.
/// Runs in EVERY `run()` invocation — including plain foreground and any process
/// that merely inherited a stranger on fd 3 — so it must not disturb the fd's
/// data or block: `MSG_PEEK` never removes queued *bytes*, and `MSG_DONTWAIT`
/// guarantees it can't block. One scoped caveat, part of the reserved-fd-3
/// contract: like any `recv`, a *failing* call consumes a socket's one-shot
/// pending asynchronous error (`sk_err` — e.g. an ICMP-delivered
/// `ECONNREFUSED` on a stranger's connected UDP socket); `MSG_PEEK` does not
/// prevent error consumption, so a stranger socket's queued error can be eaten
/// even though its data never is. Applications honoring the fd-3 reservation
/// are unaffected.
///
/// Uses the bare-`RawFd` `nix::sys::socket::recv` (a safe fn — no fd ownership,
/// no `BorrowedFd`): a closed or non-socket fd 3 returns an errno the classifier
/// folds into `Foreground`, never UB.
fn peek_token(buf: &mut [u8; TOKEN_LEN]) -> Result<&[u8], Errno> {
    loop {
        match recv(
            DAEMON_CHANNEL_FD,
            buf,
            MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(n) => return Ok(&buf[..n]),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// The shared non-consuming probe: peek up to [`TOKEN_LEN`] bytes at the head
/// of fd 3 and classify them. Both dispatch and stage 1's stage-2-token
/// re-check route through this, so the two probes can never diverge; the
/// scratch buffer `peek_token` needs is plumbing neither caller should own.
fn peek_and_classify() -> StageDispatch {
    let mut buf = [0u8; TOKEN_LEN];
    classify(peek_token(&mut buf))
}

/// Dispatch-time channel probe: peek the head of fd 3, classify it, and on a
/// stage match CONSUME exactly [`TOKEN_LEN`] bytes so the next reader (stage 2's
/// own probe, or the framed RPC) starts clean. On no match, consumes nothing.
pub(crate) fn dispatch_from_channel() -> StageDispatch {
    let decision = peek_and_classify();
    if matches!(
        decision,
        StageDispatch::DaemonStage1 | StageDispatch::DaemonStage2
    ) {
        consume_token();
    }
    decision
}

/// Consume exactly [`TOKEN_LEN`] bytes from fd 3 (the token a prior peek
/// matched). Non-blocking (`MSG_DONTWAIT`) with an `EINTR` retry; a partial read
/// loops until the full token is gone. Called only after a peek confirmed a full
/// token is queued and while this process is the sole reader, so the loop
/// terminates.
fn consume_token() {
    let mut consumed = 0;
    let mut scratch = [0u8; TOKEN_LEN];
    while consumed < TOKEN_LEN {
        match recv(
            DAEMON_CHANNEL_FD,
            &mut scratch[consumed..],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => return, // peer closed mid-token; shouldn't happen post-peek
            Ok(n) => consumed += n,
            Err(Errno::EINTR) => continue,
            // EAGAIN can't occur (the peek saw the bytes and we're the sole
            // reader); anything else is a channel the stage will fail on anyway.
            Err(_) => return,
        }
    }
}

/// Non-consuming check that the head of fd 3 is `TOKEN_MAGIC ‖ TOKEN_STAGE2`.
/// Stage 1 calls this AFTER dispatch consumed token 1, to prove the parent
/// queued token 2 as well — a crafted socket carrying only token 1 is rejected
/// here (in stage 1, before `setsid`), instead of the stage-2 image later
/// finding no token and silently running foreground code in a detached process.
pub(crate) fn channel_has_stage2_token() -> bool {
    peek_and_classify() == StageDispatch::DaemonStage2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn magic_with(stage: u8) -> Vec<u8> {
        let mut v = TOKEN_MAGIC.to_vec();
        v.push(stage);
        v
    }

    #[test]
    fn classify_decision_table() {
        // Every errno → Foreground: this is a catch-all, not an allowlist.
        for errno in [
            Errno::EAGAIN,
            Errno::EINVAL,   // Linux AF_UNIX listening socket
            Errno::ENOTCONN, // macOS/BSD listening socket
            Errno::EBADF,    // closed fd
            Errno::ENOTSOCK, // FIFO / file / tty
            Errno::ECONNRESET,
            Errno::EIO, // any other errno
        ] {
            assert_eq!(
                classify(Err(errno)),
                StageDispatch::Foreground,
                "errno {errno:?} must map to Foreground"
            );
        }

        // Peer closed / nothing queued, and short reads → Foreground.
        assert_eq!(classify(Ok(&[])), StageDispatch::Foreground);
        assert_eq!(classify(Ok(&[TOKEN_MAGIC[0]])), StageDispatch::Foreground);
        assert_eq!(
            classify(Ok(&TOKEN_MAGIC[..])), // 32 bytes: magic but no stage tag
            StageDispatch::Foreground
        );

        // Wrong magic of full length → Foreground.
        let mut wrong = magic_with(TOKEN_STAGE1);
        wrong[0] ^= 0xff;
        assert_eq!(classify(Ok(&wrong)), StageDispatch::Foreground);

        // Exact tokens route to their stages.
        assert_eq!(
            classify(Ok(&magic_with(TOKEN_STAGE1))),
            StageDispatch::DaemonStage1
        );
        assert_eq!(
            classify(Ok(&magic_with(TOKEN_STAGE2))),
            StageDispatch::DaemonStage2
        );

        // Right magic, unknown stage tag → Foreground.
        for tag in [0u8, 3, 255] {
            assert_eq!(
                classify(Ok(&magic_with(tag))),
                StageDispatch::Foreground,
                "unknown stage tag {tag} must map to Foreground"
            );
        }

        // A classifier fed a longer slice must key only on the first token.
        let mut trailing = magic_with(TOKEN_STAGE1);
        trailing.extend_from_slice(b"more data");
        assert_eq!(classify(Ok(&trailing)), StageDispatch::DaemonStage1);
    }
}
