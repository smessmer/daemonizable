//! In-band stage-identity tokens on the channel fd, and the peer-credential
//! check that authenticates a genuine channel.
//!
//! Stage identity rides the head of [`DAEMON_CHANNEL_FD`] (see [`TOKEN_MAGIC`]'s
//! doc for the protocol and threat model). This module owns the parent's token
//! bytes, the dispatch-time probe (`recv(MSG_PEEK|MSG_DONTWAIT)` + a pure
//! classifier), the token consume, and the stage-2 `SO_PEERCRED`/`getpeereid`
//! provenance check.

use std::os::fd::BorrowedFd;

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
        // Any errno at all → not a routable channel.
        return StageDispatch::Foreground;
    };
    // Need a whole token; a short read (including 0 == peer closed) is not one.
    if bytes.len() < TOKEN_LEN || bytes[..TOKEN_MAGIC.len()] != TOKEN_MAGIC {
        return StageDispatch::Foreground;
    }
    match bytes[TOKEN_MAGIC.len()] {
        TOKEN_STAGE1 => StageDispatch::DaemonStage1,
        TOKEN_STAGE2 => StageDispatch::DaemonStage2,
        // Right magic, unknown stage tag: a future/garbage token → Foreground,
        // consume nothing (the boring, safe choice).
        _ => StageDispatch::Foreground,
    }
}

/// Non-consuming peek of up to `TOKEN_LEN` bytes at the head of the channel fd.
/// Runs in EVERY `run()` invocation — including plain foreground and any process
/// that merely inherited a stranger on fd 3 — so it must be side-effect-free:
/// `MSG_PEEK` never removes bytes, and `MSG_DONTWAIT` guarantees it can't block.
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

/// Dispatch-time channel probe: peek the head of fd 3, classify it, and on a
/// stage match CONSUME exactly [`TOKEN_LEN`] bytes so the next reader (stage 2's
/// own probe, or the framed RPC) starts clean. On no match, consumes nothing.
pub(crate) fn dispatch_from_channel() -> StageDispatch {
    let mut buf = [0u8; TOKEN_LEN];
    let decision = classify(peek_token(&mut buf));
    if matches!(
        decision,
        StageDispatch::DaemonStage1 | StageDispatch::DaemonStage2
    ) {
        // The peek proved TOKEN_LEN bytes are queued and we are the only reader
        // of fd 3 at this point (dispatch runs before any app code), so this
        // non-blocking consume removes exactly the token.
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
            Ok(0) => return, // peer closed mid-token (shouldn't happen post-peek); stop
            Ok(n) => consumed += n,
            Err(Errno::EINTR) => continue,
            // EAGAIN can't occur (peek saw the bytes, we're the sole reader); any
            // other error means a broken channel the stage will fail on anyway.
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
    let mut buf = [0u8; TOKEN_LEN];
    classify(peek_token(&mut buf)) == StageDispatch::DaemonStage2
}

/// Error establishing the channel peer's identity, or a peer whose effective
/// credentials don't match ours.
#[derive(Debug)]
pub(crate) enum PeerCredError {
    /// Reading the peer credentials failed (`getsockopt`/`getpeereid` errno).
    Lookup(Errno),
    /// The peer's effective uid or gid differs from ours — a cross-privilege
    /// forgery.
    CredMismatch {
        peer_uid: u32,
        our_uid: u32,
        peer_gid: u32,
        our_gid: u32,
    },
}

impl std::fmt::Display for PeerCredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerCredError::Lookup(e) => {
                write!(f, "could not read the channel peer's credentials: {e}")
            }
            PeerCredError::CredMismatch {
                peer_uid,
                our_uid,
                peer_gid,
                our_gid,
            } => write!(
                f,
                "channel peer credentials (uid {peer_uid}, gid {peer_gid}) do not match ours \
                 (uid {our_uid}, gid {our_gid}); refusing to serve a channel from a different \
                 principal"
            ),
        }
    }
}

/// Authenticate the channel: the process on the other end of fd 3 must run with
/// our own effective uid AND gid. See [`TOKEN_MAGIC`]'s threat model — the token
/// is a public accident-authenticator, so this credential check (unforgeable by
/// the peer, captured by the kernel at socketpair/connect time) is what stops a
/// lower-privileged principal from driving a daemon image that gained privilege
/// **by changing uid/gid** (a setuid- or setgid-to-a-different-id binary) into
/// `run_daemon` over a crafted channel.
///
/// Compares EFFECTIVE ids (`geteuid`/`getegid`), because that is what
/// `SO_PEERCRED` (Linux fills `ucred` from the peer's `cred->euid`/`egid`) and
/// `getpeereid` (POSIX: effective ids) report. In the genuine flow the peer is
/// our own parent running the SAME binary, so its effective ids equal ours
/// whether or not the binary is setuid/setgid — the daemon re-execs the same
/// image so the id change is re-applied. Comparing REAL ids instead would
/// wrongly reject a legitimate setuid-root foreground (euid 0, real uid =
/// invoking user).
///
/// # The socket-activation / handed-in-connection case
///
/// This check is also what keeps the design safe under **`inetd`-style socket
/// activation** (systemd `Accept=yes`, classic inetd), where the service is
/// exec'd with an already-*connected* client socket on fd 3 instead of a
/// framework socketpair. There `fstat` reports a socket and `recv` succeeds (it
/// is not the listening-socket case the classifier folds to foreground via
/// `EINVAL`/`ENOTCONN`), so the classifier will match a token the peer sends —
/// and the token is public, so a client can deliberately send `TOKEN_MAGIC ‖ 1`
/// then `‖ 2`. The peer credential is the barrier a network client cannot cross:
/// for a **remote TCP/IP peer** the kernel has no local process to attribute, so
/// `SO_PEERCRED` reports `uid == gid == (uid_t)-1` (`4294967295`) — a reserved
/// value that is never a real process's euid — and the comparison below rejects
/// it (exit 1, before the claim and before `run_daemon`; the attacker gets the
/// stage-1 `setsid`+fork side effects but no application code and no RPC). A
/// **local** `AF_UNIX` activation peer of a *different* uid/gid is rejected the
/// same way; only a *same-principal* local peer passes, which is the documented
/// ptrace-equivalent limit. (On BSD/macOS `getpeereid` does not yield a matching
/// credential for such a peer either — the lookup fails, giving the same
/// rejection via [`PeerCredError::Lookup`].) The [`TOKEN_MAGIC`] threat-model doc
/// names socket activation only as an *accidental*-collision concern; this is the
/// *deliberate* case, and this check is what handles it.
///
/// # Scope and limits (important)
///
/// - This protects **only** binaries that gain privilege by changing uid or gid.
///   It does **NOT** protect a **file-capabilities** binary (`setcap …+ep`): file
///   caps grant privilege without changing uid/gid, so the daemon runs with the
///   *invoker's* ids and a same-uid/gid attacker's crafted socketpair passes this
///   check. For those deployments — and for any same-principal peer generally —
///   `run_daemon`'s RPC input must be treated as UNtrusted-by-provenance (the
///   same caveat that applies to a same-uid local peer, which could `ptrace` a
///   non-privilege-elevated process anyway). setgid-to-a-different-gid IS caught,
///   by the gid half of this comparison.
/// - **Spawn before dropping privileges.** The peer creds are frozen at
///   socketpair-creation time. If a setuid-root app drops to an unprivileged uid
///   *before* calling `spawn_daemon`, the socket records the dropped uid while
///   the re-exec'd daemon regains euid 0 — this check would then reject the
///   legitimate daemon. Create the daemon while still holding the binary's
///   startup credentials.
/// - The creds report the *creator's* euid/egid; a daemon whose fd 3 was
///   supplied by an unrelated higher-privileged process (e.g. a root helper that
///   hands sockets to unprivileged users) could be spoofed. That is outside the
///   normal spawn model (the framework always creates its own socketpair).
pub(crate) fn verify_channel_peer_creds() -> Result<(), PeerCredError> {
    // SAFETY: fd 3 (`DAEMON_CHANNEL_FD`) is open here — dispatch's peek and token
    // consume just succeeded on it, and nothing has closed it since (the caller
    // only read process ids before this) — so borrowing it for the credential
    // read is I/O-safe. The borrow does not outlive this function and takes no
    // ownership (the fd is adopted later, by the claim).
    let fd = unsafe { BorrowedFd::borrow_raw(DAEMON_CHANNEL_FD) };
    let peer = peer_creds(fd).map_err(PeerCredError::Lookup)?;
    let ours = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    creds_match(peer, ours)
}

/// The (uid, gid) equality decision, split out from the syscall path so it is
/// unit-testable: the full [`verify_channel_peer_creds`] reads the real fd 3 and
/// the process's real euid/egid, so its mismatch arm can only fire when the peer
/// runs as a *different* principal — which a same-uid test harness cannot
/// arrange without a second uid/privilege. This pure comparison lets the reject
/// path (both the uid and gid halves, and the error it builds) be exercised
/// directly.
fn creds_match(peer: (u32, u32), ours: (u32, u32)) -> Result<(), PeerCredError> {
    let (peer_uid, peer_gid) = peer;
    let (our_uid, our_gid) = ours;
    if peer_uid != our_uid || peer_gid != our_gid {
        return Err(PeerCredError::CredMismatch {
            peer_uid,
            our_uid,
            peer_gid,
            our_gid,
        });
    }
    Ok(())
}

/// The effective (uid, gid) of the process connected to the other end of `fd`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_creds(fd: BorrowedFd<'_>) -> Result<(u32, u32), Errno> {
    // Linux/Android: SO_PEERCRED via getsockopt (reports the peer's euid/egid).
    let creds = nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok((creds.uid(), creds.gid()))
}

/// The effective (uid, gid) of the process connected to the other end of `fd`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_creds(fd: BorrowedFd<'_>) -> Result<(u32, u32), Errno> {
    // BSD/macOS: LOCAL_PEERCRED under the hood, via getpeereid (effective ids).
    let (uid, gid) = nix::unistd::getpeereid(fd)?;
    Ok((uid.as_raw(), gid.as_raw()))
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
        // Errors of every stripe → Foreground (catch-all, not an allowlist).
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

        // Peer closed / nothing queued (ret == 0) and short reads → Foreground,
        // no full token yet.
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

        // A valid token followed by trailing bytes still classifies (the peek
        // buffer is TOKEN_LEN, so extra queued bytes aren't even peeked, but a
        // classifier fed a longer slice must key only on the first token).
        let mut trailing = magic_with(TOKEN_STAGE1);
        trailing.extend_from_slice(b"more data");
        assert_eq!(classify(Ok(&trailing)), StageDispatch::DaemonStage1);
    }

    #[test]
    fn creds_match_accepts_equal_and_rejects_any_difference() {
        // Same principal on both ends → accepted (the genuine flow: the peer is
        // our own parent running the same image).
        assert!(creds_match((1000, 1000), (1000, 1000)).is_ok());
        assert!(creds_match((0, 0), (0, 0)).is_ok());

        // A difference in EITHER half is a cross-principal channel and must be
        // refused, with the mismatching values carried through for the message.
        // (The live `verify_channel_peer_creds` can't reach this arm under a
        // same-uid test harness, so this pure check is the reject-path coverage.)
        let uid_only = creds_match((1001, 1000), (1000, 1000));
        assert!(matches!(
            uid_only,
            Err(PeerCredError::CredMismatch {
                peer_uid: 1001,
                our_uid: 1000,
                peer_gid: 1000,
                our_gid: 1000,
            })
        ));

        // gid-only difference (the setgid-to-a-different-gid case the gid half
        // exists to catch) is rejected too.
        let gid_only = creds_match((1000, 1001), (1000, 1000));
        assert!(matches!(
            gid_only,
            Err(PeerCredError::CredMismatch {
                peer_gid: 1001,
                our_gid: 1000,
                ..
            })
        ));

        // Both halves differing is still a single rejection.
        assert!(matches!(
            creds_match((0, 0), (1000, 1000)),
            Err(PeerCredError::CredMismatch { .. })
        ));
    }
}
