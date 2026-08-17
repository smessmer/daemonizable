//! The stage-2 peer-credential check that authenticates a genuine channel:
//! `SO_PEERCRED` (Linux/Android) / `getpeereid` (BSD/macOS) against our own
//! effective uid/gid.
//!
//! This is deliberately a separate module from the stage-token machinery in
//! [`mod@super::token`]: the two share nothing but the channel fd number. The
//! tokens are a PUBLIC accident-authenticator (routing, not security — see
//! [`TOKEN_MAGIC`](super::TOKEN_MAGIC)'s threat model); the credential check
//! here is the unforgeable barrier that backs it.
//!
//! The check is part of the daemonization protocol; the public step-by-step
//! reference is [`crate::protocol`] — keep that page in sync when changing
//! behavior here.

use std::os::fd::BorrowedFd;

use nix::errno::Errno;

use super::DAEMON_CHANNEL_FD;

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
/// our own effective uid AND gid. See [`TOKEN_MAGIC`](super::TOKEN_MAGIC)'s
/// threat model — the token is a public accident-authenticator, so this
/// credential check (unforgeable by the peer, captured by the kernel at
/// socketpair/connect time) is what stops a lower-privileged principal from
/// driving a daemon image that gained privilege **by changing uid/gid** (a
/// setuid- or setgid-to-a-different-id binary) into `run_daemon` over a crafted
/// channel.
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
/// rejection via [`PeerCredError::Lookup`].) The [`TOKEN_MAGIC`](super::TOKEN_MAGIC)
/// threat-model doc names socket activation only as an *accidental*-collision
/// concern; this is the *deliberate* case, and this check is what handles it.
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
/// - **User-namespace credential munging (Linux).** The reserved `(uid_t)-1`
///   above covers only a peer with *no* local credentials (a remote network
///   client). A local peer whose credentials exist but are *unmappable into the
///   daemon's user namespace* is reported differently: the kernel munges them to
///   the **overflow** ids (`/proc/sys/kernel/overflowuid`/`overflowgid`, default
///   `65534`, i.e. `nobody`) — and unlike `(uid_t)-1`, the overflow uid IS an id
///   a daemon can legitimately run as. A daemon whose own euid/egid equal the
///   overflow ids therefore cannot distinguish such a cross-namespace peer from
///   a same-principal one; daemons that may receive handed-in sockets should not
///   run as the overflow uid/gid. (Only reachable when the daemon itself runs
///   inside a non-init user namespace with a partial id map — in the init
///   namespace every kernel id is mappable and the munging never happens.)
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

    #[test]
    fn creds_match_accepts_equal_and_rejects_any_difference() {
        // The genuine flow: the peer is our own parent running the same image.
        assert!(creds_match((1000, 1000), (1000, 1000)).is_ok());
        assert!(creds_match((0, 0), (0, 0)).is_ok());

        // The live `verify_channel_peer_creds` can't reach this arm under a
        // same-uid test harness, so this pure check is the reject-path coverage.
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

        // The setgid-to-a-different-gid case the gid half exists to catch.
        let gid_only = creds_match((1000, 1001), (1000, 1000));
        assert!(matches!(
            gid_only,
            Err(PeerCredError::CredMismatch {
                peer_gid: 1001,
                our_gid: 1000,
                ..
            })
        ));

        assert!(matches!(
            creds_match((0, 0), (1000, 1000)),
            Err(PeerCredError::CredMismatch { .. })
        ));
    }
}
