//! The daemon child's one-time claim of the single IPC channel fd it inherited
//! from its parent across `execve`, rebuilt into a typed [`RpcServer`].

use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Serialize, de::DeserializeOwned};

use super::DAEMON_CHANNEL_FD;
use crate::ipc::RpcServer;
use crate::ipc::cloexec::set_cloexec;
use crate::ipc::error::InheritedFdsError;

/// Guards the process-wide claim on the inherited daemon channel fd (3).
///
/// [`rpc_server_from_inherited_fds`] adopts that fixed fd number into an owning
/// `OwnedFd` (the one raw-fd `unsafe`). A second call would hand out a *second*
/// owner of the same fd; once the first `RpcServer` drops and closes it, the
/// kernel can reassign fd 3 to an unrelated file, and the second server would
/// then read/write/close the wrong resource. The fd is a process singleton
/// (like stdio), so it can be claimed at most once — this flag turns a double
/// claim into a clean error instead of undefined behavior.
static DAEMON_FDS_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Helper for the daemon side of [`start_background_process_with_exe`]: parse
/// the conventional fd 3 (`DAEMON_CHANNEL_FD`) into an [`RpcServer`]. Aborts with
/// a human-readable message if the fd is not a socket — almost always the result
/// of a curious user invoking the daemon entry point manually from a shell.
///
/// Must be called at most once per process (it takes ownership of fd 3); a
/// second call returns an [`InheritedFdsError::AlreadyClaimed`] error rather
/// than aliasing the descriptor.
///
/// The claim guard is deliberately one-way: it is set before validation and
/// never rolls back, so a first call that fails validation
/// ([`InheritedFdsError::NotOpen`] / [`InheritedFdsError::NotASocket`] /
/// [`InheritedFdsError::SetCloexec`] / [`InheritedFdsError::CloneFd`])
/// permanently poisons the process — every later call reports `AlreadyClaimed`
/// even though no fd was adopted. That is intentional, not an oversight: a
/// process whose fd 3 failed validation once has no legitimate second chance at
/// it, and partial side effects of the failed attempt (e.g. `FD_CLOEXEC` already
/// restored) would make a retry unreliable anyway.
///
/// Also re-sets `FD_CLOEXEC` on the fd: the spawn's `dup2` cleared it so the fd
/// would survive `execve`, and without restoring it the daemon's own
/// subprocesses would inherit the channel end and hold the parent's EOF open
/// past the daemon's exit. If restoring the flag fails, the fd has already been
/// adopted at that point and is closed on the error return (the `NotOpen` /
/// `NotASocket` validation failures happen before adoption and leave the fd
/// untouched).
///
/// Used by the test helper binary. Production applications go through the
/// framework's daemon dispatch in [`crate::run`], which additionally sends
/// the build-id handshake before handing the server to the app.
///
/// # Safety
/// Fd `DAEMON_CHANNEL_FD` (3) must be the daemon's *exclusively owned* inherited
/// channel socket: call this only in a process the framework re-exec'd as a
/// daemon child, where `spawn_daemon_process` / [`start_background_process_with_exe`]
/// mapped the parent's socketpair end onto exactly that fd number across
/// `execve`. This function takes ownership of the fd — wrapping it in an
/// `OwnedFd` that closes it on drop — so if any other live `OwnedFd`/`File` in
/// the calling process already owns fd 3 (e.g. an unrelated program that
/// happened to open a socket there and called this directly), the second owner
/// minted here causes a double-close / use-after-free once both drop. The
/// `fstat` open+socket probe (`validate_inherited_fds` — crate-private, so not
/// linkable from these public docs) and the process-wide `DAEMON_FDS_CLAIMED`
/// guard are best-effort validation — they reject the common "invoked by hand"
/// mistake and any second claim — but they cannot prove exclusive ownership,
/// which is why that obligation falls on the caller.
///
/// Two clarifications. First, "exclusively owned" spans the whole call:
/// nothing else in the process may close or reuse fd 3 while it runs (starting
/// from a raw fd number leaves an unavoidable validate→adopt window). Second,
/// if the process-wide claim guard is already set, the call returns
/// [`InheritedFdsError::AlreadyClaimed`] *before* touching any file descriptor —
/// such a call has no safety preconditions at all (the in-module unit test
/// relies on exactly this guarantee).
///
/// [`start_background_process_with_exe`]: super::start_background_process_with_exe
pub unsafe fn rpc_server_from_inherited_fds<Request, Response>()
-> Result<RpcServer<Request, Response>, InheritedFdsError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    if DAEMON_FDS_CLAIMED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(InheritedFdsError::AlreadyClaimed {
            channel_fd: DAEMON_CHANNEL_FD,
        });
    }
    validate_inherited_fds()?;
    // The fd validated as an open socket above; adopt ownership now. This is the
    // one irreducible `unsafe` in the claim — turning the inherited raw fd number
    // into an owning `OwnedFd` — and the reason this function is `unsafe`.
    //
    // SAFETY: by this function's `# Safety` contract the caller guarantees fd 3
    // is the daemon's exclusively-owned inherited channel end; `DAEMON_FDS_CLAIMED`
    // made this the sole claim in the process, and it was just `fstat`ed as an
    // open socket, so the `OwnedFd` (which closes on drop) is the one and only
    // owner. The same exclusive-ownership contract rules out a concurrent
    // close/reuse between the check and this adoption (there is an unavoidable
    // check→adopt window when starting from a raw fd number — it is part of why
    // this fn is `unsafe`).
    let channel = unsafe { OwnedFd::from_raw_fd(DAEMON_CHANNEL_FD) };
    // Restore FD_CLOEXEC. The parent set it at creation, but the `dup2` onto
    // fd 3 during the spawn necessarily cleared it so the fd would survive the
    // `execve` into this daemon. Nothing re-sets it, so without this the fd
    // stays inheritable for the daemon's whole lifetime: every subprocess the
    // daemon later spawns (`std::process::Command` inherits non-CLOEXEC fds
    // across its own fork+exec) gets a duplicate of the channel end, and since
    // EOF only fires once ALL copies of an end close, such a subprocess
    // outliving the daemon suppresses the EOF the parent waits on — silently
    // defeating the liveness of `recv_response_blocking`.
    //
    // Runs on the adopted `OwnedFd` — `as_fd()` needs no raw-fd `unsafe`, and
    // there is no fstat→borrow window to reason about. A failure here closes the
    // fd on the error return; acceptable, since the claim has begun and this
    // function's contract says it takes ownership of it. Done BEFORE building the
    // server, so the internal `dup` (via `F_DUPFD_CLOEXEC`, itself CLOEXEC)
    // clones an already-CLOEXEC fd — both halves of the channel end up
    // close-on-exec.
    set_cloexec(channel.as_fd()).map_err(|(operation, source)| InheritedFdsError::SetCloexec {
        fd: DAEMON_CHANNEL_FD,
        operation,
        source,
    })?;
    // Build the server, which `dup`s the one socket into its send/recv halves.
    // A `dup` failure closes `channel` on the error return (`CloneFd`).
    RpcServer::from_owned_fd(channel)
}

/// Probe fd `DAEMON_CHANNEL_FD` (3) as an open socket **without taking any
/// ownership**: bare `fstat` on the raw number — no fd wrapper, no claim, no flag
/// changes. Because it owns nothing and changes nothing, it is safe to call any
/// number of times, before or instead of the owning claim — which is what lets
/// the daemon stages validate independently on both sides of their exec boundary
/// (a pre-fork rejection with a clean error in stage 1, and the mandatory
/// validation step inside [`rpc_server_from_inherited_fds`]'s claim).
pub(crate) fn validate_inherited_fds() -> Result<(), InheritedFdsError> {
    let fd = DAEMON_CHANNEL_FD;
    // Probe the raw fd number with a bare `fstat` BEFORE building any fd
    // wrapper. A hand-invoked daemon may have closed fd 3, and a `BorrowedFd` /
    // `OwnedFd` must point at an *open* fd — whereas `libc::fstat` on a bare
    // descriptor is defined for any int (EBADF for a closed one), so it can
    // reject a bad fd without an I/O-safety-contract violation.
    //
    // SAFETY: `std::mem::zeroed()` yields a valid `libc::stat` — a `repr(C)`
    // struct of integer fields with no niche/validity constraints — used only as
    // the out-buffer that `fstat` fills before any field is read.
    let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` writes through `&mut statbuf`, a live, correctly aligned,
    // writable `libc::stat`. `fd` is a bare int — a closed/invalid descriptor
    // yields EBADF (handled below as `NotOpen`), never UB — and `fstat` neither
    // takes ownership of nor closes it.
    if unsafe { libc::fstat(fd, &mut statbuf) } < 0 {
        return Err(InheritedFdsError::NotOpen {
            fd,
            source: std::io::Error::last_os_error(),
        });
    }
    if statbuf.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(InheritedFdsError::NotASocket {
            fd,
            st_mode: statbuf.st_mode,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_server_from_inherited_fds_rejects_a_second_claim() {
        // The daemon channel fd (3) is a process singleton; claiming it twice
        // would alias owning `OwnedFd`s and risk a use-after-free. Simulate a
        // prior claim by setting the flag directly — this deterministically
        // exercises the guard without depending on what fd 3 happens to be in
        // the test process, and without taking ownership of it.
        //
        // This swap→call→restore sequence is not atomic as a whole, so it is
        // only sound while this test is the binary's SOLE claimant: a
        // concurrent test that genuinely claimed fd 3 could observe a spurious
        // `AlreadyClaimed`, or have its claim's flag clobbered back to `false`
        // by the restore below — re-arming a second, aliasing claim. The assert
        // enforces that invariant: if it ever fires, some other test in this
        // binary now touches the claim guard, and this test needs a different
        // design (e.g. a spawned-process test).
        let previously = DAEMON_FDS_CLAIMED.swap(true, Ordering::SeqCst);
        assert!(
            !previously,
            "DAEMON_FDS_CLAIMED was already set: another test in this binary \
             claims the daemon channel fd, which this test's flag swap/restore \
             cannot coexist with"
        );
        // SAFETY: `rpc_server_from_inherited_fds` is `unsafe` because it would
        // take ownership of fd 3. Here `DAEMON_FDS_CLAIMED` is pre-set to `true`,
        // so the call short-circuits with `AlreadyClaimed` *before* reaching the
        // fd-claiming code — it never wraps a descriptor, so the
        // exclusive-ownership precondition is vacuously satisfied.
        let result = unsafe { rpc_server_from_inherited_fds::<(), ()>() };
        // Restore the flag (asserted `false` above) so a later claim in this
        // process — none exists today — isn't spuriously rejected.
        DAEMON_FDS_CLAIMED.store(false, Ordering::SeqCst);

        let err = result
            .err()
            .expect("a second claim of the daemon channel fd must be rejected");
        assert!(
            matches!(err, InheritedFdsError::AlreadyClaimed { .. }),
            "expected AlreadyClaimed, got: {err:?}"
        );
    }
}
