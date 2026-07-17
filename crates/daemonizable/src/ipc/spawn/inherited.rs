//! The daemon child's one-time claim of the IPC pipe fds it inherited from its
//! parent across `execve`, rebuilt into a typed [`RpcServer`].

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Serialize, de::DeserializeOwned};

use super::{CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD};
use crate::ipc::RpcServer;
use crate::ipc::cloexec::set_cloexec;
use crate::ipc::error::InheritedFdsError;

/// Guards the process-wide claim on the inherited daemon fds (3 and 4).
///
/// [`rpc_server_from_inherited_fds`] adopts those fixed fd numbers into owning
/// `OwnedFd`s (the one raw-fd `unsafe`). A second call would
/// hand out a *second* owner of the same fds; once the first `RpcServer` drops
/// and closes them, the kernel can reassign 3/4 to unrelated files, and the
/// second server would then read/write/close the wrong resource. The fds are a
/// process singleton (like stdio), so they can be claimed at most once — this
/// flag turns a double claim into a clean error instead of undefined behavior.
static DAEMON_FDS_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Helper for the daemon side of [`start_background_process_with_exe`]: parse
/// the conventional fds 3 and 4 into an [`RpcServer`]. Aborts with a
/// human-readable message if the fds are not pipes — almost always the result
/// of a curious user invoking the daemon entry point manually from a shell.
///
/// Must be called at most once per process (it takes ownership of fds 3/4); a
/// second call returns an [`InheritedFdsError::AlreadyClaimed`] error rather
/// than aliasing the descriptors.
///
/// The claim guard is deliberately one-way: it is set before validation and
/// never rolls back, so a first call that fails validation
/// ([`InheritedFdsError::NotOpen`] / [`InheritedFdsError::NotAPipe`] /
/// [`InheritedFdsError::SetCloexec`]) permanently poisons the process — every
/// later call reports `AlreadyClaimed` even though no fd was adopted. That is
/// intentional, not an oversight: a process whose fds 3/4 failed validation
/// once has no legitimate second chance at them, and partial side effects of
/// the failed attempt (e.g. `FD_CLOEXEC` already restored on fd 3 when fd 4
/// fails) would make a retry unreliable anyway.
///
/// Also re-sets `FD_CLOEXEC` on the two fds: the spawn's `dup2` cleared it so
/// they'd survive `execve`, and without restoring it the daemon's own
/// subprocesses would inherit the RPC pipe ends and hold the parent's EOF open
/// past the daemon's exit. If restoring the flag fails, the fds have already
/// been adopted at that point and are closed on the error return (validation
/// failures — [`InheritedFdsError::NotOpen`] / [`InheritedFdsError::NotAPipe`]
/// — happen before adoption and leave the fds untouched).
///
/// Used by the test helper binary. Production applications go through the
/// framework's daemon dispatch in [`crate::run`], which additionally sends
/// the build-id handshake before handing the server to the app.
///
/// # Safety
/// Fds `CHILD_REQUEST_RECV_FD` (3) and `CHILD_RESPONSE_SEND_FD` (4) must be
/// the daemon's *exclusively owned* inherited RPC pipe ends: call this only in a
/// process the framework re-exec'd as a daemon child, where `spawn_daemon_process`
/// / [`start_background_process_with_exe`] mapped the parent's pipe ends onto
/// exactly those fd numbers across `execve`. This function takes ownership of
/// both fds — wrapping each in an `OwnedFd` that closes it on drop — so if any
/// other live `OwnedFd`/`File` in the calling process already owns fd 3 or 4
/// (e.g. an unrelated program that happened to open pipes there and called this
/// directly), the second owner minted here causes a double-close / use-after-free
/// once both drop. The `fstat` open+FIFO check and the process-wide
/// `DAEMON_FDS_CLAIMED` guard below are best-effort validation — they reject the
/// common "invoked by hand" mistake and any second claim — but they cannot prove
/// exclusive ownership, which is why that obligation falls on the caller.
///
/// Two clarifications. First, "exclusively owned" spans the whole call:
/// nothing else in the process may close or reuse fds 3/4 while it runs
/// (starting from raw fd numbers leaves an unavoidable validate→adopt
/// window). Second, if the process-wide claim guard is already set, the call
/// returns [`InheritedFdsError::AlreadyClaimed`] *before* touching any file
/// descriptor — such a call has no safety preconditions at all (the
/// in-module unit test relies on exactly this guarantee).
///
/// [`start_background_process_with_exe`]: super::start_background_process_with_exe
pub unsafe fn rpc_server_from_inherited_fds<Request, Response>()
-> Result<RpcServer<Request, Response>, InheritedFdsError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    if DAEMON_FDS_CLAIMED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(InheritedFdsError::AlreadyClaimed {
            request_recv_fd: CHILD_REQUEST_RECV_FD,
            response_send_fd: CHILD_RESPONSE_SEND_FD,
        });
    }
    for (label, fd) in [
        ("request-recv", CHILD_REQUEST_RECV_FD),
        ("response-send", CHILD_RESPONSE_SEND_FD),
    ] {
        // Probe the raw fd number with a bare `fstat` BEFORE building any fd
        // wrapper. A hand-invoked daemon may have closed 3/4, and a `BorrowedFd`
        // / `OwnedFd` must point at an *open* fd — whereas `libc::fstat` on a
        // bare descriptor is defined for any int (EBADF for a closed one), so it
        // can reject a bad fd without an I/O-safety-contract violation.
        //
        // SAFETY: `std::mem::zeroed()` yields a valid `libc::stat` — a `repr(C)`
        // struct of integer fields with no niche/validity constraints — used
        // only as the out-buffer that `fstat` fills before any field is read.
        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstat` writes through `&mut statbuf`, a live, correctly
        // aligned, writable `libc::stat`. `fd` is a bare int — a closed/invalid
        // descriptor yields EBADF (handled below as `NotOpen`), never UB — and
        // `fstat` neither takes ownership of nor closes it.
        if unsafe { libc::fstat(fd, &mut statbuf) } < 0 {
            return Err(InheritedFdsError::NotOpen {
                fd,
                label,
                source: std::io::Error::last_os_error(),
            });
        }
        if statbuf.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(InheritedFdsError::NotAPipe {
                fd,
                label,
                st_mode: statbuf.st_mode,
            });
        }
    }
    // Both fds validated as open FIFOs above; adopt ownership now. This is the
    // one irreducible `unsafe` in the claim — turning the inherited raw fd
    // numbers into owning `OwnedFd`s — and the reason this function is `unsafe`.
    //
    // SAFETY: by this function's `# Safety` contract the caller guarantees fds
    // 3/4 are the daemon's exclusively-owned inherited pipe ends;
    // `DAEMON_FDS_CLAIMED` made this the sole claim in the process, and each was
    // just `fstat`ed as an open FIFO, so each `OwnedFd` (which closes on drop) is
    // the one and only owner. The same exclusive-ownership contract rules out a
    // concurrent close/reuse between those checks and this adoption (there is an
    // unavoidable check→adopt window when starting from a raw fd number — it is
    // part of why this fn is `unsafe`). The two fd numbers are distinct (3 vs
    // 4), so the pair does not alias each other either.
    let (request_recv, response_send) = unsafe {
        (
            OwnedFd::from_raw_fd(CHILD_REQUEST_RECV_FD),
            OwnedFd::from_raw_fd(CHILD_RESPONSE_SEND_FD),
        )
    };
    // Restore FD_CLOEXEC. The parent set it on every pipe end at creation,
    // but the `dup2` onto fds 3/4 during the spawn necessarily cleared it so
    // they'd survive the `execve` into this daemon. Nothing re-sets it, so
    // without this the fds stay inheritable for the daemon's whole lifetime:
    // every subprocess the daemon later spawns (`std::process::Command`
    // inherits non-CLOEXEC fds across its own fork+exec) gets a duplicate of
    // the response pipe's write end, and since EOF only fires once ALL write
    // ends close, such a subprocess outliving the daemon suppresses the EOF
    // the parent waits on — silently defeating the liveness of
    // `recv_response_blocking`. (The symmetric effect on fd 3 delays the
    // parent's `send_request` EPIPE.)
    //
    // Runs on the adopted `OwnedFd`s — `as_fd()` needs no raw-fd `unsafe`, and
    // there is no fstat→borrow window to reason about. A failure here closes
    // both fds on the error return; acceptable, since the claim has begun and
    // this function's contract says it takes ownership of them.
    for (label, fd) in [
        ("request-recv", &request_recv),
        ("response-send", &response_send),
    ] {
        set_cloexec(fd.as_fd()).map_err(|(operation, source)| InheritedFdsError::SetCloexec {
            fd: fd.as_raw_fd(),
            label,
            operation,
            source,
        })?;
    }
    Ok(RpcServer::from_owned_fds(request_recv, response_send))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_server_from_inherited_fds_rejects_a_second_claim() {
        // The daemon fds (3/4) are a process singleton; claiming them twice
        // would alias owning `OwnedFd`s and risk a use-after-free. Simulate a
        // prior claim by setting the flag directly — this deterministically
        // exercises the guard without depending on what fds 3/4 happen to be in
        // the test process, and without taking ownership of them.
        //
        // This swap→call→restore sequence is not atomic as a whole, so it is
        // only sound while this test is the binary's SOLE claimant: a
        // concurrent test that genuinely claimed fds 3/4 could observe a
        // spurious `AlreadyClaimed`, or have its claim's flag clobbered back
        // to `false` by the restore below — re-arming a second, aliasing
        // claim. The assert enforces that invariant: if it ever fires, some
        // other test in this binary now touches the claim guard, and this
        // test needs a different design (e.g. a spawned-process test).
        let previously = DAEMON_FDS_CLAIMED.swap(true, Ordering::SeqCst);
        assert!(
            !previously,
            "DAEMON_FDS_CLAIMED was already set: another test in this binary \
             claims the daemon fds, which this test's flag swap/restore cannot \
             coexist with"
        );
        // SAFETY: `rpc_server_from_inherited_fds` is `unsafe` because it would
        // take ownership of fds 3/4. Here `DAEMON_FDS_CLAIMED` is pre-set to
        // `true`, so the call short-circuits with `AlreadyClaimed` *before*
        // reaching the fd-claiming code — it never wraps a descriptor, so the
        // exclusive-ownership precondition is vacuously satisfied.
        let result = unsafe { rpc_server_from_inherited_fds::<(), ()>() };
        // Restore the flag (asserted `false` above) so a later claim in this
        // process — none exists today — isn't spuriously rejected.
        DAEMON_FDS_CLAIMED.store(false, Ordering::SeqCst);

        let err = result
            .err()
            .expect("a second claim of the daemon fds must be rejected");
        assert!(
            matches!(err, InheritedFdsError::AlreadyClaimed { .. }),
            "expected AlreadyClaimed, got: {err:?}"
        );
    }
}
