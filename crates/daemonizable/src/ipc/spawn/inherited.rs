//! The daemon child's one-time claim of the IPC pipe fds it inherited from its
//! parent across `execve`, rebuilt into a typed [`RpcServer`].

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Serialize, de::DeserializeOwned};

use super::{CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD};
use crate::ipc::RpcServer;
use crate::ipc::cloexec::set_cloexec;
use crate::ipc::error::InheritedFdsError;

/// Guards the process-wide claim on the inherited daemon fds (3 and 4).
///
/// [`rpc_server_from_inherited_fds`] mints owning `OwnedFd`s from those fixed
/// fd numbers via the `unsafe` [`RpcServer::from_raw_fds`]. A second call would
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
/// second call returns an error rather than aliasing the descriptors.
///
/// Also re-sets `FD_CLOEXEC` on the two fds: the spawn's `dup2` cleared it so
/// they'd survive `execve`, and without restoring it the daemon's own
/// subprocesses would inherit the RPC pipe ends and hold the parent's EOF open
/// past the daemon's exit.
///
/// Used by the test helper binary. Production applications go through the
/// framework's daemon dispatch in [`crate::run`], which additionally sends
/// the build-id handshake before handing the server to the app.
///
/// [`start_background_process_with_exe`]: super::start_background_process_with_exe
pub fn rpc_server_from_inherited_fds<Request, Response>()
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
        // SAFETY: `std::mem::zeroed` is sound here because `libc::stat` is a
        // `repr(C)` plain-old-data struct made up entirely of integer fields
        // (device/inode/mode/uid/gid/size/block counts and `time_t`/`c_long`
        // timestamp members, plus reserved integer padding). None of these have
        // a validity invariant that excludes zero, so the all-zero bit pattern
        // is a valid value. It is only ever used as the out-buffer for the
        // `fstat` call below, which initializes it before any field is read.
        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fstat` writes the file status through its second argument,
        // which here is `&mut statbuf` — a live, non-null, correctly aligned,
        // fully initialized `libc::stat` local (zeroed above; a repr(C) POD of
        // integer fields matching the platform `struct stat`), valid for the
        // whole call. `fd` is only an int: a bad or non-open descriptor yields
        // -1/EBADF (handled below via `NotOpen`), never UB, and `fstat` neither
        // takes ownership of nor closes it, so no aliasing obligation applies.
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
        set_cloexec(fd).map_err(|(operation, source)| InheritedFdsError::SetCloexec {
            fd,
            label,
            operation,
            source,
        })?;
    }
    Ok(unsafe { RpcServer::from_raw_fds(CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD) })
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
        // the test process, and without taking ownership of them. Restore the
        // previous value so we don't disturb any other test in this binary.
        let previously = DAEMON_FDS_CLAIMED.swap(true, Ordering::SeqCst);
        let result = rpc_server_from_inherited_fds::<(), ()>();
        DAEMON_FDS_CLAIMED.store(previously, Ordering::SeqCst);

        let err = result
            .err()
            .expect("a second claim of the daemon fds must be rejected");
        assert!(
            matches!(err, InheritedFdsError::AlreadyClaimed { .. }),
            "expected AlreadyClaimed, got: {err:?}"
        );
    }
}
