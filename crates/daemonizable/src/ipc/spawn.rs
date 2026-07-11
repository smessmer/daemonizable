use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use command_fds::{CommandFdExt, FdMapping};
use serde::{Serialize, de::DeserializeOwned};
use tokio::runtime::Handle;

use crate::ipc::RpcConnection;

use super::error::{HandshakeError, InheritedFdsError, PipeSendError, SpawnDaemonError};
use super::{RpcClient, RpcServer};

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

/// How long the spawning parent will wait for the daemon to send its
/// build-id handshake after fork+exec. The child handshakes before any app
/// code runs, so this only has to cover the exec itself plus the child arm's
/// few syscalls (fstat of two fds, `setsid`, `chdir`) — sub-millisecond on a
/// healthy system; the generous bound is for loaded CI machines. The timeout
/// also matters when the parent accidentally exec'd a wrong binary that
/// opens fd 4 but never writes (or hangs); without a bound the spawn would
/// hang forever in that case.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the daemon child waits for the parent's bootstrap payload after
/// sending its build-id handshake, and how long the parent waits for the
/// child's ack after shipping the payload. Sub-millisecond on any healthy
/// system (each side only serializes/acks a small message); generous bound
/// so a slow CI doesn't flake.
pub(crate) const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve the path to exec for the daemon child.
///
/// On Linux we pass the **literal string** `"/proc/self/exe"` to `execve`.
/// The kernel's magic-link resolver for that path returns `mm->exe_file` of
/// the calling process (via `proc_exe_link` / `nd_jump_link`), so the child
/// is loaded from the exact same inode the parent was loaded from — even if
/// the installed binary was replaced on disk (e.g. by a package upgrade)
/// between parent startup and this `execve`. This is **not** the same as
/// `std::env::current_exe()`, which `readlink`s the symlink into a path
/// string and then re-resolves it through the filesystem; a future reader
/// who "simplifies" this to `current_exe` everywhere will silently lose the
/// upgrade-mid-run guarantee.
///
/// On non-Linux, `current_exe()` is the best we have. The build-id handshake
/// covers the gap.
fn daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().map_err(SpawnDaemonError::ExePath)
    }
}

/// Spawn the current binary as a background daemon via fork+exec — the
/// engine behind `Daemonizer::spawn_daemon`. Re-execs the current binary
/// with the [`DAEMON_CHILD_ENV_VAR`] marker (no argv flag; the child
/// receives its two pipe ends as fds `CHILD_REQUEST_RECV_FD` (3) and
/// `CHILD_RESPONSE_SEND_FD` (4); every other parent fd is CLOEXEC so the
/// kernel closes them during `execve`), validates the build-id handshake,
/// ships `payload_bytes` as the raw bootstrap frame, and waits for the
/// daemon's ack (= payload received and decoded).
///
/// The handshake is a raw (not postcard-encoded) frame *from* the daemon
/// child, bounded by `HANDSHAKE_TIMEOUT`, and the spawn is rejected if the
/// bytes don't match `expected_build_id`. This catches three classes of
/// mistake at once:
///   - macOS-style binary replacement during the spawn window (the daemon
///     binary is a different build than the parent),
///   - a parent that accidentally exec'd a non-application binary (no
///     handshake arrives → EOF or timeout),
///   - any future operator mistake exec'ing a stranger binary that happens
///     to write something to fd 4 (handshake bytes won't match the
///     expected build id).
///
/// On handshake/bootstrap failure the just-spawned child is killed and reaped
/// (best-effort) before the error is returned — a failed spawn must not leave
/// an orphaned process or an unreapable zombie behind in a long-lived caller.
pub(crate) fn spawn_daemon_process<Request, Response>(
    expected_build_id: &str,
    payload_bytes: &[u8],
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    if Handle::try_current().is_ok() {
        panic!(
            "Cannot daemonize a process if tokio is running. Please daemonize \
             before initializing tokio. See https://github.com/tokio-rs/tokio/issues/4301"
        );
    }

    let exe = daemon_exe_path()?;
    // The execve path is `/proc/self/exe` on Linux (kernel magic-link, see
    // `daemon_exe_path`), but that string would also become argv[0] by
    // default, so `ps`/`top` would show "/proc/self/exe" instead of the
    // actual binary name. Override argv[0] to the resolved path so operators
    // see a recognizable command line. Falls back to the exec path if
    // `current_exe()` fails — preserves correctness over cosmetics.
    let argv0 = std::env::current_exe().unwrap_or_else(|_| exe.clone());
    let (client, mut child) = start_background_process_inner::<Request, Response>(
        &exe,
        Some(argv0.as_path()),
        &[],
        &[(
            OsStr::new(DAEMON_CHILD_ENV_VAR),
            OsStr::new(DAEMON_CHILD_ENV_VALUE),
        )],
    )?;

    match handshake_and_ship_bootstrap(client, expected_build_id, payload_bytes) {
        Ok(client) => Ok(client),
        Err(err) => {
            // The child is not (yet) a validated daemon of ours — reap it so a
            // failed spawn is fully cleaned up. Best-effort: it usually has
            // already exited (its own handshake/bootstrap timeout), making
            // kill() a no-op and wait() an immediate reap.
            //
            // TODO This kill+wait cleanup is a documented API promise (README
            //   "Process contract", crate docs, spawn_daemon rustdoc) with
            //   zero test coverage: no test drives spawn_daemon_process into
            //   a failure with a real child, so a refactor that breaks the
            //   cleanup (e.g. moving the Child into
            //   handshake_and_ship_bootstrap, or replacing the match with `?`)
            //   would keep the whole workspace green. It can't be covered
            //   as-is because spawn_daemon_process always re-execs
            //   /proc/self/exe (re-exec'ing the libtest binary is unusable)
            //   and the test-helper spawn path bypasses handshake validation
            //   and drops the Child. Fix: extract a testable seam — e.g. a
            //   fn taking (RpcClient, Child) that does
            //   validate/ship-then-kill+wait-on-error, or a
            //   testutils-gated spawn variant taking an exe path — then, from
            //   daemonizable-e2e-tests, spawn daemonizable-test-background
            //   with a new "wrong handshake then idle" behavior (writes its
            //   pid to a file) and assert the error is HandshakeError::Mismatch
            //   AND the child was reaped (libc::kill(pid, 0) == ESRCH,
            //   waitpid == ECHILD).
            // TODO When the double-fork lands in run_as_daemon_child (see
            //   the TODO at its setsid() call in app.rs), this cleanup must
            //   switch to process-group signaling: the direct child will be
            //   a long-dead session-leader intermediate, so kill() here
            //   would hit a corpse while the real daemon (its forked child)
            //   survives. Replacement: libc::kill(-child_pid, SIGKILL)
            //   (valid because the child's setsid() made its pid the pgid,
            //   and the pid is not recycled while the group has members),
            //   tolerate ESRCH (child died before setsid), then keep the
            //   direct kill()+wait() below as fallback and reaper.
            let _ = child.kill();
            let _ = child.wait();
            Err(err)
        }
    }
}

/// The exact value `spawn_daemon_process` sets [`DAEMON_CHILD_ENV_VAR`] to.
/// Dispatch matches this value exactly; anything else is not a daemon child.
pub(crate) const DAEMON_CHILD_ENV_VALUE: &str = "1";

fn handshake_and_ship_bootstrap<Request, Response>(
    client: RpcClient<Request, Response>,
    expected_build_id: &str,
    payload_bytes: &[u8],
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let mut client = validate_handshake_and_build_client(client, expected_build_id)?;
    // TODO This send is the only unbounded step of the spawn protocol: the
    //   handshake recv and the ack recv below are timeout-bounded, but
    //   send_raw_bootstrap goes through a blocking write_all, which blocks
    //   once the kernel pipe buffer is full (64 KiB default on Linux, 4 KiB
    //   under the pipe-user-pages-soft limit) while MAX_MESSAGE_SIZE allows
    //   payloads up to 1 MiB. Against a child that passed the handshake and
    //   is then stopped without executing (SIGSTOP/ptrace targeting just the
    //   child — a merely slow child unblocks us or times out and exits →
    //   EPIPE), spawn_daemon hangs forever and the kill+wait failure cleanup
    //   below never runs, contradicting the documented bounded-failure
    //   contract. Irrelevant for cryfs (the LoggingConfig payload is tiny),
    //   but the published API allows app-defined payloads. Fix: set the
    //   sender nonblocking and mirror read_exact_with_timeout with a
    //   poll(POLLOUT)-based write_all_with_timeout bounded by
    //   BOOTSTRAP_TIMEOUT, mapped to a new PipeSendError::Timeout variant so
    //   the cleanup path runs; or at minimum document that payloads above
    //   the OS pipe capacity may block spawn_daemon indefinitely against a
    //   wedged child.
    client
        .send_raw_bootstrap(payload_bytes)
        .map_err(SpawnDaemonError::SendPayload)?;
    client
        .recv_raw_bootstrap_ack_with_timeout(BOOTSTRAP_TIMEOUT)
        .map_err(|err| match err {
            super::error::BootstrapAckError::NonEmptyAck { len } => {
                SpawnDaemonError::MalformedAck { len }
            }
            super::error::BootstrapAckError::Recv(err) => SpawnDaemonError::RecvAck(err),
        })?;
    Ok(client)
}

/// Test-only variant: spawn an arbitrary helper binary instead of re-exec'ing
/// the current one. Used by the daemon-lifecycle integration tests to drive
/// the spawn machinery against a controlled daemon. Does not send a build-id
/// handshake — the helper bin doesn't expect one.
pub fn start_background_process_with_exe<Request, Response>(
    exe: &Path,
    extra_env: &[(&OsStr, &OsStr)],
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    if Handle::try_current().is_ok() {
        panic!(
            "Cannot spawn a background process if tokio is running. \
             Spawn before initializing tokio."
        );
    }
    let (client, _child) = start_background_process_inner(exe, None, &[], extra_env)?;
    Ok(client)
}

/// Common fork+exec machinery shared by [`start_background_process`] and
/// [`start_background_process_with_exe`].
fn start_background_process_inner<Request, Response>(
    exe: &Path,
    argv0: Option<&Path>,
    args: &[&str],
    extra_env: &[(&OsStr, &OsStr)],
) -> Result<(RpcClient<Request, Response>, std::process::Child), SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let rpc_pipes = RpcConnection::<Request, Response>::new_pipe()?;
    let (client, child_in_fd, child_out_fd) = rpc_pipes.into_client_and_child_fds();

    let mut cmd = Command::new(exe);
    if let Some(argv0) = argv0 {
        cmd.arg0(argv0);
    }
    cmd.args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    // TODO Replace `command-fds` with stdlib `CommandExt::fd` once
    // https://github.com/rust-lang/rust/pull/145687 lands and stabilizes.
    // The stdlib version is expected to route through `posix_spawn` +
    // `posix_spawn_file_actions_adddup2` when possible, which would close
    // the fork-after-multithread hazard (see https://github.com/tokio-rs/tokio/issues/4301).
    // `command-fds` itself uses `pre_exec` (it has no way around that
    // through `std::process::Command` today), so this switch is a code-shape
    // and edge-case-correctness improvement rather than a safety improvement
    // — but it puts the migration one line away when the stdlib API lands.
    cmd.fd_mappings(vec![
        FdMapping {
            parent_fd: child_in_fd,
            child_fd: CHILD_REQUEST_RECV_FD,
        },
        FdMapping {
            parent_fd: child_out_fd,
            child_fd: CHILD_RESPONSE_SEND_FD,
        },
    ])
    // Invariant, not an error path: a collision needs two mappings onto the
    // same child fd, and we map two distinct owned parent fds onto the
    // distinct constants 3 and 4.
    .expect("fd mappings onto the distinct fds 3 and 4 cannot collide");

    let child = cmd.spawn().map_err(|source| SpawnDaemonError::Spawn {
        path: exe.to_owned(),
        source,
    })?;

    Ok((client, child))
}

/// Parent-side counterpart to [`send_handshake`]: read the build-id the
/// daemon sent and reject the spawn if it doesn't match
/// `expected_build_id`. Returns the client unchanged on match.
///
/// Must run before any postcard-typed RPC: a mismatch would otherwise let
/// the parent deserialize structured data from a daemon whose
/// Request/Response schemas may not agree.
fn validate_handshake_and_build_client<Request, Response>(
    mut client: RpcClient<Request, Response>,
    expected_build_id: &str,
) -> Result<RpcClient<Request, Response>, HandshakeError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let received = client
        .recv_raw_handshake_with_timeout(HANDSHAKE_TIMEOUT)
        .map_err(HandshakeError::Recv)?;
    let received_str = std::str::from_utf8(&received).map_err(HandshakeError::InvalidUtf8)?;
    if received_str != expected_build_id {
        return Err(HandshakeError::Mismatch {
            expected: expected_build_id.to_string(),
            received: received_str.to_string(),
        });
    }
    Ok(client)
}

/// Daemon-side counterpart to `validate_handshake_and_build_client`: send
/// `build_id` to the parent so the parent can confirm it exec'd the binary
/// it intended to. Must be called before any postcard-typed RPC on `server`.
pub fn send_handshake<Request, Response>(
    server: &mut RpcServer<Request, Response>,
    build_id: &str,
) -> Result<(), PipeSendError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    server.send_raw_handshake(build_id.as_bytes())
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::ipc::{PipeRecvError, RpcConnection};
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize)]
    struct Req(u32);
    #[derive(Debug, Serialize, Deserialize)]
    struct Resp(u32);

    /// Stand-in for a real binary's build id. The handshake just compares
    /// bytes; the framework doesn't care what string the application
    /// supplies as long as it's deterministic across the parent/child pair.
    const TEST_BUILD_ID: &str = "test-build-id-1.2.3";

    #[test]
    fn accepts_matching_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();
        send_handshake(&mut server, TEST_BUILD_ID).unwrap();
        validate_handshake_and_build_client(client, TEST_BUILD_ID).expect("matching build_id");
    }

    #[test]
    fn rejects_mismatched_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();
        send_handshake(&mut server, "some-other-version-1.2.3").unwrap();
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("mismatched build_id should be rejected");
        match err {
            HandshakeError::Mismatch { expected, received } => {
                assert_eq!(TEST_BUILD_ID, expected);
                assert_eq!("some-other-version-1.2.3", received);
            }
            other => panic!("expected Mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_utf8_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();
        // 0xff is never valid as a leading UTF-8 byte.
        server.send_raw_handshake(&[0xff, 0xfe]).unwrap();
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("non-UTF-8 should be rejected");
        assert!(
            matches!(err, HandshakeError::InvalidUtf8(_)),
            "expected InvalidUtf8, got: {err:?}",
        );
    }

    #[test]
    fn rejects_when_daemon_closes_before_handshake() {
        // Daemon dies (or was a non-application binary that just exited)
        // before writing the handshake. Parent's `recv_raw_timeout` sees
        // EOF and bails — must surface as an error rather than hang.
        let (server, client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();
        drop(server);
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("missing handshake should be rejected");
        assert!(
            matches!(err, HandshakeError::Recv(PipeRecvError::SenderClosed)),
            "expected Recv(SenderClosed), got: {err:?}",
        );
    }

    #[test]
    fn rejects_when_daemon_hangs_without_sending() {
        // Daemon (or a wrong binary like a hung `/bin/cat`) holds fd 4 open
        // but never writes. Without a timeout the parent would hang forever;
        // bounded `recv_raw_handshake_with_timeout` surfaces a timeout error
        // instead. Tiny timeout so the test doesn't actually wait 10s.
        let (_server_keepalive, mut client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();
        let err = client
            .recv_raw_handshake_with_timeout(Duration::from_millis(50))
            .err()
            .expect("hung daemon should be rejected via timeout");
        assert!(
            matches!(err, PipeRecvError::Timeout),
            "expected Timeout, got: {err:?}",
        );
    }

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
/// Used by the test helper binary. Production applications go through the
/// framework's daemon dispatch in [`crate::run`], which additionally sends
/// the build-id handshake and consumes the bootstrap before handing the
/// server to the app.
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
        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
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
    // TODO Restore FD_CLOEXEC on the claimed fds here (reuse pipe.rs's
    //   set_cloexec helper). The parent set it on all pipe ends at creation,
    //   but the dup2 onto fds 3/4 during the spawn necessarily cleared it so
    //   they survive the execve — and nothing re-sets it, so the fds stay
    //   inheritable for the daemon's whole lifetime. Every subprocess the
    //   daemon spawns (std::process::Command inherits non-CLOEXEC fds) gets a
    //   duplicate of the response pipe's write end; since EOF only fires once
    //   ALL write ends close, a grandchild that outlives the daemon
    //   suppresses the EOF the parent is waiting on — silently defeating the
    //   documented EOF liveness of recv_response_blocking (a parent can hang
    //   on a dead daemon for as long as the grandchild lives). The symmetric
    //   effect on fd 3 delays the parent's send_request EPIPE. cryfs is only
    //   exposed for the milliseconds fusermount3 runs, but a published-crate
    //   user whose run_daemon spawns a long-lived helper hits this fully.
    Ok(unsafe { RpcServer::from_raw_fds(CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD) })
}
