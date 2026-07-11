//! Parent-side fork+exec machinery: re-exec the current binary (or a test
//! helper) as a background child, wire up the IPC pipes, and — for the real
//! daemon path — validate the handshake and ship the bootstrap payload.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use command_fds::{CommandFdExt, FdMapping};
use serde::{Serialize, de::DeserializeOwned};
use tokio::runtime::Handle;

use super::handshake::validate_handshake_and_build_client;
use super::{
    BOOTSTRAP_TIMEOUT, CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD, DAEMON_CHILD_ENV_VALUE,
    DAEMON_CHILD_ENV_VAR,
};
use crate::ipc::RpcClient;
use crate::ipc::RpcConnection;
use crate::ipc::error::{BootstrapAckError, SpawnDaemonError};

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
            BootstrapAckError::NonEmptyAck { len } => SpawnDaemonError::MalformedAck { len },
            BootstrapAckError::Recv(err) => SpawnDaemonError::RecvAck(err),
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

/// Common fork+exec machinery shared by [`spawn_daemon_process`] and
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
