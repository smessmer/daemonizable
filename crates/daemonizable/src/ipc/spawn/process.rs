//! Parent-side fork+exec machinery: re-exec the current binary (or a test
//! helper) as a background child, wire up the IPC pipes, and — for the real
//! daemon path — validate the build-id handshake. The validated daemon is a
//! *grandchild*: the re-exec'd child forks once more so it is never a session
//! leader, and the direct child this parent holds a `Child` handle for is a
//! short-lived intermediate.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use command_fds::{CommandFdExt, FdMapping};
use serde::{Serialize, de::DeserializeOwned};

use super::handshake::validate_handshake_and_build_client;
use super::{
    CHILD_REQUEST_RECV_FD, CHILD_RESPONSE_SEND_FD, DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR,
};
use crate::ipc::RpcClient;
use crate::ipc::RpcConnection;
use crate::ipc::error::SpawnDaemonError;

/// Resolve the path to exec for the daemon child.
///
/// On Linux we prefer the **literal string** `"/proc/self/exe"` for `execve`.
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
/// When `/proc` is **not** mounted (a bare chroot, a minimal container) the
/// magic link doesn't exist, so we degrade gracefully instead of failing the
/// spawn: fall back to the path the kernel recorded at `execve` time in the
/// auxiliary vector ([`AT_EXECFN`](https://man7.org/linux/man-pages/man3/getauxval.3.html)),
/// and finally to `argv[0]`. The fallback gives up the same-inode guarantee —
/// the on-disk binary could have been replaced since startup, and a relative
/// `argv[0]` is resolved against a cwd that may have changed — but the
/// build-id handshake still turns a swapped or wrong binary into a clean typed
/// error ([`HandshakeError::Mismatch`](crate::HandshakeError)) rather than a
/// silently wrong daemon. `current_exe()` is deliberately **not** the Linux
/// fallback: on Linux it `readlink`s `/proc/self/exe` itself, so it fails for
/// the very same reason the primary path did.
///
/// On non-Linux, `current_exe()` is the best we have. The build-id handshake
/// covers the gap.
fn daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
    #[cfg(target_os = "linux")]
    {
        linux_daemon_exe_path()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().map_err(SpawnDaemonError::ExePath)
    }
}

/// Linux path resolution with the `/proc`-absent fallback (see
/// [`daemon_exe_path`]).
#[cfg(target_os = "linux")]
fn linux_daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
    // Detect whether `/proc` is actually mounted by trying to *read* the magic
    // link. `read_link` succeeding proves the link resolves; we then hand the
    // LITERAL "/proc/self/exe" string (not the read-link target) to `execve` so
    // the same-inode guarantee is preserved. A TOCTOU where `/proc` disappears
    // between this probe and the `execve` is astronomically unlikely and no
    // worse than the previous unconditional behavior.
    if std::fs::read_link("/proc/self/exe").is_ok() {
        return Ok(PathBuf::from("/proc/self/exe"));
    }

    // `/proc` is unavailable. Fall back to the exec-time pathname the kernel
    // stashed in the auxiliary vector.
    if let Some(path) = exe_path_from_auxv() {
        return Ok(path);
    }

    // Last resort: `argv[0]`. It may be a bare command name (then `Command`
    // resolves it via `$PATH`) or a path relative to a since-changed cwd —
    // best-effort, and again backstopped by the build-id handshake.
    if let Some(argv0) = std::env::args_os().next() {
        if !argv0.is_empty() {
            return Ok(PathBuf::from(argv0));
        }
    }

    Err(SpawnDaemonError::ExePath(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "/proc is not mounted and neither AT_EXECFN nor argv[0] yielded an \
         executable path to re-exec",
    )))
}

/// The pathname used to `execve` this process, as recorded by the kernel in
/// the auxiliary vector under `AT_EXECFN`. Returns `None` if the entry is
/// absent (e.g. a statically odd libc, or a stripped auxv). Available on
/// glibc and musl via `getauxval(3)`.
#[cfg(target_os = "linux")]
fn exe_path_from_auxv() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: `getauxval` is always safe to call; it returns 0 when the
    // requested type isn't present. On a non-zero return the value is a pointer
    // into the process's own auxiliary vector — a NUL-terminated string that
    // lives for the life of the process — so building a `CStr` from it is
    // sound.
    let ptr = unsafe { libc::getauxval(libc::AT_EXECFN) };
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` is the non-zero return of `getauxval(AT_EXECFN)` (the
    // `ptr == 0` case returned above), which for this pointer-typed auxv entry
    // is the kernel-supplied pointer to the NUL-terminated pathname the process
    // was `execve`'d with. That string is correctly aligned (`c_char` has
    // alignment 1) and lives for the whole process lifetime, and the borrowed
    // `CStr` is consumed inline (its bytes copied into a `PathBuf` below), so it
    // is never mutated or outlived.
    let bytes = unsafe { CStr::from_ptr(ptr as *const libc::c_char) }.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(bytes)))
}

/// Spawn the current binary as a background daemon via fork+exec — the
/// engine behind `Daemonizer::spawn_daemon`. Re-execs the current binary
/// with the [`DAEMON_CHILD_ENV_VAR`] marker (no argv flag; the child
/// receives its two pipe ends as fds `CHILD_REQUEST_RECV_FD` (3) and
/// `CHILD_RESPONSE_SEND_FD` (4); every other parent fd is CLOEXEC so the
/// kernel closes them during `execve`) and validates the build-id handshake.
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
/// The re-exec'd child forks a second time (see `run_as_daemon_child`) so the
/// daemon is the grandchild; the direct child is a short-lived session-leader
/// intermediate. On success the intermediate is reaped here (it has already
/// `_exit(0)`d). On handshake/spawn failure the spawn is killed via its
/// process group — `kill(-child_pid, SIGKILL)`, which reaches the grandchild —
/// and the intermediate reaped before the error is returned, so a failed spawn
/// leaves no orphan and no unreapable zombie behind in a long-lived caller.
pub(crate) fn spawn_daemon_process<Request, Response>(
    expected_build_id: &str,
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let exe = daemon_exe_path()?;
    // The execve path is usually `/proc/self/exe` on Linux (kernel magic-link,
    // see `daemon_exe_path`), but that string would also become argv[0] by
    // default, so `ps`/`top` would show "/proc/self/exe" instead of the actual
    // binary name. Override argv[0] to the resolved path so operators see a
    // recognizable command line. Falls back to the exec path if `current_exe()`
    // fails — preserves correctness over cosmetics. (In the `/proc`-absent
    // fallback, `current_exe()` also fails, so argv[0] becomes `exe`, which is
    // then already the real AT_EXECFN / argv[0] path — still recognizable.)
    let argv0 = std::env::current_exe().unwrap_or_else(|_| exe.clone());
    let (client, child) = start_background_process_inner::<Request, Response>(
        &exe,
        Some(argv0.as_path()),
        &[],
        &[(
            OsStr::new(DAEMON_CHILD_ENV_VAR),
            OsStr::new(DAEMON_CHILD_ENV_VALUE),
        )],
    )?;

    complete_spawn(client, child, expected_build_id)
}

/// Test-only variant of [`spawn_daemon_process`]: spawn an arbitrary helper
/// binary instead of re-exec'ing the current one, but keep the full handshake
/// validation and success/failure child cleanup. Exists so the documented
/// failed-spawn cleanup contract is testable — [`spawn_daemon_process`] always
/// re-execs the current binary (via `/proc/self/exe`, or its `AT_EXECFN` /
/// `argv[0]` fallback), which is unusable from a libtest binary, and the raw
/// [`start_background_process_with_exe`] path bypasses handshake validation and
/// drops the `Child`.
///
/// `#[doc(hidden)]` and gated behind `test`/`testutils`: not part of the stable
/// surface.
#[cfg(any(test, feature = "testutils"))]
#[doc(hidden)]
pub fn spawn_daemon_process_with_exe<Request, Response>(
    exe: &Path,
    expected_build_id: &str,
    extra_env: &[(&OsStr, &OsStr)],
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let (client, child) = start_background_process_inner(exe, None, &[], extra_env)?;
    complete_spawn(client, child, expected_build_id)
}

/// Drive the parent side of the spawn protocol to completion against an
/// already-spawned `child`: validate the build-id handshake and — on any
/// failure — kill and reap the child before returning the error, so a failed
/// spawn leaves no orphan and no unreapable zombie behind in a long-lived
/// caller. Shared by [`spawn_daemon_process`] and the test-only
/// [`spawn_daemon_process_with_exe`] so the cleanup path has one home and one
/// set of tests (`daemonizable-e2e-tests/tests/failed_spawn_cleanup.rs`).
fn complete_spawn<Request, Response>(
    client: RpcClient<Request, Response>,
    mut child: std::process::Child,
    expected_build_id: &str,
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    // `child` is the session-leader intermediate from the second fork in
    // run_as_daemon_child; the real daemon is its forked grandchild. Capture the
    // pid before any wait() so it still names the (live or zombie) direct child.
    let child_pid = child.id() as libc::pid_t;

    match validate_handshake_and_build_client(client, expected_build_id) {
        Ok(client) => {
            // The intermediate _exit(0)s before the handshake is sent, so a
            // successful handshake proves it is already dead; this reaps it
            // (near-)immediately. Without it, every successful spawn would park
            // a zombie intermediate in a long-lived caller.
            //
            // Blocking wait(): an externally SIGSTOPped or ptraced intermediate
            // would block here indefinitely (documented on `spawn_daemon`). This
            // is the only unbounded step of the spawn — the handshake recv is
            // timeout-bounded. Since this wait is only zombie hygiene — the real
            // daemon is the orphaned grandchild — it could degrade to
            // try_wait()+timeout if that ever mattered.
            let _ = child.wait();
            Ok(client)
        }
        Err(err) => {
            // Kill the whole spawn, then reap the direct child. Post-fork the
            // direct child is the already-dead intermediate while the real
            // daemon is the grandchild, so a plain child.kill() would signal a
            // corpse and leave the daemon running — we must signal the process
            // GROUP.
            //
            // kill(-child_pid) reaches the grandchild because the child's
            // setsid() made child_pid the process-group id and the grandchild
            // stays in that group. It is race-free even though we hold only the
            // pid: child_pid is our OWN unreaped direct child, so by the POSIX
            // pid-reuse rule (XBD 4.14 — a pid is not reused until BOTH the
            // process lifetime ends AND any equal-pgid group's lifetime ends)
            // plus the zombie-retention contract, child_pid cannot name any
            // foreign process or group until the wait() below. MUST signal
            // BEFORE wait(): reaping first frees child_pid for reuse and
            // -child_pid could then hit an unrelated group.
            //   * post-fork:  -child_pid SIGKILLs the live grandchild (the daemon)
            //   * pre-setsid: -child_pid is ESRCH (the child is still in our
            //     group, whose id is our pgid, not child_pid); the direct
            //     child.kill() gets it instead
            // A grandchild the group-kill somehow misses (it left the group via
            // its own setsid/setpgid) still self-terminates via pipe EOF once
            // the client is dropped on the error return.
            //
            // `Pid::from_raw(-child_pid)` is the process group: nix passes it
            // straight to `kill(2)`, so a negative pid signals the group, same
            // as the raw call. Which group is actually signalled — that
            // `-child_pid` reaches the daemon grandchild and cannot hit a
            // pid-reused foreign group — is the correctness property argued
            // above. A stale/foreign pid only yields ESRCH/EPERM (discarded).
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-child_pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = child.kill();
            let _ = child.wait();
            Err(SpawnDaemonError::Handshake(err))
        }
    }
}

/// Test-only variant: spawn an arbitrary helper binary instead of re-exec'ing
/// the current one. Used by the daemon-lifecycle integration tests to drive
/// the spawn machinery against a controlled daemon. Does not send a build-id
/// handshake — the helper bin doesn't expect one.
///
/// Gated behind `test`/`testutils` and hidden from docs — like
/// [`spawn_daemon_process_with_exe`] — so it doesn't ship in the default
/// published surface.
#[cfg(any(test, feature = "testutils"))]
#[doc(hidden)]
pub fn start_background_process_with_exe<Request, Response>(
    exe: &Path,
    extra_env: &[(&OsStr, &OsStr)],
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let (client, _child) = start_background_process_inner(exe, None, &[], extra_env)?;
    Ok(client)
}

/// Common fork+exec machinery shared by [`spawn_daemon_process`] and the
/// `testutils` spawn helpers (`start_background_process_with_exe` and
/// `spawn_daemon_process_with_exe`).
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn prefers_proc_self_exe_when_proc_is_mounted() {
        // The test process runs on a normal Linux box with `/proc` mounted, so
        // resolution must take the primary path and hand `execve` the LITERAL
        // magic-link string (preserving the same-inode guarantee), not a
        // resolved or fallback path.
        assert!(
            std::fs::read_link("/proc/self/exe").is_ok(),
            "precondition: this test assumes /proc is mounted"
        );
        assert_eq!(
            daemon_exe_path().unwrap(),
            PathBuf::from("/proc/self/exe"),
            "with /proc mounted, the exec path must be the literal magic link"
        );
    }

    #[test]
    fn auxv_fallback_resolves_to_this_test_binary() {
        // `AT_EXECFN` is the pathname this process was `execve`'d with. It must
        // be present and point at a real, existing file (the libtest binary) —
        // this is the path the spawn would re-exec if `/proc` were unmounted.
        let from_auxv = exe_path_from_auxv().expect("AT_EXECFN should be present under glibc/musl");
        assert!(
            from_auxv.exists(),
            "AT_EXECFN path {from_auxv:?} should name an existing file"
        );
        // It refers to the same on-disk file as `current_exe()` (which resolves
        // via `/proc/self/exe`). Compare canonical paths so a relative or
        // symlinked `AT_EXECFN` still matches.
        let via_proc = std::env::current_exe().unwrap();
        assert_eq!(
            std::fs::canonicalize(&from_auxv).unwrap(),
            std::fs::canonicalize(&via_proc).unwrap(),
            "AT_EXECFN and /proc/self/exe should name the same binary"
        );
    }
}
