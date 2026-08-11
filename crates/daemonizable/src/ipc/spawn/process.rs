//! Parent-side fork+exec machinery: re-exec the current binary (or a test
//! helper) as a background child, wire up the IPC channel, and — for the real
//! daemon path — validate the build-id handshake. The validated daemon is a
//! *grandchild*: the re-exec'd child (stage 1) forks once more so the daemon
//! is never a session leader, and the forked child immediately re-execs into
//! the final daemon image (stage 2); the direct child this parent holds a
//! `Child` handle for is the short-lived stage-1 intermediate.
//!
//! The parent's half of the daemonization protocol lives here; the public
//! step-by-step reference is [`crate::protocol`] — keep that page in sync
//! when changing behavior here.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use command_fds::{CommandFdExt, FdMapping};
use serde::{Serialize, de::DeserializeOwned};

use super::handshake::{HANDSHAKE_TIMEOUT, validate_handshake_and_build_client};
use super::{DAEMON_CHANNEL_FD, TOKEN_LEN, TOKEN_STAGE1, TOKEN_STAGE2, stage_token};
use crate::ipc::RpcClient;
use crate::ipc::error::SpawnDaemonError;
// Via the `rpc` submodule, not `crate::ipc`'s re-export: that re-export is the
// `testutils` surface (cfg-gated), while this is `ipc`-internal plumbing.
use crate::ipc::rpc::RpcConnection;

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
/// `AT_EXECFN` or `argv[0]` is resolved against a cwd that may have changed — but the
/// build-id handshake still turns a swapped or wrong binary into a clean typed
/// error ([`HandshakeError::Mismatch`](crate::HandshakeError)) rather than a
/// silently wrong daemon. `current_exe()` is deliberately **not** the Linux
/// fallback: on Linux it `readlink`s `/proc/self/exe` itself, so it fails for
/// the very same reason the primary path did.
///
/// On non-Linux, `current_exe()` is the best we have. The build-id handshake
/// covers the gap.
///
/// Crate-visible because the daemon child's stage 1 resolves the same path
/// again for its stage-2 re-exec (see `app::daemon_child`).
pub(crate) fn daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
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
/// [`daemon_exe_path`]): gather the process facts, then let the pure
/// [`resolve_linux_exe_path`] make the decision — the split exists so every
/// arm of the policy (including the secure-execution refusal, unreachable in
/// any test environment) is unit-testable without a /proc-less setuid host.
#[cfg(target_os = "linux")]
fn linux_daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
    // Detect whether `/proc` is actually mounted by trying to *read* the magic
    // link. `read_link` succeeding proves the link resolves; the resolver then
    // hands the LITERAL "/proc/self/exe" string (not the read-link target) to
    // `execve` so the same-inode guarantee is preserved. A TOCTOU where `/proc`
    // disappears between this probe and the `execve` is astronomically unlikely
    // and no worse than the previous unconditional behavior.
    let proc_self_exe_ok = std::fs::read_link("/proc/self/exe").is_ok();
    // SAFETY: `getauxval` reads the process's own auxiliary vector; it takes
    // no pointers, has no preconditions, and is callable in any process
    // state. It returns 0 when the entry is absent, and AT_SECURE's value is
    // a plain 0/1 flag, not a pointer.
    let secure_exec = unsafe { libc::getauxval(libc::AT_SECURE) } != 0;
    resolve_linux_exe_path(
        proc_self_exe_ok,
        secure_exec,
        exe_path_from_auxv(),
        std::env::args_os().next(),
    )
}

/// The pure decision core of [`linux_daemon_exe_path`]: given the gathered
/// process facts, pick the path to re-exec (or refuse). No syscalls — every
/// arm is exercised by the unit tests below, including the two arms no CI
/// environment can reach live (the secure-execution refusal and the final
/// `NotFound`).
#[cfg(target_os = "linux")]
fn resolve_linux_exe_path(
    proc_self_exe_ok: bool,
    secure_exec: bool,
    auxv_execfn: Option<PathBuf>,
    argv0: Option<std::ffi::OsString>,
) -> Result<PathBuf, SpawnDaemonError> {
    if proc_self_exe_ok {
        return Ok(PathBuf::from("/proc/self/exe"));
    }

    // `/proc` is unavailable, so only the invoker-chosen fallbacks remain. In
    // a secure-execution process (setuid/setgid/file-caps — AT_SECURE != 0)
    // both AT_EXECFN and argv[0] are picked by the *unprivileged* invoker and
    // may be relative paths resolved against a caller-controlled cwd, so
    // re-exec'ing them would let the invoker steer which binary runs with the
    // elevated credentials. Refuse instead — deliberately BEFORE consulting
    // either fallback: /proc-less *and* setuid is vanishingly rare, and a
    // clean error beats a privilege-preserving exec of an unverified path.
    // (The build-id handshake only catches accidents — a malicious binary can
    // read the real binary's build id and replay it, and it has already run
    // arbitrary code by handshake time.) The PermissionDenied kind is a
    // documented contract on `SpawnDaemonError::ExePath` — callers distinguish
    // this refusal from the NotFound exhaustion below via `Error::kind()`.
    if secure_exec {
        return Err(SpawnDaemonError::ExePath(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "/proc is not mounted and this is a secure-execution (setuid/setgid) process; \
             refusing to re-exec via the invoker-controlled AT_EXECFN / argv[0] fallback",
        )));
    }

    // Fall back to the exec-time pathname the kernel stashed in the auxiliary
    // vector.
    if let Some(path) = auxv_execfn {
        return Ok(path);
    }

    // Last resort: `argv[0]`. It may be a bare command name (then `Command`
    // resolves it via `$PATH`) or a path relative to a since-changed cwd —
    // best-effort, and again backstopped by the build-id handshake.
    if let Some(argv0) = argv0
        && !argv0.is_empty()
    {
        return Ok(PathBuf::from(argv0));
    }

    // The NotFound kind is likewise part of the ExePath variant's documented
    // contract: fallbacks consulted and exhausted, not refused.
    Err(SpawnDaemonError::ExePath(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "/proc is not mounted and neither AT_EXECFN nor argv[0] yielded an \
         executable path to re-exec",
    )))
}

/// The pathname used to `execve` this process, as recorded by the kernel in
/// the auxiliary vector under `AT_EXECFN`. Returns `None` if the entry is
/// absent (e.g. a statically odd libc, or a stripped auxv) or useless — a
/// `/dev/fd/N` path from an `fexecve`-style exec, which cannot resolve
/// without `/proc`. Available on glibc and musl via `getauxval(3)`.
#[cfg(target_os = "linux")]
fn exe_path_from_auxv() -> Option<PathBuf> {
    use std::ffi::CStr;

    // SAFETY: `getauxval` is always safe to call; it takes no pointers and
    // returns 0 when the requested type isn't present. On a non-zero return
    // the value is a pointer into the process's own auxiliary vector.
    let val = unsafe { libc::getauxval(libc::AT_EXECFN) };
    if val == 0 {
        return None;
    }
    // `getauxval` returns the pointer as an integer (`c_ulong`);
    // `with_exposed_provenance` spells out the int-to-pointer intent — the
    // address originates outside Rust's provenance tracking (the kernel wrote
    // it), so "exposed" is exactly its provenance status.
    let ptr: *const libc::c_char = std::ptr::with_exposed_provenance(val as usize);
    // SAFETY: for this pointer-typed auxv entry, `ptr` is the kernel-supplied
    // pointer to the NUL-terminated pathname the process was `execve`'d with,
    // stored in the argv/environ/auxv block at the top of the initial stack:
    // correctly aligned (`c_char` has alignment 1), NUL-terminated well within
    // `isize::MAX` bytes (the kernel caps that whole block at stack-size
    // limits, orders of magnitude below `isize::MAX`), and mapped for the
    // whole process lifetime. The borrowed `CStr` is consumed inline (its
    // bytes copied into a `PathBuf` below), so it is never mutated or
    // outlived. One assumption worth naming: nothing rewrites the initial
    // argv/environ area (setproctitle-style tricks could clobber the string
    // and its NUL terminator); neither this crate nor its dependencies does.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    usable_execfn(bytes)
}

/// The pure usability filter for an `AT_EXECFN` value (split from the auxv
/// read so it is unit-testable): reject an empty string, and reject the
/// "/dev/fd/N" shape fexecve(3) / execveat(AT_EMPTY_PATH) records — that path
/// resolves only through /proc (or a /dev/fd symlink into it), which is
/// exactly what's absent whenever the fallback runs. Rejecting it (rather than
/// returning it) also un-shadows the argv[0] fallback, which may still name a
/// usable path.
#[cfg(target_os = "linux")]
fn usable_execfn(bytes: &[u8]) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    if bytes.is_empty() || bytes.starts_with(b"/dev/fd/") {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(bytes)))
}

/// Spawn the current binary as a background daemon via fork+exec — the
/// engine behind `Daemonizer::spawn_daemon`. Re-execs the current binary with
/// an EMPTY argv; stage identity rides in-band channel tokens the parent
/// pre-queues before the spawn (see `TOKEN_MAGIC`'s doc). The child receives
/// its full-duplex channel as fd `DAEMON_CHANNEL_FD` (3); every other fd the
/// framework or Rust's std opened carries `FD_CLOEXEC`, so the kernel closes
/// those during `execve` — fds the application deliberately created
/// *non*-CLOEXEC still survive into the daemon. Validates the build-id
/// handshake.
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
///     to write something to the channel fd (handshake bytes won't match the
///     expected build id).
///
/// The re-exec'd child (stage 1, see `app::daemon_child`) forks a second time
/// and the forked child immediately re-execs into the final daemon image
/// (stage 2), so the daemon is the grandchild; the direct child is a
/// short-lived session-leader intermediate. On success the intermediate is
/// reaped here (it has already `_exit(0)`d). On handshake/spawn failure the
/// spawn is killed via its process group — `kill(-child_pid, SIGKILL)`, which
/// reaches the grandchild — and the intermediate reaped before the error is
/// returned, so a failed spawn leaves no orphan and no unreapable zombie
/// behind in a long-lived caller.
pub(crate) fn spawn_daemon_process<Request, Response>(
    expected_build_id: &str,
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize,
    Response: DeserializeOwned,
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
    // Pre-queue both stage-identity tokens into the parent→daemon direction as
    // one contiguous write before the spawn: stage 1's dispatch consumes
    // token 1, stage 2's (in the re-exec'd image) consumes token 2, then the
    // framed RPC begins. Written by `start_background_process_inner` after the
    // client is built; the test-only `*_with_exe` spawns pass `None` and never
    // pollute their stream.
    let mut tokens = [0u8; TOKEN_LEN * 2];
    tokens[..TOKEN_LEN].copy_from_slice(&stage_token(TOKEN_STAGE1));
    tokens[TOKEN_LEN..].copy_from_slice(&stage_token(TOKEN_STAGE2));
    let (client, child) = start_background_process_inner::<Request, Response>(
        &exe,
        Some(argv0.as_path()),
        &[],
        Some(&tokens),
    )?;

    complete_spawn(client, child, expected_build_id, HANDSHAKE_TIMEOUT)
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
    Request: Serialize,
    Response: DeserializeOwned,
{
    // `None` prequeue: this helper's daemon (`daemonizable-test-background`)
    // builds its `RpcServer` directly and never runs `run()`/dispatch, so it
    // would not consume tokens — writing them would corrupt its first
    // `next_request`. The tradeoff is that this path doesn't exercise
    // tokens+cleanup together; the real framework path (`spawn_daemon_process`)
    // is covered by the framework e2e tests.
    let (client, child) = start_background_process_inner(exe, None, extra_env, None)?;
    complete_spawn(client, child, expected_build_id, HANDSHAKE_TIMEOUT)
}

/// Like [`spawn_daemon_process_with_exe`], with the handshake timeout
/// injectable: exists solely so the failed-spawn-cleanup contract's *timeout*
/// trigger (a child that holds the channel open but never handshakes) is
/// testable without waiting out the production `HANDSHAKE_TIMEOUT`.
#[cfg(any(test, feature = "testutils"))]
#[doc(hidden)]
pub fn spawn_daemon_process_with_exe_and_timeout<Request, Response>(
    exe: &Path,
    expected_build_id: &str,
    extra_env: &[(&OsStr, &OsStr)],
    handshake_timeout: std::time::Duration,
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let (client, child) = start_background_process_inner(exe, None, extra_env, None)?;
    complete_spawn(client, child, expected_build_id, handshake_timeout)
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
    handshake_timeout: std::time::Duration,
) -> Result<RpcClient<Request, Response>, SpawnDaemonError>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    // `child` is the session-leader stage-1 intermediate (see
    // `app::daemon_child`); the real daemon is its forked-then-re-exec'd
    // grandchild. Capture the
    // pid before any wait() so it still names the (live or zombie) direct child.
    let child_pid = child.id() as libc::pid_t;

    match validate_handshake_and_build_client(client, expected_build_id, handshake_timeout) {
        Ok(client) => {
            // The intermediate's only remaining act after spawning stage 2 is
            // `_exit(0)` — but nothing ORDERS that exit before stage 2's
            // handshake (the two run concurrently once the spawn returns), so
            // a successful handshake proves the intermediate is dead or
            // imminently dying, not already dead. This wait() therefore reaps
            // it (near-)immediately in practice. Without it, every successful
            // spawn would park a zombie intermediate in a long-lived caller.
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
            //     child.kill() gets it instead — and the group kill is
            //     repeated after it, for the sliver where setsid lands
            //     between the two.
            // A grandchild the group kills somehow miss (it left the group via
            // its own setsid/setpgid) is delivered channel EOF as soon as the
            // client is dropped on the error return; a daemon that honors the
            // documented run_daemon contract (exit on SenderClosed) then shuts
            // down promptly, but that is the app's obligation — the framework
            // cannot force an escapee that ignores its channel to exit.
            //
            // `Pid::from_raw(-child_pid)` is the process group: nix passes it
            // straight to `kill(2)`, so a negative pid signals the group, same
            // as the raw call. A stale/foreign pid only yields ESRCH/EPERM
            // (discarded).
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-child_pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = child.kill();
            // Repeat the group kill AFTER the direct kill: if stage 1 was
            // still pre-setsid at the first group kill (ESRCH) but got
            // scheduled and completed setsid+spawn in the window before
            // child.kill() delivered, a grandchild now exists in a group the
            // first kill predated. The repeat catches it, and it is safe by
            // the same argument as the first: the direct child is still
            // unreaped (the wait() below hasn't run), so child_pid cannot yet
            // name a foreign process or group.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-child_pid),
                nix::sys::signal::Signal::SIGKILL,
            );
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
    Request: Serialize,
    Response: DeserializeOwned,
{
    // `None` prequeue — see `spawn_daemon_process_with_exe`.
    let (client, _child) = start_background_process_inner(exe, None, extra_env, None)?;
    Ok(client)
}

/// Common fork+exec machinery shared by [`spawn_daemon_process`] and the
/// `testutils` spawn helpers (`start_background_process_with_exe` and
/// `spawn_daemon_process_with_exe`).
///
/// `prequeue`, when `Some`, is written raw to the parent→daemon direction after
/// the client is built but BEFORE `Command::spawn` — the stage-identity tokens,
/// queued in the socket buffer before the child exists so no ordering race is
/// possible. Only the real [`spawn_daemon_process`] passes it; the `*_with_exe`
/// helpers pass `None`.
fn start_background_process_inner<Request, Response>(
    exe: &Path,
    argv0: Option<&Path>,
    extra_env: &[(&OsStr, &OsStr)],
    prequeue: Option<&[u8]>,
) -> Result<(RpcClient<Request, Response>, std::process::Child), SpawnDaemonError>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let rpc_channel = RpcConnection::<Request, Response>::new_channel()?;
    let (mut client, child_fd) = rpc_channel.into_client_and_child_fd();

    // Pre-queue the stage-identity tokens (if any) BEFORE the spawn, so they sit
    // in the socket buffer before the child exists — the daemon's dispatch reads
    // them ahead of any framed request. A single small write into an empty
    // AF_UNIX stream buffer can't block or short-write.
    if let Some(prequeue) = prequeue {
        client
            .write_channel_prelude(prequeue)
            .map_err(|source| SpawnDaemonError::Spawn {
                path: exe.to_owned(),
                source,
            })?;
    }

    // No argv beyond argv0, BY DESIGN: stage identity rides the in-band
    // channel tokens (see `TOKEN_MAGIC`), and the documented contract is that
    // the daemon's argv stays empty (`run_daemon` sees no injected argument).
    // Do not add an args parameter here without confronting that invariant.
    let mut cmd = Command::new(exe);
    if let Some(argv0) = argv0 {
        cmd.arg0(argv0);
    }
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
    cmd.fd_mappings(vec![FdMapping {
        parent_fd: child_fd,
        child_fd: DAEMON_CHANNEL_FD,
    }])
    // Invariant, not an error path: a collision needs two mappings onto the
    // same child fd, and we map a single owned parent fd onto fd 3.
    .expect("a single fd mapping onto fd 3 cannot collide");

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

    /// Every arm of the pure resolution policy, including the two no CI
    /// environment can reach live: the secure-execution refusal and the final
    /// NotFound exhaustion. The io::ErrorKind assertions pin the documented
    /// `SpawnDaemonError::ExePath` kind contract (PermissionDenied = refused
    /// unconsulted, NotFound = fallbacks exhausted).
    #[test]
    fn resolve_linux_exe_path_covers_every_arm() {
        use std::ffi::OsString;

        fn expath_kind(r: Result<PathBuf, SpawnDaemonError>) -> std::io::ErrorKind {
            match r {
                Err(SpawnDaemonError::ExePath(e)) => e.kind(),
                other => panic!("expected ExePath error, got {other:?}"),
            }
        }

        // /proc mounted → the literal magic link, regardless of everything else.
        assert_eq!(
            resolve_linux_exe_path(true, true, None, None).unwrap(),
            PathBuf::from("/proc/self/exe")
        );

        // /proc absent + secure-exec → refusal, BEFORE consulting the
        // fallbacks (they are Some here and must not be used).
        assert_eq!(
            expath_kind(resolve_linux_exe_path(
                false,
                true,
                Some(PathBuf::from("/usr/bin/app")),
                Some(OsString::from("app")),
            )),
            std::io::ErrorKind::PermissionDenied
        );

        // /proc absent, not secure → AT_EXECFN wins over argv[0].
        assert_eq!(
            resolve_linux_exe_path(
                false,
                false,
                Some(PathBuf::from("/usr/bin/app")),
                Some(OsString::from("other")),
            )
            .unwrap(),
            PathBuf::from("/usr/bin/app")
        );

        // No usable AT_EXECFN → argv[0]; an empty argv[0] is skipped.
        assert_eq!(
            resolve_linux_exe_path(false, false, None, Some(OsString::from("app"))).unwrap(),
            PathBuf::from("app")
        );
        assert_eq!(
            expath_kind(resolve_linux_exe_path(
                false,
                false,
                None,
                Some(OsString::new())
            )),
            std::io::ErrorKind::NotFound
        );

        // Nothing at all → NotFound exhaustion.
        assert_eq!(
            expath_kind(resolve_linux_exe_path(false, false, None, None)),
            std::io::ErrorKind::NotFound
        );
    }

    /// The AT_EXECFN usability filter: empty and fexecve-style "/dev/fd/N"
    /// values are rejected (unresolvable without /proc, and returning them
    /// would shadow a possibly-usable argv[0]); ordinary paths pass through.
    #[test]
    fn usable_execfn_rejects_empty_and_dev_fd() {
        assert_eq!(usable_execfn(b""), None);
        assert_eq!(usable_execfn(b"/dev/fd/7"), None);
        assert_eq!(
            usable_execfn(b"/usr/bin/app"),
            Some(PathBuf::from("/usr/bin/app"))
        );
        assert_eq!(usable_execfn(b"./app"), Some(PathBuf::from("./app")));
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
