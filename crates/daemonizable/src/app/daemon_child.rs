//! The re-exec'd daemon child's two-stage startup sequence, run straight from
//! [`run`](super::run) before any app code.
//!
//! **Stage 1** (env-marker arm; a fresh image the parent spawned): validate
//! the inherited fds, `setsid`, fork — and the forked child immediately
//! re-execs this binary into stage 2, so the only post-fork instructions are
//! `execve` and, on its failure, `write`/`_exit`. **Stage 2** (argv-sentinel
//! arm; another fresh image): claim the inherited fds, detach the working
//! directory, complete the build-id handshake, then hand off to the
//! application's daemon entry point.
//!
//! The exec between the forks is what makes the second fork unconditionally
//! sound: even if pre-main constructors spawned threads in stage 1's image,
//! everything the forked child runs is async-signal-safe, and stage 2 never
//! forks at all. The env marker never reaches stage 2 (stage 1 builds the
//! `execve` environment without it), so nothing ever mutates the daemon's
//! environment either — the historical `env::remove_var` (and its
//! no-concurrent-env-readers contract) is gone. What used to be a chain of
//! "the process is genuinely single-threaded here" arguments is now two
//! structural facts: post-fork code is async-signal-safe, and the daemon
//! image is never forked from.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use super::Daemonizable;
use crate::ipc::{
    DAEMON_CHILD_ENV_VAR, DAEMON_STAGE2_ARGV, RpcServer, daemon_exe_path,
    rpc_server_from_inherited_fds, send_handshake, validate_inherited_fds,
};

/// Stage 1: the parent's direct child lands here, straight from
/// [`run`](super::run) — before any app code. Order matters: validate fds
/// (exit 2) → `setsid` (exit 1) → resolve the re-exec path and build the
/// `execve` arrays (exit 1) → fork (failure exit 1) → the forked child execs
/// stage 2 (exec failure `_exit(126)`), while this process — the short-lived
/// session-leader intermediate — `_exit(0)`s. Every failure before the fork
/// reports on the still-attached stderr; the parent additionally observes any
/// stage-1 death as EOF on the handshake pipe.
pub(super) fn run_as_daemon_stage1() -> ! {
    // Probe fds 3/4 (no ownership taken — the authoritative claim happens in
    // stage 2) so the overwhelmingly-common failure mode — a curious user
    // hand-exporting the env marker in a shell, with nothing plumbed onto
    // fds 3/4 — fails HERE, pre-fork: explanatory message on the inherited
    // stderr, exit code 2 for the shell, no session created, no process left
    // behind. Exactly the historical single-stage behavior.
    if let Err(err) = validate_inherited_fds() {
        eprintln!("daemon child: {err}");
        std::process::exit(2);
    }

    // setsid is fatal on failure: without a new session the daemon would die
    // along with the parent's controlling terminal. Runs in stage 1, before
    // the fork, for two reasons: the forked child must be a NON-leader member
    // of the new session (see the fork comment below), and setsid() makes
    // this pid — the parent's direct child — the process-group id that the
    // parent's failed-spawn cleanup signals via kill(-child_pid).
    if let Err(err) = nix::unistd::setsid() {
        eprintln!("daemon child: setsid() failed: {err}");
        std::process::exit(1);
    }

    // Resolve the path to re-exec for stage 2 — the same resolver the parent's
    // spawn used: the literal "/proc/self/exe" where available (same-inode
    // guarantee even if the on-disk binary was replaced mid-run), the
    // AT_EXECFN/argv[0] fallback without /proc, `current_exe()` elsewhere. A
    // swapped or wrong binary is caught by the parent's build-id handshake
    // validation, exactly as for the first exec.
    let exe = match daemon_exe_path() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("daemon child: cannot resolve the executable to re-exec for stage 2: {err}");
            std::process::exit(1);
        }
    };

    // Build execve's argument and environment arrays BEFORE forking. The
    // forked child must not allocate (fork SAFETY below), so everything it
    // will dereference is materialized here, in ordinary pre-fork code where
    // allocation is unrestricted — threads or not.
    //
    // argv: [inherited argv0 (cosmetic — keeps `ps` output stable across the
    // stages), stage-2 sentinel]. The sentinel rides argv rather than env
    // because argv is not inherited by the daemon's own children: there is
    // nothing to scrub later, which is what lets stage 2 avoid
    // `env::remove_var` entirely.
    //
    // envp: the current environment minus DAEMON_CHILD_ENV_VAR. Filtering it
    // out here — rather than removing it in stage 2 — means the marker never
    // exists in the daemon's image at all.
    let exe_c = match CString::new(exe.into_os_string().into_vec()) {
        Ok(c) => c,
        Err(_) => {
            // Unix paths cannot contain an interior NUL; unreachable in practice.
            eprintln!("daemon child: executable path contains a NUL byte");
            std::process::exit(1);
        }
    };
    let argv0 = std::env::args_os()
        .next()
        .filter(|a| !a.is_empty())
        .and_then(|a| CString::new(a.into_vec()).ok())
        .unwrap_or_else(|| exe_c.clone());
    let sentinel =
        CString::new(DAEMON_STAGE2_ARGV).expect("DAEMON_STAGE2_ARGV contains no NUL byte");
    let argv_storage = [argv0, sentinel];
    let mut envp_storage = Vec::new();
    for (key, value) in std::env::vars_os() {
        if key.as_os_str() == OsStr::new(DAEMON_CHILD_ENV_VAR) {
            continue;
        }
        let mut entry = Vec::with_capacity(key.len() + 1 + value.len());
        entry.extend_from_slice(key.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        match CString::new(entry) {
            Ok(c) => envp_storage.push(c),
            Err(_) => {
                // environ entries are themselves NUL-terminated C strings, so
                // an interior NUL cannot round-trip out of them; unreachable
                // in practice. Failing loudly beats silently dropping a
                // variable the daemon might need.
                eprintln!("daemon child: environment entry contains a NUL byte");
                std::process::exit(1);
            }
        }
    }
    // NULL-terminated pointer arrays into the storage above, in the shape
    // execve consumes. Also built pre-fork: the child only dereferences.
    let argv_ptrs: Vec<*const libc::c_char> = argv_storage
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp_storage
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Second fork (daemon(7) step 7): the session-leader intermediate exits
    // immediately, so the surviving child is never a session leader and can
    // never acquire a controlling terminal — per POSIX XBD 11.1.3 a ctty-less
    // session leader that open()s a tty without O_NOCTTY may acquire it as
    // its controlling terminal, and TIOCSCTTY likewise requires a session
    // leader; a non-leader is structurally immune to both.
    //
    // SAFETY: after `fork()` in a multithreaded process, the child may only
    // run async-signal-safe code until it execs. That requirement is met BY
    // CONSTRUCTION here, with no assumption about how many threads exist: the
    // child branch calls only `execve` (async-signal-safe; on success it never
    // returns) and, on exec failure, `write` and `_exit` (both
    // async-signal-safe). Every pointer the child dereferences was
    // materialized before the fork. This is what the exec-between-forks buys:
    // stage 1 may legally be multithreaded — e.g. a pre-main constructor in
    // the application's dependency graph spawned a thread — without making
    // this fork unsound.
    //
    // Ordering — all load-bearing:
    //   * AFTER setsid(): the forked child must be a non-leader member of the
    //     new session, and setsid() made this pid the process-group id that
    //     the parent's failed-spawn cleanup signals via kill(-child_pid); the
    //     child stays in that group across its exec.
    //   * BEFORE the handshake (sent by stage 2): the parent must validate —
    //     and pipe-EOF liveness must track — the process that actually serves.
    //   * The intermediate must do NO work between fork and _exit — no
    //     subprocess, no fd dup that escapes — so it cannot linger as a pipe
    //     write-end holder.
    //
    // Alternative considered and rejected: clone3(CLONE_PARENT) would keep the
    // daemon a direct child of the spawner (no group-kill, trivial PPID), but
    // it is Linux-only, bypasses std::process::Command, and resurrects the
    // zombie caveat this second fork removes.
    match unsafe { libc::fork() } {
        -1 => {
            // Fatal, like a failed setsid: without the second fork the daemon
            // would remain a session leader that can acquire a controlling
            // terminal. Degrading to single-fork operation would silently
            // break the documented "never a session leader" guarantee, so
            // fail the spawn instead — the parent sees EOF on the handshake
            // and the caller can retry.
            eprintln!(
                "daemon child: fork() after setsid failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        0 => {
            // The future daemon: exec stage 2. The ONLY post-fork code.
            //
            // SAFETY: `execve` is async-signal-safe and dereferences exactly
            // its three arguments: `exe_c` is a live NUL-terminated `CString`;
            // `argv_ptrs`/`envp_ptrs` are live NULL-terminated arrays of
            // pointers into live `CString`s — all materialized before the
            // fork and kept alive in this frame (the fork's copy-on-write
            // image preserves them at the same addresses). On success it does
            // not return; on failure it only sets errno.
            let _ =
                unsafe { libc::execve(exe_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
            // exec failed. Only async-signal-safe calls are permitted here —
            // no eprintln! (allocates, locks) — so report with a raw write of
            // a static message and _exit. The parent independently observes
            // the failure as EOF on the handshake pipe.
            const MSG: &[u8] = b"daemon child: execve for stage-2 re-exec failed\n";
            // SAFETY: `write` is async-signal-safe; it reads `MSG.len()` bytes
            // from `MSG`, a static buffer valid for exactly that length, and
            // fd 2 is a bare int (a closed stderr yields EBADF, never UB).
            // Best-effort: the result is deliberately ignored.
            let _ = unsafe { libc::write(libc::STDERR_FILENO, MSG.as_ptr().cast(), MSG.len()) };
            // SAFETY: `_exit` takes a plain int, passes no pointers, is
            // async-signal-safe and unconditionally callable; it diverges,
            // matching the `-> !` context. 126 distinguishes "exec failed"
            // from stage 2's exit codes in post-mortems.
            unsafe { libc::_exit(126) };
        }
        _stage2_pid => {
            // Intermediate session leader: its only job was the fork above.
            // `_exit`, not `std::process::exit`/return — `_exit` skips atexit
            // handlers and C stdio flushing (a buffered write from a
            // hand-written main preamble must flush at most once, in the
            // daemon) and skips Rust drops. Its inherited copies of fds 3/4
            // close with it; the stage-2 child's copies keep the pipes open.
            //
            // SAFETY: `libc::_exit(0)` takes a plain int, passes no pointers,
            // owns/aliases nothing, is async-signal-safe and unconditionally
            // callable in any process state. It diverges, matching the `-> !`
            // context.
            unsafe { libc::_exit(0) };
        }
    }
}

/// Stage 2: the final daemon image, re-exec'd by stage 1 with the argv
/// sentinel, lands here straight from [`run`](super::run) — before any app
/// code. Order: claim fds (exit 2) → `chdir("/")` (warn only) → send the
/// build-id handshake (exit 127) → hand off to the app. This image never
/// forks and never mutates its environment: threads that pre-main
/// constructors may have spawned here are ordinary daemon threads, hazardous
/// to nothing in this function.
pub(super) fn run_as_daemon_stage2<A: Daemonizable>() -> ! {
    // SAFETY: `rpc_server_from_inherited_fds` requires fds 3/4 to be this
    // process's exclusively-owned inherited RPC pipe ends (see its `# Safety`).
    // The load-bearing argument is positional, not trust in the argv sentinel
    // (which any user can pass by hand): this call runs in a fresh post-exec
    // image before all app code — `run` executed only the once-guard CAS, one
    // env read, and one argv read before dispatching here — so no live
    // `OwnedFd`/`File` in this process can own fd 3 or 4, and the claim mints
    // the *sole* owners of whatever sits there. In the intended configuration
    // that is the parent's pipe ends: `dup2`'d onto fds 3/4 across the first
    // exec, then preserved untouched across stage 1's fork and second exec
    // (stage 1 only probes them; FD_CLOEXEC is restored by this claim, below,
    // exactly once, in the image that keeps them). A hand-launched
    // `app __daemonizable-daemon` with closed or non-pipe fds is rejected by
    // the callee's fstat probe with a clean error; even deliberately plumbed
    // FIFOs yield a broken RPC channel, never aliased ownership. It is also
    // the sole claim. Residual assumption, stated in [`run`](super::run)'s
    // docs: no pre-main constructor deliberately claimed or closed raw fds
    // 3/4 — they are open in this image, so a constructor's own `open`s
    // cannot land on those numbers accidentally.
    let mut server: RpcServer<A::Request, A::Response> =
        match unsafe { rpc_server_from_inherited_fds() } {
            Ok(s) => s,
            Err(err) => {
                eprintln!("daemon child: {err}");
                std::process::exit(2);
            }
        };

    // Drop the inherited working directory (chdir to `/`) so the daemon doesn't
    // pin the parent's cwd filesystem for its whole lifetime — otherwise
    // unmounting e.g. the USB stick the user launched from would fail with
    // EBUSY. Safe because the app must resolve any cwd-relative paths *before*
    // it daemonizes (canonicalize them on the parent side); the daemon should
    // only ever receive absolute paths. Non-fatal: if chdir somehow fails
    // the daemon still works, it just keeps the parent's cwd pinned — worth a
    // warning, not a crash. Runs before the handshake so a failure can still
    // surface on the not-yet-detached stderr.
    if let Err(err) = std::env::set_current_dir("/") {
        eprintln!(
            "daemon child: warning: chdir(\"/\") failed, keeping inherited working directory: {err}"
        );
    }

    if let Err(err) = send_handshake(&mut server, &A::build_id()) {
        eprintln!("daemon child: failed to send build-id handshake to parent: {err}");
        std::process::exit(127);
    }

    // TODO Batteries (see the full plan in README.md, "No batteries (yet)"):
    //   opt-in daemonization options — flock-locked pid file, privilege drop
    //   (initgroups/setgid/setuid), chroot, umask, signal-mask reset, fd
    //   hygiene (close_range), log-file stdio redirection — configured on the
    //   parent side and applied HERE, before entering `run_daemon`, so every
    //   failure can be reported to the parent as a typed error before it exits.
    //   This reintroduces a framework-owned bootstrap frame (config-in from the
    //   parent, result-out back: empty = ok, otherwise a framework error the
    //   parent maps into SpawnDaemonError variants like AlreadyRunning /
    //   DropPrivileges) — a deliberate, framework-level addition, distinct from
    //   the app-facing payload that once lived here. Ordering within this
    //   block: umask → sigmask reset → close_range (must NOT close the
    //   inherited pipe fds 3/4) → pid file (this process IS the final daemon —
    //   stage 1's fork already happened — so std::process::id() here is the
    //   pid to record) → chown pid file → open log files → chroot →
    //   initgroups/setgid → setuid → report result. Note: setuid must stay in
    //   stage 2 — dropping privileges in stage 1 could give the intermediate
    //   a different uid and make the parent's kill(-child_pid) cleanup hit
    //   EPERM.

    // The stage-1 env marker never existed in this image (stage 1 filtered it
    // out of execve's envp), and the stage-2 sentinel rides argv, which
    // children don't inherit — so processes spawned from `run_daemon` below
    // can't be misdetected as daemon stages.
    A::run_daemon(server)
}
