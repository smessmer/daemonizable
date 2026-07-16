//! The re-exec'd daemon child's startup sequence, run straight from
//! [`run`](super::run) before any app code: claim the inherited fds, start a
//! new session, fork again so the daemon is never a session leader, detach the
//! working directory, complete the build-id handshake, then hand off to the
//! application's daemon entry point.

use super::Daemonizable;
use crate::ipc::{DAEMON_CHILD_ENV_VAR, RpcServer, rpc_server_from_inherited_fds, send_handshake};

/// The re-exec'd daemon child lands here, straight from [`run`](super::run) —
/// before any app code. Order matters: drop the daemon-child marker (while
/// still genuinely single-threaded) → claim fds (exit 2) → `setsid` (exit 1) →
/// second fork (intermediate `_exit(0)`; fork failure exit 1) → `chdir("/")`
/// (warn only) → send handshake (exit 127) → hand off to the app. Exit codes 2
/// and 1 come from the direct child (pre-fork); the 127 and the chdir warning
/// come from the surviving grandchild (post-fork).
pub(super) fn run_as_daemon_child<A: Daemonizable>() -> ! {
    // Drop the daemon-child marker before anything else runs. Its detection job
    // is done (`run` already read it to dispatch us here) and it must be gone
    // before this process spawns any child of its own — including a future
    // daemonizable app that re-exec's itself — so those children aren't
    // misdetected as OUR daemon child.
    //
    // SAFETY: `std::env::remove_var` is unsound if another thread is
    // concurrently in libc code that reads `environ` (getenv, or localtime_r via
    // TZ, getaddrinfo, ...). It is sound *here* precisely because this is the
    // FIRST statement of the daemon-child arm: we reached it from a fresh
    // post-exec image with no app-controlled code yet run — `A::build_id()`
    // (in send_handshake) runs later — and the application's `main` preamble is
    // empty
    // (guaranteed by `#[daemonizable::main]`; required of any hand-written
    // `main`, see [`run`](super::run)). So the process is genuinely
    // single-threaded at this point, and no other thread can observe `environ`
    // mid-mutation.
    unsafe {
        std::env::remove_var(DAEMON_CHILD_ENV_VAR);
    }

    // SAFETY: `rpc_server_from_inherited_fds` requires fds 3/4 to be the
    // daemon's exclusively-owned inherited RPC pipe ends (see its `# Safety`).
    // That holds here: `run` only dispatches to `run_as_daemon_child` after
    // detecting the `DAEMON_CHILD_ENV_VAR` marker the parent's spawn sets, so
    // this is a fresh post-exec image the framework launched as the daemon
    // child, with the parent's pipe ends `dup2`'d onto fds 3/4 across `execve`
    // and owned by nothing else in this process. It is also the sole claim.
    let mut server: RpcServer<A::Request, A::Response> =
        match unsafe { rpc_server_from_inherited_fds() } {
            Ok(s) => s,
            Err(err) => {
                eprintln!("daemon child: {err}");
                std::process::exit(2);
            }
        };

    // setsid is fatal on failure: without a new session the daemon would die
    // along with the parent's controlling terminal.
    if let Err(err) = nix::unistd::setsid() {
        eprintln!("daemon child: setsid() failed: {err}");
        std::process::exit(1);
    }

    // Second fork (daemon(7) step 7): the session-leader intermediate exits
    // immediately, so the surviving grandchild is never a session leader and
    // can never acquire a controlling terminal — per POSIX XBD 11.1.3 a
    // ctty-less session leader that open()s a tty without O_NOCTTY may acquire
    // it as its controlling terminal, and TIOCSCTTY likewise requires a
    // session leader; a non-leader is structurally immune to both.
    //
    // SAFETY: `libc::fork()` in a *multithreaded* process may run only
    // async-signal-safe code in the child, and this grandchild's post-fork path
    // is NOT async-signal-safe (chdir, then send_handshake allocates and
    // serializes), so soundness requires that the process be single-threaded
    // here. It is: we are a fresh single-threaded post-exec image — no app code
    // has run in this arm yet (`A::build_id()` first runs in send_handshake
    // below), so this is not a fork-in-a-multithreaded-process. (The one
    // residual assumption is that the application's `main` preamble started no
    // thread before `run()`; `#[daemonizable::main]` guarantees an empty
    // preamble. Same assumption as the remove_var SAFETY note at the top.) The
    // claimed pipe fds 3/4 are inherited across fork (FD_CLOEXEC only affects
    // execve), so the grandchild owns them.
    //
    // Ordering — all load-bearing:
    //   * AFTER setsid(): the grandchild must be a non-leader member of the new
    //     session, and setsid() made this pid the process-group id that the
    //     parent's failed-spawn cleanup signals via kill(-child_pid).
    //   * BEFORE send_handshake() below: the parent must validate — and
    //     pipe-EOF liveness must track — the process that actually serves.
    //   * BEFORE chdir("/") below: the chdir (and its warning) belongs to the
    //     grandchild, the process that keeps the cwd.
    //   * The pid-file battery (planned, in the batteries block below) already
    //     sits after this fork, so it records the FINAL daemon pid.
    //
    // The intermediate must do NO work between fork and _exit — no subprocess,
    // no fd dup that escapes — so it cannot linger as a pipe write-end holder.
    //
    // Alternative considered and rejected: clone3(CLONE_PARENT) would keep the
    // daemon a direct child of the spawner (no group-kill, trivial PPID), but
    // it is Linux-only, bypasses std::process::Command, and resurrects the
    // zombie caveat this second fork removes.
    match unsafe { libc::fork() } {
        -1 => {
            // Fatal, like a failed setsid: without the second fork the daemon
            // would remain a session leader that can acquire a controlling
            // terminal. Degrading to single-fork operation would silently break
            // the documented "never a session leader" guarantee, so fail the
            // spawn instead — the parent sees EOF on the handshake and the
            // caller can retry.
            eprintln!(
                "daemon child: fork() after setsid failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        0 => {
            // Grandchild: the actual daemon. Falls through to chdir and the
            // handshake below.
        }
        _grandchild_pid => {
            // Intermediate session leader: its only job was the fork above.
            // `_exit`, not `std::process::exit`/return — `_exit` skips atexit
            // handlers and C stdio flushing (a buffered write from a
            // hand-written main preamble must flush at most once, in the
            // daemon) and skips Rust drops (the live `server` owns fds 3/4;
            // the grandchild's inherited copies keep the pipes open regardless).
            //
            // SAFETY: `libc::_exit(0)` is `unsafe` only under libc's blanket
            // `extern "C"` rule. POSIX `_exit(int)` takes a plain int (here the
            // valid `c_int` `0`), passes no pointers, owns/aliases nothing, is
            // async-signal-safe, and is unconditionally callable in any process
            // state — so it has no preconditions to satisfy. It diverges,
            // matching the `-> !` context.
            unsafe { libc::_exit(0) };
        }
    }

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
    //   inherited pipe fds 3/4) → pid file (write the FINAL pid — this runs in
    //   the grandchild, after the second fork above) → chown pid file → open
    //   log files → chroot → initgroups/setgid → setuid → report result.
    //   Note: setuid must stay AFTER the second fork — dropping privileges
    //   before it could give the intermediate a different uid and make the
    //   parent's kill(-child_pid) cleanup hit EPERM.

    // The daemon-child marker was already dropped at the top of this function
    // (see the SAFETY note there), so processes spawned from `run_daemon` below
    // won't be misdetected as our daemon child.
    A::run_daemon(server)
}
