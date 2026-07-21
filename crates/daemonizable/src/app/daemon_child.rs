//! The re-exec'd daemon child's two-stage startup sequence, run straight from
//! [`run`](super::run) before any app code. `run`'s dispatch peeks and consumes
//! the stage's in-band token off the channel fd before calling into these.
//!
//! **Stage 1** (its token is `TOKEN_MAGIC ‖ TOKEN_STAGE1`; a fresh image the
//! parent spawned): verify stage 2's token is queued, `setsid`, then re-exec
//! this binary into stage 2 via [`std::process::Command`] — the intermediate
//! session leader `_exit(0)`s once the spawn returns, so the surviving child is
//! never a session leader. **Stage 2** (its token is `TOKEN_MAGIC ‖ TOKEN_STAGE2`;
//! another fresh image): guard provenance (topology + peer credentials), claim
//! the channel fd, detach the working directory, complete the build-id
//! handshake, then hand off to the application's daemon entry point.
//!
//! Routing the second spawn through `std::process::Command` is what makes it
//! sound without any single-threadedness argument: even if pre-main
//! constructors spawned threads in stage 1's image, std performs the fork+exec
//! (or `posix_spawn`) with its own async-signal-safe child setup, so this crate
//! runs no hand-written post-fork code at all, and stage 2 never forks. (The
//! one residue outside anyone's control is `pthread_atfork` child handlers,
//! which libc runs inside `fork()` itself — a handler that is not fork-safe
//! under threads is broken for any fork+exec spawn, `std::process::Command`
//! included, and is its registrant's responsibility.) The surviving
//! intermediate still `_exit(0)`s directly (the one remaining raw call) rather
//! than returning, so it skips atexit handlers, C stdio flushing, and Rust
//! drops. Stage identity rides an in-band channel token in both stages (see
//! `TOKEN_MAGIC`'s doc), so the daemon's argv stays empty and neither image
//! ever reads or mutates the environment for dispatch: the environment passes
//! through both execs untouched (no `environ` walk to race a constructor
//! thread's `setenv`, and no marker to scrub — the tokens live only in the
//! socket buffer and are consumed before any framed byte).

use std::os::unix::process::CommandExt;

use super::Daemonizable;
use crate::ipc::{
    RpcServer, channel_has_stage2_token, daemon_exe_path, rpc_server_from_inherited_fds,
    send_handshake, verify_channel_peer_creds,
};

/// Stage 1: the parent's direct child lands here, straight from
/// [`run`](super::run) — before any app code. `run`'s dispatch already peeked
/// and consumed stage 1's token off fd 3. Order matters: verify token 2 is
/// queued (exit 2) → `setsid` (exit 1) → resolve the re-exec path (exit 1) →
/// spawn stage 2 via [`std::process::Command`] (spawn failure exit 1), then this
/// process — the short-lived session-leader intermediate — `_exit(0)`s. Every
/// failure reports on the still-attached stderr; the parent additionally
/// observes any stage-1 death as EOF on the channel.
pub(super) fn run_as_daemon_stage1() -> ! {
    // Verify — MANDATORY, before setsid — that the parent also queued stage 2's
    // token behind stage 1's (a non-consuming, non-blocking peek). The genuine
    // spawn writes BOTH tokens; a crafted socket carrying only token 1 is
    // rejected HERE, pre-fork (explanatory message on the inherited stderr, exit
    // 2, no session created, no process left behind) — rather than the stage-2
    // image later finding no token and silently running foreground code in a
    // detached process. `run` reached this arm only because token 1 matched, so
    // this doubles as the fd-3-is-a-usable-socket check the old fstat probe did.
    if !channel_has_stage2_token() {
        eprintln!(
            "daemon stage 1: the channel is missing stage 2's token. This entry point is \
             internal to this binary; do not invoke it directly."
        );
        std::process::exit(2);
    }

    // setsid is fatal on failure: without a new session the daemon would die
    // along with the parent's controlling terminal. Runs in stage 1, before
    // the fork, for two reasons: the forked child must be a NON-leader member
    // of the new session (see the fork comment below), and setsid() makes
    // this pid — the parent's direct child — the process-group id that the
    // parent's failed-spawn cleanup signals via kill(-child_pid). (A
    // hand-launched shell job is a process-group leader, so setsid also
    // fails EPERM here for that misuse, exactly like the historical
    // single-stage arm.)
    if let Err(err) = nix::unistd::setsid() {
        eprintln!("daemon stage 1: setsid() failed: {err}");
        std::process::exit(1);
    }

    // Resolve the path to re-exec for stage 2 — the same resolver the
    // parent's spawn used: the literal "/proc/self/exe" where available
    // (same-inode guarantee even if the on-disk binary was replaced mid-run),
    // the AT_EXECFN/argv[0] fallback without /proc, `current_exe()`
    // elsewhere. A swapped or wrong binary is caught by the parent's build-id
    // handshake validation, exactly as for the first exec.
    let exe = match daemon_exe_path() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!(
                "daemon stage 1: cannot resolve the executable to re-exec for stage 2: {err}"
            );
            std::process::exit(1);
        }
    };
    // Second spawn (daemon(7) step 7): re-exec stage 2 as a child of this
    // session-leader intermediate, which exits immediately below — so the
    // surviving daemon is never a session leader and can never acquire a
    // controlling terminal (per POSIX XBD 11.1.3 a ctty-less session leader
    // that open()s a tty without O_NOCTTY may acquire it as its controlling
    // terminal, and TIOCSCTTY likewise requires a session leader; a non-leader
    // is structurally immune to both).
    //
    // Routing through `std::process::Command` rather than a hand-rolled
    // fork+execv means std performs the fork+exec (or `posix_spawn`) with its
    // own async-signal-safe child-side setup — so this crate runs no
    // post-fork code and needs no single-threadedness argument, even if a
    // pre-main constructor spawned threads. The inherited `environ` passes
    // through as the child's environment (`Command` inherits it by default),
    // and argv is `[inherited argv0]` and NOTHING ELSE: stage identity rides
    // an in-band channel token, not argv, so `run_daemon` sees no injected
    // argument. `arg0` keeps `ps`/`top` output stable across the stages (the
    // exe path is often the `/proc/self/exe` magic link). `Command` resolves a
    // bare argv[0]/AT_EXECFN name via $PATH natively — matching what the
    // parent's own first spawn (`spawn_daemon_process`, same `Command`+`arg0`
    // shape) did — so no manual $PATH search is needed here.
    //
    // Fd inheritance: the inherited channel on fd 3 is non-CLOEXEC at this
    // point (the parent's `dup2` cleared the flag), and `Command` neither
    // closes nor remaps it, so it survives into stage 2 exactly as the old
    // `execv` passed it through; stage 2's claim restores CLOEXEC. Only stdio
    // (0/1/2) is touched by `Command`, and it inherits by default.
    //
    // Ordering — all load-bearing:
    //   * AFTER setsid(): the spawned child must be a non-leader member of the
    //     new session, and setsid() made this pid the process-group id that the
    //     parent's failed-spawn cleanup signals via kill(-child_pid); `Command`
    //     does not change the child's process group, so it stays in that group
    //     across its exec.
    //   * BEFORE the handshake (sent by stage 2): the parent must validate —
    //     and channel-EOF liveness must track — the process that actually serves.
    //
    // Alternative considered and rejected: clone3(CLONE_PARENT) would keep the
    // daemon a direct child of the spawner (no group-kill, trivial PPID), but
    // it is Linux-only, bypasses std::process::Command, and resurrects the
    // zombie caveat this second spawn removes.
    let mut cmd = std::process::Command::new(&exe);
    if let Some(argv0) = std::env::args_os().next().filter(|a| !a.is_empty()) {
        cmd.arg0(argv0);
    }
    match cmd.spawn() {
        Ok(_child) => {
            // Intermediate session leader: its only job was the spawn above.
            // `_exit`, not `std::process::exit`/return — `_exit` skips atexit
            // handlers and C stdio flushing (a buffered write from a
            // hand-written main preamble must flush at most once, in the
            // daemon) and skips Rust drops (so `_child` is never waited on —
            // the daemon must outlive this intermediate). Its inherited copy of
            // fd 3 closes with it; the stage-2 child's copy keeps the channel
            // open.
            //
            // SAFETY: `libc::_exit(0)` takes a plain int, passes no pointers,
            // owns/aliases nothing, is async-signal-safe and unconditionally
            // callable in any process state. It diverges, matching the `-> !`
            // context.
            unsafe { libc::_exit(0) };
        }
        Err(err) => {
            // Fatal, like a failed setsid: without the second spawn the daemon
            // would remain a session leader that can acquire a controlling
            // terminal. Degrading to single-fork operation would silently
            // break the documented "never a session leader" guarantee, so
            // fail the spawn instead — the parent sees EOF on the handshake
            // and the caller can retry. (`Command::spawn` collapses fork and
            // exec failures into one error; the parent's handshake EOF is the
            // same signal either way.)
            eprintln!("daemon stage 1: failed to re-exec stage 2 ({exe:?}): {err}");
            std::process::exit(1);
        }
    }
}

/// Stage 2: the final daemon image, re-exec'd by stage 1, lands here straight
/// from [`run`](super::run) — before any app code. `run`'s dispatch already
/// peeked and consumed stage 2's token off fd 3. Order: provenance guard
/// (session/group topology, exit 1) → peer-credential check (exit 1) → claim
/// the channel fd (exit 2) → `chdir("/")` (warn only) → send the build-id
/// handshake (exit 127) → hand off to the app. This image never forks and never
/// touches its environment: threads that pre-main constructors may have spawned
/// here are ordinary daemon threads, hazardous to nothing in this function.
///
/// Do NOT add `setsid`/`setpgid` here: the parent's failed-spawn cleanup
/// signals `kill(-stage1_pid)`, and it reaches this process only because it
/// stays in stage 1's process group (which `execve` preserved).
pub(super) fn run_as_daemon_stage2<A: Daemonizable>() -> ! {
    // Provenance guard on the session/group topology. In the intended flow this
    // image is a non-leader grandchild of stage 1, so sid == pgid == stage 1's
    // pid ≠ our pid. Refuse if any of that fails:
    //   * a session or group LEADER was not started by stage 1's setsid+fork —
    //     it is a hand-run from a shell/supervisor, which running on would turn
    //     into a silently-degraded "daemon" (launcher's session, possibly able
    //     to acquire a controlling terminal), a configuration the historical
    //     single-stage arm made unrepresentable — keep it so;
    //   * sid != pgid means we are NOT in stage 1's setsid'd group even though
    //     we're a non-leader. This is defense-in-depth against the token-eaten
    //     degradation: if a pre-main constructor in the stage-1 IMAGE consumed
    //     token 1, that image's own dispatch would see token 2 and run THIS arm
    //     in the parent's direct child, which never setsid'd/double-forked. It
    //     catches that only when the foreground's own sid != pgid — true under
    //     an interactive job-control shell (the job is its own group leader
    //     while the shell is the session leader), but NOT under a non-job-control
    //     launcher whose sid == pgid (a non-interactive shell/script, cron, or a
    //     process that setsid'd itself — systemd, a container init). So this is a
    //     backstop, not a complete guard; the real protection against a
    //     token-eating constructor is the documented "constructors must not read
    //     fd 3" caveat, plus the peer-cred check below for the cross-principal
    //     case.
    // (A non-leader hand-run with a deliberately plumbed same-principal socket,
    // in a matching session/group, still gets past this — provenance can't be
    // fully authenticated from inheritable state — but the peer-cred check below
    // and "a non-leader can't acquire a controlling terminal" keep the core
    // guarantees.)
    let pid = nix::unistd::getpid();
    let sid = nix::unistd::getsid(None).ok();
    let pgid = nix::unistd::getpgrp();
    let is_session_leader = sid == Some(pid);
    let is_group_leader = pgid == pid;
    let in_stage1_group = sid == Some(pgid);
    if is_session_leader || is_group_leader || !in_stage1_group {
        eprintln!(
            "daemon stage 2: session/process-group topology is not that of a framework-spawned \
             daemon; this entry point is internal and must be reached through the framework's \
             daemon spawn"
        );
        std::process::exit(1);
    }

    // Peer-credential check: the process on the other end of the channel must
    // run with our own effective uid AND gid. The stage token is a PUBLIC
    // accident authenticator (see `TOKEN_MAGIC`), so this — unforgeable by the
    // peer — is what stops a lower-privileged principal from driving a daemon
    // image that gained privilege by changing uid/gid (setuid/setgid) into
    // `run_daemon` over a crafted channel. (It does NOT cover a file-caps binary
    // that keeps the invoker's ids — see `verify_channel_peer_creds`'s scope note.)
    // Runs before the claim, while fd 3 is still just borrowed.
    if let Err(err) = verify_channel_peer_creds() {
        eprintln!("daemon stage 2: {err}");
        std::process::exit(1);
    }

    // SAFETY: `rpc_server_from_inherited_fds` requires fd 3 to be this
    // process's exclusively-owned inherited channel socket (see its `# Safety`).
    // The load-bearing argument is positional, not trust in the channel token
    // (a public constant any user can write): this call runs in a fresh post-exec
    // image before all app code — `run` executed only the once-guard CAS and the
    // dispatch peek/consume before dispatching here, and the guards above read
    // process ids and peer credentials, not fds — so no live `OwnedFd`/`File` in
    // this process can
    // own fd 3, and the claim mints the *sole* owner of whatever sits
    // there. In the intended configuration that is the parent's socketpair end:
    // `dup2`'d onto fd 3 across the first exec, then preserved untouched
    // across stage 1's fork and second exec (stage 1 only probes it;
    // FD_CLOEXEC is restored by this claim, exactly once, in the image
    // that keeps it). Reaching this claim at all means dispatch already peeked a
    // stage-2 token off fd 3, so it is a live socket that also cleared the
    // topology and peer-cred guards above — a closed or non-socket fd 3
    // classifies as foreground and never routes here, and the former
    // `__daemonizable-daemon` argv is inert as a dispatch signal now. Even a
    // deliberately plumbed socket that clears those guards yields at most a
    // broken RPC channel, never aliased ownership. It is also the sole claim. Residual
    // assumption, stated in [`run`](super::run)'s docs: no pre-main
    // constructor deliberately claimed or closed raw fd 3 — it is open
    // in this image, so a constructor's own `open`s cannot land on that
    // number accidentally.
    let mut server: RpcServer<A::Request, A::Response> =
        match unsafe { rpc_server_from_inherited_fds() } {
            Ok(s) => s,
            Err(err) => {
                eprintln!("daemon stage 2: {err}");
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
            "daemon stage 2: warning: chdir(\"/\") failed, keeping inherited working directory: {err}"
        );
    }

    if let Err(err) = send_handshake(&mut server, &A::build_id()) {
        eprintln!("daemon stage 2: failed to send build-id handshake to parent: {err}");
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
    //   inherited channel fd 3, nor the server's runtime dup of it) → pid file
    //   (this process IS the final daemon —
    //   stage 1's fork already happened — so std::process::id() here is the
    //   pid to record) → chown pid file → open log files → chroot →
    //   initgroups/setgid → setuid → report result. Note: setuid must stay in
    //   stage 2 — dropping privileges in stage 1 could give the intermediate
    //   a different uid and make the parent's kill(-child_pid) cleanup hit
    //   EPERM.

    // The stage tokens can't leak to the daemon's children: they live only in
    // the channel socket buffer and were consumed by dispatch before we got
    // here, and the channel fd itself is CLOEXEC (restored by the claim above),
    // so a child never inherits it — and even if it did, the tokens are already
    // gone. No environment marker or argv sentinel exists anywhere in this
    // design (see `TOKEN_MAGIC`'s doc). Processes spawned from `run_daemon`
    // below therefore can't be misdetected as daemon stages.
    A::run_daemon(server)
}
