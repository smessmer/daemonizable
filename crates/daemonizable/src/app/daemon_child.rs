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
//! runs no hand-written post-fork code at all, and stage 2 never forks (the
//! constructor caveats that remain are listed on [`run`](super::run)). The
//! surviving intermediate still `_exit(0)`s directly (the one remaining raw
//! call) rather than returning, so it skips atexit handlers, C stdio flushing,
//! and Rust drops. Stage identity rides an in-band channel token in both stages
//! (see `TOKEN_MAGIC`'s doc), so the daemon's argv stays empty and neither
//! image reads or mutates the environment for dispatch — the environment passes
//! through both execs untouched.
//!
//! Both stage sequences are part of the daemonization protocol; the public
//! step-by-step reference is [`crate::protocol`] — keep that page in sync
//! when changing behavior here.

use std::os::unix::process::CommandExt;

use super::Daemonizable;
use crate::ipc::{
    RpcServer, channel_has_stage2_token, daemon_exe_path, rpc_server_from_inherited_fd,
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
    if !channel_has_stage2_token() {
        eprintln!(
            "daemon stage 1: the channel is missing stage 2's token. This entry point is \
             internal to this binary; do not invoke it directly."
        );
        std::process::exit(2);
    }

    if let Err(err) = nix::unistd::setsid() {
        eprintln!("daemon stage 1: setsid() failed: {err}");
        std::process::exit(1);
    }

    let exe = match daemon_exe_path() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!(
                "daemon stage 1: cannot resolve the executable to re-exec for stage 2: {err}"
            );
            std::process::exit(1);
        }
    };
    // Alternative considered and rejected: clone3(CLONE_PARENT) would keep the
    // daemon a direct child of the spawner (no group-kill, trivial PPID), but it
    // is Linux-only, bypasses std::process::Command, and resurrects the zombie
    // caveat this second spawn removes.
    let mut cmd = std::process::Command::new(&exe);
    if let Some(argv0) = std::env::args_os().next().filter(|a| !a.is_empty()) {
        cmd.arg0(argv0);
    }
    match cmd.spawn() {
        Ok(_child) => {
            // SAFETY: `libc::_exit(0)` takes a plain int, passes no pointers,
            // owns/aliases nothing, is async-signal-safe and unconditionally
            // callable in any process state. It diverges, matching the `-> !`
            // context.
            unsafe { libc::_exit(0) };
        }
        Err(err) => {
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
    // The `sid != pgid` arm is a backstop against a stage-1 pre-main constructor
    // consuming token 1 and thereby routing the parent's direct child here; it
    // only fires when the launcher itself has sid != pgid, so the documented
    // "constructors must not read fd 3" caveat remains the real protection.
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

    if let Err(err) = verify_channel_peer_creds() {
        eprintln!("daemon stage 2: {err}");
        std::process::exit(1);
    }

    // SAFETY: `rpc_server_from_inherited_fd` requires fd 3 to be this process's
    // exclusively-owned inherited channel socket (see its `# Safety`). The
    // load-bearing argument is positional, not trust in the channel token (a
    // public constant any user can write): this call runs in a fresh post-exec
    // image before all app code — `run` executed only the once-guard CAS and the
    // dispatch peek/consume before dispatching here, and the guards above read
    // process ids and peer credentials, not fds — so no live `OwnedFd`/`File` in
    // this process can own fd 3, and the claim mints the *sole* owner of whatever
    // sits there. In the intended configuration that is the parent's socketpair
    // end: `dup2`'d onto fd 3 across the first exec, then preserved untouched
    // across stage 1's fork and second exec (stage 1 only probes it; FD_CLOEXEC is
    // restored by this claim, exactly once, in the image that keeps it). Reaching
    // this claim at all means dispatch already peeked a stage-2 token off fd 3, so
    // it is a live socket — a closed or non-socket fd 3 classifies as foreground
    // and never routes here. Even a deliberately plumbed socket that clears the
    // guards above yields at most a broken RPC channel, never aliased ownership.
    // Residual assumption, stated in [`run`](super::run)'s docs: no pre-main
    // constructor deliberately claimed or closed raw fd 3 — it is open in this
    // image, so a constructor's own `open`s cannot land on that number by accident.
    let mut server: RpcServer<A::Request, A::Response> =
        match unsafe { rpc_server_from_inherited_fd() } {
            Ok(s) => s,
            Err(err) => {
                eprintln!("daemon stage 2: {err}");
                std::process::exit(2);
            }
        };

    if let Err(err) = std::env::set_current_dir("/") {
        eprintln!(
            "daemon stage 2: warning: chdir(\"/\") failed, keeping inherited working directory: {err}"
        );
    }

    if let Err(err) = send_handshake(&mut server, &A::build_id()) {
        eprintln!("daemon stage 2: failed to send build-id handshake to parent: {err}");
        std::process::exit(127);
    }

    // TODO Batteries (full plan in README.md, "No batteries (yet)"): opt-in
    //   daemonization options applied here, before entering `run_daemon`, in the
    //   order umask → sigmask reset → close_range (must NOT close fd 3, nor the
    //   server's runtime dup of it) → pid file → chown pid file → open log files
    //   → chroot → initgroups/setgid → setuid. setuid must stay in stage 2:
    //   dropping privileges in stage 1 could give the intermediate a different
    //   uid and make the parent's kill(-child_pid) cleanup hit EPERM.

    A::run_daemon(server)
}
