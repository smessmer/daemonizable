//! The re-exec'd daemon child's startup sequence, run straight from
//! [`run`](super::run) before any app code: claim the inherited fds, start a
//! new session, fork again so the daemon is never a session leader, detach the
//! working directory, complete the build-id handshake, receive and ack the
//! bootstrap payload, then hand off to the application's daemon entry point.

use super::Daemonizable;
use crate::ipc::{
    BOOTSTRAP_TIMEOUT, DAEMON_CHILD_ENV_VAR, RpcServer, rpc_server_from_inherited_fds,
    send_handshake,
};

/// The re-exec'd daemon child lands here, straight from [`run`](super::run) —
/// before any app code. Order matters: claim fds (exit 2) → `setsid` (exit 1) →
/// second fork (intermediate `_exit(0)`; fork failure exit 1) → `chdir("/")`
/// (warn only) → send handshake (exit 127) → receive + decode payload → ack
/// (exit 127) → hand off to the app. Exit codes 2 and 1 come from the direct
/// child (pre-fork); the 127s and the chdir warning come from the surviving
/// grandchild (post-fork).
pub(super) fn run_as_daemon_child<A: Daemonizable>() -> ! {
    let mut server: RpcServer<A::Request, A::Response> = match rpc_server_from_inherited_fds() {
        Ok(s) => s,
        Err(err) => {
            eprintln!("daemon child: {err}");
            std::process::exit(2);
        }
    };

    // setsid is fatal on failure: without a new session the daemon would die
    // along with the parent's controlling terminal.
    if unsafe { libc::setsid() } < 0 {
        eprintln!(
            "daemon child: setsid() failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // Second fork (daemon(7) step 7): the session-leader intermediate exits
    // immediately, so the surviving grandchild is never a session leader and
    // can never acquire a controlling terminal — per POSIX XBD 11.1.3 a
    // ctty-less session leader that open()s a tty without O_NOCTTY may acquire
    // it as its controlling terminal, and TIOCSCTTY likewise requires a
    // session leader; a non-leader is structurally immune to both.
    //
    // Safe here: we are a fresh single-threaded post-exec image — no app code
    // has run in this arm yet (`A::build_id()` first runs in send_handshake
    // below), so this is not a fork-in-a-multithreaded-process. (The one
    // residual assumption is that the application's `main` preamble started no
    // thread before `run()`; `#[daemonizable::main]` guarantees an empty
    // preamble. Same assumption as the remove_var SAFETY note below.) The
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
    //   * The pid-file battery (planned, between handshake and ack) already
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
    if unsafe { libc::chdir(c"/".as_ptr()) } < 0 {
        eprintln!(
            "daemon child: warning: chdir(\"/\") failed, keeping inherited working directory: {}",
            std::io::Error::last_os_error()
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
    //   parent side, shipped as a framework-level part of the bootstrap frame
    //   below, and applied HERE, between handshake and ack, so every failure
    //   can be reported to the parent as a typed error before it exits.
    //   Requires extending the empty bootstrap ack into a result frame
    //   (empty = ok, otherwise a framework error the parent maps into
    //   SpawnDaemonError variants like AlreadyRunning / DropPrivileges).
    //   Ordering within this block: umask → sigmask reset → close_range (must
    //   NOT close the inherited pipe fds 3/4) → pid file (write the FINAL pid
    //   — this runs in the grandchild, after the second fork above) → chown
    //   pid file → open log files → chroot → initgroups/setgid → setuid → ack.
    //   Note: setuid must stay AFTER the second fork — dropping privileges
    //   before it could give the intermediate a different uid and make the
    //   parent's kill(-child_pid) cleanup hit EPERM.
    let payload_bytes = match server.recv_raw_bootstrap_with_timeout(BOOTSTRAP_TIMEOUT) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("daemon child: failed to receive bootstrap payload from parent: {err}");
            std::process::exit(127);
        }
    };
    let payload: A::BootstrapPayload = match postcard::from_bytes(&payload_bytes) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("daemon child: failed to decode bootstrap payload: {err}");
            std::process::exit(127);
        }
    };
    // Ack = "received and decoded". The app applies the payload inside
    // `run_daemon`; if that fails and the daemon exits, the parent's next
    // (blocking) RPC receive sees EOF — that's the liveness backstop.
    if let Err(err) = server.send_raw_bootstrap_ack() {
        eprintln!("daemon child: failed to send bootstrap ack to parent: {err}");
        std::process::exit(127);
    }

    // Drop the marker so processes this daemon spawns (including a future
    // daemonizable app re-exec'ing itself) aren't misdetected as OUR daemon
    // child. SAFETY: the daemon child is still single-threaded here — we
    // re-exec'd with a fresh process image (and the second fork above added no
    // threads) and haven't started any runtime; `run_daemon` (e.g. its tokio
    // init) comes after this line. This runs in the surviving grandchild, the
    // process that actually spawns the daemon's children.
    //
    // TODO The SAFETY claim above is an unenforced assumption, not an
    //   invariant: by this point two pieces of app-controlled code have
    //   already run in the child — `A::build_id()` (in the send_handshake
    //   call above) and the app's `Deserialize` impl for `BootstrapPayload`
    //   (in the postcard::from_bytes above) — and nothing forbids either
    //   from spawning a thread (e.g. a build-info/telemetry library whose
    //   lazy init starts a background thread). A thread doing C-level
    //   getenv (localtime_r reading TZ, getaddrinfo, ...) concurrent with
    //   this remove_var is UB (glibc environ data race). Fix: hoist the
    //   remove_var to the FIRST statement of run_as_daemon_child (the
    //   dispatch in `run` has already consumed the marker, nothing later
    //   reads it, and at that point the exec image genuinely is
    //   single-threaded), and document the residual requirement on `run`'s
    //   contract: `run` must be called before any thread is spawned — the
    //   re-exec'd daemon child executes the application's main preamble
    //   too, so a thread started before `run` also exists in the child
    //   (#[daemonizable::main] guarantees an empty preamble). Note: no
    //   in-tree binary can trigger this today (cryfs's build_id is a
    //   format! of constants and its payload Deserialize is derived); this
    //   matters for external consumers of the published crate.
    unsafe {
        std::env::remove_var(DAEMON_CHILD_ENV_VAR);
    }

    A::run_daemon(payload, server)
}

// The bootstrap frame plumbing above (`recv_raw_bootstrap_with_timeout` /
// `send_raw_bootstrap_ack`, and the parent-side `send_raw_bootstrap` /
// `recv_raw_bootstrap_ack_with_timeout`) is exercised end-to-end here so a
// regression in the raw-frame path is caught without spawning a real child.
#[cfg(test)]
mod tests {
    use crate::ipc::RpcConnection;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Debug, Serialize, Deserialize)]
    struct Req(u32);
    #[derive(Debug, Serialize, Deserialize)]
    struct Resp(u32);
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Payload {
        a: u32,
        b: String,
    }

    #[test]
    fn bootstrap_payload_round_trips_over_the_raw_frame_path() {
        // The exact plumbing spawn_daemon and the child arm use: postcard
        // encode → raw bootstrap frame → decode, then the empty ack back.
        let (mut server, mut client) = RpcConnection::<Req, Resp>::new_pipe()
            .unwrap()
            .into_server_and_client();

        let sent = Payload {
            a: 42,
            b: "hello".to_string(),
        };
        let bytes = postcard::to_stdvec(&sent).unwrap();
        client
            .send_raw_bootstrap_with_timeout(&bytes, Duration::from_secs(1))
            .unwrap();

        let received_bytes = server
            .recv_raw_bootstrap_with_timeout(Duration::from_secs(1))
            .unwrap();
        let received: Payload = postcard::from_bytes(&received_bytes).unwrap();
        assert_eq!(sent, received);

        server.send_raw_bootstrap_ack().unwrap();
        client
            .recv_raw_bootstrap_ack_with_timeout(Duration::from_secs(1))
            .unwrap();
    }
}
