//! The re-exec'd daemon child's startup sequence, run straight from
//! [`run`](super::run) before any app code: claim the inherited fds, start a
//! new session, detach the working directory, complete the build-id
//! handshake, receive and ack the bootstrap payload, then hand off to the
//! application's daemon entry point.

use super::Daemonizable;
use crate::ipc::{
    BOOTSTRAP_TIMEOUT, DAEMON_CHILD_ENV_VAR, RpcServer, rpc_server_from_inherited_fds,
    send_handshake,
};

/// The re-exec'd daemon child lands here, straight from [`run`](super::run) —
/// before any app code. Order matters and mirrors the legacy framework: claim
/// fds (exit 2) → `setsid` (exit 1) → `chdir("/")` (warn only) → send
/// handshake (exit 127) → receive + decode payload → ack (exit 127) → hand off
/// to the app.
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

    // TODO Double-fork: fork once more right here and let this
    //   session-leader intermediate _exit(0), so the surviving grandchild
    //   can never acquire a controlling terminal (daemon(7) step 7; per
    //   POSIX XBD 11.1.3 a ctty-less session leader that open()s a tty
    //   without O_NOCTTY may acquire it as controlling terminal). Safe at
    //   this point: we are a fresh single-threaded post-exec image, and the
    //   claimed pipe fds are inherited across the fork. Ordering: the
    //   second fork must happen BEFORE send_handshake below (the parent
    //   must validate the final daemon, and EOF liveness must track the
    //   process that actually serves), and the planned pid-file battery
    //   must write its pid AFTER this fork. This change must land TOGETHER
    //   with the matching cleanup TODO in ipc/spawn/process.rs (on the kill+wait in
    //   spawn_daemon_process): the parent's Child handle will point at the
    //   already-dead intermediate, so failed-spawn cleanup has to become
    //   process-group signaling — kill(-child_pid), race-free because
    //   setsid() above made our pid the pgid and a pid is not recycled
    //   while it names a live process group; ESRCH falls back to
    //   kill(child_pid) for deaths before setsid. On success the parent
    //   should wait() the intermediate immediately, which removes the
    //   zombie caveat from the process contract. Update the README
    //   ("Process contract" + the session-leader cost bullet), the crate
    //   docs, and the process-tree expectations in
    //   daemon_survives_parent_exit.rs / daemon_child_lifecycle.rs.

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
    //   Ordering within this block: umask → sigmask reset → close_range →
    //   pid file (write the FINAL pid — after the planned double fork above)
    //   → chown pid file → open log files → chroot → initgroups/setgid →
    //   setuid → ack.
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
    // re-exec'd with a fresh process image and haven't started any runtime;
    // `run_daemon` (e.g. its tokio init) comes after this line.
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
        client.send_raw_bootstrap(&bytes).unwrap();

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
