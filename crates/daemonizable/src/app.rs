//! The minimal, policy-free application API: the [`Daemonizable`] trait, the
//! [`Daemonizer`] capability token, and the [`run`] entry point.
//!
//! This API makes no policy decisions at all. The library only handles the
//! process mechanics: detecting whether this invocation *is* the re-exec'd
//! daemon child (via an environment-variable marker — no argv flag, so apps
//! aren't forced onto any particular argument parser), the fork+exec spawn,
//! the build-id handshake, and shipping one app-defined bootstrap payload
//! from parent to daemon. Everything else — CLI parsing, logging, panic
//! hooks, banners — is the application's business, inside
//! [`Daemonizable::run_foreground`] and [`Daemonizable::run_daemon`].

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Serialize, de::DeserializeOwned};

use crate::ipc::{
    BOOTSTRAP_TIMEOUT, DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR, RpcClient, RpcServer,
    SpawnDaemonError, rpc_server_from_inherited_fds, send_handshake, spawn_daemon_process,
};

/// An application that can spawn itself as a background daemon.
///
/// Implement this and call [`run::<MyApp>()`](run) from `main` — or let
/// `#[daemonizable::main]` (default-on `macros` feature) generate that main
/// by attaching it to the impl block. The trait deliberately has no hooks
/// for argument parsing, logging, or other startup policy —
/// [`run_foreground`](Self::run_foreground) *is* your application; do
/// whatever you like in it, and daemonize at the moment of your choosing via
/// the [`Daemonizer`] handed to it.
pub trait Daemonizable: Sized {
    /// Typed request the parent sends to the daemon over the RPC channel.
    type Request: Serialize + DeserializeOwned;

    /// Typed response the daemon sends back.
    type Response: Serialize + DeserializeOwned + Send;

    /// App-defined payload shipped from the parent to the daemon child
    /// between the build-id handshake and the first typed RPC. Opaque to
    /// this library. Typical content: logging configuration the daemon
    /// should install before it starts serving (its argv is empty, so it
    /// can't learn such things any other way).
    type BootstrapPayload: Serialize + DeserializeOwned;

    /// The identity string exchanged in the parent↔daemon handshake.
    ///
    /// The daemon child sends it; the parent refuses the spawn on mismatch.
    /// Include everything that must agree between the two processes for the
    /// postcard-typed RPC to be sound — at minimum the application name and
    /// its exact build version (two different binaries built from the same
    /// commit share a version, so a version alone can't tell them apart).
    fn build_id() -> String;

    /// Normal (non-daemon-child) entry point — this is your `main`.
    ///
    /// Runs on every invocation except the re-exec'd daemon child. Spawn the
    /// daemon whenever (and only if) you decide to via
    /// [`Daemonizer::spawn_daemon`]; a foreground-only invocation simply
    /// never calls it.
    fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode;

    /// Daemon-side entry point, running in the re-exec'd child.
    ///
    /// By the time this is called the framework has claimed the inherited
    /// IPC fds, started a new session (`setsid`), changed the working
    /// directory to `/`, passed the build-id handshake, and decoded
    /// `payload`. The process is otherwise pristine: no logging, no panic
    /// hooks, stdio still inherited from the parent — install whatever you
    /// need (typically from `payload`) before serving requests.
    ///
    /// Diverges: drive the request loop until [`RpcServer::next_request`]
    /// returns [`PipeRecvError::SenderClosed`](crate::PipeRecvError::SenderClosed)
    /// (the parent dropped its client), then exit.
    fn run_daemon(
        payload: Self::BootstrapPayload,
        rpc: RpcServer<Self::Request, Self::Response>,
    ) -> !;
}

/// Capability to spawn the daemon for application `A`.
///
/// The only way to obtain one is via [`run::<A>()`](run), which hands it to
/// [`A::run_foreground`](Daemonizable::run_foreground) — so the type system
/// guarantees the spawner and the daemon entry point agree on `A` (and with
/// it the `Request`/`Response`/`BootstrapPayload` types and the build id).
/// A `Copy` zero-sized token: store it in your CLI state, pass it around
/// freely.
pub struct Daemonizer<A: Daemonizable> {
    // `fn() -> A` (not `A`) so the token is Copy/Send/Sync regardless of `A`.
    _private: std::marker::PhantomData<fn() -> A>,
}

impl<A: Daemonizable> Clone for Daemonizer<A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<A: Daemonizable> Copy for Daemonizer<A> {}

impl<A: Daemonizable> std::fmt::Debug for Daemonizer<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Daemonizer")
    }
}

impl<A: Daemonizable> Daemonizer<A> {
    /// Private on purpose: minting a `Daemonizer` outside [`run`] would break
    /// the guarantee that spawner and daemon entry point share the same `A`.
    fn new() -> Self {
        Self {
            _private: std::marker::PhantomData,
        }
    }

    /// Spawn the current binary as a background daemon via fork+exec and
    /// return the typed RPC client connected to it.
    ///
    /// Blocks until the daemon has passed the build-id handshake and acked
    /// receipt of `payload` (ack means received and decoded; the daemon
    /// *applies* it inside [`Daemonizable::run_daemon`] afterwards). On
    /// handshake or bootstrap failure the child is killed and reaped
    /// (best-effort) before the error is returned.
    ///
    /// # Panics
    ///
    /// Panics if a tokio runtime is running — daemonize before initializing
    /// tokio (see <https://github.com/tokio-rs/tokio/issues/4301>).
    pub fn spawn_daemon(
        &self,
        payload: &A::BootstrapPayload,
    ) -> Result<RpcClient<A::Request, A::Response>, SpawnDaemonError> {
        let payload_bytes =
            postcard::to_stdvec(payload).map_err(SpawnDaemonError::EncodePayload)?;
        spawn_daemon_process(&A::build_id(), &payload_bytes)
    }
}

/// Guards against a second `run` call in the same process. The daemon-child
/// dispatch and the fd claim are process singletons, so `run` must be too.
static RUN_CALLED: AtomicBool = AtomicBool::new(false);

/// The single entry point: call this from `main` and nothing else.
///
/// Dispatches on the process role: a normal invocation calls
/// [`A::run_foreground`](Daemonizable::run_foreground) with the [`Daemonizer`]
/// capability; the re-exec'd daemon child (recognized by the environment
/// marker its parent set for it) runs the daemon protocol and diverges into
/// [`A::run_daemon`](Daemonizable::run_daemon).
///
/// # Panics
///
/// Panics if called more than once in the same process.
pub fn run<A: Daemonizable>() -> ExitCode {
    if RUN_CALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        panic!("daemonizable::run may only be called once per process");
    }
    match dispatch_decision(std::env::var_os(DAEMON_CHILD_ENV_VAR)) {
        DispatchDecision::DaemonChild => run_as_daemon_child::<A>(), // diverges
        DispatchDecision::Foreground => A::run_foreground(Daemonizer::new()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DispatchDecision {
    Foreground,
    DaemonChild,
}

/// Pure dispatch decision, split out so it's unit-testable without invoking
/// the child arm (which claims fds and exits the process).
///
/// Only the exact marker value the spawner sets counts; anything else —
/// including a user exporting the variable with some other value — falls
/// through to the foreground arm, where the app can produce a proper error
/// path instead of a hijacked process.
fn dispatch_decision(marker: Option<std::ffi::OsString>) -> DispatchDecision {
    match marker {
        Some(value) if value == DAEMON_CHILD_ENV_VALUE => DispatchDecision::DaemonChild,
        _ => DispatchDecision::Foreground,
    }
}

/// The re-exec'd daemon child lands here, straight from [`run`] — before any
/// app code. Order matters and mirrors the legacy framework: claim fds (exit
/// 2) → `setsid` (exit 1) → `chdir("/")` (warn only) → send handshake (exit
/// 127) → receive + decode payload → ack (exit 127) → hand off to the app.
fn run_as_daemon_child<A: Daemonizable>() -> ! {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::RpcConnection;
    use serde::Deserialize;
    use std::ffi::OsString;
    use std::sync::atomic::AtomicU32;
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

    struct StubApp;
    static STUB_FOREGROUND_RUNS: AtomicU32 = AtomicU32::new(0);

    impl Daemonizable for StubApp {
        type Request = Req;
        type Response = Resp;
        type BootstrapPayload = Payload;
        fn build_id() -> String {
            "stub-app 1.2.3".to_string()
        }
        fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
            STUB_FOREGROUND_RUNS.fetch_add(1, Ordering::SeqCst);
            ExitCode::SUCCESS
        }
        fn run_daemon(_payload: Payload, _rpc: RpcServer<Req, Resp>) -> ! {
            unreachable!("tests never take the daemon-child arm in-process")
        }
    }

    #[test]
    fn dispatch_decision_table() {
        let cases: &[(Option<&str>, DispatchDecision)] = &[
            (None, DispatchDecision::Foreground),
            (Some("1"), DispatchDecision::DaemonChild),
            // Only the exact marker value counts; anything else falls
            // through to the foreground arm (see fn docs).
            (Some(""), DispatchDecision::Foreground),
            (Some("0"), DispatchDecision::Foreground),
            (Some("true"), DispatchDecision::Foreground),
            (Some("11"), DispatchDecision::Foreground),
        ];
        for (marker, expected) in cases {
            assert_eq!(
                *expected,
                dispatch_decision(marker.map(OsString::from)),
                "wrong decision for marker {marker:?}",
            );
        }
    }

    /// The ONLY in-process test allowed to call `run` — the once-guard is a
    /// process-global, so any second test calling `run` would race this one
    /// for the first-call slot. Marker-PRESENT dispatch can't be tested
    /// in-process at all (the child arm claims fds 3/4 and exits the
    /// process); that path is covered by the spawned-binary e2e tests.
    #[test]
    fn run_dispatches_to_foreground_and_panics_on_second_call() {
        assert_eq!(0, STUB_FOREGROUND_RUNS.load(Ordering::SeqCst));
        let exit = run::<StubApp>();
        assert_eq!(format!("{:?}", ExitCode::SUCCESS), format!("{exit:?}"));
        assert_eq!(
            1,
            STUB_FOREGROUND_RUNS.load(Ordering::SeqCst),
            "run_foreground must have been dispatched exactly once"
        );

        let second = std::panic::catch_unwind(run::<StubApp>);
        assert!(
            second.is_err(),
            "a second run() in the same process must panic"
        );
        assert_eq!(
            1,
            STUB_FOREGROUND_RUNS.load(Ordering::SeqCst),
            "the second run() must not have dispatched"
        );
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

    #[test]
    fn daemonizer_is_copy_send_sync() {
        fn assert_copy<T: Copy>() {}
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        // `StubApp` itself is none of Copy/Send-relevant — the token must be
        // all three regardless, thanks to `PhantomData<fn() -> A>`.
        assert_copy::<Daemonizer<StubApp>>();
        assert_send::<Daemonizer<StubApp>>();
        assert_sync::<Daemonizer<StubApp>>();
    }
}
