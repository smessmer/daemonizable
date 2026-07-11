//! Library for CLI applications that can run as a foreground process or
//! fork+exec themselves into a background daemon and talk to the child via
//! typed RPC.
//!
//! Implement [`Daemonizable`] for your app type and put `#[daemonizable::main]`
//! on the impl block: the attribute (default-on `macros` feature) generates the
//! whole of your `main`, which is nothing but [`run::<MyApp>()`](run). The
//! library handles the process mechanics only — daemon-child detection (via an
//! environment marker, no argv flag), the `fork+exec` re-exec spawn, the
//! build-id handshake, and the typed RPC channel. All policy (argument parsing,
//! logging, panic hooks, banners) stays in the application.
//!
//! The typed RPC channel between parent and daemon uses the app's own
//! [`Daemonizable::Request`] / [`Daemonizable::Response`] types — the
//! framework's build-id handshake travels out-of-band on the same pipe, before
//! the typed phase and invisible to app code.
//!
//! # Example
//!
//! `src/main.rs` — the attribute generates `main`, so this is the whole file:
//!
//! ```no_run
//! use std::process::ExitCode;
//!
//! use daemonizable::{Daemonizable, Daemonizer, RpcServer};
//!
//! struct MyApp;
//!
#![cfg_attr(feature = "macros", doc = "#[daemonizable::main]")]
//! impl Daemonizable for MyApp {
//!     type Request = String;
//!     type Response = String;
//!
//!     fn build_id() -> String {
//!         format!("my-app {}", env!("CARGO_PKG_VERSION"))
//!     }
//!
//!     fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
//!         // This is your `main`: parse arguments however you like, then
//!         // daemonize whenever (and only if) you decide to.
//!         let mut rpc = daemonizer.spawn_daemon().unwrap();
//!         rpc.send_request(&"hello".to_string()).unwrap();
//!         println!("daemon says: {}", rpc.recv_response_blocking().unwrap());
//!         ExitCode::SUCCESS
//!     }
//!
//!     fn run_daemon(mut rpc: RpcServer<String, String>) -> ! {
//!         // Runs in the re-exec'd daemon child. Serve requests until the
//!         // parent drops its client (EOF), then exit.
//!         while let Ok(request) = rpc.next_request() {
//!             rpc.send_response(&format!("echo: {request}")).unwrap();
//!         }
//!         std::process::exit(0)
//!     }
//! }
#![cfg_attr(not(feature = "macros"), doc = "")]
#![cfg_attr(not(feature = "macros"), doc = "fn main() -> ExitCode {")]
#![cfg_attr(not(feature = "macros"), doc = "    daemonizable::run::<MyApp>()")]
#![cfg_attr(not(feature = "macros"), doc = "}")]
//! ```
//!
//! `#[daemonizable::main]` comes from the default-on `macros` feature. It leaves
//! the impl untouched and appends
//! `fn main() -> ExitCode { daemonizable::run::<MyApp>() }` — the entire `main` an
//! application on this library should have. Build with `default-features = false`
//! and the attribute is gone; write that one line yourself (and keep it to that
//! one line — see [`run`] for why).
//!
//! # Process contract
//!
//! The re-exec'd child forks a **second time** after `setsid()` (the classic
//! double fork, daemon(7) step 7): the session-leader intermediate exits
//! immediately and is reaped by [`Daemonizer::spawn_daemon`] itself, and the
//! surviving daemon — a grandchild, never a session leader, so it can never
//! acquire a controlling terminal — is orphaned to init (or the nearest
//! [`PR_SET_CHILD_SUBREAPER`](https://man7.org/linux/man-pages/man2/prctl.2.html)
//! ancestor, e.g. a systemd user manager) at spawn time. A **successful** spawn
//! therefore leaves the caller no child and no zombie, whatever the caller's
//! own lifetime.
//!
//! A **failed** spawn (handshake mismatch or spawn failure) is killed via its
//! process group (`kill(-child_pid, SIGKILL)`, which reaches the grandchild;
//! ESRCH falls back to a direct kill for a child that died before `setsid`) and
//! the intermediate reaped before the error is returned. A grandchild the group
//! signal somehow misses (it left the group via its own `setsid`/`setpgid`)
//! still self-terminates via pipe EOF once the client is dropped, so
//! failed-spawn teardown of the daemon is asynchronous, not synchronous with
//! the returned error.
//!
//! Two caveats. [`Daemonizer::spawn_daemon`] can block indefinitely if the
//! intermediate is externally stopped (SIGSTOP/ptrace) in the instant before it
//! exits, since it is reaped with a blocking `wait()` (the build-id handshake
//! recv is timeout-bounded, so a wedged child during the handshake is not). And
//! the caller must not concurrently reap arbitrary children (a
//! `SIGCHLD` handler that calls `waitpid(-1)`, say) during the spawn, or it may
//! reap the intermediate first and defeat the cleanup's pid bookkeeping.
//!
//! Because the daemon is spawned with fork+exec (not a bare `fork()`), a
//! running thread pool or async runtime is fine — `execve` hands the child a
//! fresh process image, so the fork-vs-threads hazard of traditional
//! daemonization (see <https://github.com/tokio-rs/tokio/issues/4301>) doesn't
//! apply. (The second fork above runs in that fresh, single-threaded post-exec
//! image, before any application code, so it is not exposed to that hazard
//! either.)

// On the platforms that have `pipe2(O_CLOEXEC)` (Linux/Android, the *BSDs, and
// more), pipe fds are now created with FD_CLOEXEC set atomically, so the
// fd-inheritance race is closed there regardless of runtime — including a
// second spawn_daemon from another thread, an advertised use of the
// Copy+Send+Sync Daemonizer. macOS/iOS lack `pipe2` (and any atomic
// equivalent), so on those targets the CLOEXEC flag is still set in a separate
// step and a concurrent fork/Command::spawn in that window can leak duplicate
// pipe ends across execve, silently defeating EOF liveness (EOF only fires once
// ALL write ends close). There we rely on the documented spawn-at-startup
// caller contract instead. See the race discussion in ipc/pipe/mod.rs.

mod app;
mod ipc;

pub use app::{Daemonizable, Daemonizer, run};

// The #[daemonizable::main] attribute: generates `fn main` from an
// `impl Daemonizable for X` block. Lives in the companion proc-macro crate
// (proc macros can't be defined here) and is re-exported so applications
// only ever depend on `daemonizable` itself.
#[cfg(feature = "macros")]
pub use daemonizable_macros::main;

// Re-exported so applications can name the typed handles they receive: the
// client handle from `Daemonizer::spawn_daemon` and the server handle passed
// to `Daemonizable::run_daemon`, and so test code can construct in-process
// connections for unit testing.
pub use ipc::{RpcClient, RpcConnection, RpcServer};

// Typed errors returned by the IPC layer (thiserror, not anyhow) so callers
// can match on failure modes, e.g. distinguish a peer that closed the pipe
// (`PipeRecvError::SenderClosed`) from a timeout.
pub use ipc::{
    DetachStdioError, HandshakeError, InheritedFdsError, PipeCreateError, PipeRecvError,
    PipeSendError, SpawnDaemonError,
};

// Process-global helper: the daemon calls this at its post-startup boundary
// to detach the inherited stdio from the parent's terminal.
pub use ipc::detach_stdio;

// Lower-level handles for integration tests that substitute an external
// helper binary for the re-execed self and drive the spawn machinery
// directly, skipping the handshake.
//
// Production app code should not reach for these — implement
// [`Daemonizable`] and let [`run`] orchestrate the daemon side.
// `send_handshake` is the daemon-side primitive the child arm uses; helper
// binaries need it to stand in for a (correct or deliberately wrong) daemon.
#[doc(hidden)]
pub use ipc::{rpc_server_from_inherited_fds, send_handshake, start_background_process_with_exe};

// Like `start_background_process_with_exe` but keeps the full handshake +
// failed-spawn cleanup, against an arbitrary helper binary. Exists
// only so `daemonizable-e2e-tests` can cover the cleanup contract that
// `spawn_daemon` promises (production always re-execs `/proc/self/exe`, which a
// libtest binary cannot stand in for). Gated off the stable surface.
#[cfg(any(test, feature = "testutils"))]
#[doc(hidden)]
pub use ipc::spawn_daemon_process_with_exe;
