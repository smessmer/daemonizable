//! Library for CLI applications that can run as a foreground process or
//! fork+exec themselves into a background daemon and talk to the child via
//! typed RPC.
//!
//! Implement [`Daemonizable`] for your app type and call [`run::<MyApp>()`](run)
//! from `main`. The library handles the process mechanics only — daemon-child
//! detection (via an environment marker, no argv flag), the `fork+exec`
//! re-exec spawn, the build-id handshake, shipping one app-defined bootstrap
//! payload, and the typed RPC channel. All policy (argument parsing, logging,
//! panic hooks, banners) stays in the application.
//!
//! The typed RPC channel between parent and daemon uses the app's own
//! [`Daemonizable::Request`] / [`Daemonizable::Response`] types — framework
//! messages travel out-of-band on the same pipe and are invisible to app code.
//!
//! # Example
//!
//! ```no_run
//! use std::process::ExitCode;
//!
//! use daemonizable::{Daemonizable, Daemonizer, RpcServer};
//!
//! struct MyApp;
//!
//! impl Daemonizable for MyApp {
//!     type Request = String;
//!     type Response = String;
//!     type BootstrapPayload = ();
//!
//!     fn build_id() -> String {
//!         format!("my-app {}", env!("CARGO_PKG_VERSION"))
//!     }
//!
//!     fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
//!         // This is your `main`: parse arguments however you like, then
//!         // daemonize whenever (and only if) you decide to.
//!         let mut rpc = daemonizer.spawn_daemon(&()).unwrap();
//!         rpc.send_request(&"hello".to_string()).unwrap();
//!         println!("daemon says: {}", rpc.recv_response_blocking().unwrap());
//!         ExitCode::SUCCESS
//!     }
//!
//!     fn run_daemon(_payload: (), mut rpc: RpcServer<String, String>) -> ! {
//!         // Runs in the re-exec'd daemon child. Serve requests until the
//!         // parent drops its client (EOF), then exit.
//!         while let Ok(request) = rpc.next_request() {
//!             rpc.send_response(&format!("echo: {request}")).unwrap();
//!         }
//!         std::process::exit(0)
//!     }
//! }
//!
//! fn main() -> ExitCode {
//!     daemonizable::run::<MyApp>()
//! }
//! ```
//!
//! With the default-on `macros` feature, `#[daemonizable::main]` on the impl
//! block generates that `main` for you.
//!
//! # Process contract
//!
//! There is **no double-fork**: a successfully spawned daemon remains a child
//! of the spawning process. If the parent exits promptly (the typical CLI
//! pattern), the daemon is reparented to init; a long-lived parent will see a
//! zombie once the daemon exits (reap it, or accept it). A **failed** spawn
//! (handshake mismatch, bootstrap failure) is killed and reaped by
//! [`Daemonizer::spawn_daemon`] itself before the error is returned. Because
//! the daemon is spawned with fork+exec (not a bare `fork()`), a running
//! thread pool or async runtime is fine — `execve` hands the child a fresh
//! process image, so the fork-vs-threads hazard of traditional daemonization
//! (see <https://github.com/tokio-rs/tokio/issues/4301>) doesn't apply.

// TODO The one residual hazard is a narrow fd-inheritance race, unrelated to
//   any particular runtime: the pipe fds get FD_CLOEXEC set non-atomically
//   after creation (see the race discussion in ipc/pipe/mod.rs), so a
//   concurrent fork/Command::spawn on another thread during that window —
//   including a second spawn_daemon from another thread, an advertised use of
//   the Copy+Send+Sync Daemonizer — can leak duplicate pipe ends into an
//   unrelated child across execve, which silently defeats the documented EOF
//   liveness (EOF only fires once ALL write ends close). To close the race
//   rather than only document it: (a) create pipes with pipe2(O_CLOEXEC)
//   (nix::unistd::pipe2, nix is already a dependency) on the platforms that
//   have it, leaving only macOS reliant on the documented invariant;
//   (b) optionally serialize pipe-creation + spawn behind a private static
//   Mutex to close the spawn-vs-spawn instance of the race on every platform.

mod app;
mod ipc;

pub use app::{Daemonizable, Daemonizer, run};

// The #[daemonizable::main] attribute: generates `fn main` from an
// `impl Daemonizable for X` block. Lives in the companion proc-macro crate
// (proc macros can't be defined here) and is re-exported so applications
// only ever depend on `daemonizable` itself.
#[cfg(feature = "macros")]
pub use daemonizable_macros::main;

// Re-exported so applications can name the typed handles they receive in
// `run_parent` / `run_daemon`, and so test code can construct in-process
// connections for unit testing.
//
// TODO Stale name from the deleted legacy framework: no `run_parent` exists
//   in this API. The client handle comes from `Daemonizer::spawn_daemon`,
//   the server handle is passed to `Daemonizable::run_daemon` — reword the
//   comment above accordingly.
pub use ipc::{RpcClient, RpcConnection, RpcServer};

// Typed errors returned by the IPC layer (thiserror, not anyhow) so callers
// can match on failure modes, e.g. distinguish a peer that closed the pipe
// (`PipeRecvError::SenderClosed`) from a timeout.
pub use ipc::{
    HandshakeError, InheritedFdsError, PipeCreateError, PipeRecvError, PipeSendError,
    SpawnDaemonError,
};

// Process-global helper: the daemon calls this at its post-startup boundary
// to detach the inherited stdio from the parent's terminal.
pub use ipc::detach_stdio;

// Lower-level handles for integration tests that substitute an external
// helper binary for the re-execed self and drive the spawn machinery
// directly, skipping handshake and bootstrap.
//
// Production app code should not reach for these — implement
// [`Daemonizable`] and let [`run`] orchestrate the daemon side.
#[doc(hidden)]
pub use ipc::{rpc_server_from_inherited_fds, start_background_process_with_exe};
