//! The application contract: the [`Daemonizable`] trait.

use std::process::ExitCode;

use serde::{Serialize, de::DeserializeOwned};

use super::Daemonizer;
use crate::ipc::RpcServer;

/// An application that can spawn itself as a background daemon.
///
/// Implement this and attach `#[daemonizable::main]` to the impl block: the
/// attribute (default-on `macros` feature) generates the `main` that calls
/// [`run::<MyApp>()`](super::run), which is all a `main` on this library should
/// do. Without the feature, write that one-line `main` yourself — see
/// [`run`](super::run) for the contract it has to keep. The trait deliberately
/// has no hooks for argument parsing, logging, or other startup policy —
/// [`run_foreground`](Self::run_foreground) *is* your application; do
/// whatever you like in it, and daemonize at the moment of your choosing via
/// the [`Daemonizer`] handed to it.
///
/// # Example
///
/// A typical daemon: the foreground process hands the daemon its startup
/// configuration, waits until the daemon confirms it came up, and then exits —
/// leaving the daemon running in the background. `src/main.rs` in full (the
/// attribute generates `main`, so this is the whole file):
///
/// ```ignore
/// use std::process::ExitCode;
/// use std::time::Duration;
///
/// use daemonizable::{detach_stdio, Daemonizable, Daemonizer, RpcServer};
/// use serde::{Deserialize, Serialize};
///
/// struct MyApp;
///
/// /// Startup configuration the foreground process hands to the daemon.
/// /// The daemon gets no app arguments (its argv carries only an internal
/// /// framework sentinel), so this is how it learns what to do.
/// #[derive(Serialize, Deserialize)]
/// struct Config {
///     workdir: String,
///     poll_interval_secs: u64,
/// }
///
/// #[daemonizable::main]
/// impl Daemonizable for MyApp {
///     type Request = Config;
///     // The daemon reports whether its startup succeeded, so the foreground
///     // can exit non-zero if the daemon failed to come up.
///     type Response = Result<(), String>;
///
///     fn build_id() -> String {
///         format!("my-app {}", env!("CARGO_PKG_VERSION"))
///     }
///
///     fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
///         // This is your `main`: parse arguments however you like, then
///         // start the daemon once you know what it should do.
///         let mut rpc = daemonizer.spawn_daemon().unwrap();
///
///         // Hand the daemon its startup configuration...
///         rpc.send_request(&Config {
///             workdir: "/var/lib/my-app".to_string(),
///             poll_interval_secs: 30,
///         })
///         .unwrap();
///
///         // ...and wait for it to confirm it actually started before we exit.
///         match rpc.recv_response_blocking() {
///             Ok(Ok(())) => {
///                 println!("daemon is up; leaving it running in the background");
///                 // Returning drops `rpc`, closing our end of the channel. The
///                 // daemon has stopped listening on it, so it keeps running.
///                 ExitCode::SUCCESS
///             }
///             Ok(Err(err)) => {
///                 eprintln!("daemon failed to start: {err}");
///                 ExitCode::FAILURE
///             }
///             Err(err) => {
///                 eprintln!("daemon died during startup: {err}");
///                 ExitCode::FAILURE
///             }
///         }
///     }
///
///     fn run_daemon(mut rpc: RpcServer<Config, Result<(), String>>) -> ! {
///         // Runs in the re-exec'd daemon child. First receive the startup
///         // configuration the foreground process sent.
///         let config = rpc
///             .next_request()
///             .expect("parent closed before sending config");
///
///         // Do whatever setup the config asks for. If it fails, report the
///         // failure so the foreground's `spawn_daemon` caller can exit non-zero.
///         if let Err(err) = std::env::set_current_dir(&config.workdir) {
///             let _ = rpc.send_response(&Err(format!("bad workdir: {err}")));
///             std::process::exit(1);
///         }
///
///         // Setup succeeded — tell the foreground it's safe to exit.
///         rpc.send_response(&Ok(())).unwrap();
///
///         // The foreground can now leave. Detach from its terminal so our
///         // output doesn't land on the user's shell, and drop `rpc`: from here
///         // on we no longer depend on the parent being alive.
///         detach_stdio().unwrap();
///         drop(rpc);
///
///         // Our real work: a long-lived loop that outlives the foreground.
///         loop {
///             // ...do periodic work using `config`...
///             std::thread::sleep(Duration::from_secs(config.poll_interval_secs));
///         }
///     }
/// }
/// ```
///
/// `#[daemonizable::main]` comes from the default-on `macros` feature. It leaves
/// the impl untouched and appends
/// `fn main() -> ExitCode { daemonizable::run::<MyApp>() }` — the entire `main`
/// an application on this library should have. Build with
/// `default-features = false` and the attribute is gone; write that one line
/// yourself, and keep `main` to exactly that one line: the re-exec'd daemon
/// child runs the same `main`, so anything in front of [`run`](super::run) runs
/// in the daemon too (a thread spawned there exists in the child as well). The
/// attribute guarantees an empty preamble by construction. (The example above
/// is shown, not compiled; the compiled equivalent is the doctest on
/// [`run`](super::run), and the macro's expansion is covered by the trybuild
/// snapshots in `daemonizable-e2e-tests/tests/macro_ui/`.)
pub trait Daemonizable: Sized {
    /// Typed request the parent sends to the daemon over the RPC channel.
    type Request: Serialize + DeserializeOwned;

    /// Typed response the daemon sends back.
    type Response: Serialize + DeserializeOwned + Send;

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
    /// IPC fds, started a new session (`setsid`), forked again so this process
    /// is a grandchild that is *not* the session leader, changed the working
    /// directory to `/`, and passed the build-id handshake. The process is
    /// otherwise pristine: no logging, no panic hooks, stdio still inherited
    /// from the parent — install whatever you need before serving requests.
    /// Any configuration the daemon needs (it gets no app arguments — its
    /// argv carries only an internal framework sentinel — so it can't
    /// parse flags) travels as an ordinary first RPC request on `rpc`.
    ///
    /// Diverges: drive the request loop until [`RpcServer::next_request`]
    /// returns [`PipeRecvError::SenderClosed`](crate::PipeRecvError::SenderClosed)
    /// (the parent dropped its client), then exit.
    fn run_daemon(rpc: RpcServer<Self::Request, Self::Response>) -> !;
}
