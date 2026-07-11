//! The application contract: the [`Daemonizable`] trait.

use std::process::ExitCode;

use serde::{Serialize, de::DeserializeOwned};

use super::Daemonizer;
use crate::ipc::RpcServer;

/// An application that can spawn itself as a background daemon.
///
/// Implement this and call [`run::<MyApp>()`](super::run) from `main` — or let
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
