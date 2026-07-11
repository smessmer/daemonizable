//! The [`Daemonizer`] capability token: the type-system proof that whoever
//! spawns the daemon agrees with the daemon entry point on the application
//! type `A`.

use std::marker::PhantomData;

use super::Daemonizable;
use crate::ipc::{RpcClient, SpawnDaemonError, spawn_daemon_process};

/// Capability to spawn the daemon for application `A`.
///
/// The only way to obtain one is via [`run::<A>()`](super::run), which hands
/// it to [`A::run_foreground`](Daemonizable::run_foreground) — so the type
/// system guarantees the spawner and the daemon entry point agree on `A` (and
/// with it the `Request`/`Response`/`BootstrapPayload` types and the build
/// id). A `Copy` zero-sized token: store it in your CLI state, pass it around
/// freely.
pub struct Daemonizer<A: Daemonizable> {
    // `fn() -> A` (not `A`) so the token is Copy/Send/Sync regardless of `A`.
    _private: PhantomData<fn() -> A>,
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
    /// Crate-internal on purpose: only [`run`](super::run) mints a
    /// `Daemonizer`. Minting one anywhere else would break the guarantee that
    /// the spawner and the daemon entry point share the same `A`.
    pub(super) fn new() -> Self {
        Self {
            _private: PhantomData,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::RpcServer;
    use std::process::ExitCode;

    struct StubApp;

    // A minimal `Daemonizable` impl whose only job is to give `Daemonizer` a
    // concrete `A` to be generic over. `StubApp` itself is none of
    // Copy/Send/Sync-relevant — the token must be all three regardless,
    // thanks to `PhantomData<fn() -> A>`.
    impl Daemonizable for StubApp {
        type Request = ();
        type Response = ();
        type BootstrapPayload = ();
        fn build_id() -> String {
            String::new()
        }
        fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
            ExitCode::SUCCESS
        }
        fn run_daemon(_payload: (), _rpc: RpcServer<(), ()>) -> ! {
            unreachable!("this stub is never actually run")
        }
    }

    #[test]
    fn daemonizer_is_copy_send_sync() {
        fn assert_copy<T: Copy>() {}
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_copy::<Daemonizer<StubApp>>();
        assert_send::<Daemonizer<StubApp>>();
        assert_sync::<Daemonizer<StubApp>>();
    }
}
