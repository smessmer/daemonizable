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
/// with it the `Request`/`Response` types and the build id). A `Copy`
/// zero-sized token: store it in your CLI state, pass it around freely.
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
    /// Blocks until the daemon has passed the build-id handshake. Any
    /// configuration the daemon needs travels afterwards as an ordinary
    /// request on the returned client (its argv is empty, so it can't parse
    /// flags itself).
    ///
    /// The daemon is a **grandchild**: the re-exec'd child forks again after
    /// `setsid` so it is never a session leader (and can never acquire a
    /// controlling terminal). The short-lived intermediate is reaped here, so a
    /// successful spawn leaves the caller no child and no zombie. On handshake
    /// or spawn failure the spawn is killed via its process group and the
    /// intermediate reaped before the error is returned. See the crate-level
    /// [Process contract](crate#process-contract) for the full detail, including
    /// two caveats: this call can block indefinitely if the intermediate is
    /// externally SIGSTOPped/ptraced in the instant before it exits, and the
    /// caller must not concurrently `waitpid(-1)`/reap arbitrary children during
    /// the spawn.
    ///
    /// Because the daemon is created with fork+exec (not a bare `fork()`), it
    /// is safe to call this with a thread pool or async runtime already
    /// running — `execve` gives the child a fresh process image, so none of
    /// the parent's threads or lock state carry over. On Linux/Android, the
    /// *BSDs, and the other targets with `pipe2(O_CLOEXEC)`, the pipe fds are
    /// created with `FD_CLOEXEC` already set, so there is no fd-inheritance
    /// race regardless of what other threads are doing. macOS/iOS have no
    /// `pipe2`, so there the flag is set in a separate step just after
    /// creation and a narrow race remains: if another thread performs its own
    /// fork+exec in that brief window it can leak a copy of those fds into an
    /// unrelated child. On those targets, spawning the daemon before the
    /// process starts spawning other subprocesses avoids it entirely.
    pub fn spawn_daemon(&self) -> Result<RpcClient<A::Request, A::Response>, SpawnDaemonError> {
        spawn_daemon_process::<A::Request, A::Response>(&A::build_id())
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
        fn build_id() -> String {
            String::new()
        }
        fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
            ExitCode::SUCCESS
        }
        fn run_daemon(_rpc: RpcServer<(), ()>) -> ! {
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
