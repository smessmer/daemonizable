//! The single entry point [`run`] and its process-role dispatch: a normal
//! invocation goes to the app's foreground code; the two re-exec'd daemon
//! stages (each recognized by an in-band token at the head of the channel fd)
//! go to the daemon startup sequence.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use super::daemon_child::{run_as_daemon_stage1, run_as_daemon_stage2};
use super::{Daemonizable, Daemonizer};
use crate::ipc::{StageDispatch, dispatch_from_channel};

/// Guards against a second `run` call in the same process. The daemon-child
/// dispatch and the fd claim are process singletons, so `run` must be too.
static RUN_CALLED: AtomicBool = AtomicBool::new(false);

/// The single entry point: `main` calls this and does nothing else.
///
/// You normally don't write that `main` yourself — `#[daemonizable::main]` on
/// the impl block generates it (default-on `macros` feature). Without the
/// feature, write exactly this and nothing more:
///
/// ```no_run
/// # use std::process::ExitCode;
/// # use daemonizable::{Daemonizable, Daemonizer, RpcServer};
/// # struct MyApp;
/// # impl Daemonizable for MyApp {
/// #     type Request = ();
/// #     type Response = ();
/// #     fn build_id() -> String { String::new() }
/// #     fn run_foreground(_: Daemonizer<Self>) -> ExitCode { ExitCode::SUCCESS }
/// #     fn run_daemon(_: RpcServer<(), ()>) -> ! { std::process::exit(0) }
/// # }
/// fn main() -> ExitCode {
///     daemonizable::run::<MyApp>()
/// }
/// ```
///
/// "And nothing else" is a real constraint, not a style note: the daemon
/// spawn re-execs your binary **twice** (a short-lived staging image, then
/// the final daemon), and both run the same `main` — so anything you put in
/// front of `run` executes three times in total, in processes where argv and
/// stdio are not what your foreground code expects. The attribute guarantees
/// an empty preamble by construction; a hand-written `main` has to keep that
/// promise itself (and must return `run`'s [`ExitCode`] rather than
/// swallowing it).
///
/// Pre-main constructors (`#[ctor]`-style crates,
/// `__attribute__((constructor))` code in linked C libraries, LD_PRELOAD
/// shims — in your program or any of its dependencies) also run again in both
/// daemon-stage images, before `run` gets control. Constructor-spawned
/// *threads* are tolerated by design: the code this crate runs after the
/// staging image's fork is exclusively async-signal-safe, the daemon image
/// never forks, and neither stage reads or mutates the environment for
/// dispatch (stage identity rides an in-band channel token). Three caveats
/// remain, none of them amplified beyond what any fork+exec spawn implies: a
/// `pthread_atfork` handler that is not fork-safe under threads is its
/// registrant's problem (libc runs it inside `fork()` itself, for
/// `std::process::Command` spawns just the same); a constructor thread mutating
/// the environment via C `setenv` concurrently with *any* env read in the
/// process is the usual libc `environ` caveat; and constructors must not claim,
/// close, read from, or write to raw file descriptor 3 (it carries the
/// full-duplex RPC channel the daemon image takes exclusive ownership of — a
/// constructor *read* would consume the stage-identity token dispatch relies on
/// or steal request bytes, and a *write* would inject bytes ahead of the
/// build-id handshake, either way breaking startup; fd 3 is open in both stage
/// images, so an ordinary `open` in a constructor can never land on that number
/// accidentally) — and should avoid fork+exec'ing long-lived helpers of their
/// own from the stage images, which would inherit a duplicate channel end
/// during the pre-claim window and can suppress the parent's EOF liveness.
///
/// Dispatches on the process role: a normal invocation calls
/// [`A::run_foreground`](Daemonizable::run_foreground) with the [`Daemonizer`]
/// capability; the two re-exec'd daemon stages run the daemon protocol, and
/// stage 2 diverges into [`A::run_daemon`](Daemonizable::run_daemon). Stage
/// identity is carried **in-band on the channel fd (3)**, not in argv or the
/// environment: the parent pre-queues a per-stage token into the socket, and
/// dispatch peeks the head of fd 3 (a non-consuming, non-blocking `recv`) to
/// route. A foreground invocation has no framework channel there — fd 3 closed,
/// or a stranger — so its peek finds no token and it runs foreground having
/// touched nothing; the daemon's argv stays empty (`run_daemon` sees no injected
/// argument) and nothing is left in `ps`. Fd 3 is a **reserved descriptor**: a
/// process that inherits a socket there whose peer writes the (public) token
/// bytes is routed to a daemon stage, which then authenticates the channel —
/// the peer's effective uid and gid must equal ours (`SO_PEERCRED`/`getpeereid`)
/// and the process must have the session/group topology of a framework-spawned
/// daemon — before any application code runs. Applications must not treat
/// `run_daemon`'s RPC input as authenticated-by-provenance against a
/// *same-principal* local peer (which could equally `ptrace` a
/// non-privilege-elevated process). The peer-credential check is the
/// load-bearing barrier for a binary that gains privilege by CHANGING uid/gid
/// (setuid/setgid); a **file-capabilities** binary keeps the invoker's ids, so
/// the check cannot distinguish a same-id attacker there — such a daemon must
/// treat `run_daemon` input as untrusted (see `verify_channel_peer_creds`).
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
    // Dispatch reads nothing but the head of the channel fd (3): peek an
    // in-band stage token (non-consuming, non-blocking), consume it on a match,
    // and route. A plain foreground invocation has no framework socket there —
    // closed, or a stranger — so the peek yields no token and this falls to the
    // foreground arm having touched nothing. See `crate::ipc`'s `TOKEN_MAGIC`.
    match dispatch_from_channel() {
        StageDispatch::DaemonStage1 => run_as_daemon_stage1(), // diverges
        StageDispatch::DaemonStage2 => run_as_daemon_stage2::<A>(), // diverges
        StageDispatch::Foreground => A::run_foreground(Daemonizer::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::RpcServer;
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::AtomicU32;

    #[derive(Debug, Serialize, Deserialize)]
    struct Req(u32);
    #[derive(Debug, Serialize, Deserialize)]
    struct Resp(u32);

    struct StubApp;
    static STUB_FOREGROUND_RUNS: AtomicU32 = AtomicU32::new(0);

    impl Daemonizable for StubApp {
        type Request = Req;
        type Response = Resp;
        fn build_id() -> String {
            "stub-app 1.2.3".to_string()
        }
        fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
            STUB_FOREGROUND_RUNS.fetch_add(1, Ordering::SeqCst);
            ExitCode::SUCCESS
        }
        fn run_daemon(_rpc: RpcServer<Req, Resp>) -> ! {
            unreachable!("tests never take the daemon-child arm in-process")
        }
    }

    // The pure token classifier is unit-tested in `ipc::spawn::token`; the
    // stage arms (which peek/claim fd 3 and exit the process) are covered by
    // the spawned-binary e2e tests.

    /// The ONLY in-process test allowed to call `run` — the once-guard is a
    /// process-global, so any second test calling `run` would race this one
    /// for the first-call slot. In this libtest process fd 3 is not a framework
    /// channel (no queued token), so dispatch falls to the foreground arm; the
    /// stage arms can't be tested in-process (they claim fd 3 and exit) and are
    /// covered by the spawned-binary e2e tests.
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
}
