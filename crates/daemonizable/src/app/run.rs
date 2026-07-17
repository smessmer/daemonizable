//! The single entry point [`run`] and its process-role dispatch: a normal
//! invocation goes to the app's foreground code; the two re-exec'd daemon
//! stages (each recognized by its argv[1] sentinel) go to the daemon startup
//! sequence.

use std::ffi::OsStr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use super::daemon_child::{run_as_daemon_stage1, run_as_daemon_stage2};
use super::{Daemonizable, Daemonizer};
use crate::ipc::{DAEMON_STAGE1_ARGV, DAEMON_STAGE2_ARGV};

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
/// dispatch (stage identity rides argv). Three caveats remain, none of them
/// amplified beyond what any fork+exec spawn implies: a `pthread_atfork`
/// handler that is not fork-safe under threads is its registrant's problem
/// (libc runs it inside `fork()` itself, for `std::process::Command` spawns
/// just the same); a constructor thread mutating the environment via C
/// `setenv` concurrently with *any* env read in the process is the usual
/// libc `environ` caveat; and constructors must not claim or close raw file
/// descriptors 3/4 (they carry the RPC pipe ends the daemon image takes
/// exclusive ownership of; they are open in both stage images, so an
/// ordinary `open` in a constructor can never land on those numbers
/// accidentally) — and should avoid fork+exec'ing long-lived helpers of
/// their own from the stage images, which would inherit duplicate pipe ends
/// during the pre-claim window and can suppress the parent's EOF liveness.
///
/// Dispatches on the process role: a normal invocation calls
/// [`A::run_foreground`](Daemonizable::run_foreground) with the [`Daemonizer`]
/// capability; the two re-exec'd daemon stages (each recognized by an
/// internal, namespaced `argv[1]` sentinel) run the daemon protocol, and
/// stage 2 diverges into [`A::run_daemon`](Daemonizable::run_daemon).
/// Foreground invocations never see either sentinel, and dispatch happens
/// before any app code, so an application *flag* cannot collide with them —
/// but they are reserved tokens: an invocation whose first argument is
/// exactly one of them is routed to the corresponding daemon stage, which
/// rejects anything the framework didn't actually plumb (fd validation, and
/// stage 2 additionally refuses to run as a session/group leader). The
/// stage-2 sentinel stays in `argv[1]` for the daemon's whole lifetime — it
/// is visible in `ps` and in `std::env::args()` inside `run_daemon`.
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
    match dispatch_decision(std::env::args_os().nth(1)) {
        DispatchDecision::DaemonStage1 => run_as_daemon_stage1(), // diverges
        DispatchDecision::DaemonStage2 => run_as_daemon_stage2::<A>(), // diverges
        DispatchDecision::Foreground => A::run_foreground(Daemonizer::new()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DispatchDecision {
    Foreground,
    DaemonStage1,
    DaemonStage2,
}

/// Pure dispatch decision, split out so it's unit-testable without invoking
/// the daemon arms (which probe/claim fds and exit the process).
///
/// Each sentinel is matched exactly, as the whole first argument; anything
/// else — including near-misses — falls through to the foreground arm, where
/// the app can produce a proper error path instead of a hijacked process.
/// Dispatch deliberately reads nothing but `argv[1]`: no environment access
/// (see [`DAEMON_STAGE2_ARGV`]'s doc for why stage identity rides argv), no
/// fd probing, no side effects.
fn dispatch_decision(first_arg: Option<std::ffi::OsString>) -> DispatchDecision {
    match first_arg.as_deref() {
        Some(arg) if arg == OsStr::new(DAEMON_STAGE1_ARGV) => DispatchDecision::DaemonStage1,
        Some(arg) if arg == OsStr::new(DAEMON_STAGE2_ARGV) => DispatchDecision::DaemonStage2,
        _ => DispatchDecision::Foreground,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::RpcServer;
    use serde::{Deserialize, Serialize};
    use std::ffi::OsString;
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

    #[test]
    fn dispatch_decision_table() {
        let cases: &[(Option<&str>, DispatchDecision)] = &[
            // No or ordinary first argument → foreground.
            (None, DispatchDecision::Foreground),
            (Some(""), DispatchDecision::Foreground),
            (Some("--verbose"), DispatchDecision::Foreground),
            // Exact sentinels route to their stages.
            (Some(DAEMON_STAGE1_ARGV), DispatchDecision::DaemonStage1),
            (Some(DAEMON_STAGE2_ARGV), DispatchDecision::DaemonStage2),
            // Near-misses must match exactly as the whole argument; anything
            // else falls through to the foreground arm (see fn docs).
            (Some("__daemonizable-daemonX"), DispatchDecision::Foreground),
            (Some("__daemonizable"), DispatchDecision::Foreground),
            (Some("__daemonizable-stage1 "), DispatchDecision::Foreground),
            // The legacy env marker is no longer a dispatch signal at all —
            // it is exercised end-to-end in framework_e2e
            // (legacy_env_marker_is_ignored); dispatch never reads env.
        ];
        for (first_arg, expected) in cases {
            assert_eq!(
                *expected,
                dispatch_decision(first_arg.map(OsString::from)),
                "wrong decision for first_arg {first_arg:?}",
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
}
