//! The single entry point [`run`] and its process-role dispatch: a normal
//! invocation goes to the app's foreground code; the two re-exec'd daemon
//! stages (stage 1 recognized by an environment marker, stage 2 — the final
//! daemon image — by an argv sentinel) go to the daemon startup sequence.

use std::ffi::OsStr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use super::daemon_child::{run_as_daemon_stage1, run_as_daemon_stage2};
use super::{Daemonizable, Daemonizer};
use crate::ipc::{DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR, DAEMON_STAGE2_ARGV};

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
/// daemon-stage images, before `run` gets control. Threads or environment
/// access from such constructors are tolerated by design — the staging image
/// only ever runs async-signal-safe code after its fork, and the daemon image
/// never forks or mutates its environment — but constructors must not
/// deliberately claim or close raw file descriptors 3/4 (they carry the RPC
/// pipe ends the daemon image takes exclusive ownership of; they are open in
/// both stage images, so an ordinary `open` in a constructor can never land
/// on those numbers accidentally).
///
/// Dispatches on the process role: a normal invocation calls
/// [`A::run_foreground`](Daemonizable::run_foreground) with the [`Daemonizer`]
/// capability; the re-exec'd daemon stages (stage 1 recognized by the
/// environment marker its parent set for it, stage 2 by an internal argv
/// sentinel) run the daemon protocol, and stage 2 diverges into
/// [`A::run_daemon`](Daemonizable::run_daemon). The sentinel occupies
/// `argv[1]` in the daemon image only — foreground invocations never see it,
/// and an application flag can't collide with it accidentally (dispatch
/// happens before any app code, and the name is deliberately namespaced).
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
    match dispatch_decision(
        std::env::var_os(DAEMON_CHILD_ENV_VAR),
        std::env::args_os().nth(1),
    ) {
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
/// The stage-2 argv sentinel is checked first: a well-formed stage 2 never
/// carries the env marker (stage 1 filters it out of execve's envp), so the
/// only way to see both signals is a malformed hand-invocation — and the
/// sentinel arm is the stricter one (its fd claim rejects a hand-run with a
/// clean error). For the env marker, only the exact value the spawner sets
/// counts; anything else — including a user exporting the variable with some
/// other value — falls through to the foreground arm, where the app can
/// produce a proper error path instead of a hijacked process. The sentinel,
/// by contrast, is matched as a whole `argv[1]`; there is no "wrong value"
/// variant of it.
fn dispatch_decision(
    marker: Option<std::ffi::OsString>,
    first_arg: Option<std::ffi::OsString>,
) -> DispatchDecision {
    if first_arg.as_deref() == Some(OsStr::new(DAEMON_STAGE2_ARGV)) {
        return DispatchDecision::DaemonStage2;
    }
    match marker {
        Some(value) if value == DAEMON_CHILD_ENV_VALUE => DispatchDecision::DaemonStage1,
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
        const S2: &str = DAEMON_STAGE2_ARGV;
        let cases: &[(Option<&str>, Option<&str>, DispatchDecision)] = &[
            // No signals → foreground.
            (None, None, DispatchDecision::Foreground),
            (None, Some("--verbose"), DispatchDecision::Foreground),
            // The exact env marker value → stage 1.
            (Some("1"), None, DispatchDecision::DaemonStage1),
            (Some("1"), Some("--verbose"), DispatchDecision::DaemonStage1),
            // Only the exact marker value counts; anything else falls
            // through to the foreground arm (see fn docs).
            (Some(""), None, DispatchDecision::Foreground),
            (Some("0"), None, DispatchDecision::Foreground),
            (Some("true"), None, DispatchDecision::Foreground),
            (Some("11"), None, DispatchDecision::Foreground),
            // The argv sentinel → stage 2, and it must match exactly as a
            // whole argument.
            (None, Some(S2), DispatchDecision::DaemonStage2),
            (None, Some("__daemonizable-daemonX"), DispatchDecision::Foreground),
            (None, Some("__daemonizable"), DispatchDecision::Foreground),
            // Both signals is a malformed hand-invocation (stage 1 filters
            // the marker out of stage 2's environment); the sentinel wins so
            // the stricter fd-validating arm handles it.
            (Some("1"), Some(S2), DispatchDecision::DaemonStage2),
            (Some("0"), Some(S2), DispatchDecision::DaemonStage2),
        ];
        for (marker, first_arg, expected) in cases {
            assert_eq!(
                *expected,
                dispatch_decision(marker.map(OsString::from), first_arg.map(OsString::from)),
                "wrong decision for marker {marker:?}, first_arg {first_arg:?}",
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
