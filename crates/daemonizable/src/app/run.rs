//! The single entry point [`run`] and its process-role dispatch: a normal
//! invocation goes to the app's foreground code; the re-exec'd daemon child
//! (recognized by an environment marker) goes to the daemon startup sequence.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use super::daemon_child::run_as_daemon_child;
use super::{Daemonizable, Daemonizer};
use crate::ipc::{DAEMON_CHILD_ENV_VALUE, DAEMON_CHILD_ENV_VAR};

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
/// "And nothing else" is a real constraint, not a style note: the re-exec'd
/// daemon child runs the same `main`, so anything you put in front of `run`
/// runs *twice* — once in the foreground process and again in the daemon child,
/// where argv is empty and the process has not yet claimed its IPC fds. A
/// thread spawned before `run` therefore also exists in the child. The
/// attribute guarantees an empty preamble by construction; a hand-written
/// `main` has to keep that promise itself (and must return `run`'s
/// [`ExitCode`] rather than swallowing it).
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
}
