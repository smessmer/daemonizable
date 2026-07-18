//! Parent-exit survival of the FULL framework path.
//!
//! `daemon_survives_parent_exit.rs` proves a daemon outlives the process that
//! spawned it — but through the raw spawn machinery
//! (`start_background_process_with_exe`), which deliberately bypasses the
//! framework's daemon-stage arms, and the `setsid` it observes is one its
//! helper binary performs by hand. `framework_e2e.rs` covers the framework's
//! own detachment *mechanism* (setsid + second fork) via session-id
//! assertions, but its daemon exits with the parent, so nothing there
//! observes a framework-spawned daemon alive after the foreground is gone.
//! This test closes that gap: the production path end-to-end (`run::<App>()`
//! in-band channel-token dispatch, `/proc/self/exe` re-exec spawn, build-id
//! handshake, typed RPC), the foreground process exits, and the daemon is
//! observed STILL DOING WORK afterward.
//!
//! Mechanics: the `daemonizable-test-app` helper is launched with
//! `--daemonize` plus `DAEMONIZABLE_TEST_APP_SENTINEL` in the environment.
//! Argv does not survive the re-exec spawn but the environment passes through
//! both daemon-stage execs untouched, so the daemon sees the variable and,
//! after answering the parent's single round-trip (whose response carries its
//! pid into the outfile), detaches stdio and writes a tick counter to the
//! sentinel path forever (see the sentinel-mode comment in the test app's
//! `run_daemon`). The foreground process exits as usual; the test then checks
//! the surviving daemon's session ids live via `getsid()` — not just the
//! values it self-reported over RPC while the parent still ran — and polls
//! the sentinel until its contents change. Cleans up via `DaemonGuard`
//! (SIGTERM, then SIGKILL).

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use daemonizable_e2e_tests::DaemonGuard;
use nix::unistd::{Pid, getsid};

#[test]
fn framework_daemon_survives_parent_exit() {
    let tmp = tempfile::Builder::new()
        .prefix("daemonizable-framework-survive-test")
        .tempdir()
        .unwrap();
    let outfile = tmp.path().join("result.txt");
    let sentinel_path = tmp.path().join("sentinel");

    // Run the foreground CLI: it spawns the daemon through the full framework
    // path, does one RPC round-trip, writes the outfile, and exits.
    // `output()` reaps it AND waits for EOF on its captured stdout/stderr —
    // which the daemon's inherited pipe copies hold open until its
    // sentinel-mode `detach_stdio`. Returning from this call therefore
    // already proves the daemon released the parent's stdio; a daemon that
    // failed to detach would hang the test here, not pass it.
    let output = Command::new(env!("CARGO_BIN_EXE_daemonizable-test-app"))
        .args(["--daemonize", "--outfile"])
        .arg(&outfile)
        .env("DAEMONIZABLE_TEST_APP_SENTINEL", &sentinel_path)
        .output()
        .expect("failed to run daemonizable-test-app");
    assert!(
        output.status.success(),
        "foreground process failed: status={:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The foreground process is gone (reaped by `output()` above). Everything
    // it learned before exiting is in the outfile; `parent-got:43` confirms
    // the round-trip really went through the daemon (spawn + handshake + RPC),
    // so the pid below is the daemon's own report, not a stale file.
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    let fields = parse_outfile(&result);
    assert_eq!(fields["parent-got"], "43", "outfile: {result}");
    let daemon_pid = Pid::from_raw(fields["pid"].parse().expect("pid not an int"));
    // Installed *before* any assertion below, so the daemon gets killed even
    // if a check panics.
    let _guard = DaemonGuard(daemon_pid);

    // Session checks, live against the SURVIVING daemon rather than trusting
    // the sid it self-reported while the parent still ran. Its session
    // differs from the test's (the framework `setsid` took effect — without
    // it the daemon would die on SIGHUP when the launching terminal closes)
    // and from its own pid (it is not a session leader — the second fork
    // happened).
    let daemon_sid = getsid(Some(daemon_pid)).expect("getsid(daemon)");
    let test_sid = getsid(None).expect("getsid(test)");
    assert_ne!(
        daemon_sid, test_sid,
        "daemon and test share a session — framework setsid did not take effect",
    );
    assert_ne!(
        daemon_sid, daemon_pid,
        "daemon is a session leader (sid == pid) — the second fork did not happen",
    );

    // The daemon must keep working now that the foreground process is gone.
    // Wait for the sentinel to appear, then poll until its contents change.
    // The daemon writes every 50 ms, so observing a change normally takes
    // <100 ms; 5 s is a generous ceiling that fails fast if the daemon has
    // actually stopped.
    let sentinel_appear_deadline = Instant::now() + Duration::from_secs(5);
    while !sentinel_path.exists() {
        assert!(
            Instant::now() < sentinel_appear_deadline,
            "daemon did not create sentinel file within 5s",
        );
        thread::sleep(Duration::from_millis(20));
    }
    let first = std::fs::read_to_string(&sentinel_path).expect("read sentinel");
    let change_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        thread::sleep(Duration::from_millis(20));
        let next = std::fs::read_to_string(&sentinel_path).expect("read sentinel");
        if next != first {
            break; // observed a change → daemon is alive
        }
        assert!(
            Instant::now() < change_deadline,
            "daemon stopped writing sentinel after the foreground process exited (no change in 5s)",
        );
    }

    // Cleanup happens via DaemonGuard's Drop.
}

/// Parse the test app's `key:value key:value ...` outfile. All values are
/// space-free (paths are `/`, tags/markers are single tokens, ids are numbers),
/// so a split on spaces then on the first `:` is unambiguous.
fn parse_outfile(s: &str) -> std::collections::HashMap<String, String> {
    s.split(' ')
        .filter_map(|kv| {
            let (k, v) = kv.split_once(':')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}
