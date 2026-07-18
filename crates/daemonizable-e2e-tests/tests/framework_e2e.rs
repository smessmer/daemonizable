//! End-to-end test of the framework's `run::<App>()` dispatch, using the
//! `daemonizable-test-app` helper binary (which implements
//! [`daemonizable::Daemonizable`] and gets its `main` from
//! `#[daemonizable::main]`).
//!
//! Unlike the daemon-lifecycle tests (which drive the raw IPC primitives via
//! `start_background_process_with_exe`, skipping the handshake), these tests
//! cover the full production path: the argv-sentinel stage dispatch, the real
//! `/proc/self/exe` re-exec spawn, the build-id handshake, and the typed RPC
//! channel between parent and daemon.

use std::path::PathBuf;
use std::process::Command;

fn test_app_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-app")
}

fn run_test_app(args: &[&str], outfile: Option<&PathBuf>) -> std::process::Output {
    let mut cmd = Command::new(test_app_exe());
    cmd.args(args);
    if let Some(outfile) = outfile {
        cmd.arg("--outfile").arg(outfile);
    }
    cmd.output().expect("failed to spawn daemonizable-test-app")
}

#[test]
fn daemonize_dispatch_does_full_spawn_handshake_and_rpc_roundtrip() {
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = run_test_app(&["--daemonize"], Some(&outfile));

    assert!(
        output.status.success(),
        "test app failed: status={:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    // "parent-got:43" proves the whole chain worked: the parent re-exec'd
    // itself, the daemon passed the build-id handshake, and the typed echo+1
    // RPC round-tripped through `run_daemon`. "cwd:/" proves the framework
    // chdir'd the daemon to `/` instead of pinning the parent's cwd.
    // "marker:removed" proves no framework env var exists in the daemon's
    // environment (stage identity rides an in-band channel token now — nothing
    // is ever set, so nothing can leak to the daemon's own children; this pins
    // that absence against any future design change). "argv1:empty" pins the
    // argv contract: the daemon receives NO arguments (only argv[0]), since the
    // token is carried in-band on the channel fd, not in argv.
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    let fields = parse_outfile(&result);
    assert_eq!(fields["parent-got"], "43", "outfile: {result}");
    assert_eq!(fields["cwd"], "/", "outfile: {result}");
    assert_eq!(fields["marker"], "removed", "outfile: {result}");
    assert_eq!(fields["argv1"], "empty", "outfile: {result}");

    // Session assertions — the payoff of the framework's `setsid` + second fork.
    let daemon_sid: i32 = fields["sid"].parse().expect("sid not an int");
    let daemon_pid: i32 = fields["pid"].parse().expect("pid not an int");
    // `getsid(None)` queries this process's own session id, which cannot fail.
    let test_sid = nix::unistd::getsid(None)
        .expect("getsid for the calling process")
        .as_raw();
    assert!(daemon_sid > 0, "daemon reported a bogus sid: {daemon_sid}");
    // setsid took effect: the daemon is in its own session, not the test's
    // (the test-app parent shares this test's session; the daemon left it).
    assert_ne!(
        daemon_sid, test_sid,
        "daemon shares the test's session — framework setsid did not take effect",
    );
    // The daemon is NOT a session leader: its sid is the (dead) intermediate's
    // pid, so sid != its own pid. Under a single fork the daemon WOULD be the
    // leader (sid == pid), so this is the assertion that pins the second fork.
    assert_ne!(
        daemon_sid, daemon_pid,
        "daemon is a session leader (sid == pid) — the second fork did not happen",
    );

    // The successful spawn left no zombie: `spawn_daemon` reaped the
    // intermediate (Linux-only scan; 0 elsewhere — see the test app).
    assert_eq!(
        fields["zombies"], "0",
        "spawn_daemon left a zombie intermediate: {result}",
    );
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

#[test]
fn foreground_dispatch_runs_run_foreground_without_spawning() {
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = run_test_app(&[], Some(&outfile));

    assert!(
        output.status.success(),
        "test app failed: status={:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    assert_eq!("foreground-ran", result);
}

/// Spawn the test app with `arg` as its first argument (the way a shell
/// hand-run would) and assert it is treated as an ORDINARY foreground argument,
/// not a daemon-stage trigger. Dispatch reads only the in-band channel token on
/// fd 3 now, so the former argv sentinels are inert as dispatch signals: the app
/// runs `run_foreground`, whose hand-rolled parser rejects the unknown argument
/// with its own "unknown argument" message — proving the process was NOT
/// hijacked into a daemon stage (which would print "internal to this binary").
fn assert_former_sentinel_is_foreground(arg: &str) {
    let output = Command::new(test_app_exe())
        .arg(arg)
        .output()
        .expect("failed to spawn daemonizable-test-app");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Reached the app's own foreground argument parser...
    assert!(
        stderr.contains(&format!("unknown argument: {arg}")),
        "expected the foreground arg parser to reject {arg:?}, got stderr: {stderr}"
    );
    // ...and did NOT go down any daemon-stage arm.
    assert!(
        !stderr.contains("internal to this binary"),
        "the {arg} argument was routed to a daemon stage; it must be inert as a \
         dispatch signal now. stderr: {stderr}"
    );
}

#[test]
fn former_stage1_sentinel_is_an_ordinary_argument() {
    // The old stage-1 argv sentinel is no longer a dispatch signal — dispatch
    // reads the channel token on fd 3, never argv. Passing it by hand must reach
    // the app's foreground code as a plain (here, unrecognized) argument.
    assert_former_sentinel_is_foreground("__daemonizable-stage1");
}

#[test]
fn former_stage2_sentinel_is_an_ordinary_argument() {
    // Same for the old stage-2 sentinel.
    assert_former_sentinel_is_foreground("__daemonizable-daemon");
}

#[test]
fn legacy_env_marker_is_ignored() {
    // The pre-argv-sentinel design dispatched on this environment variable.
    // It must now be completely inert — an app whose environment happens to
    // carry it (stale wrapper scripts, supervisor units written against the
    // old scheme) runs its normal foreground code instead of being hijacked
    // into a daemon arm.
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = Command::new(test_app_exe())
        .env("DAEMONIZABLE_DAEMON_CHILD", "1")
        .arg("--outfile")
        .arg(&outfile)
        .output()
        .expect("failed to spawn daemonizable-test-app");

    assert!(
        output.status.success(),
        "test app failed: status={:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    assert_eq!("foreground-ran", result);
}
