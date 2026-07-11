//! End-to-end test of the framework's `run::<App>()` dispatch, using the
//! `daemonizable-test-app` helper binary (which implements
//! [`daemonizable::Daemonizable`] and calls `run` from `main`).
//!
//! Unlike the daemon-lifecycle tests (which drive the raw IPC primitives via
//! `start_background_process_with_exe`, skipping handshake and bootstrap),
//! these tests cover the full production path: the env-marker child
//! dispatch, the real `/proc/self/exe` re-exec spawn, the build-id
//! handshake, the bootstrap payload round-trip, and the typed RPC channel
//! between parent and daemon.

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
fn daemonize_dispatch_does_full_spawn_handshake_bootstrap_and_rpc_roundtrip() {
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
    // "payload:tag-from-parent" proves the bootstrap payload was shipped,
    // decoded, and handed to `run_daemon`. "marker:removed" proves the child
    // env marker was dropped before `run_daemon` was entered, so the
    // daemon's own children can't be misdetected as daemon children.
    // (Note: "before run_daemon", not "before app code" — `build_id()` and
    // the payload's `Deserialize` run earlier in the child arm; see the
    // remove_var TODO in app/daemon_child.rs.)
    //
    // TODO This test doesn't assert the framework's `setsid` (the single
    //   most important line for daemon survival) — no test does; the
    //   daemon_survives_parent_exit test observes only the helper binary's
    //   own setsid. Fix: add `sid: i32` (libc::getsid(0)) to TestResponse,
    //   include it in the outfile, and assert here that the daemon's
    //   session differs from this test process's session id.
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    assert_eq!(
        "parent-got:43 cwd:/ payload:tag-from-parent marker:removed",
        result
    );
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

#[test]
fn env_marker_from_shell_is_rejected() {
    // A user (or stray script) exporting the daemon-child marker has no
    // pipes on fds 3/4, so the child arm must refuse with a clear message
    // instead of misinterpreting whatever happens to be open on those fds.
    let output = Command::new(test_app_exe())
        .env("DAEMONIZABLE_DAEMON_CHILD", "1")
        .output()
        .expect("failed to spawn daemonizable-test-app");

    assert!(
        !output.status.success(),
        "the daemon-child marker without inherited fds must fail, but it succeeded"
    );
    assert_eq!(
        Some(2),
        output.status.code(),
        "the child arm must exit with code 2 when the fd claim fails"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("internal to this binary; do not invoke it directly"),
        "expected the fstat-guard message on stderr, got: {stderr}"
    );
}

#[test]
fn env_marker_with_wrong_value_falls_through_to_foreground() {
    // Only the exact marker value the spawner sets counts as "daemon child";
    // a user exporting the variable with some other value gets the normal
    // foreground behavior instead of a hijacked process.
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = Command::new(test_app_exe())
        .env("DAEMONIZABLE_DAEMON_CHILD", "0")
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
