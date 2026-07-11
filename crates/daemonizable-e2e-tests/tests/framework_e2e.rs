//! End-to-end test of the framework's `run::<App>()` dispatch, using the
//! `daemonizable-test-app` helper binary (which implements
//! [`daemonizable::Daemonizable`] and gets its `main` from
//! `#[daemonizable::main]`).
//!
//! Unlike the daemon-lifecycle tests (which drive the raw IPC primitives via
//! `start_background_process_with_exe`, skipping the handshake), these tests
//! cover the full production path: the env-marker child dispatch, the real
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
    // "marker:removed" proves the child env marker was dropped before
    // `run_daemon` was entered, so the daemon's own children can't be
    // misdetected as daemon children. (Note: "before run_daemon", not "before
    // app code" — `build_id()` runs earlier in the child arm; see the
    // remove_var TODO in app/daemon_child.rs.)
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    let fields = parse_outfile(&result);
    assert_eq!(fields["parent-got"], "43", "outfile: {result}");
    assert_eq!(fields["cwd"], "/", "outfile: {result}");
    assert_eq!(fields["marker"], "removed", "outfile: {result}");

    // Session assertions — the payoff of the framework's `setsid` + second fork.
    let daemon_sid: i32 = fields["sid"].parse().expect("sid not an int");
    let daemon_pid: i32 = fields["pid"].parse().expect("pid not an int");
    let test_sid = unsafe { libc::getsid(0) };
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
