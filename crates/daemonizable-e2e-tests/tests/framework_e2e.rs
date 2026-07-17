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
    // environment (stage identity rides argv now — nothing is ever set, so
    // nothing can leak to the daemon's own children; this pins that absence
    // against any future design change). "argv1:sentinel" pins the documented
    // argv contract: the stage-2 sentinel stays visible in the daemon's
    // std::env::args() for its whole lifetime.
    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    let fields = parse_outfile(&result);
    assert_eq!(fields["parent-got"], "43", "outfile: {result}");
    assert_eq!(fields["cwd"], "/", "outfile: {result}");
    assert_eq!(fields["marker"], "removed", "outfile: {result}");
    assert_eq!(fields["argv1"], "sentinel", "outfile: {result}");

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

/// Spawn the test app with `arg` as its first argument and fds 3/4 known
/// CLOSED in the child, then assert the daemon-stage arm rejects it: exit
/// code 2 and the fstat-guard message. Shared by both sentinel-rejection
/// tests. The explicit close matters: the harness environment can leave
/// non-CLOEXEC FIFOs on low fd numbers (the classic case is an old-style GNU
/// make jobserver wrapping `cargo test`), which would pass the FIFO probe
/// and turn this test into a hang that eats jobserver tokens.
fn assert_sentinel_rejected(arg: &str) {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(test_app_exe());
    cmd.arg(arg);
    // SAFETY: the pre_exec closure runs in the forked child before exec and
    // may only run async-signal-safe code: `close` on two bare fd ints
    // qualifies (a not-open fd yields EBADF, which is fine — the goal is
    // "known closed"). It touches no memory beyond its own constants.
    unsafe {
        cmd.pre_exec(|| {
            libc::close(3);
            libc::close(4);
            Ok(())
        });
    }
    let output = cmd.output().expect("failed to spawn daemonizable-test-app");

    assert!(
        !output.status.success(),
        "the {arg} sentinel without inherited fds must fail, but it succeeded"
    );
    assert_eq!(
        Some(2),
        output.status.code(),
        "the daemon-stage arm must exit with code 2 when the fd probe fails"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("internal to this binary; do not invoke it directly"),
        "expected the fstat-guard message on stderr, got: {stderr}"
    );
}

#[test]
fn stage1_sentinel_from_shell_is_rejected() {
    // The stage-1 argv sentinel is internal plumbing: an invocation passing
    // it by hand has no pipes on fds 3/4, so stage 1's pre-fork probe must
    // refuse with a clear message — before setsid, before any process is
    // forked. (Literal deliberately hard-coded, kept in sync with
    // DAEMON_STAGE1_ARGV in ipc/spawn/mod.rs: if they drift, dispatch falls
    // through to the foreground arm and this test fails on the exit code.)
    assert_sentinel_rejected("__daemonizable-stage1");
}

#[test]
fn stage2_sentinel_from_shell_is_rejected() {
    // Same for the stage-2 sentinel: without the framework's plumbed fds the
    // claim must refuse. (Command-spawned children are not session/group
    // leaders, so this exercises the fd probe, not the leader guard — the
    // guard is exercised implicitly by every shell hand-run.) Literal kept
    // in sync with DAEMON_STAGE2_ARGV in ipc/spawn/mod.rs, as above.
    assert_sentinel_rejected("__daemonizable-daemon");
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
