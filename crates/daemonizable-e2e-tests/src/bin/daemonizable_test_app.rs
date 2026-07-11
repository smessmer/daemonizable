//! Minimal [`Daemonizable`] app used by the framework end-to-end test
//! (`tests/framework_e2e.rs`). Unlike `daemonizable-test-background` (which
//! bypasses the framework and drives the raw IPC primitives), this binary
//! goes through the full production path: `#[daemonizable::main]` generates
//! the `main` that calls `daemonizable::run::<TestApp>()`, so a
//! `--daemonize` invocation exercises the env-marker dispatch, the real
//! `/proc/self/exe` re-exec spawn, the build-id handshake, and the typed RPC
//! channel end-to-end — and dogfoods the attribute macro under that real
//! fork+exec path.
//!
//! Arguments are parsed by hand — the new API imposes no argument parser on
//! applications, and this binary proves none is needed.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use daemonizable::{Daemonizable, Daemonizer, RpcServer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestRequest {
    v: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResponse {
    v: i32,
    /// The daemon's working directory, so the test can assert the framework
    /// chdir'd it to `/` (it must not pin the parent's cwd).
    daemon_cwd: String,
    /// Whether the daemon-child env marker is still set inside `run_daemon`.
    /// The framework must have removed it (so the daemon's own children
    /// aren't misdetected); the test asserts "removed".
    marker: String,
    /// The daemon's own pid (`std::process::id()`). With `sid` below it proves
    /// the daemon is a grandchild, not a session leader.
    pid: u32,
    /// The daemon's session id (`getsid(0)`). The test asserts it differs from
    /// the test's own session (the framework `setsid` took effect) AND from
    /// `pid` (the daemon is not a session leader — the sid is the dead
    /// intermediate's pid, which only holds once the second fork has run).
    sid: i32,
}

struct Args {
    daemonize: bool,
    outfile: Option<PathBuf>,
}

/// Hand-rolled argv parsing. Flags: `--daemonize` (spawn the daemon and do
/// one RPC round-trip), `--outfile PATH` (where the observable result goes,
/// so the integration test can assert which dispatch path ran).
fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        daemonize: false,
        outfile: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--daemonize" => args.daemonize = true,
            "--outfile" => {
                let value = it.next().ok_or("--outfile needs a value")?;
                args.outfile = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

struct TestApp;

#[daemonizable::main]
impl Daemonizable for TestApp {
    type Request = TestRequest;
    type Response = TestResponse;

    fn build_id() -> String {
        // Parent and daemon are the same binary, so any deterministic string
        // works; name + version mirrors what a real application should use.
        format!("daemonizable-test-app {}", env!("CARGO_PKG_VERSION"))
    }

    fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
        let args = match parse_args() {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(2);
            }
        };
        let outfile = args.outfile.expect("test app invoked without --outfile");
        let result = if args.daemonize {
            run_parent(daemonizer, &outfile)
        } else {
            std::fs::write(&outfile, "foreground-ran")
                .map_err(|err| format!("failed to write outfile: {err}"))
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        }
    }

    fn run_daemon(mut rpc: RpcServer<TestRequest, TestResponse>) -> ! {
        // Report the daemon's cwd so the test can confirm the framework
        // chdir'd it to `/` rather than inheriting the parent's working
        // directory, and whether the child env marker was removed.
        let daemon_cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let marker = if std::env::var_os("DAEMONIZABLE_DAEMON_CHILD").is_some() {
            "set"
        } else {
            "removed"
        };
        // `run_daemon` runs in the surviving grandchild (post second fork), so
        // these report the FINAL daemon identity: pid is the grandchild's, sid
        // is the (dead) intermediate's pid.
        let pid = std::process::id();
        let sid = unsafe { libc::getsid(0) };
        // Echo+1 until the parent drops its client (EOF), then exit cleanly.
        while let Ok(request) = rpc.next_request() {
            rpc.send_response(&TestResponse {
                v: request.v + 1,
                daemon_cwd: daemon_cwd.clone(),
                marker: marker.to_string(),
                pid,
                sid,
            })
            .expect("daemon: failed to send response");
        }
        std::process::exit(0);
    }
}

/// Parent side of the `--daemonize` path: spawn the daemon, do one typed RPC
/// round-trip, and write everything observable into the outfile.
fn run_parent(daemonizer: Daemonizer<TestApp>, outfile: &Path) -> Result<(), String> {
    let mut rpc = daemonizer
        .spawn_daemon()
        .map_err(|err| format!("spawn_daemon failed: {err}"))?;
    rpc.send_request(&TestRequest { v: 42 })
        .map_err(|err| format!("send_request failed: {err}"))?;
    let response = rpc
        .recv_response(Duration::from_secs(10))
        .map_err(|err| format!("recv_response failed: {err}"))?;
    // After a successful spawn, this process must have no zombie children: the
    // double-fork intermediate was reaped by `spawn_daemon`'s success-path
    // wait(), and the daemon itself is a grandchild orphaned away from us.
    let zombies = count_own_zombie_children();
    std::fs::write(
        outfile,
        format!(
            "parent-got:{} cwd:{} marker:{} sid:{} pid:{} zombies:{}",
            response.v, response.daemon_cwd, response.marker, response.sid, response.pid, zombies,
        ),
    )
    .map_err(|err| format!("failed to write outfile: {err}"))
}

/// Count this process's zombie (`State: Z`) children by scanning `/proc`. Used
/// to prove `spawn_daemon` reaped the second-fork intermediate on success.
/// Linux-only; on other platforms the framework_e2e hang-canary is the
/// remaining guard, so this reports 0 (nothing to assert).
#[cfg(target_os = "linux")]
fn count_own_zombie_children() -> usize {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{name}/status")) else {
            continue;
        };
        let mut is_zombie = false;
        let mut ppid: Option<u32> = None;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:") {
                is_zombie = rest.trim_start().starts_with('Z');
            } else if let Some(rest) = line.strip_prefix("PPid:") {
                ppid = rest.trim().parse().ok();
            }
        }
        if is_zombie && ppid == Some(me) {
            count += 1;
        }
    }
    count
}

#[cfg(not(target_os = "linux"))]
fn count_own_zombie_children() -> usize {
    0
}
