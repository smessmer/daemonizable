//! Minimal [`Daemonizable`] app used by the framework end-to-end test
//! (`tests/framework_e2e.rs`). Unlike `daemonizable-test-background` (which
//! bypasses the framework and drives the raw IPC primitives), this binary
//! goes through the full production path: `#[daemonizable::main]` generates
//! the `main` that calls `daemonizable::run::<TestApp>()`, so a
//! `--daemonize` invocation exercises the env-marker dispatch, the real
//! `/proc/self/exe` re-exec spawn, the build-id handshake, the bootstrap
//! payload round-trip, and the typed RPC channel end-to-end — and dogfoods
//! the attribute macro under that real fork+exec path.
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
    /// Round-tripped from the bootstrap payload, proving it was shipped,
    /// decoded, and handed to `run_daemon`.
    payload_tag: String,
    /// Whether the daemon-child env marker is still set inside `run_daemon`.
    /// The framework must have removed it (so the daemon's own children
    /// aren't misdetected); the test asserts "removed".
    marker: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestPayload {
    tag: String,
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
    type BootstrapPayload = TestPayload;

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

    fn run_daemon(payload: TestPayload, mut rpc: RpcServer<TestRequest, TestResponse>) -> ! {
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
        // Echo+1 until the parent drops its client (EOF), then exit cleanly.
        while let Ok(request) = rpc.next_request() {
            rpc.send_response(&TestResponse {
                v: request.v + 1,
                daemon_cwd: daemon_cwd.clone(),
                payload_tag: payload.tag.clone(),
                marker: marker.to_string(),
            })
            .expect("daemon: failed to send response");
        }
        std::process::exit(0);
    }
}

/// Parent side of the `--daemonize` path: spawn the daemon (shipping a
/// payload tag it must echo back), do one typed RPC round-trip, and write
/// everything observable into the outfile.
fn run_parent(daemonizer: Daemonizer<TestApp>, outfile: &Path) -> Result<(), String> {
    let mut rpc = daemonizer
        .spawn_daemon(&TestPayload {
            tag: "tag-from-parent".to_string(),
        })
        .map_err(|err| format!("spawn_daemon failed: {err}"))?;
    rpc.send_request(&TestRequest { v: 42 })
        .map_err(|err| format!("send_request failed: {err}"))?;
    let response = rpc
        .recv_response(Duration::from_secs(10))
        .map_err(|err| format!("recv_response failed: {err}"))?;
    std::fs::write(
        outfile,
        format!(
            "parent-got:{} cwd:{} payload:{} marker:{}",
            response.v, response.daemon_cwd, response.payload_tag, response.marker
        ),
    )
    .map_err(|err| format!("failed to write outfile: {err}"))
}
