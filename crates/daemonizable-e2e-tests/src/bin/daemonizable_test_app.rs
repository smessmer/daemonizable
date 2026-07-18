//! Minimal [`Daemonizable`] app used by the framework end-to-end test
//! (`tests/framework_e2e.rs`). Unlike `daemonizable-test-background` (which
//! bypasses the framework and drives the raw IPC primitives), this binary
//! goes through the full production path: `#[daemonizable::main]` generates
//! the `main` that calls `daemonizable::run::<TestApp>()`, so a
//! `--daemonize` invocation exercises the in-band channel-token stage dispatch, the real
//! `/proc/self/exe` re-exec spawn, the build-id handshake, and the typed RPC
//! channel end-to-end — and dogfoods the attribute macro under that real
//! fork+exec path.
//!
//! Arguments are parsed by hand — the new API imposes no argument parser on
//! applications, and this binary proves none is needed.
//!
//! Beyond the single-daemon `--daemonize` path (`tests/framework_e2e.rs`), it
//! also drives the *multiple-daemon* paths exercised by
//! `tests/multiple_daemons.rs`: `--spawn-many N` spawns N daemons from one
//! foreground (all live at once, then a round-trip each), `--spawn-many N
//! --concurrent` spawns them from N threads that all enter `spawn_daemon`
//! together (the advertised `Copy + Send + Sync` `Daemonizer` use), and
//! `--spawn-interleaved` keeps two daemons live and interleaves requests to
//! prove the two channels never cross-talk.
//!
//! One knob rides the environment instead of argv, because it must reach the
//! *daemon* image (argv does not survive the re-exec spawn; the environment
//! passes through both daemon-stage execs untouched):
//! `DAEMONIZABLE_TEST_APP_SENTINEL`, used by
//! `tests/framework_daemon_survives_parent_exit.rs`, switches `run_daemon`
//! into a long-lived mode that outlives the foreground process — see the
//! comment in `run_daemon`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use daemonizable::{Daemonizable, Daemonizer, RpcClient, RpcServer};
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
    /// Whether the legacy daemon-child env marker is set inside `run_daemon`.
    /// Stage identity rides an in-band channel token now, so no framework env var may exist in
    /// the daemon's environment at all (its children would inherit it); the
    /// test asserts "removed". Kept as a regression pin against any future
    /// design reintroducing environment leakage.
    marker: String,
    /// Whether the daemon's `argv` is empty (only `argv[0]`). Stage identity
    /// rides an in-band channel token now, not argv, so the daemon receives NO
    /// arguments — `std::env::args().nth(1)` is `None`. The test asserts
    /// "empty". Kept as a regression pin against any future design reintroducing
    /// argv injection.
    argv1: String,
    /// The daemon's own pid (`std::process::id()`). With `sid` below it proves
    /// the daemon is a grandchild, not a session leader.
    pid: u32,
    /// The daemon's session id (`getsid(0)`). The test asserts it differs from
    /// the test's own session (the framework `setsid` took effect) AND from
    /// `pid` (the daemon is not a session leader — the sid is the dead
    /// intermediate's pid, which only holds once the second fork has run).
    sid: i32,
}

/// What the foreground process should do. Selected by the flags below;
/// `Foreground` (no daemon flag) is the default.
enum Mode {
    /// No daemon flag: just record that `run_foreground` ran.
    Foreground,
    /// `--daemonize`: spawn one daemon and do a single RPC round-trip.
    Daemonize,
    /// `--spawn-many N [--concurrent]`: spawn N daemons from this one
    /// foreground — sequentially (all live at once) or, with `--concurrent`,
    /// from N threads entering `spawn_daemon` together.
    SpawnMany { count: usize, concurrent: bool },
    /// `--spawn-interleaved`: keep two daemons live and interleave requests to
    /// prove the two channels don't cross-talk.
    Interleaved,
}

struct Args {
    mode: Mode,
    outfile: Option<PathBuf>,
}

/// Hand-rolled argv parsing. Flags: `--daemonize` (spawn one daemon, one RPC
/// round-trip), `--spawn-many N` / `--concurrent` and `--spawn-interleaved`
/// (the multi-daemon paths), and `--outfile PATH` (where the observable result
/// goes, so the integration test can assert which dispatch path ran).
fn parse_args() -> Result<Args, String> {
    let mut outfile = None;
    let mut mode = Mode::Foreground;
    let mut spawn_many: Option<usize> = None;
    let mut concurrent = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--daemonize" => mode = Mode::Daemonize,
            "--spawn-interleaved" => mode = Mode::Interleaved,
            "--spawn-many" => {
                let value = it.next().ok_or("--spawn-many needs a value")?;
                let count = value
                    .parse::<usize>()
                    .map_err(|_| format!("--spawn-many needs an integer, got {value:?}"))?;
                if count == 0 {
                    return Err("--spawn-many needs a positive count".to_string());
                }
                spawn_many = Some(count);
            }
            "--concurrent" => concurrent = true,
            "--outfile" => {
                let value = it.next().ok_or("--outfile needs a value")?;
                outfile = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    // `--spawn-many` (with its optional `--concurrent`) wins over the simpler
    // flags if both are somehow present; `--concurrent` alone is a no-op.
    if let Some(count) = spawn_many {
        mode = Mode::SpawnMany { count, concurrent };
    }
    Ok(Args { mode, outfile })
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
        let result = match args.mode {
            Mode::Foreground => std::fs::write(&outfile, "foreground-ran")
                .map_err(|err| format!("failed to write outfile: {err}")),
            Mode::Daemonize => run_parent(daemonizer, &outfile),
            Mode::SpawnMany { count, concurrent } => {
                run_spawn_many(daemonizer, &outfile, count, concurrent)
            }
            Mode::Interleaved => run_spawn_interleaved(daemonizer, &outfile),
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
        // directory, plus the marker/argv1 environment- and argv-contract probes.
        let daemon_cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let marker = if std::env::var_os("DAEMONIZABLE_DAEMON_CHILD").is_some() {
            "set"
        } else {
            "removed"
        };
        // The daemon's argv must be empty (stage identity rides an in-band
        // channel token now, not argv). Pin that nth(1) is None.
        let argv1 = if std::env::args_os().nth(1).is_none() {
            "empty"
        } else {
            "present"
        };
        // `run_daemon` runs in the surviving grandchild (post second fork), so
        // these report the FINAL daemon identity: pid is the grandchild's, sid
        // is the (dead) intermediate's pid.
        let pid = std::process::id();
        // `getsid(None)` queries the calling process's own session id, which
        // cannot fail for the caller itself.
        let sid = nix::unistd::getsid(None)
            .expect("getsid for the calling process")
            .as_raw();

        // Sentinel mode (`DAEMONIZABLE_TEST_APP_SENTINEL` set — inherited from
        // the test through the foreground process and both daemon-stage
        // execs): the daemon must OUTLIVE the foreground process, which is
        // what `tests/framework_daemon_survives_parent_exit.rs` asserts.
        // Answer the parent's single round-trip first (its response carries
        // pid/sid into the outfile the test reads), then behave like a real
        // long-lived daemon: detach stdio and keep working — writing an
        // incrementing tick to the sentinel path forever, never watching for
        // RPC EOF. The detach is load-bearing for the test harness, not just
        // verisimilitude: the test captures the foreground process with
        // `Command::output()`, which reads until ALL write ends of the
        // stdout/stderr pipes close — including the copies this daemon
        // inherited across the spawn — so without it the test would hang.
        if let Some(sentinel) = std::env::var_os("DAEMONIZABLE_TEST_APP_SENTINEL") {
            let sentinel = PathBuf::from(sentinel);
            let request = rpc
                .next_request()
                .expect("daemon: expected the parent's request");
            rpc.send_response(&TestResponse {
                v: request.v + 1,
                daemon_cwd: daemon_cwd.clone(),
                marker: marker.to_string(),
                argv1: argv1.to_string(),
                pid,
                sid,
            })
            .expect("daemon: failed to send response");
            if let Err(err) = daemonizable::detach_stdio() {
                // Still on the inherited stderr (detach failed), so this
                // reaches the test's captured output; exiting makes the test
                // fail its liveness check with that diagnostic available.
                eprintln!("daemon: detach_stdio failed: {err}");
                std::process::exit(1);
            }
            drop(rpc);
            let mut tick: u64 = 0;
            loop {
                tick += 1;
                // Best-effort: stdio is detached, so there's nowhere useful to
                // report a write failure; a persistently failing write shows
                // up as the test's "sentinel stopped changing" assertion.
                let _ = std::fs::write(&sentinel, tick.to_string());
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        // Echo+1 until the parent drops its client (EOF), then exit cleanly.
        while let Ok(request) = rpc.next_request() {
            rpc.send_response(&TestResponse {
                v: request.v + 1,
                daemon_cwd: daemon_cwd.clone(),
                marker: marker.to_string(),
                argv1: argv1.to_string(),
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
            "parent-got:{} cwd:{} marker:{} argv1:{} sid:{} pid:{} zombies:{}",
            response.v,
            response.daemon_cwd,
            response.marker,
            response.argv1,
            response.sid,
            response.pid,
            zombies,
        ),
    )
    .map_err(|err| format!("failed to write outfile: {err}"))
}

/// The request value handed to daemon `idx`. Unique per daemon, so the echoed
/// response (`v + 1`) is a distinct fingerprint: if two channels ever crossed,
/// a client would receive another daemon's fingerprint and the test would
/// catch it. Kept well clear of zero so an accidental default value can't
/// masquerade as a real one.
fn request_value(idx: usize) -> i32 {
    100 * (idx as i32 + 1)
}

/// Do one typed RPC round-trip on `client`: send `value`, wait for the echo.
fn roundtrip(
    client: &mut RpcClient<TestRequest, TestResponse>,
    value: i32,
) -> Result<TestResponse, String> {
    client
        .send_request(&TestRequest { v: value })
        .map_err(|err| format!("send_request failed: {err}"))?;
    client
        .recv_response(Duration::from_secs(10))
        .map_err(|err| format!("recv_response failed: {err}"))
}

/// `--spawn-many N [--concurrent]`: spawn N daemons from this one foreground,
/// round-trip a unique value with each, and record one line per daemon plus a
/// final `zombies:` count. The test asserts N distinct daemon processes, each
/// echoing *its own* value (isolation) with no leftover zombie intermediates.
fn run_spawn_many(
    daemonizer: Daemonizer<TestApp>,
    outfile: &Path,
    count: usize,
    concurrent: bool,
) -> Result<(), String> {
    let results = if concurrent {
        spawn_many_concurrent(daemonizer, count)?
    } else {
        spawn_many_sequential(daemonizer, count)?
    };

    // Grandchild daemons are orphaned to init, so they never become *our*
    // zombies; the only direct children were the double-fork intermediates,
    // which `spawn_daemon` reaps on success. This must therefore read 0.
    let zombies = count_own_zombie_children();

    let mut out = String::new();
    for (idx, resp) in &results {
        out.push_str(&format!(
            "idx:{} got:{} pid:{} sid:{} cwd:{} marker:{}\n",
            idx, resp.v, resp.pid, resp.sid, resp.daemon_cwd, resp.marker,
        ));
    }
    out.push_str(&format!("zombies:{zombies}\n"));
    std::fs::write(outfile, out).map_err(|err| format!("failed to write outfile: {err}"))
}

/// Spawn all `count` daemons first — so every one is *simultaneously* live —
/// and only then round-trip each on its own channel. Holding all the clients
/// across the whole round-trip loop is what makes the isolation check
/// meaningful: N daemons are up at once, each answering only its own client.
fn spawn_many_sequential(
    daemonizer: Daemonizer<TestApp>,
    count: usize,
) -> Result<Vec<(usize, TestResponse)>, String> {
    let mut clients: Vec<RpcClient<TestRequest, TestResponse>> = Vec::with_capacity(count);
    for idx in 0..count {
        let client = daemonizer
            .spawn_daemon()
            .map_err(|err| format!("spawn_daemon #{idx} failed: {err}"))?;
        clients.push(client);
    }

    let mut results = Vec::with_capacity(count);
    for (idx, client) in clients.iter_mut().enumerate() {
        let resp = roundtrip(client, request_value(idx))?;
        results.push((idx, resp));
    }

    // Every daemon was live throughout the loop above; drop them now so each
    // sees EOF on its client and exits.
    drop(clients);
    Ok(results)
}

/// Spawn `count` daemons from `count` threads that all enter `spawn_daemon`
/// together (a `Barrier`), exercising the advertised concurrent-spawn use of
/// the `Copy + Send + Sync` `Daemonizer`. Each thread owns its own client, so
/// the round-trips can't alias. Results are sorted by index for a stable
/// outfile regardless of thread scheduling.
fn spawn_many_concurrent(
    daemonizer: Daemonizer<TestApp>,
    count: usize,
) -> Result<Vec<(usize, TestResponse)>, String> {
    use std::sync::{Arc, Barrier};

    let barrier = Arc::new(Barrier::new(count));
    let handles: Vec<_> = (0..count)
        .map(|idx| {
            // `Daemonizer` is `Copy`, so the `move` closure copies the token
            // into each thread; only the `Arc` needs an explicit clone.
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || -> Result<(usize, TestResponse), String> {
                // Release all threads into `spawn_daemon` at once so the calls
                // genuinely overlap instead of being serialized by startup skew.
                barrier.wait();
                let mut client = daemonizer
                    .spawn_daemon()
                    .map_err(|err| format!("concurrent spawn_daemon #{idx} failed: {err}"))?;
                let resp = roundtrip(&mut client, request_value(idx))?;
                Ok((idx, resp))
            })
        })
        .collect();

    let mut results = Vec::with_capacity(count);
    for handle in handles {
        let joined = handle
            .join()
            .map_err(|_| "a concurrent spawn thread panicked".to_string())??;
        results.push(joined);
    }
    results.sort_by_key(|(idx, _)| *idx);
    Ok(results)
}

/// `--spawn-interleaved`: keep two daemons (A, B) live at once and interleave
/// requests so a crossed pair of channels would surface as a swapped echo.
/// Round 1 sends to *both* before receiving from *either*; round 2 reverses
/// the send order and reuses the same channels, proving each client stays
/// bound to its own daemon across multiple requests.
fn run_spawn_interleaved(daemonizer: Daemonizer<TestApp>, outfile: &Path) -> Result<(), String> {
    let mut a = daemonizer
        .spawn_daemon()
        .map_err(|err| format!("spawn A failed: {err}"))?;
    let mut b = daemonizer
        .spawn_daemon()
        .map_err(|err| format!("spawn B failed: {err}"))?;

    let recv = |c: &mut RpcClient<TestRequest, TestResponse>, tag: &str| {
        c.recv_response(Duration::from_secs(10))
            .map_err(|err| format!("{tag} recv failed: {err}"))
    };
    let send = |c: &mut RpcClient<TestRequest, TestResponse>, v: i32, tag: &str| {
        c.send_request(&TestRequest { v })
            .map_err(|err| format!("{tag} send failed: {err}"))
    };

    // Round 1: both sends before either receive.
    send(&mut a, 100, "A r1")?;
    send(&mut b, 200, "B r1")?;
    let a1 = recv(&mut a, "A r1")?;
    let b1 = recv(&mut b, "B r1")?;

    // Round 2: reversed send order, same channels.
    send(&mut b, 400, "B r2")?;
    send(&mut a, 300, "A r2")?;
    let b2 = recv(&mut b, "B r2")?;
    let a2 = recv(&mut a, "A r2")?;

    drop(a);
    drop(b);

    let zombies = count_own_zombie_children();
    let out = format!(
        "tag:A got1:{} got2:{} pid1:{} pid2:{} sid:{}\n\
         tag:B got1:{} got2:{} pid1:{} pid2:{} sid:{}\n\
         zombies:{}\n",
        a1.v, a2.v, a1.pid, a2.pid, a1.sid, b1.v, b2.v, b1.pid, b2.pid, b1.sid, zombies,
    );
    std::fs::write(outfile, out).map_err(|err| format!("failed to write outfile: {err}"))
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
