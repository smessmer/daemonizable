//! End-to-end tests that a single foreground process can spawn **multiple**
//! daemons through the public [`Daemonizer::spawn_daemon`] API — sequentially,
//! and concurrently from several threads (the advertised `Copy + Send + Sync`
//! use of the `Daemonizer` token) — with each daemon a distinct, isolated
//! process on its own RPC channel.
//!
//! The library documents this as supported (`lib.rs` calls out "a second
//! `spawn_daemon` from another thread, an advertised use of the
//! Copy+Send+Sync Daemonizer"), but the rest of the suite only ever spawns one
//! daemon per test. These tests close that gap.
//!
//! Like `framework_e2e.rs`, they drive the full production path through the
//! `daemonizable-test-app` helper binary — argv-sentinel stage dispatch, the real
//! `/proc/self/exe` re-exec spawn, the build-id handshake, and the typed RPC
//! channel — rather than the raw `start_background_process_with_exe` shortcut,
//! so they cover `spawn_daemon` exactly as an application calls it.
//!
//! The isolation checks rest on two observable fingerprints the helper reports
//! per daemon: the echoed request value (each daemon is sent a value unique to
//! it, and echoes `v + 1`, so a crossed channel yields the wrong number) and
//! the daemon's own pid/sid (distinct across genuinely separate processes).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::{Command, Output};

fn test_app_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-app")
}

fn run_test_app(args: &[&str], outfile: &Path) -> Output {
    Command::new(test_app_exe())
        .args(args)
        .arg("--outfile")
        .arg(outfile)
        .output()
        .expect("failed to spawn daemonizable-test-app")
}

fn assert_app_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "test app failed: status={:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Parse one `key:value key:value ...` record line into a map. Values are
/// space-free (numbers, `/`, single-token markers), matching the helper's
/// output convention, so splitting on spaces then the first `:` is unambiguous.
fn parse_record(line: &str) -> HashMap<String, String> {
    line.split(' ')
        .filter_map(|kv| kv.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Split the helper's outfile into the per-daemon records and the trailing
/// `zombies:` count. Panics with the raw text on any malformed line, so a
/// helper-side format drift fails loudly instead of silently under-checking.
fn parse_outfile(result: &str) -> (Vec<HashMap<String, String>>, u32) {
    let mut records = Vec::new();
    let mut zombies = None;
    for line in result.lines().filter(|l| !l.trim().is_empty()) {
        let rec = parse_record(line);
        if let Some(z) = rec.get("zombies") {
            zombies = Some(z.parse().expect("zombies value is not an integer"));
        } else if rec.contains_key("idx") || rec.contains_key("tag") {
            records.push(rec);
        } else {
            panic!("unexpected outfile line: {line:?}\nfull outfile:\n{result}");
        }
    }
    let zombies = zombies.unwrap_or_else(|| panic!("outfile has no zombies line:\n{result}"));
    (records, zombies)
}

/// Assertions shared by the sequential and concurrent multi-daemon tests: `n`
/// distinct daemon processes, each echoing *its own* fingerprint value, each a
/// non-session-leader grandchild, and no leftover zombie intermediates.
fn assert_n_isolated_daemons(result: &str, n: usize) {
    let (records, zombies) = parse_outfile(result);
    assert_eq!(
        zombies, 0,
        "successful spawns left zombie intermediates behind:\n{result}"
    );
    assert_eq!(
        records.len(),
        n,
        "expected {n} daemon records, got {}:\n{result}",
        records.len()
    );

    let mut seen_idx = HashSet::new();
    let mut pids = HashSet::new();
    let mut sids = HashSet::new();
    for rec in &records {
        let idx: usize = rec["idx"].parse().expect("idx is not an integer");
        assert!(idx < n, "idx {idx} out of range 0..{n}:\n{result}");
        assert!(
            seen_idx.insert(idx),
            "duplicate daemon idx {idx}:\n{result}"
        );

        // Isolation: the value this client got back must be *its* daemon's
        // echo (sent value + 1), not another daemon's. A crossed pair of
        // channels would surface here as a mismatched fingerprint.
        let got: i32 = rec["got"].parse().expect("got is not an integer");
        let expected = 100 * (idx as i32 + 1) + 1;
        assert_eq!(
            got, expected,
            "daemon {idx} returned the wrong fingerprint — channels crossed?\n{result}"
        );

        // The framework put every daemon at cwd `/`, and no framework env
        // var exists in any daemon's environment (stage identity rides argv;
        // nothing is ever set) — same as the single-daemon case.
        assert_eq!(rec["cwd"], "/", "daemon {idx} cwd is not /:\n{result}");
        assert_eq!(
            rec["marker"], "removed",
            "daemon {idx} still carries the child env marker:\n{result}"
        );

        let pid: i64 = rec["pid"].parse().expect("pid is not an integer");
        let sid: i64 = rec["sid"].parse().expect("sid is not an integer");
        assert!(
            pid > 0 && sid > 0,
            "daemon {idx} reported bogus ids:\n{result}"
        );
        // Grandchild, not a session leader: its sid is the (dead) intermediate's
        // pid, so sid != its own pid. This is what pins the framework's second
        // fork, per daemon.
        assert_ne!(
            sid, pid,
            "daemon {idx} is a session leader (sid == pid) — second fork missing:\n{result}"
        );
        // Genuinely separate processes and sessions.
        assert!(
            pids.insert(pid),
            "two daemons share pid {pid} — not distinct processes:\n{result}"
        );
        assert!(
            sids.insert(sid),
            "two daemons share sid {sid} — not distinct sessions:\n{result}"
        );
    }
}

#[test]
fn foreground_spawns_many_daemons_sequentially_each_isolated() {
    // Three daemons, all brought up before any round-trip, so all three are
    // live simultaneously while each answers only its own client.
    const N: usize = 3;
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = run_test_app(&["--spawn-many", "3"], &outfile);
    assert_app_succeeded(&output);

    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    assert_n_isolated_daemons(&result, N);
}

// Concurrent `spawn_daemon` from several threads is race-free only on targets
// with `pipe2(O_CLOEXEC)` (Linux/Android, the *BSDs, …), where the pipe fds are
// close-on-exec from creation. macOS/iOS lack `pipe2`, so the crate documents a
// narrow spawn-time window there in which one thread's `Command::spawn` can leak
// another thread's not-yet-CLOEXEC pipe ends across `execve` — which would keep
// a daemon's channel open past its client drop, defeat EOF liveness, and hang
// this test's `Command::output()`. That is exactly the case the library's
// caller contract says to avoid (spawn before starting other subprocesses), so
// exercising the concurrent path is only valid on the pipe2 platforms; the
// serial `--spawn-many` / `--spawn-interleaved` tests cover macOS.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[test]
fn foreground_spawns_many_daemons_concurrently_from_threads() {
    // Five threads enter `spawn_daemon` together (a Barrier in the helper), the
    // advertised concurrent use of the Copy+Send+Sync Daemonizer. All five must
    // come up as distinct, correctly-answering daemons.
    const N: usize = 5;
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = run_test_app(&["--spawn-many", "5", "--concurrent"], &outfile);
    assert_app_succeeded(&output);

    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    assert_n_isolated_daemons(&result, N);
}

#[test]
fn two_live_daemons_do_not_cross_talk() {
    // Two daemons kept live at once, with interleaved requests across two
    // rounds. Proves each client's channel stays bound to its own daemon and
    // never receives the other's responses.
    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");

    let output = run_test_app(&["--spawn-interleaved"], &outfile);
    assert_app_succeeded(&output);

    let result = std::fs::read_to_string(&outfile).expect("outfile was not written");
    let (records, zombies) = parse_outfile(&result);
    assert_eq!(
        zombies, 0,
        "interleaved spawn left zombies behind:\n{result}"
    );
    assert_eq!(records.len(), 2, "expected two daemon records:\n{result}");

    let by_tag: HashMap<&str, &HashMap<String, String>> = records
        .iter()
        .map(|rec| (rec["tag"].as_str(), rec))
        .collect();
    let a = by_tag.get("A").expect("no record for daemon A");
    let b = by_tag.get("B").expect("no record for daemon B");

    // Correct routing across both rounds: A was sent 100 then 300, B was sent
    // 200 then 400; each echoes its own value + 1. A crossed pair of channels
    // would swap these numbers.
    assert_eq!(a["got1"], "101", "A round 1 wrong — cross-talk?\n{result}");
    assert_eq!(a["got2"], "301", "A round 2 wrong — cross-talk?\n{result}");
    assert_eq!(b["got1"], "201", "B round 1 wrong — cross-talk?\n{result}");
    assert_eq!(b["got2"], "401", "B round 2 wrong — cross-talk?\n{result}");

    // Each channel stayed bound to the *same* daemon process across both
    // rounds (its pid didn't change between requests).
    assert_eq!(
        a["pid1"], a["pid2"],
        "channel A jumped to a different daemon between rounds:\n{result}"
    );
    assert_eq!(
        b["pid1"], b["pid2"],
        "channel B jumped to a different daemon between rounds:\n{result}"
    );
    // The two daemons are genuinely distinct processes in distinct sessions.
    assert_ne!(
        a["pid1"], b["pid1"],
        "A and B share a pid — not distinct daemons:\n{result}"
    );
    assert_ne!(a["sid"], b["sid"], "A and B share a session:\n{result}");
}
