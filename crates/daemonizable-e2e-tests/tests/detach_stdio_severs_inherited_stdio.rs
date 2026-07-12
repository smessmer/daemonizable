//! Regression test for [`daemonizable::detach_stdio`]'s contract at the
//! post-startup boundary: output a daemon writes to stdout/stderr *before*
//! calling `detach_stdio` must still reach the stdio it inherited from the
//! shell, while output written *after* the call must be swallowed by
//! `/dev/null` instead of leaking to the user's terminal.
//!
//! We spawn the `daemonizable-test-detach-stdio` helper with its stdout and
//! stderr captured through pipes — those pipes stand in for the inherited
//! terminal stdio a real daemon is spawned with. The helper writes a "before"
//! sentinel to each stream, calls `detach_stdio`, then writes an "after"
//! sentinel to each stream. Capturing exactly the pre-detach bytes and none of
//! the post-detach bytes proves the boundary works in both directions and on
//! both streams.
//!
//! (`detach_stdio`'s `dup2` closes the helper's write ends of the pipes, so the
//! captured reads hit EOF as soon as the call runs — `output()` returns
//! promptly with just the pre-detach bytes.)

use std::process::Command;

fn detach_helper_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-detach-stdio")
}

// These MUST stay in sync with the sentinels in
// src/bin/daemonizable_test_detach_stdio.rs — that binary is a separate crate
// artifact, so the strings can't be shared via a common constant.
const BEFORE_STDOUT: &str = "detach-test: BEFORE-DETACH-STDOUT";
const BEFORE_STDERR: &str = "detach-test: BEFORE-DETACH-STDERR";
const AFTER_STDOUT: &str = "detach-test: AFTER-DETACH-STDOUT";
const AFTER_STDERR: &str = "detach-test: AFTER-DETACH-STDERR";

#[test]
fn pre_detach_stdio_reaches_inherited_streams_and_post_detach_is_severed() {
    let output = Command::new(detach_helper_exe())
        .output()
        .expect("failed to spawn daemonizable-test-detach-stdio");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Exit code 3 means `detach_stdio` itself returned an error (the helper
    // reports it on the pre-detach stderr, surfaced here).
    assert!(
        output.status.success(),
        "helper did not exit cleanly: status={:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );

    // Pre-detach writes must survive: the daemon's inherited stdio was still
    // live, so this is the startup logging the user needs to see.
    assert!(
        stdout.contains(BEFORE_STDOUT),
        "pre-detach stdout was lost — inherited stdout not live before detach_stdio\nstdout: {stdout}",
    );
    assert!(
        stderr.contains(BEFORE_STDERR),
        "pre-detach stderr was lost — inherited stderr not live before detach_stdio\nstderr: {stderr}",
    );

    // Post-detach writes must be swallowed by /dev/null: leaking them would
    // dump background-daemon output onto the user's terminal, which is exactly
    // what detach_stdio exists to prevent.
    assert!(
        !stdout.contains(AFTER_STDOUT),
        "post-detach stdout leaked to inherited stdout — detach_stdio did not sever fd 1\nstdout: {stdout}",
    );
    assert!(
        !stderr.contains(AFTER_STDERR),
        "post-detach stderr leaked to inherited stderr — detach_stdio did not sever fd 2\nstderr: {stderr}",
    );
}
