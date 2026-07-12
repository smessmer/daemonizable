//! Helper binary for `tests/detach_stdio_severs_inherited_stdio.rs`.
//!
//! Exercises the [`daemonizable::detach_stdio`] boundary from the daemon's
//! point of view: it writes a sentinel to both stdout and stderr *before*
//! detaching (this output must still reach the inherited stdio the daemon was
//! spawned with), calls `detach_stdio`, then writes a second sentinel to both
//! streams *after* detaching (this output must be swallowed by `/dev/null`).
//!
//! The test spawns this binary with its stdout/stderr captured, so the
//! captured bytes are exactly the daemon's inherited stdio. It then asserts
//! the "before" sentinels are present and the "after" sentinels are absent.
//!
//! Exit codes: 0 on success, 3 if `detach_stdio` itself returned an error
//! (reported on the pre-detach stderr, which the test still captures).

use std::io::Write;

/// Written to stdout before `detach_stdio`; must survive to the captured pipe.
const BEFORE_STDOUT: &str = "detach-test: BEFORE-DETACH-STDOUT";
/// Written to stderr before `detach_stdio`; must survive to the captured pipe.
const BEFORE_STDERR: &str = "detach-test: BEFORE-DETACH-STDERR";
/// Written to stdout after `detach_stdio`; must be swallowed by `/dev/null`.
const AFTER_STDOUT: &str = "detach-test: AFTER-DETACH-STDOUT";
/// Written to stderr after `detach_stdio`; must be swallowed by `/dev/null`.
const AFTER_STDERR: &str = "detach-test: AFTER-DETACH-STDERR";

fn main() {
    // Pre-detach logging on the inherited stdio. Flush so the bytes reach the
    // captured pipe *before* `detach_stdio`'s `dup2` closes this end of it —
    // exactly the ordering a real daemon relies on when it logs startup
    // progress and only then detaches.
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    writeln!(stdout, "{BEFORE_STDOUT}").expect("write BEFORE_STDOUT");
    writeln!(stderr, "{BEFORE_STDERR}").expect("write BEFORE_STDERR");
    stdout.flush().expect("flush stdout before detach");
    stderr.flush().expect("flush stderr before detach");

    if let Err(err) = daemonizable::detach_stdio() {
        // This still lands on the captured stderr (detach hasn't taken effect),
        // so the test sees a diagnostic rather than a bare non-zero exit.
        let _ = writeln!(stderr, "detach-test: detach_stdio failed: {err}");
        let _ = stderr.flush();
        std::process::exit(3);
    }

    // Post-detach logging. fds 1/2 now point at `/dev/null`, so these writes
    // (and the flushes that force them out of the userspace buffer to the fd)
    // must go nowhere the test can observe.
    writeln!(stdout, "{AFTER_STDOUT}").expect("write AFTER_STDOUT");
    writeln!(stderr, "{AFTER_STDERR}").expect("write AFTER_STDERR");
    stdout.flush().expect("flush stdout after detach");
    stderr.flush().expect("flush stderr after detach");
}
