//! Adversarial coverage for the in-band channel dispatch (Phase 3): what a
//! process does when fd 3 carries something OTHER than a genuine framework
//! channel — a foreign non-socket (a make jobserver FIFO), a socket with the
//! wrong bytes, a socket carrying a truncated (short-read) token, a crafted
//! socket carrying only the first token, and a crafted socket carrying a valid
//! stage-2 token from a hand-run.
//!
//! Each test spawns the real framework app (`daemonizable-test-app`, which goes
//! through `daemonizable::run`) with fd 3 set up in a `pre_exec` closure, and
//! asserts the observable outcome: a benign foreground run, or a clean typed
//! rejection — never a hijack into a silently-degraded daemon.
//!
//! The pure classifier (every errno/short-read/wrong-tag row) is unit-tested in
//! the library (`ipc::spawn::token`); these tests exercise the same logic
//! end-to-end through a spawned binary, plus the stage guards the classifier
//! can't reach.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn test_app_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-app")
}

/// Session/group topology to force on the spawned child before exec, so the
/// stage-2 provenance guard's different branches can be exercised.
#[derive(Clone, Copy)]
enum Topology {
    /// Inherit the test's session/group (a plain `Command` child).
    Inherit,
    /// `setsid()` → the child is a session (and group) leader.
    NewSession,
    /// `setpgid(0, 0)` → the child is a process-group leader but not a session
    /// leader (and, since its pgid != the session's, `sid != pgid`).
    NewGroup,
}

/// Run the app with `fd3` dup'd onto file descriptor 3 in the child, after
/// forcing `topology`. `keep_alive` is held open in this process for the whole
/// spawn so the crafted socket stays connected while the child peeks. Returns
/// the process output.
fn run_with_fd3(
    args: &[&str],
    fd3: &impl AsRawFd,
    topology: Topology,
    _keep_alive: &impl AsRawFd,
) -> std::process::Output {
    let fd3_raw = fd3.as_raw_fd();
    let mut cmd = Command::new(test_app_exe());
    cmd.args(args);
    // SAFETY: the closure runs in the forked child before exec and executes only
    // async-signal-safe calls — `setsid`/`setpgid` and `dup2` on bare fd ints.
    // `fd3_raw` is a live fd in the parent at fork time (its owner outlives this
    // spawn), and touches no memory beyond its captured int.
    unsafe {
        cmd.pre_exec(move || {
            match topology {
                Topology::Inherit => {}
                Topology::NewSession => {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Topology::NewGroup => {
                    if libc::setpgid(0, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            if libc::dup2(fd3_raw, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.output().expect("failed to spawn daemonizable-test-app")
}

#[test]
fn foreign_fifo_on_fd3_dispatches_foreground() {
    // A make-jobserver-style FIFO (a pipe) on fd 3 is not a socket, so the
    // dispatch probe's `recv` returns ENOTSOCK and the app runs foreground —
    // never touching (consuming from) the jobserver.
    let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe");

    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");
    let outfile_str = outfile.to_str().unwrap();

    // Keep the write end open so the pipe isn't at EOF (belt-and-suspenders; the
    // ENOTSOCK verdict doesn't depend on it).
    let output = run_with_fd3(
        &["--outfile", outfile_str],
        &read_fd,
        Topology::Inherit,
        &write_fd,
    );

    assert!(
        output.status.success(),
        "app failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = std::fs::read_to_string(&outfile).expect("outfile");
    assert_eq!(
        "foreground-ran", result,
        "a FIFO on fd 3 must not hijack dispatch"
    );
}

#[test]
fn wrong_magic_socket_on_fd3_dispatches_foreground() {
    // A connected socket on fd 3 whose queued bytes are not the framework magic
    // (33 bytes of garbage) → the classifier returns Foreground and the socket
    // is left unconsumed.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    // 33 = TOKEN_LEN worth of non-magic bytes.
    (&ours)
        .write_all(&[0xABu8; 33])
        .expect("queue wrong-magic bytes");

    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");
    let outfile_str = outfile.to_str().unwrap();

    let output = run_with_fd3(
        &["--outfile", outfile_str],
        &childs,
        Topology::Inherit,
        &ours,
    );

    assert!(
        output.status.success(),
        "app failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = std::fs::read_to_string(&outfile).expect("outfile");
    assert_eq!(
        "foreground-ran", result,
        "a wrong-magic socket on fd 3 must not hijack dispatch"
    );
}

#[test]
fn partial_token_socket_on_fd3_dispatches_foreground() {
    // A socket on fd 3 carrying a real stage-1 token with its final byte missing
    // (one byte short of a full token), then left open with no further writes:
    // the non-blocking `MSG_PEEK` sees a short read, the classifier returns
    // Foreground, and — crucially — dispatch does NOT block waiting for the rest
    // of the token. The socket is never closed (`ours` is held open for the whole
    // spawn), so a *blocking* read here would hang the child forever; the fact
    // that `cmd.output()` returns at all is the non-hang assertion.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    let full = daemonizable::stage_token_bytes(1);
    (&ours)
        .write_all(&full[..full.len() - 1])
        .expect("queue a truncated token");

    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");
    let outfile_str = outfile.to_str().unwrap();

    let output = run_with_fd3(
        &["--outfile", outfile_str],
        &childs,
        Topology::Inherit,
        &ours,
    );

    assert!(
        output.status.success(),
        "app failed or hung on a truncated token: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = std::fs::read_to_string(&outfile).expect("outfile");
    assert_eq!(
        "foreground-ran", result,
        "a truncated token on fd 3 must not hijack dispatch"
    );
}

#[test]
fn single_token_socket_is_rejected_by_stage1() {
    // A crafted socket carrying ONLY stage 1's token: dispatch routes to stage
    // 1 (token 1 matched), but stage 1's mandatory token-2 peek finds nothing —
    // so it exits 2 (pre-setsid, pre-fork) rather than letting a detached
    // stage-2 image later run foreground code. This is the defense against a
    // pre-main constructor consuming token 1.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    (&ours)
        .write_all(&daemonizable::stage_token_bytes(1))
        .expect("queue only token 1");

    let output = run_with_fd3(&[], &childs, Topology::Inherit, &ours);

    assert_eq!(
        Some(2),
        output.status.code(),
        "a single-token channel must be rejected by stage 1 with exit 2; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing stage 2's token"),
        "expected the missing-token-2 message, got: {stderr}"
    );
}

#[test]
fn stage2_token_hand_run_as_leader_is_rejected() {
    // A crafted socket carrying a valid stage-2 token, hand-run as a session
    // leader (pre_exec setsid): dispatch routes to stage 2, but the provenance
    // guard refuses a session/group leader (a framework-spawned daemon is a
    // non-leader grandchild). Exit 1, before the claim or handshake — a forged
    // token cannot yield a running daemon.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    (&ours)
        .write_all(&daemonizable::stage_token_bytes(2))
        .expect("queue token 2");

    let output = run_with_fd3(&[], &childs, Topology::NewSession, &ours);

    assert_eq!(
        Some(1),
        output.status.code(),
        "a hand-run stage-2 token as a session leader must be rejected with exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("session/process-group topology"),
        "expected the provenance-guard message, got: {stderr}"
    );
}

#[test]
fn stage2_token_hand_run_as_group_leader_is_rejected() {
    // A crafted socket carrying a valid stage-2 token, hand-run as a process-
    // GROUP leader (pre_exec `setpgid(0, 0)`, no new session): the child is not
    // a session leader, but it IS a group leader and its `sid != pgid`, so the
    // provenance guard still refuses it. This exercises the group-leader arm of
    // the guard that the session-leader test above does not reach — a genuine
    // framework daemon is a non-leader grandchild whose session id equals its
    // process-group id. Exit 1, before the claim or handshake.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    (&ours)
        .write_all(&daemonizable::stage_token_bytes(2))
        .expect("queue token 2");

    let output = run_with_fd3(&[], &childs, Topology::NewGroup, &ours);

    assert_eq!(
        Some(1),
        output.status.code(),
        "a hand-run stage-2 token as a group leader must be rejected with exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("session/process-group topology"),
        "expected the provenance-guard message, got: {stderr}"
    );
}
