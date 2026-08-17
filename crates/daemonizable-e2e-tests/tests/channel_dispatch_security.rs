//! Adversarial coverage for the in-band channel dispatch: what a process does
//! when fd 3 carries something OTHER than a genuine framework channel — a
//! foreign non-socket (a make jobserver FIFO), a socket with the wrong bytes,
//! a socket carrying a truncated (short-read) token, a crafted socket carrying
//! only the first token, and a crafted socket carrying a valid stage-2 token
//! from a hand-run.
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

use nix::sys::socket::MsgFlags;

fn test_app_exe() -> &'static str {
    env!("CARGO_BIN_EXE_daemonizable-test-app")
}

/// Assert the child consumed nothing from the crafted socket: everything the
/// test queued must still be readable from our retained copy after the child
/// exited. The foreground assertions alone would keep passing if dispatch
/// started eating queued bytes on the no-match path.
fn assert_socket_unconsumed(childs: &UnixStream, expected: &[u8]) {
    let mut buf = vec![0u8; expected.len() + 16];
    let n = nix::sys::socket::recv(childs.as_raw_fd(), &mut buf, MsgFlags::MSG_DONTWAIT)
        .expect("recv on the retained crafted-socket end");
    assert_eq!(
        &buf[..n],
        expected,
        "dispatch consumed bytes from a non-framework socket on fd 3"
    );
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
    // The queued byte stands in for a make jobserver token: eating it would
    // wedge a real parallel build.
    let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe");
    nix::unistd::write(&write_fd, b"J").expect("queue the jobserver-token stand-in");

    let tmpdir = tempfile::tempdir().unwrap();
    let outfile = tmpdir.path().join("result.txt");
    let outfile_str = outfile.to_str().unwrap();

    // The write end stays open so the pipe isn't at EOF, though the ENOTSOCK
    // verdict doesn't depend on that.
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

    // Non-blocking: the write end is still open, so a blocking read would hang
    // here rather than fail if the byte had been consumed.
    nix::fcntl::fcntl(
        &read_fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("set read end non-blocking");
    let mut buf = [0u8; 4];
    let n = nix::unistd::read(&read_fd, &mut buf).expect(
        "the jobserver-token byte was consumed by dispatch (read would block on an empty pipe)",
    );
    assert_eq!(&buf[..n], b"J", "dispatch consumed or corrupted the FIFO");
}

#[test]
fn wrong_magic_socket_on_fd3_dispatches_foreground() {
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
    assert_socket_unconsumed(&childs, &[0xABu8; 33]);
}

#[test]
fn partial_token_socket_on_fd3_dispatches_foreground() {
    // `ours` is held open for the whole spawn and nothing more is written, so a
    // dispatch that blocked waiting for the rest of the token would hang the
    // child forever — `cmd.output()` returning at all is the non-hang assertion.
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
    assert_socket_unconsumed(&childs, &full[..full.len() - 1]);
}

#[test]
fn single_token_socket_is_rejected_by_stage1() {
    // The defense against a pre-main constructor consuming token 1.
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
fn both_tokens_hand_run_as_group_leader_fails_stage1_setsid() {
    // A faithful forgery of the parent's prequeue gets past the token-2 peek, so
    // `setsid` is what refuses it — POSIX forbids a group leader from creating a
    // session. This is the only test reaching stage 1's setsid-failure arm: the
    // single-token test exits earlier, and genuine spawns are never group leaders.
    let (ours, childs) = UnixStream::pair().expect("socketpair");
    let mut both = daemonizable::stage_token_bytes(1);
    both.extend_from_slice(&daemonizable::stage_token_bytes(2));
    (&ours).write_all(&both).expect("queue both tokens");

    let output = run_with_fd3(&[], &childs, Topology::NewGroup, &ours);

    assert_eq!(
        Some(1),
        output.status.code(),
        "a group-leader hand-run with both tokens must die on setsid; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("setsid() failed"),
        "expected the setsid-failure message, got: {stderr}"
    );
}

#[test]
fn stage2_token_hand_run_as_leader_is_rejected() {
    // A forged token must not yield a running daemon.
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
    // A group leader that is not a session leader, exercising the arm of the
    // provenance guard the session-leader test above doesn't reach.
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
