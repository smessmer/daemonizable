//! Helper binary used by `start_background_process_with_exe` integration
//! tests. Reads `DAEMONIZABLE_TEST_BEHAVIOR` from the environment and replays one of
//! a few canned daemon behaviors against the inherited fds 3 and 4.
//!
//! This binary is what the test_child_* daemon-lifecycle tests now spawn
//! instead of forking an in-process fn pointer, so they no longer suffer the
//! parallel-test fd-inheritance flake.

use daemonizable::{PipeRecvError, RpcServer, rpc_server_from_inherited_fds};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Request {
    request: i32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Response {
    response: i32,
}

fn main() {
    let behavior =
        std::env::var("DAEMONIZABLE_TEST_BEHAVIOR").unwrap_or_else(|_| "echo".to_string());

    let mut rpc: RpcServer<Request, Response> = rpc_server_from_inherited_fds()
        .expect("daemon: failed to rebuild RpcServer from inherited fds");

    match behavior.as_str() {
        "echo" => loop {
            let request = match rpc.next_request() {
                Ok(r) => r,
                // Parent dropped the client → EOF → clean exit.
                Err(PipeRecvError::SenderClosed) => std::process::exit(0),
                Err(err) => {
                    // Any other error is a real daemon-side failure; surface
                    // it on stderr so a hung/failing parent test isn't the
                    // only diagnostic.
                    eprintln!("daemon: echo receive failed: {err}");
                    std::process::exit(1);
                }
            };
            rpc.send_response(&Response {
                response: request.request + 1,
            })
            .expect("daemon: failed to send response");
        },
        "panic_after_request" => {
            let _ = rpc.next_request().expect("daemon: expected a request");
            panic!("daemon: panic_after_request");
        }
        "panic_before_request" => {
            panic!("daemon: panic_before_request");
        }
        "exit_after_request" => {
            let _ = rpc.next_request().expect("daemon: expected a request");
            std::process::exit(0);
        }
        "exit_before_request" => {
            std::process::exit(0);
        }
        "write_to_fd_then_idle" => {
            // Used by spawn_fd_isolation. Attempts to write a sentinel byte
            // to the file descriptor number in DAEMONIZABLE_TEST_LEAK_FD — under
            // fork+exec + FD_CLOEXEC, this fd should already be closed (no
            // longer inherited), so the write fails with EBADF. The test
            // verifies its parent-side read end gets EOF rather than the
            // sentinel byte. Then writes a PID file and idles so the test
            // can clean up.
            drop(rpc);
            let leak_fd: i32 = std::env::var("DAEMONIZABLE_TEST_LEAK_FD")
                .expect("DAEMONIZABLE_TEST_LEAK_FD not set")
                .parse()
                .expect("DAEMONIZABLE_TEST_LEAK_FD not an int");
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            // The write is expected to fail with EBADF when the test
            // succeeds. Do it before the PID file write so the parent
            // doesn't observe "pid file present" until we've at least
            // attempted the leak.
            let payload = b"LEAK\n";
            let _ = unsafe { libc::write(leak_fd, payload.as_ptr().cast(), payload.len()) };
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            if unsafe { libc::setsid() } < 0 {
                eprintln!("daemon: setsid failed: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        "spawn_child_holding_fds_then_exit" => {
            // Regression coverage for FD_CLOEXEC restoration on the inherited
            // RPC fds (3/4). Spawn a long-lived grandchild via fork+exec, then
            // exit this daemon. If the fds were left without FD_CLOEXEC, execve
            // would NOT close them and the grandchild would inherit the response
            // pipe's write end (fd 4) — keeping it open after we exit and
            // starving the parent's EOF. With CLOEXEC restored the grandchild
            // does not inherit them, so our exit closes the last write end and
            // the parent's receive returns SenderClosed promptly.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("daemon: spawn sleeper grandchild");
            // Record the grandchild's pid so the test can kill it in cleanup
            // (it is reparented to init once we exit).
            std::fs::write(&pid_file, child.id().to_string()).expect("daemon: write sleeper pid");
            drop(rpc); // close this daemon's own copies of fds 3/4
            std::process::exit(0);
        }
        "sentinel_loop" => {
            // Used by daemon_survives_parent_exit. Ignore RPC entirely;
            // loop writing the current monotonic timestamp to the path in
            // DAEMONIZABLE_TEST_SENTINEL, plus the daemon's PID to DAEMONIZABLE_TEST_PID.
            // The test verifies the file is still being updated after the
            // sub-test parent exits.
            drop(rpc);
            let sentinel = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_SENTINEL")
                    .expect("DAEMONIZABLE_TEST_SENTINEL not set"),
            );
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            // setsid for the test daemon so it survives the sub-test-process
            // exit even though we haven't gone through the framework's
            // daemon dispatch (which would have called setsid).
            if unsafe { libc::setsid() } < 0 {
                eprintln!("daemon: setsid failed: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            let mut tick: u64 = 0;
            loop {
                tick += 1;
                if let Err(err) = std::fs::write(&sentinel, tick.to_string()) {
                    eprintln!("daemon: failed to write sentinel: {err}");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        "wrong_handshake_then_idle" => {
            // Used by failed_spawn_cleanup. Drives the parent's handshake
            // validation to a Mismatch, then idles (blocks forever) so the
            // parent's failed-spawn cleanup has a LIVE child to kill and reap.
            // Writes its pid first so the test can assert it was reaped.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            daemonizable::send_handshake(&mut rpc, "deliberately-wrong-build-id")
                .expect("daemon: send wrong handshake");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        "double_fork_wrong_handshake_then_idle" => {
            // Mimics the real framework child arm (setsid → second fork →
            // intermediate _exit(0) → grandchild serves), but the grandchild
            // sends a WRONG build id. Proves the parent's failed-spawn cleanup
            // group-kill (`kill(-child_pid)`) reaches the GRANDCHILD — the real
            // daemon, reparented away from the parent — not merely the direct
            // child. The grandchild writes ITS pid so the test can assert it
            // was killed.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            if unsafe { libc::setsid() } < 0 {
                eprintln!("daemon: setsid failed: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            match unsafe { libc::fork() } {
                -1 => {
                    eprintln!("daemon: fork failed: {}", std::io::Error::last_os_error());
                    std::process::exit(1);
                }
                0 => {
                    // Grandchild: the "daemon". Owns the inherited fds 3/4.
                    std::fs::write(&pid_file, std::process::id().to_string())
                        .expect("daemon: write pid file");
                    daemonizable::send_handshake(&mut rpc, "deliberately-wrong-build-id")
                        .expect("daemon: send wrong handshake");
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                _ => unsafe { libc::_exit(0) }, // intermediate session leader
            }
        }
        "write_pid_then_exit" => {
            // Used by failed_spawn_cleanup. Dies immediately — before any
            // handshake and before setsid — so the parent's handshake recv
            // sees EOF (SenderClosed) and the cleanup has an already-dead child
            // to reap (the wait()-reaps-a-zombie path). Writes its pid first so
            // the test can assert no zombie survives.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            drop(rpc);
            std::process::exit(0);
        }
        other => {
            panic!("daemon: unknown DAEMONIZABLE_TEST_BEHAVIOR={other:?}");
        }
    }
}
