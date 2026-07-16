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
            // SAFETY: libc::write reads `count` bytes from `buf`. Here `buf` is
            // `payload.as_ptr()` and `count` is `payload.len()`, both derived from
            // `payload` (`b"LEAK\n"`, a live `&[u8; 5]`), so the pointer addresses
            // exactly 5 initialized, u8-aligned bytes and the length matches the
            // buffer — no out-of-bounds or uninitialized read. `leak_fd` may be any
            // int, but an invalid fd only yields EBADF at runtime (never UB); the
            // return value is intentionally ignored since the test expects this
            // write to fail with EBADF.
            let _ = unsafe { libc::write(leak_fd, payload.as_ptr().cast(), payload.len()) };
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            // SAFETY: `libc::setsid()` is a bare syscall wrapper that takes no
            // arguments and dereferences no pointers or file descriptors, so
            // there is no memory-safety precondition to uphold. It is `unsafe`
            // only as an FFI call. It either succeeds or returns -1/EPERM
            // (already a process-group leader), a defined error handled by the
            // `< 0` check below.
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
            // SAFETY: setsid() takes no arguments and no pointers/fds, so it has
            // no memory-safety preconditions; it is `unsafe` only as an FFI call.
            // Not in a fork/exec window, so async-signal-safety is irrelevant.
            // Its sole failure (EPERM if already a group leader) is a runtime
            // error, not UB, and is handled by the `< 0` branch below.
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
            // SAFETY: `setsid()` takes no arguments — no pointers, buffers, or
            // fds — so it has no memory-safety preconditions; it is `unsafe`
            // only because it is an `extern "C"` fn. It is not in a fork→exec
            // async-signal-safety window (the fork below happens afterwards) and
            // the process is single-threaded here regardless. Its only failure
            // is a -1/EPERM return, handled by the `< 0` check below.
            if unsafe { libc::setsid() } < 0 {
                eprintln!("daemon: setsid failed: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            // SAFETY: libc::fork() takes no arguments and is always callable; its
            // only soundness obligation is the POSIX rule that after a fork in a
            // MULTITHREADED process the child may run only async-signal-safe
            // code. The child branch below runs non-async-signal-safe work
            // (std::fs::write, send_handshake, sleep), so this is sound only
            // because the process is single-threaded here: this is a synchronous
            // `fn main` with no async runtime, and nothing on the path from
            // program start to this point (env reads, rpc_server_from_inherited_fds,
            // setsid) spawns a thread. With one thread at the fork, the child
            // inherits a consistent address space and may run arbitrary code;
            // the intermediate branch's _exit(0) is async-signal-safe regardless.
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
                // SAFETY: `libc::_exit` takes only an `int` exit status; it has
                // no pointer/buffer/fd arguments and thus no memory-safety
                // precondition a caller can violate. It is async-signal-safe, so
                // terminating the parent ("intermediate session leader") here
                // after `fork()` is permitted even in a multithreaded process.
                // It never returns.
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
