//! Helper binary used by `start_background_process_with_exe` integration
//! tests. Reads `DAEMONIZABLE_TEST_BEHAVIOR` from the environment and replays one of
//! a few canned daemon behaviors against the inherited channel fd (3).
//!
//! This binary is what the test_child_* daemon-lifecycle tests now spawn
//! instead of forking an in-process fn pointer, so they no longer suffer the
//! parallel-test fd-inheritance flake.

use daemonizable::{PipeRecvError, PipeSendError, RpcServer, rpc_server_from_inherited_fds};
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

    // SAFETY: `rpc_server_from_inherited_fds` requires fd 3 to be this
    // process's exclusively-owned inherited channel socket (see its `# Safety`).
    // The discharge is positional and holds for ANY invocation, not just the
    // intended one: this call is the first fd-related action in a fresh
    // post-exec image (only the env read above precedes it), so no live
    // `OwnedFd`/`File` here can already own fd 3 — whatever open socket
    // sits there gets its sole in-process owner, and a hand-run invocation
    // with a closed or non-socket fd is rejected by the callee's fstat probe as
    // a clean error, never as aliased ownership. Keep this call the first
    // fd-creating operation in `main`: opening any fd before it would
    // reintroduce aliasing risk in hand-run processes. The intended
    // configuration remains the test harness spawning us
    // (`start_background_process_with_exe` / `spawn_daemon_process_with_exe`),
    // which `dup2`s the parent's socketpair end onto fd 3 across `execve`; this
    // is the only claim in the process.
    let mut rpc: RpcServer<Request, Response> = unsafe { rpc_server_from_inherited_fds() }
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
            if let Err(err) = nix::unistd::setsid() {
                eprintln!("daemon: setsid failed: {err}");
                std::process::exit(1);
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        "spawn_child_holding_fds_then_exit" => {
            // Regression coverage for FD_CLOEXEC restoration on the inherited
            // channel fd (3). Spawn a long-lived grandchild via fork+exec, then
            // exit this daemon. If the fd were left without FD_CLOEXEC, execve
            // would NOT close it and the grandchild would inherit the channel
            // end (fd 3) — keeping it open after we exit and starving the
            // parent's EOF. With CLOEXEC restored the grandchild does not
            // inherit it, so our exit closes the last copy of the end and the
            // parent's receive returns SenderClosed promptly.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            // 30s: not a synchronization point — the test kills the sleeper
            // by the pid recorded below. The duration must merely outlast,
            // with a wide margin, the 5s recv_response wait in
            // daemon_child_fd_cloexec (a leaked fd 4 has to stay open past
            // that whole wait for the test to detect it), while still
            // self-cleaning eventually if the kill-based cleanup never ran.
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("daemon: spawn sleeper grandchild");
            // Record the grandchild's pid so the test can kill it in cleanup
            // (it is reparented to init once we exit).
            std::fs::write(&pid_file, child.id().to_string()).expect("daemon: write sleeper pid");
            drop(rpc); // close this daemon's own copies of the channel fd
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
            if let Err(err) = nix::unistd::setsid() {
                eprintln!("daemon: setsid failed: {err}");
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
        "send_after_parent_exit" => {
            // Used by daemon_send_after_foreground_exit: the daemon side of a
            // send whose foreground peer is ALREADY GONE. Our parent is the
            // spawner helper (`daemonizable-test-spawn-then-exit`), standing
            // in for a foreground CLI that exits right after the spawn; it
            // hands us its pid via the environment. Wait until it is fully
            // dead, then attempt `send_response` and record the outcome —
            // the test asserts it was a clean `BrokenPipe`, not a success and
            // not a hang.
            //
            // The wait is an observed event, not a delay: we poll for the
            // moment `getppid()` stops being the spawner's pid. The kernel
            // reparents us only during the spawner's teardown, after its fds
            // are closed — so once the reparent is visible, the response
            // pipe's only other end is guaranteed gone and the send outcome
            // is deterministic. (If the spawner died before we even started,
            // `getppid()` never equals its pid and the loop exits at once.)
            let outfile = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_OUTFILE")
                    .expect("DAEMONIZABLE_TEST_OUTFILE not set"),
            );
            let spawner_pid: i32 = std::env::var("DAEMONIZABLE_TEST_SPAWNER_PID")
                .expect("DAEMONIZABLE_TEST_SPAWNER_PID not set")
                .parse()
                .expect("DAEMONIZABLE_TEST_SPAWNER_PID not an int");
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            // Publish our pid first so the test can clean us up if an
            // assertion fails before we exit on our own.
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            while nix::unistd::getppid().as_raw() == spawner_pid {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let outcome = match rpc.send_response(&Response { response: 1 }) {
                Err(PipeSendError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                    "send:broken_pipe".to_string()
                }
                Ok(()) => "send:unexpected_success".to_string(),
                Err(other) => format!("send:unexpected_error:{other:?}"),
            };
            // Publish atomically (write to a sibling path, then rename) so
            // the test's existence poll can never observe a partial write.
            let tmp = outfile.with_extension("tmp");
            std::fs::write(&tmp, &outcome).expect("daemon: write outcome tmp file");
            std::fs::rename(&tmp, &outfile).expect("daemon: publish outcome file");
            std::process::exit(0);
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
            if let Err(err) = nix::unistd::setsid() {
                eprintln!("daemon: setsid failed: {err}");
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
                    // Grandchild: the "daemon". Owns the inherited channel fd (3).
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
