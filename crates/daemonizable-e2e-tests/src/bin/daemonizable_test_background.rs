//! Helper binary used by `start_background_process_with_exe` integration
//! tests. Reads `DAEMONIZABLE_TEST_BEHAVIOR` from the environment and replays
//! one of a few canned daemon behaviors against the inherited channel fd (3),
//! giving those tests a clean single-threaded daemon process image (no
//! inherited libtest threads or sibling-test fds).

use daemonizable::{ChannelRecvError, ChannelSendError, RpcServer, rpc_server_from_inherited_fd};
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

    // SAFETY: `rpc_server_from_inherited_fd` requires fd 3 to be this process's
    // exclusively-owned inherited channel socket (see its `# Safety`). The
    // discharge is positional and holds for ANY invocation, not just the intended
    // one: this call is the first fd-related action in a fresh post-exec image
    // (only the env read above precedes it), so no live `OwnedFd`/`File` here can
    // already own fd 3 — whatever open socket sits there gets its sole in-process
    // owner, and a hand-run invocation with a closed or non-socket fd is rejected
    // by the callee's fstat probe as a clean error, never as aliased ownership.
    // Keep this the first fd-creating operation in `main`: opening any fd before
    // it would reintroduce aliasing risk in hand-run processes.
    let mut rpc: RpcServer<Request, Response> = unsafe { rpc_server_from_inherited_fd() }
        .expect("daemon: failed to rebuild RpcServer from inherited fds");

    match behavior.as_str() {
        "echo" => loop {
            let request = match rpc.next_request() {
                Ok(r) => r,
                // Parent dropped the client → EOF → clean exit.
                Err(ChannelRecvError::SenderClosed) => std::process::exit(0),
                Err(err) => {
                    // On stderr, so a hung parent test isn't the only diagnostic.
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
            // For spawn_fd_isolation: write a sentinel byte to the fd named by
            // DAEMONIZABLE_TEST_LEAK_FD, which under fork+exec + FD_CLOEXEC is
            // already closed, so the test's read end sees EOF instead.
            drop(rpc);
            let leak_fd: i32 = std::env::var("DAEMONIZABLE_TEST_LEAK_FD")
                .expect("DAEMONIZABLE_TEST_LEAK_FD not set")
                .parse()
                .expect("DAEMONIZABLE_TEST_LEAK_FD not an int");
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            // Before the pid-file write, so the parent doesn't observe "pid file
            // present" until the leak has at least been attempted.
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
            // Regression coverage for FD_CLOEXEC restoration on fd 3: without it
            // the grandchild spawned below would inherit the channel end and hold
            // it open past this daemon's exit, starving the parent's EOF.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            // Not a synchronization point — the test kills the sleeper by the pid
            // recorded below. 30s merely has to outlast the 5s recv_response wait
            // in daemon_child_fd_cloexec by a wide margin, while still
            // self-cleaning if the kill-based cleanup never ran.
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("daemon: spawn sleeper grandchild");
            // The grandchild is reparented to init once we exit, so the test needs
            // its pid to clean it up.
            std::fs::write(&pid_file, child.id().to_string()).expect("daemon: write sleeper pid");
            drop(rpc);
            std::process::exit(0);
        }
        "sentinel_loop" => {
            // For daemon_survives_parent_exit, which verifies the sentinel file
            // is still being updated after the sub-test parent exits.
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
            // By hand, since this helper never goes through the framework's daemon
            // dispatch, which is what would normally call setsid.
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
            // For daemon_send_after_foreground_exit: a send whose foreground peer
            // is already gone. That peer is the spawner helper, which hands us its
            // pid via the environment.
            //
            // The wait below is an observed event, not a delay: the kernel
            // reparents us only during the spawner's teardown, after its fds are
            // closed, so once `getppid()` changes the channel's other end is
            // guaranteed gone and the send outcome is deterministic.
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
            // First, so the test can clean us up if an assertion fails before we
            // exit on our own.
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            // Forfeiting Rust's process-wide SIG_IGN, as a real daemon commonly
            // does before spawning pipeline children. The dead-peer send below
            // must still surface as a clean BrokenPipe; if that guarantee ever
            // broke, this process would die on SIGPIPE and publish no outcome.
            if std::env::var_os("DAEMONIZABLE_TEST_SIGPIPE_DFL").is_some() {
                // SAFETY: `libc::signal` with SIG_DFL installs the default
                // disposition for SIGPIPE — no handler function pointer is
                // involved (SIG_DFL is a sentinel, not code), and this helper
                // is single-threaded here, so no concurrent signal machinery
                // is in flight. The return value is checked against SIG_ERR.
                let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
                assert!(prev != libc::SIG_ERR, "daemon: signal(SIGPIPE, SIG_DFL)");
            }
            while nix::unistd::getppid().as_raw() == spawner_pid {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let outcome = match rpc.send_response(&Response { response: 1 }) {
                Err(ChannelSendError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                    "send:broken_pipe".to_string()
                }
                Ok(()) => "send:unexpected_success".to_string(),
                Err(other) => format!("send:unexpected_error:{other:?}"),
            };
            // Written to a sibling path and renamed, so the test's existence poll
            // can never observe a partial write.
            let tmp = outfile.with_extension("tmp");
            std::fs::write(&tmp, &outcome).expect("daemon: write outcome tmp file");
            std::fs::rename(&tmp, &outfile).expect("daemon: publish outcome file");
            std::process::exit(0);
        }
        "idle_without_handshake" => {
            // For failed_spawn_cleanup: the wedged-child case the parent's
            // handshake timeout exists for.
            let pid_file = std::path::PathBuf::from(
                std::env::var_os("DAEMONIZABLE_TEST_PID").expect("DAEMONIZABLE_TEST_PID not set"),
            );
            std::fs::write(&pid_file, std::process::id().to_string())
                .expect("daemon: write pid file");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        "wrong_handshake_then_idle" => {
            // For failed_spawn_cleanup: drives the handshake to a Mismatch, then
            // idles so the cleanup has a live child to kill and reap.
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
            // Mimics the real framework child arm, but with a wrong build id, to
            // prove the cleanup's group-kill reaches the grandchild — the real
            // daemon, reparented away from the parent — not merely the direct
            // child.
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
            // program start to this point (env reads, rpc_server_from_inherited_fd,
            // setsid) spawns a thread. With one thread at the fork, the child
            // inherits a consistent address space and may run arbitrary code;
            // the intermediate branch's _exit(0) is async-signal-safe regardless.
            match unsafe { libc::fork() } {
                -1 => {
                    eprintln!("daemon: fork failed: {}", std::io::Error::last_os_error());
                    std::process::exit(1);
                }
                0 => {
                    // The "daemon", owning the inherited channel fd.
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
            // For failed_spawn_cleanup: dies before any handshake and before
            // setsid, so the cleanup has an already-dead child to reap.
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
