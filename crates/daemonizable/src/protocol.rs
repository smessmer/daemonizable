//! The daemonization protocol: how the processes in a daemon spawn talk to
//! each other — every message, every check on the way, and what each check
//! defends against.
//!
//! This module contains no code; it is reference documentation. The
//! crate-root [How the handoff works](crate#how-the-handoff-works) section is
//! the mid-altitude summary of the same material — read that first if you
//! just want the shape. This page is for readers who need the wire-level
//! detail: auditors, contributors, and applications with unusual process
//! environments.
//!
//! The modules implementing the protocol are private (the public API is
//! deliberately small), so the steps below link to their source on GitHub
//! instead of to rustdoc pages. Those links follow `main`, the current
//! development tree, which may run slightly ahead of the release these docs
//! were built from.
//!
//! # The cast
//!
//! A successful [`Daemonizer::spawn_daemon`](crate::Daemonizer::spawn_daemon)
//! involves three processes, all running the same binary:
//!
//! - the **foreground parent**: your CLI, inside
//!   [`run_foreground`](crate::Daemonizable::run_foreground), calling
//!   `spawn_daemon`;
//! - the **stage-1 intermediate**: a short-lived re-exec of the binary whose
//!   only jobs are `setsid()` and spawning stage 2. It is the parent's direct
//!   child and the new session's leader, and it exits as soon as that spawn
//!   returns;
//! - the **stage-2 daemon**: the final daemon image — stage 1's child, so the
//!   parent's grandchild, and never a session leader. It ends up in
//!   [`run_daemon`](crate::Daemonizable::run_daemon) and keeps running after
//!   the parent exits.
//!
//! One `AF_UNIX` `SOCK_STREAM` socketpair connects the parent to the daemon.
//! The parent keeps one end; the other crosses both `execve`s as **file
//! descriptor 3** (a reserved descriptor, following the `sd_listen_fds(3)`
//! convention that parent-provided fds start at 3). Every protocol message
//! travels over that one socket — the stage-identity tokens, the build-id
//! handshake, then the application's typed RPC. Nothing protocol-related
//! rides argv or the environment: the daemon's argv stays empty and its
//! environment is byte-identical to the foreground's.
//!
//! # The wire format
//!
//! The channel carries three kinds of bytes, in this order:
//!
//! 1. **Stage tokens** (unframed). Each token is exactly 33 bytes: a fixed,
//!    *public* 32-byte magic number followed by one stage byte (`1` or `2`).
//!    The parent writes both tokens back-to-back as a single 66-byte write
//!    before the child even exists; each stage consumes its own token during
//!    dispatch. Defined in [`ipc/spawn/token.rs`].
//! 2. **The build-id handshake** (framed, raw payload). One frame from
//!    daemon to parent whose payload is the raw bytes of the app's
//!    [`build_id`](crate::Daemonizable::build_id) — deliberately not
//!    postcard-encoded, so validating it cannot depend on the two builds'
//!    serialization agreeing. Implemented in [`ipc/spawn/handshake.rs`].
//! 3. **Typed RPC** (framed, postcard payload). Every frame after the
//!    handshake is a postcard-encoded
//!    [`Request`](crate::Daemonizable::Request) (parent→daemon) or
//!    [`Response`](crate::Daemonizable::Response) (daemon→parent).
//!
//! A frame is a 4-byte little-endian payload length followed by the payload:
//!
//! ```text
//! [len: u32 LE][payload: len bytes]
//! ```
//!
//! Payloads are capped at 1 MiB in each direction (`MAX_MESSAGE_SIZE` in
//! [`ipc/channel/mod.rs`]) so a buggy or malicious peer cannot make the
//! other side allocate unboundedly. Each side drives the single socket
//! full-duplex through two `dup`-clones of its end — one for sending, one
//! for receiving — so a send and a receive can be in flight at once. EOF
//! semantics follow from that: the peer sees EOF once *both* clones of the
//! other side are closed, which is exactly what dropping an
//! [`RpcClient`](crate::RpcClient) / [`RpcServer`](crate::RpcServer) does —
//! that is what makes a dropped endpoint a reliable shutdown signal. An I/O
//! error partway through a frame poisons that endpoint (every later call
//! fails fast) rather than resynchronizing on a half-transferred frame
//! ([`ipc/channel/`]).
//!
//! # The sequence
//!
//! ```text
//! foreground (parent)          stage-1 intermediate            stage-2 daemon
//! ───────────────────          ────────────────────            ──────────────
//! resolve own exe path
//! socketpair; keep one end
//! queue token 1 ‖ token 2
//! fork+exec self,
//!   other end on fd 3 ───────▶ run(): peek fd 3 → token 1,
//!                              consume it
//!                              verify token 2 is queued
//!                              setsid()
//!                              fork+exec self
//!                                (fd 3 inherited) ───────────▶ run(): peek fd 3 → token 2,
//!                              _exit(0)                        consume it
//!                                                              topology guard
//!                                                              peer-credential check
//!                                                              claim fd 3, restore CLOEXEC
//!                                                              chdir("/")
//! recv build id (≤10 s) ◀──────────────────────────────────── send build id (one raw frame)
//! compare with own build id
//! reap the intermediate
//! spawn_daemon returns Ok                                      run_daemon(server) begins
//!    │                                                            │
//!    └───── typed postcard RPC: requests ▶ … ◀ responses ─────────┘
//! ```
//!
//! (Success path shown; each step's failure behavior is below.)
//!
//! ## 1. The parent prepares and spawns
//!
//! Implemented in [`ipc/spawn/process.rs`].
//!
//! - **Resolve the path to re-exec.** On Linux the parent hands `execve` the
//!   literal string `/proc/self/exe` — a kernel magic link to the running
//!   image's inode, so the daemon is byte-identical to the parent even if
//!   the on-disk binary was replaced mid-run. When `/proc` isn't mounted it
//!   degrades gracefully: first to the exec-time pathname the kernel
//!   recorded in the auxiliary vector (`AT_EXECFN`, rejecting an empty value
//!   and the `/dev/fd/N` shape an `fexecve` leaves), then to a non-empty
//!   `argv[0]`. But if the process runs under secure execution (`AT_SECURE`
//!   set: setuid/setgid/file-capabilities), those invoker-controlled
//!   fallbacks are refused outright — check 3 in the table below — and the
//!   spawn fails with a typed error instead. Other platforms use
//!   `current_exe()`.
//! - **Create the channel.** One socketpair via `UnixStream::pair`. On every
//!   target with `SOCK_CLOEXEC` both fds are close-on-exec atomically at
//!   creation; macOS/iOS lack it, so there std sets the flag a step later,
//!   leaving the narrow spawn-time race documented in the crate-root
//!   [costs list](crate#what-this-approach-costs).
//! - **Pre-queue both stage tokens**, 66 bytes written into the
//!   parent→daemon direction *before* the child exists — so no ordering race
//!   is possible: the bytes sit in the socket buffer ahead of everything
//!   else, and a single small write into an empty stream buffer cannot block
//!   or short-write.
//! - **Spawn.** `std::process::Command`, with exactly one fd mapped into the
//!   child: the socketpair's other end `dup2`'d onto fd 3 (the `dup2` clears
//!   `FD_CLOEXEC`, which is what lets this one fd survive the `execve`;
//!   every other framework/std fd is close-on-exec and dies there). argv is
//!   exactly `[argv0]` — pointed at the resolved binary path so `ps` shows a
//!   recognizable name instead of `/proc/self/exe` — and the environment
//!   passes through untouched.
//!
//! ## 2. Dispatch: every process discovers its role
//!
//! Implemented in [`app/run.rs`] and [`ipc/spawn/token.rs`].
//!
//! Every invocation of [`run`](crate::run) — a plain foreground run just as
//! much as the two spawned stages — starts by probing fd 3:
//! `recv(MSG_PEEK | MSG_DONTWAIT)` of up to 33 bytes, non-consuming and
//! non-blocking. The head of the fd decides the role:
//!
//! - the exact stage-1 token → run as stage 1, first consuming exactly the
//!   33 token bytes;
//! - the exact stage-2 token → run as stage 2, same consume;
//! - anything else — an errno of any kind (closed fd, not a socket, a
//!   listening socket, an empty connected socket…), a short read, wrong
//!   magic, or right magic with an unknown stage byte — falls through to the
//!   foreground arm having consumed nothing.
//!
//! The magic number is a fixed, public constant. Its job is to make a
//! *coincidental* match with unrelated inherited data astronomically
//! unlikely (2⁻²⁵⁶) — a systemd socket-activation socket or a make jobserver
//! pipe that happens to sit on fd 3 must not be mistaken for a framework
//! channel. It is *not* a defense against a deliberate forger, who can
//! simply write the public bytes; the checks in stages 1 and 2 below carry
//! that load.
//!
//! ## 3. Stage 1: the intermediate
//!
//! Implemented in [`app/daemon_child.rs`]. Its token already consumed by
//! dispatch, stage 1 runs these steps in order. Any failure prints to the
//! still-inherited stderr and exits with the given code; the parent
//! additionally observes any stage death as EOF on the channel.
//!
//! 1. **Verify token 2 is queued** behind the one just consumed (another
//!    non-consuming peek). A crafted socket carrying only token 1 is refused
//!    here — before any session change, leaving no process behind — rather
//!    than the stage-2 image later finding no token and silently running
//!    foreground code in a detached process. Exit 2.
//! 2. **`setsid()`**: the new, terminal-less session. This also makes
//!    stage 1's pid the process-group id that the parent's failed-spawn
//!    cleanup signals (`kill(-child_pid)`). Failure: exit 1.
//! 3. **Resolve the re-exec path again**, with the same resolver the parent
//!    used. Failure: exit 1.
//! 4. **Spawn stage 2** via `std::process::Command`: fd 3 is inherited as-is
//!    (still non-CLOEXEC from the parent's `dup2`), argv is the inherited
//!    `argv0` and nothing else, environment untouched. No crate-written code
//!    runs between fork and exec — only std's own async-signal-safe child
//!    setup — which is what makes this second fork sound regardless of
//!    threads. Failure: exit 1 (degrading to single-fork operation would
//!    silently break the "never a session leader" guarantee, so a failed
//!    spawn is fatal instead).
//! 5. **`_exit(0)`**: the session leader steps out of the way, leaving the
//!    daemon a non-leader that can never acquire a controlling terminal.
//!    `_exit`, not a normal return — no atexit handlers, no stdio flushing,
//!    no Rust drops (the child handle is deliberately never waited on; the
//!    daemon must outlive the intermediate).
//!
//! ## 4. Stage 2: the daemon
//!
//! Implemented in [`app/daemon_child.rs`]. Its own token consumed by
//! dispatch, the final image runs these steps in order, all before any
//! application code:
//!
//! 1. **Topology guard.** A genuine framework daemon is a non-leader
//!    grandchild: `sid == pgid == stage 1's pid ≠ own pid`. A session or
//!    group leader, or a process outside stage 1's group, is refused — that
//!    is a hand-run from a shell or some other non-framework launch, and
//!    running on would produce a silently degraded "daemon". Exit 1.
//! 2. **Peer-credential check** ([`ipc/spawn/peercred.rs`]). The
//!    kernel-reported credentials of the fd-3 peer (`SO_PEERCRED` on
//!    Linux/Android, `getpeereid` on BSD/macOS) must show *our own* effective
//!    uid AND gid. The stage token is public, so this check — unforgeable by
//!    the peer — is what stops a lower-privileged principal from driving a
//!    daemon image that gained privilege by changing uid/gid (setuid/setgid)
//!    into `run_daemon` over a crafted channel. Its honest scope: it cannot
//!    distinguish a same-principal attacker (who could equally `ptrace` the
//!    process), and a file-capabilities binary keeps the invoker's ids, so
//!    such a daemon must treat RPC input as untrusted — see
//!    [`run`](crate::run)'s documentation. Exit 1.
//! 3. **Claim fd 3** ([`ipc/spawn/inherited.rs`]): a process-wide
//!    once-guard, an `fstat` probe that fd 3 is open and actually a socket,
//!    then adoption into the owning [`RpcServer`](crate::RpcServer) —
//!    restoring `FD_CLOEXEC`, which the parent's `dup2` had necessarily
//!    cleared. From here on, subprocesses the daemon spawns cannot inherit
//!    the channel end (a leaked duplicate would hold the parent's EOF open
//!    past the daemon's exit). Exit 2.
//! 4. **`chdir("/")`**, so the daemon doesn't pin the launch directory's
//!    filesystem for its whole lifetime (unmounting the USB stick the user
//!    launched from would otherwise fail with `EBUSY`). Failure is a
//!    warning, not an error.
//! 5. **Send the build-id handshake**: one raw frame containing
//!    [`build_id`](crate::Daemonizable::build_id). Failure: exit 127.
//! 6. **Hand off**: [`run_daemon`](crate::Daemonizable::run_daemon) receives
//!    the server and never returns.
//!
//! ## 5. The parent completes the spawn
//!
//! Implemented in [`ipc/spawn/process.rs`] and [`ipc/spawn/handshake.rs`].
//!
//! The parent has been blocked in `spawn_daemon` reading the handshake,
//! bounded by a 10-second timeout that spans the whole two-stage startup
//! (two exec + dynamic-loader passes; normally milliseconds — the generous
//! bound is for loaded CI machines and heavy pre-main constructors). The
//! received frame must be valid UTF-8 and byte-equal to the parent's own
//! [`build_id`](crate::Daemonizable::build_id).
//!
//! - **Match**: the parent reaps the (already-exited) stage-1 intermediate
//!   with a blocking `wait()`, and `spawn_daemon` returns the connected
//!   [`RpcClient`](crate::RpcClient). A successful spawn leaves the caller
//!   no child and no zombie.
//! - **Anything else** — EOF (a stage died, or a wrong binary exited),
//!   timeout (a wrong binary holds the fd open but never writes), a build-id
//!   mismatch, or non-UTF-8 bytes — and the parent kills the whole spawn
//!   before returning a typed [`SpawnDaemonError`](crate::SpawnDaemonError):
//!   `kill(-child_pid, SIGKILL)` on the process group (reaching the
//!   grandchild through the group that stage 1's `setsid` created), a direct
//!   kill of the child (covering a death before `setsid`), the group kill
//!   repeated (covering `setsid` landing between the two), then the reap.
//!   The caveats — the blocking `wait()` versus an externally SIGSTOPped
//!   intermediate, and why the caller must not reap or auto-reap children
//!   concurrently — are in the crate-root
//!   [Process contract](crate#process-contract).
//!
//! # Every check on the way
//!
//! The stages print their refusals to the still-attached stderr and exit
//! with the listed code; the parent independently observes any
//! pre-handshake death as channel EOF and reports a typed error.
//!
//! | # | Check | Runs in | Rejects | On failure |
//! |---|-------|---------|---------|------------|
//! | 1 | stage-token probe (public 32-byte magic + stage byte) | every [`run`](crate::run) | a stranger on fd 3 mistaken for a framework channel — an accident authenticator, not a forgery defense | routes to the foreground arm, consuming nothing |
//! | 2 | token-2 presence check | stage 1 | a crafted socket carrying only token 1 | exit 2, before `setsid` |
//! | 3 | secure-execution refusal (`AT_SECURE`) in exe-path resolution | parent and stage 1 | re-exec'ing an invoker-controlled `AT_EXECFN`/`argv[0]` path in a `/proc`-less setuid/setgid process | typed `PermissionDenied` error (parent) / exit 1 (stage 1) |
//! | 4 | session/group topology guard (`sid == pgid ≠ pid`) | stage 2 | hand-runs and other non-framework launches | exit 1 |
//! | 5 | peer-credential check (`SO_PEERCRED`/`getpeereid`: peer's effective uid+gid must equal ours) | stage 2 | a cross-principal peer driving a privilege-changing (setuid/setgid) daemon image — the unforgeable barrier behind the public token | exit 1 |
//! | 6 | fd-3 claim: once-guard + `fstat` open-socket probe | stage 2 | a closed or non-socket fd 3; any double claim | exit 2 |
//! | 7 | build-id handshake (UTF-8, byte-equal) | parent | a wrong, swapped, or version-skewed binary — an accident detector, not a security boundary (a hostile binary could echo the id) | spawn group-killed and reaped; typed [`HandshakeError`](crate::HandshakeError) |
//! | 8 | handshake timeout (10 s) | parent | a wrong binary that opens the channel but never handshakes | same cleanup; timeout error |
//!
//! The split worth remembering: checks 1, 7, and 8 are accident detectors
//! (public, replayable bytes), check 5 — with check 3 — is the
//! security-bearing refusal, and checks 2, 4, and 6 close off degraded
//! configurations. None of this makes `run_daemon`'s RPC input
//! authenticated-by-provenance against a same-principal local peer; see
//! [`run`](crate::run)'s documentation for that caveat in full.
//!
//! # After startup
//!
//! The protocol ends where the API begins: the parent holds an
//! [`RpcClient`](crate::RpcClient), the daemon an
//! [`RpcServer`](crate::RpcServer), and everything on the wire from now on
//! is the application's own postcard-framed request/response traffic. When
//! [`run_foreground`](crate::Daemonizable::run_foreground) returns, the
//! client drops, both parent-side clones close, and the daemon's next
//! [`next_request`](crate::RpcServer::next_request) reports
//! [`SenderClosed`](crate::ChannelRecvError::SenderClosed) — the documented
//! signal for [`run_daemon`](crate::Daemonizable::run_daemon) to finish its
//! request loop and choose its own exit. Symmetrically, if the daemon dies,
//! the parent's next call returns an error instead of hanging.
//!
//! [`app/run.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/app/run.rs
//! [`app/daemon_child.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/app/daemon_child.rs
//! [`ipc/spawn/token.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/spawn/token.rs
//! [`ipc/spawn/process.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/spawn/process.rs
//! [`ipc/spawn/handshake.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/spawn/handshake.rs
//! [`ipc/spawn/peercred.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/spawn/peercred.rs
//! [`ipc/spawn/inherited.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/spawn/inherited.rs
//! [`ipc/channel/mod.rs`]: https://github.com/smessmer/daemonizable/blob/main/crates/daemonizable/src/ipc/channel/mod.rs
//! [`ipc/channel/`]: https://github.com/smessmer/daemonizable/tree/main/crates/daemonizable/src/ipc/channel
