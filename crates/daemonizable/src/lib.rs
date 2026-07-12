//! Run your CLI application as a foreground process or have it fork+exec itself
//! into a background daemon — with a typed RPC channel between the spawning
//! parent and the daemon.
//!
//! Implement [`Daemonizable`] for your app type and let [`run`] drive the
//! process-role dispatch. The library is deliberately policy-free: it handles
//! only the process mechanics and imposes no argument parser, logging
//! framework, panic hook, or startup banner on your application.
//!
//! The typed RPC channel between parent and daemon carries the app's own
//! [`Daemonizable::Request`] / [`Daemonizable::Response`] types; the framework's
//! build-id handshake travels out-of-band on the same pipe, before the typed
//! phase and invisible to app code.
//!
//! # What it does
//!
//! - **Daemon-child dispatch** via an environment marker (no argv flag — your
//!   CLI surface stays entirely yours; the daemon child's argv is just
//!   `[argv0]`).
//! - **fork+exec re-exec** of the current binary (`/proc/self/exe` on Linux, so
//!   the daemon runs the exact same inode as the parent even if the binary on
//!   disk was replaced mid-run).
//! - **Build-id handshake**: the daemon proves it's the binary the parent meant
//!   to spawn before either side deserializes anything typed.
//! - **Typed RPC**: [`RpcClient`] / [`RpcServer`] over pipes, postcard-encoded,
//!   with EOF-based liveness (a dead peer is an error, not a hang). The daemon
//!   child's argv is empty, so any config it needs (typically logging) travels
//!   as an ordinary first request.
//! - **Daemon hygiene**: `setsid` + a second fork (so the daemon is never a
//!   session leader and can't acquire a controlling terminal), `chdir("/")`,
//!   single-claim guard on the inherited fds, [`detach_stdio`] for when your
//!   daemon is ready to let go of the terminal.
//! - **`#[daemonizable::main]`**: put it on your `impl Daemonizable` block and
//!   the correct `main` — a single [`run`]`::<MyApp>()` call and nothing else —
//!   is generated for you.
//!
//! # Example
//!
//! `src/main.rs` — the attribute generates `main`, so this is the whole file:
//!
//! ```ignore
//! use std::process::ExitCode;
//!
//! use daemonizable::{Daemonizable, Daemonizer, RpcServer};
//!
//! struct MyApp;
//!
//! #[daemonizable::main]
//! impl Daemonizable for MyApp {
//!     type Request = String;
//!     type Response = String;
//!
//!     fn build_id() -> String {
//!         format!("my-app {}", env!("CARGO_PKG_VERSION"))
//!     }
//!
//!     fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
//!         // This is your `main`: parse arguments however you like, then
//!         // daemonize whenever (and only if) you decide to.
//!         let mut rpc = daemonizer.spawn_daemon().unwrap();
//!         rpc.send_request(&"hello".to_string()).unwrap();
//!         println!("daemon says: {}", rpc.recv_response_blocking().unwrap());
//!         ExitCode::SUCCESS
//!     }
//!
//!     fn run_daemon(mut rpc: RpcServer<String, String>) -> ! {
//!         // Runs in the re-exec'd daemon child. Serve requests until the
//!         // parent drops its client (EOF), then exit.
//!         while let Ok(request) = rpc.next_request() {
//!             rpc.send_response(&format!("echo: {request}")).unwrap();
//!         }
//!         std::process::exit(0)
//!     }
//! }
//! ```
//!
//! `#[daemonizable::main]` comes from the default-on `macros` feature. It leaves
//! the impl untouched and appends
//! `fn main() -> ExitCode { daemonizable::run::<MyApp>() }` — the entire `main`
//! an application on this library should have. Build with
//! `default-features = false` and the attribute is gone; write that one line
//! yourself, and keep `main` to exactly that one line: the re-exec'd daemon
//! child runs the same `main`, so anything in front of [`run`] runs in the
//! daemon too (a thread spawned there exists in the child as well). The
//! attribute guarantees an empty preamble by construction. (The example above
//! is shown, not compiled; the compiled equivalent is the doctest on [`run`],
//! and the
//! macro's expansion is covered by the trybuild snapshots in
//! `daemonizable-e2e-tests/tests/macro_ui/`.)
//!
//! # Why fork+exec? A comparison with the alternatives
//!
//! Every other option in this space — the classic double-fork ritual, the
//! `daemon(3)` libc call, and the crates.io daemonizers (`daemonize`,
//! `daemon`, `daemonize-me`, `daemonize-simple`, `fork`,
//! `nix::unistd::daemon`) — shares two structural decisions that this library
//! deliberately rejects:
//!
//! 1. they daemonize by **fork *without* exec**, so the daemon lives out its
//!    entire life inside a copied snapshot of the parent's process image, and
//! 2. they **cut the cord at fork time** — the parent exits (almost always
//!    with status 0) before the daemon has run a single line of real
//!    initialization, so daemon startup failures are invisible to whoever
//!    launched it.
//!
//! Both are real, documented problems, not stylistic gripes. (What this library
//! keeps from the classic ritual is the *second* fork — it performs
//! `daemon(7)`'s second fork itself, but *after* `exec`, in the fresh
//! single-threaded child, where it is unconditionally safe. What it rejects is
//! fork-without-exec and cord-cutting, not the second fork.)
//!
//! ## fork without exec: the daemon inherits a broken process image
//!
//! `fork()` in a threaded process hands the child a frozen snapshot: every
//! other thread vanishes mid-step, but everything those threads were holding
//! — mutexes, allocator arenas, channel internals — is copied into the child
//! in its locked state, forever.
//! [POSIX is explicit](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html)
//! about this: the child contains "a replica of the calling thread and its
//! entire address space, possibly including the states of mutexes and other
//! resources", and consequently "may only execute async-signal-safe
//! operations until such time as one of the exec functions is called."
//! Rust's own [`CommandExt::pre_exec`](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec)
//! docs describe that post-fork world as "a very constrained environment
//! where normal operations like malloc, accessing environment variables
//! through `std::env` or acquiring a mutex are not guaranteed to work".
//!
//! The rest of the ecosystem agrees. Tokio doesn't support `fork()` while a
//! runtime is running
//! ([tokio#4301](https://github.com/tokio-rs/tokio/issues/4301), closed by
//! runtime documentation merged in
//! [tokio#8202](https://github.com/tokio-rs/tokio/pull/8202)). Go's standard
//! library has never offered a bare fork (only fork+exec via
//! `syscall.ForkExec` / `os/exec`). CPython 3.12+ raises a
//! `DeprecationWarning` from
//! [`os.fork()`](https://docs.python.org/3/library/os.html#os.fork) when it
//! detects threads, because "it has never been safe to mix threading with
//! `os.fork()` on POSIX platforms".
//!
//! A fork-only daemonizer therefore bets your daemon's life on *nothing* in
//! the process having started a thread yet — not your code, not a lazy
//! static, not an allocator or telemetry background thread in any dependency
//! — and keeps paying that bet for the daemon's entire lifetime, because the
//! daemon *is* the forked image. The fork-based crates leave this assumption
//! implicit.
//!
//! fork+exec is the escape hatch POSIX itself names: the async-signal-safe
//! restriction applies only *until the exec*.
//! [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html)
//! resets the process image — all other threads are gone by construction
//! ("mutexes, condition variables, and other pthreads objects are not
//! preserved"), caught signal dispositions revert to their defaults, the
//! memory image and allocator state are rebuilt from scratch, and only file
//! descriptors deliberately left inheritable survive. The re-exec'd daemon
//! can start tokio, spawn threads, and generally behave like the freshly
//! started process it actually is. State it needs from the parent arrives
//! explicitly — as a typed request on the RPC channel — instead of implicitly
//! through a memory snapshot.
//!
//! (The symmetric honesty: the *parent* can already have a tokio runtime
//! running when it calls `spawn_daemon` — fork+exec makes that safe. On the
//! platforms with `pipe2(O_CLOEXEC)` there is no residual constraint at all;
//! only on macOS/iOS, which lack it, does a narrow spawn-time race remain while
//! the pipe fds get their CLOEXEC flag set non-atomically — and even there it
//! covers a moment at spawn time, not the daemon's whole life.)
//!
//! ## cutting the cord at fork time: nobody hears the daemon fail
//!
//! The canonical description of SysV daemonization —
//! [`daemon(7)`](https://man7.org/linux/man-pages/man7/daemon.7.html)'s
//! 15-step ritual — makes readiness reporting *mandatory*: the daemon must
//! "notify the original process started that initialization is complete"
//! via "an unnamed pipe or similar communication channel" (step 14), and the
//! invoker "must be able to rely on" the original process exiting only
//! "after initialization is complete and all external communication channels
//! are established" (step 15). Those are exactly the steps everyone skips:
//!
//! - **`daemon(3)`** provides no channel at all: by the time it returns, the
//!   parent has already `_exit(0)`'d.
//! - **The `daemonize` crate** has the parent exit the instant the second
//!   fork succeeds. Pid-file locking (the "already running" check!), stdio
//!   redirection, privilege drop, and your entire daemon body all run *after*
//!   the CLI has already reported success, and their errors go to `/dev/null`
//!   by default. It's worse than that: `start()` passes the raw `waitpid`
//!   status (not `WEXITSTATUS`) to `exit()`, so even a first-child failure
//!   with code N becomes wait status `N << 8`, which truncates to exit
//!   code 0 — success. The fix
//!   ([PR #53](https://github.com/knsd/daemonize/pull/53)) has been open
//!   since May 2023.
//! - **An init system can't reconstruct readiness from the outside**:
//!   [`systemd.service(5)`](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
//!   says of `Type=forking` — the mode built for exactly these daemons —
//!   "The use of this type is discouraged, use notify, notify-reload, or
//!   dbus instead."
//!
//! The pipe handshake that `daemon(7)` demands is what serious daemons end up
//! hand-rolling, because fork-based self-daemonization — the classic Unix
//! pattern — otherwise loses every startup error. `sshd` backgrounds itself
//! with the libc [`daemon(3)`](https://man7.org/linux/man-pages/man3/daemon.3.html)
//! call, but only *after* it has bound its listen sockets, so "address already
//! in use" still reaches your terminal
//! ([`sshd.c`](https://github.com/openssh/openssh-portable/blob/master/sshd.c);
//! `-D` skips the backgrounding entirely). nginx does the same bind-before-fork,
//! and its [`ngx_daemon()`](https://github.com/nginx/nginx/blob/master/src/os/unix/ngx_daemon.c)
//! deliberately leaves stderr attached — it `dup2`s stdin/stdout to `/dev/null`
//! but the stderr redirect sits under `#if 0` — so config errors still print;
//! [`daemon off;`](https://nginx.org/en/docs/faq/daemon_master_process_off.html)
//! drops backgrounding entirely for a supervisor or container. PostgreSQL
//! splits the roles: the `postgres` server never daemonizes, and the
//! [`pg_ctl`](https://www.postgresql.org/docs/current/app-pg-ctl.html) wrapper
//! backgrounds it and then polls `postmaster.pid` until it reads "ready to
//! accept connections" before returning (the `-w` wait is the default since
//! PostgreSQL 10) — the same readiness handshake through a status file instead
//! of a pipe. Even [Apache httpd](https://httpd.apache.org/docs/current/programs/httpd.html)
//! only detaches (`fork` + `setsid`) once its config is parsed, and ships
//! `-DNO_DETACH` / `-DFOREGROUND` to suppress each half for a supervisor. And
//! libfuse — this library's home turf, it was extracted from
//! [CryFS](https://www.cryfs.org) — grew a whole new API for it
//! ([`fuse_daemonize_early_start` / `_success` / `_fail`](https://github.com/libfuse/libfuse))
//! so the mounting parent stays alive until the mount actually succeeded and
//! can report failure otherwise. The modern answer is to skip self-daemonization
//! altogether: under systemd the recommended shape is a foreground process
//! reporting readiness via [`sd_notify(3)`](https://man7.org/linux/man-pages/man3/sd_notify.html),
//! with the self-backgrounding
//! [`Type=forking`](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
//! discouraged (see the last entry in the costs list below).
//!
//! daemonizable builds that handshake in as the core primitive instead of an
//! afterthought. [`Daemonizer::spawn_daemon`] blocks through the build-id handshake; a child
//! that fails it is killed, reaped, and surfaced as a typed error — your CLI
//! prints a real message and exits non-zero. And
//! it doesn't stop at "started": the RPC channel stays open, so the parent
//! can wait for whatever *its* definition of ready is before exiting (CryFS
//! exits 0 only after the daemon reports the filesystem is actually mounted).
//! If the daemon dies instead of answering, the parent gets an EOF error
//! rather than a hang. The inherited pipe fds are re-marked close-on-exec as
//! soon as the daemon claims them, so subprocesses the daemon spawns don't
//! inherit the RPC pipe ends and can't hold that EOF open past the daemon's
//! own exit.
//!
//! ## The crates, specifically
//!
//! A point-in-time snapshot (July 2026) — versions and maintenance status
//! will drift, check crates.io for where things stand now:
//!
//! | crate | mechanics | CLI sees daemon startup errors? | parent↔daemon channel | notes |
//! |---|---|---|---|---|
//! | `daemonize` 0.5.0 | double fork, no exec | no — parent exits 0 first, plus the raw-`waitpid` bug above | none (parent never even learns the daemon's pid) | last release 2023-02; GitHub issue tracker disabled; exit-code and soundness fixes unmerged since 2023/2024 |
//! | `daemon` 0.0.8 | none — despite the name it never forks or calls `setsid`; it's a signal-to-channel run loop + Windows service shim | n/a | n/a | last release 2018-09 |
//! | `daemonize-me` 2.0.2 | single fork + `setsid` | no | none | 2.0.2 (2025-03) came after a 3-year gap |
//! | `daemonize-simple` 0.1.6 | double fork | no | none | maintained; all errors are bare `&'static str` |
//! | `fork` 0.8.0 | double fork | no | none | actively maintained; note that 0.1.x–0.3.x closed fds 0–2 outright (fd-reuse hazard) and returned the intermediate session leader to the caller — fixed across 0.4.0–0.6.0 (Nov–Dec 2025) |
//! | `nix::unistd::daemon` / `libc::daemon` | `daemon(3)`: single fork | no | none | `nix`'s wrapper isn't even compiled on Apple targets; Apple has deprecated `daemon()` since macOS 10.5 ("Use posix_spawn APIs instead") |
//!
//! On `daemon(3)` itself: it's a 4.4BSD invention that is in no standard
//! ([`STANDARDS: None`](https://man7.org/linux/man-pages/man3/daemon.3.html)),
//! its own BUGS section admits it skips the double fork ("the resulting
//! daemon is a session leader"), and Apple deprecated it two decades ago.
//!
//! To be fair to the fork-based crates: several carry battle-tested SysV
//! batteries this library doesn't have yet — locked pid files, setuid/
//! setgid privilege drop, chroot, umask control (planned as opt-in options;
//! see the TODO in the costs list below). If you need
//! fire-and-forget backgrounding with those knobs, and you can guarantee the
//! fork happens before any thread exists, `fork` (the crate) is a reasonable
//! minimal choice. What none of them can do is tell you whether your daemon
//! actually came up.
//!
//! ## Why not a second binary?
//!
//! The other conventional design is to ship a separate `myapp-daemon`
//! executable and `Command::spawn` it (the dockerd / ssh-agent shape). That
//! costs you two artifacts to build, package and install, a lookup problem
//! (absolute path? `$PATH`? relative to `argv[0]`?), and — worst — a version
//! skew problem: nothing stops CLI 1.4 from spawning a daemon 1.3 whose wire
//! format differs silently.
//!
//! Re-exec'ing the current binary makes skew structurally impossible on
//! Linux: [`/proc/self/exe`](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
//! is a kernel magic link to the running image's inode, so the daemon is
//! byte-identical to the parent even if the on-disk binary was replaced by a
//! package upgrade mid-run, and the build-id handshake catches whatever the
//! platform can't guarantee (the macOS `current_exe()` fallback, operator
//! mistakes). This is well-trodden ground: Docker/Moby ships a dedicated
//! [`reexec` package](https://pkg.go.dev/github.com/moby/sys/reexec) whose
//! `Self()` returns the literal string `/proc/self/exe` ("safe to delete or
//! replace the on-disk binary"); [runc](https://github.com/opencontainers/runc)
//! re-execs itself as `runc init` with a bootstrap pipe fd passed through an
//! environment variable — env-marker plus inherited-fd, the same shape used
//! here; and `systemctl daemon-reexec` re-execs PID 1 itself.
//!
//! ## What this approach costs
//!
//! An honest comparison cuts both ways. The price of fork+exec plus a typed
//! channel:
//!
//! - **The binary must cooperate.** [`run`]`::<App>()` has to be the whole of
//!   `main` — `#[daemonizable::main]` guarantees that by construction, but the
//!   binary being re-exec'd must still be *your* binary, so a wrapper-script
//!   entry point breaks re-exec. Fork-based crates work on any code with zero
//!   cooperation.
//! - **procfs.** On Linux the re-exec needs `/proc` mounted (bare chroots and
//!   minimal containers may not have it); other platforms fall back to
//!   `current_exe()` plus the handshake.
//!   *TODO: degrade gracefully instead of failing — when `/proc/self/exe`
//!   is unavailable, fall back to `getauxval(AT_EXECFN)` / `argv[0]`
//!   resolution (`current_exe()` is not a fallback on Linux; it reads
//!   `/proc/self/exe` itself). The fallback gives up the same-inode
//!   guarantee, but the build-id handshake already turns a swapped binary
//!   into a clean error rather than a wrong daemon.*
//! - **At most a narrow spawn-time race on macOS.** Because the daemon is
//!   created with fork+exec, a running tokio runtime (or any thread pool) is
//!   fine to spawn under — the parent-side restriction is *not* "no tokio." On
//!   Linux/Android, the *BSDs, and every other target with `pipe2(O_CLOEXEC)`,
//!   the pipe fds are created with `FD_CLOEXEC` already set, so there is no
//!   race at all. macOS/iOS have no `pipe2` (nor any atomic equivalent), so
//!   there the flag is set a moment after creation and a concurrent fork on
//!   another thread in that window can leak the fds; those targets keep the
//!   spawn-at-startup invariant.
//!   *TODO: migrating from `command-fds`' `pre_exec` to std's planned fd
//!   mappings ([rust#145687](https://github.com/rust-lang/rust/pull/145687))
//!   would drop the last bit of non-atomic fd handling in the spawn path.*
//! - **No batteries (yet).** Pid files, privilege drop, chroot, umask,
//!   signal-mask reset, and log-file stdio redirection are currently the
//!   application's job.
//!   *TODO (planned): add these as opt-in options, applied in the daemon
//!   child before entering [`Daemonizable::run_daemon`] — carried by a framework-owned
//!   bootstrap frame reintroduced with the batteries (config-in, result-out),
//!   distinct from the removed app-facing payload — so that every
//!   failure — an "already running" pid-file lock conflict, a failed
//!   `setuid`, an unwritable log path — surfaces as a typed error in the
//!   parent and a non-zero CLI exit. That is exactly what the fork-based
//!   crates structurally cannot offer: they perform these same steps after
//!   their parent already exited 0, with errors going to `/dev/null`. The
//!   planned set, following `daemon(7)` and the `daemonize` feature list:
//!   an `flock`-locked pid file written with the final daemon pid (the
//!   kernel drops the lock on process death, so stale pid files are
//!   harmless; the lock can even be taken in the parent before spawning —
//!   `flock` belongs to the open file description, which the daemon inherits
//!   across the exec and the second fork — so "already running" fails before a
//!   child is ever spawned), `initgroups`/`setgid`/`setuid` privilege drop,
//!   optional `chroot`, explicit `umask` (currently silently inherited — it
//!   survives `execve`), signal-mask reset (the mask, unlike handlers, also
//!   survives `execve`), fd hygiene for non-CLOEXEC fds inherited from the
//!   CLI's own environment (`close_range(5, ~0)` on Linux, sparing the pipe
//!   fds 3/4), and `detach_stdio` gaining redirect-to-log-file targets (log
//!   files opened before the privilege drop, so root-owned log directories
//!   work). Defaults stay policy-free: every battery is opt-in.*
//! - **Initialization runs twice.** The daemon re-runs the dynamic loader and
//!   everything before `run` (with `#[daemonizable::main]`, that's nothing);
//!   parent state must be shipped explicitly via the typed RPC channel.
//! - **If systemd manages your process, don't daemonize at all.**
//!   `daemon(7)`'s "new-style daemons" doctrine is that services should run
//!   in the foreground and report readiness via `sd_notify(3)`; SysV-style
//!   self-daemonization "interfere\[s\] with process monitoring, file
//!   descriptor passing, and other functionality of the service manager".
//!   That applies to this library too. daemonizable is for processes a *user*
//!   launches — mount helpers, agents started from a shell — which is exactly
//!   the niche it was extracted from.
//!
//! That's the design in one sentence: fork+exec buys the daemon a clean
//! process image, and the typed channel turns daemonization from a leap of
//! faith into an operation that can fail loudly.
//!
//! # Process contract
//!
//! - The daemon is a **grandchild**: the re-exec'd child forks a second time
//!   after `setsid` (the classic double fork, `daemon(7)` step 7). The
//!   session-leader intermediate exits immediately and is reaped by
//!   [`Daemonizer::spawn_daemon`] itself, and the surviving daemon — never a session leader,
//!   so it can never acquire a controlling terminal — is orphaned to init (or
//!   the nearest `PR_SET_CHILD_SUBREAPER` ancestor, e.g. a systemd user
//!   manager) at spawn time. A **successful** spawn leaves the caller no child
//!   and no zombie, regardless of the caller's own lifetime.
//! - A **failed** spawn (handshake mismatch or spawn failure) is killed via its
//!   process group (`kill(-child_pid, SIGKILL)`, which reaches the grandchild;
//!   ESRCH falls back to a direct kill for a child that died before `setsid`)
//!   and the intermediate reaped before the error is returned. A grandchild the
//!   group signal misses (it left the group via its own `setsid`/`setpgid`)
//!   still self-terminates via pipe EOF within ~10 s once the client is dropped
//!   — so failed-spawn teardown of the daemon is asynchronous, not synchronous
//!   with the returned error.
//! - Two caveats on [`Daemonizer::spawn_daemon`] itself: it can block
//!   indefinitely if the intermediate is externally SIGSTOPped/ptraced in the
//!   instant before it exits, since it is reaped with a blocking `wait()` (the
//!   build-id handshake recv is timeout-bounded, so a wedged child during the
//!   handshake is not); and the caller must not concurrently reap arbitrary
//!   children (e.g. a `SIGCHLD` handler that calls `waitpid(-1)`) during the
//!   spawn, which could reap the intermediate first and defeat the cleanup's
//!   pid bookkeeping.
//! - [`Daemonizer::spawn_daemon`] is safe to call with a tokio runtime already running —
//!   fork+exec hands the daemon a fresh process image, so the fork-vs-threads
//!   hazard ([tokio#4301](https://github.com/tokio-rs/tokio/issues/4301))
//!   doesn't apply (the second fork runs in that fresh single-threaded image,
//!   before any app code, so it is safe too). On targets with `pipe2(O_CLOEXEC)`
//!   (Linux/Android, the *BSDs, …) the pipe fds are `FD_CLOEXEC` from creation,
//!   so there is no fd-inheritance race; only on macOS/iOS, which lack `pipe2`,
//!   does a narrow race remain if another thread forks while the spawn sets
//!   `FD_CLOEXEC` on its pipe fds, and spawning before the process starts other
//!   subprocesses avoids it there.
//!
//! # Features
//!
//! - `macros` *(default)*: re-exports `#[daemonizable::main]` from the
//!   `daemonizable-macros` companion crate — the recommended way to write your
//!   `main`. Disable it and you hand-write
//!   `fn main() -> ExitCode { daemonizable::run::<MyApp>() }` instead; nothing
//!   else about the API changes.
//! - `testutils`: test-only helpers (e.g.
//!   `RpcConnection::into_server_and_client`) so downstream crates can drive the
//!   IPC primitives in their own unit tests. Not part of the stable surface.
//!
//! Unix-only (Linux is the primary target; macOS works with caveats documented
//! in the source).

// On the platforms that have `pipe2(O_CLOEXEC)` (Linux/Android, the *BSDs, and
// more), pipe fds are now created with FD_CLOEXEC set atomically, so the
// fd-inheritance race is closed there regardless of runtime — including a
// second spawn_daemon from another thread, an advertised use of the
// Copy+Send+Sync Daemonizer. macOS/iOS lack `pipe2` (and any atomic
// equivalent), so on those targets the CLOEXEC flag is still set in a separate
// step and a concurrent fork/Command::spawn in that window can leak duplicate
// pipe ends across execve, silently defeating EOF liveness (EOF only fires once
// ALL write ends close). There we rely on the documented spawn-at-startup
// caller contract instead. See the race discussion in ipc/pipe/mod.rs.

mod app;
mod ipc;

pub use app::{Daemonizable, Daemonizer, run};

// The #[daemonizable::main] attribute: generates `fn main` from an
// `impl Daemonizable for X` block. Lives in the companion proc-macro crate
// (proc macros can't be defined here) and is re-exported so applications
// only ever depend on `daemonizable` itself.
#[cfg(feature = "macros")]
pub use daemonizable_macros::main;

// Re-exported so applications can name the typed handles they receive: the
// client handle from `Daemonizer::spawn_daemon` and the server handle passed
// to `Daemonizable::run_daemon`, and so test code can construct in-process
// connections for unit testing.
pub use ipc::{RpcClient, RpcConnection, RpcServer};

// Typed errors returned by the IPC layer (thiserror, not anyhow) so callers
// can match on failure modes, e.g. distinguish a peer that closed the pipe
// (`PipeRecvError::SenderClosed`) from a timeout.
pub use ipc::{
    DetachStdioError, HandshakeError, InheritedFdsError, PipeCreateError, PipeRecvError,
    PipeSendError, SpawnDaemonError,
};

// Process-global helper: the daemon calls this at its post-startup boundary
// to detach the inherited stdio from the parent's terminal.
pub use ipc::detach_stdio;

// Lower-level handles for integration tests that substitute an external
// helper binary for the re-execed self and drive the spawn machinery
// directly, skipping the handshake.
//
// Production app code should not reach for these — implement
// [`Daemonizable`] and let [`run`] orchestrate the daemon side.
// `send_handshake` is the daemon-side primitive the child arm uses; helper
// binaries need it to stand in for a (correct or deliberately wrong) daemon.
#[doc(hidden)]
pub use ipc::{rpc_server_from_inherited_fds, send_handshake, start_background_process_with_exe};

// Like `start_background_process_with_exe` but keeps the full handshake +
// failed-spawn cleanup, against an arbitrary helper binary. Exists
// only so `daemonizable-e2e-tests` can cover the cleanup contract that
// `spawn_daemon` promises (production always re-execs `/proc/self/exe`, which a
// libtest binary cannot stand in for). Gated off the stable surface.
#[cfg(any(test, feature = "testutils"))]
#[doc(hidden)]
pub use ipc::spawn_daemon_process_with_exe;
