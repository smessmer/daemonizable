# daemonizable

Run your CLI application as a foreground process or have it fork+exec itself
into a background daemon — with a typed RPC channel between the spawning
parent and the daemon.

The library is deliberately policy-free: it handles only the process
mechanics and imposes no argument parser, logging framework, panic hook, or
startup banner on your application.

## What it does

- **Daemon-child dispatch** via an environment marker (no argv flag — your
  CLI surface stays entirely yours; the daemon child's argv is just
  `[argv0]`).
- **fork+exec re-exec** of the current binary (`/proc/self/exe` on Linux, so
  the daemon runs the exact same inode as the parent even if the binary on
  disk was replaced mid-run).
- **Build-id handshake**: the daemon proves it's the binary the parent meant
  to spawn before either side deserializes anything typed.
- **Bootstrap payload**: one app-defined `serde` value shipped from parent to
  daemon before the RPC phase (typical use: logging configuration — the
  daemon child can't learn it from argv).
- **Typed RPC**: `RpcClient<Request, Response>` / `RpcServer<Request,
  Response>` over pipes, postcard-encoded, with EOF-based liveness (a dead
  peer is an error, not a hang).
- **Daemon hygiene**: `setsid`, `chdir("/")`, single-claim guard on the
  inherited fds, `detach_stdio()` for when your daemon is ready to let go of
  the terminal.

## Example

```rust,no_run
use std::process::ExitCode;

use daemonizable::{Daemonizable, Daemonizer, RpcServer};

struct MyApp;

impl Daemonizable for MyApp {
    type Request = String;
    type Response = String;
    type BootstrapPayload = ();

    fn build_id() -> String {
        format!("my-app {}", env!("CARGO_PKG_VERSION"))
    }

    fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
        // This is your `main`: parse arguments however you like, then
        // daemonize whenever (and only if) you decide to.
        let mut rpc = daemonizer.spawn_daemon(&()).unwrap();
        rpc.send_request(&"hello".to_string()).unwrap();
        println!("daemon says: {}", rpc.recv_response_blocking().unwrap());
        ExitCode::SUCCESS
    }

    fn run_daemon(_payload: (), mut rpc: RpcServer<String, String>) -> ! {
        // Runs in the re-exec'd daemon child. Serve requests until the
        // parent drops its client (EOF), then exit.
        while let Ok(request) = rpc.next_request() {
            rpc.send_response(&format!("echo: {request}")).unwrap();
        }
        std::process::exit(0)
    }
}

fn main() -> ExitCode {
    daemonizable::run::<MyApp>()
}
```

With the default-on `macros` feature, `#[daemonizable::main]` on the impl
block generates that `main` for you.

## Why fork+exec? A comparison with the alternatives

Every other option in this space — the classic double-fork ritual, the
`daemon(3)` libc call, and the crates.io daemonizers (`daemonize`,
`daemon`, `daemonize-me`, `daemonize-simple`, `fork`,
`nix::unistd::daemon`) — shares two structural decisions that this library
deliberately rejects:

1. they daemonize by **fork *without* exec**, so the daemon lives out its
   entire life inside a copied snapshot of the parent's process image, and
2. they **cut the cord at fork time** — the parent exits (almost always
   with status 0) before the daemon has run a single line of real
   initialization, so daemon startup failures are invisible to whoever
   launched it.

Both are real, documented problems, not stylistic gripes.

### fork without exec: the daemon inherits a broken process image

`fork()` in a threaded process hands the child a frozen snapshot: every
other thread vanishes mid-step, but everything those threads were holding
— mutexes, allocator arenas, channel internals — is copied into the child
in its locked state, forever.
[POSIX is explicit](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html)
about this: the child contains "a replica of the calling thread and its
entire address space, possibly including the states of mutexes and other
resources", and consequently "may only execute async-signal-safe
operations until such time as one of the exec functions is called."
Rust's own [`CommandExt::pre_exec`](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec)
docs describe that post-fork world as "a very constrained environment
where normal operations like malloc, accessing environment variables
through `std::env` or acquiring a mutex are not guaranteed to work".

The rest of the ecosystem agrees. Tokio doesn't support `fork()` while a
runtime is running
([tokio#4301](https://github.com/tokio-rs/tokio/issues/4301), closed by
runtime documentation merged in
[tokio#8202](https://github.com/tokio-rs/tokio/pull/8202)). Go's standard
library has never offered a bare fork (only fork+exec via
`syscall.ForkExec` / `os/exec`). CPython 3.12+ raises a
`DeprecationWarning` from
[`os.fork()`](https://docs.python.org/3/library/os.html#os.fork) when it
detects threads, because "it has never been safe to mix threading with
`os.fork()` on POSIX platforms".

A fork-only daemonizer therefore bets your daemon's life on *nothing* in
the process having started a thread yet — not your code, not a lazy
static, not an allocator or telemetry background thread in any dependency
— and keeps paying that bet for the daemon's entire lifetime, because the
daemon *is* the forked image. The fork-based crates leave this assumption
implicit.

fork+exec is the escape hatch POSIX itself names: the async-signal-safe
restriction applies only *until the exec*. [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html)
resets the process image — all other threads are gone by construction
("mutexes, condition variables, and other pthreads objects are not
preserved"), caught signal dispositions revert to their defaults, the
memory image and allocator state are rebuilt from scratch, and only file
descriptors deliberately left inheritable survive. The re-exec'd daemon
can start tokio, spawn threads, and generally behave like the freshly
started process it actually is. State it needs from the parent arrives
explicitly — the typed bootstrap payload — instead of implicitly through
a memory snapshot.

(The symmetric honesty: `spawn_daemon` must still be called before the
*parent* starts its tokio runtime, because pipe creation and fd remapping
touch the same fork machinery. But that constraint covers a moment at
spawn time, not the daemon's whole life.)

### cutting the cord at fork time: nobody hears the daemon fail

The canonical description of SysV daemonization —
[`daemon(7)`](https://man7.org/linux/man-pages/man7/daemon.7.html)'s
15-step ritual — makes readiness reporting *mandatory*: the daemon must
"notify the original process started that initialization is complete"
via "an unnamed pipe or similar communication channel" (step 14), and the
invoker "must be able to rely on" the original process exiting only
"after initialization is complete and all external communication channels
are established" (step 15). Those are exactly the steps everyone skips:

- **`daemon(3)`** provides no channel at all: by the time it returns, the
  parent has already `_exit(0)`'d.
- **The `daemonize` crate** has the parent exit the instant the second
  fork succeeds. Pid-file locking (the "already running" check!), stdio
  redirection, privilege drop, and your entire daemon body all run *after*
  the CLI has already reported success, and their errors go to `/dev/null`
  by default. It's worse than that: `start()` passes the raw `waitpid`
  status (not `WEXITSTATUS`) to `exit()`, so even a first-child failure
  with code N becomes wait status `N << 8`, which truncates to exit
  code 0 — success. The fix
  ([PR #53](https://github.com/knsd/daemonize/pull/53)) has been open
  since May 2023.
- **An init system can't reconstruct readiness from the outside**:
  [`systemd.service(5)`](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
  says of `Type=forking` — the mode built for exactly these daemons —
  "The use of this type is discouraged, use notify, notify-reload, or
  dbus instead."

The pipe handshake that `daemon(7)` demands is what serious daemons end up
hand-rolling. nginx binds its listen sockets *before* daemonizing so
port-in-use errors still reach your terminal. libfuse — this library's
home turf, it was extracted from [CryFS](https://www.cryfs.org) — grew a
whole new API for it
([`fuse_daemonize_early_start` / `_success` / `_fail`](https://github.com/libfuse/libfuse))
so the mounting parent stays alive until the mount actually succeeded and
can report failure otherwise.

daemonizable builds that handshake in as the core primitive instead of an
afterthought. `spawn_daemon` blocks through the build-id handshake and the
bootstrap ack; a child that fails either is killed, reaped, and surfaced
as a typed error — your CLI prints a real message and exits non-zero. And
it doesn't stop at "started": the RPC channel stays open, so the parent
can wait for whatever *its* definition of ready is before exiting (CryFS
exits 0 only after the daemon reports the filesystem is actually mounted).
If the daemon dies instead of answering, the parent gets an EOF error
rather than a hang — provided the daemon hasn't leaked its inherited pipe
fds to a longer-lived subprocess of its own (they are not currently
re-marked close-on-exec after the daemon claims them; a known limitation
tracked in a TODO in `ipc/spawn/inherited.rs`).

### The crates, specifically

A point-in-time snapshot (July 2026) — versions and maintenance status
will drift, check crates.io for where things stand now:

| crate | mechanics | CLI sees daemon startup errors? | parent↔daemon channel | notes |
|---|---|---|---|---|
| `daemonize` 0.5.0 | double fork, no exec | no — parent exits 0 first, plus the raw-`waitpid` bug above | none (parent never even learns the daemon's pid) | last release 2023-02; GitHub issue tracker disabled; exit-code and soundness fixes unmerged since 2023/2024 |
| `daemon` 0.0.8 | none — despite the name it never forks or calls `setsid`; it's a signal-to-channel run loop + Windows service shim | n/a | n/a | last release 2018-09 |
| `daemonize-me` 2.0.2 | single fork + `setsid` | no | none | 2.0.2 (2025-03) came after a 3-year gap |
| `daemonize-simple` 0.1.6 | double fork | no | none | maintained; all errors are bare `&'static str` |
| `fork` 0.8.0 | double fork | no | none | actively maintained; note that 0.1.x–0.3.x closed fds 0–2 outright (fd-reuse hazard) and returned the intermediate session leader to the caller — fixed across 0.4.0–0.6.0 (Nov–Dec 2025) |
| `nix::unistd::daemon` / `libc::daemon` | `daemon(3)`: single fork | no | none | `nix`'s wrapper isn't even compiled on Apple targets; Apple has deprecated `daemon()` since macOS 10.5 ("Use posix_spawn APIs instead") |

On `daemon(3)` itself: it's a 4.4BSD invention that is in no standard
([`STANDARDS: None`](https://man7.org/linux/man-pages/man3/daemon.3.html)),
its own BUGS section admits it skips the double fork ("the resulting
daemon is a session leader"), and Apple deprecated it two decades ago.

To be fair to the fork-based crates: several carry battle-tested SysV
batteries this library doesn't have yet — locked pid files, setuid/
setgid privilege drop, chroot, umask control (planned as opt-in options;
see the TODO in the costs list below) — and their second fork means
the daemon is not a session leader (see the tradeoffs below). If you need
fire-and-forget backgrounding with those knobs, and you can guarantee the
fork happens before any thread exists, `fork` (the crate) is a reasonable
minimal choice. What none of them can do is tell you whether your daemon
actually came up.

### Why not a second binary?

The other conventional design is to ship a separate `myapp-daemon`
executable and `Command::spawn` it (the dockerd / ssh-agent shape). That
costs you two artifacts to build, package and install, a lookup problem
(absolute path? `$PATH`? relative to `argv[0]`?), and — worst — a version
skew problem: nothing stops CLI 1.4 from spawning a daemon 1.3 whose wire
format differs silently.

Re-exec'ing the current binary makes skew structurally impossible on
Linux: [`/proc/self/exe`](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
is a kernel magic link to the running image's inode, so the daemon is
byte-identical to the parent even if the on-disk binary was replaced by a
package upgrade mid-run, and the build-id handshake catches whatever the
platform can't guarantee (the macOS `current_exe()` fallback, operator
mistakes). This is well-trodden ground: Docker/Moby ships a dedicated
[`reexec` package](https://pkg.go.dev/github.com/moby/sys/reexec) whose
`Self()` returns the literal string `/proc/self/exe` ("safe to delete or
replace the on-disk binary"); [runc](https://github.com/opencontainers/runc)
re-execs itself as `runc init` with a bootstrap pipe fd passed through an
environment variable — env-marker plus inherited-fd, the same shape used
here; and `systemctl daemon-reexec` re-execs PID 1 itself.

### What this approach costs

An honest comparison cuts both ways. The price of fork+exec plus a typed
channel:

- **The binary must cooperate.** `run::<App>()` has to be the first thing
  in `main`; a wrapper-script entry point breaks re-exec. Fork-based
  crates work on any code with zero cooperation.
- **procfs.** On Linux the re-exec needs `/proc` mounted (bare chroots and
  minimal containers may not have it); other platforms fall back to
  `current_exe()` plus the handshake.
  *TODO: degrade gracefully instead of failing — when `/proc/self/exe`
  is unavailable, fall back to `getauxval(AT_EXECFN)` / `argv[0]`
  resolution (`current_exe()` is not a fallback on Linux; it reads
  `/proc/self/exe` itself). The fallback gives up the same-inode
  guarantee, but the build-id handshake already turns a swapped binary
  into a clean error rather than a wrong daemon.*
- **The daemon is a session leader.** There is no second fork, so — per
  [POSIX XBD 11.1.3](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap11.html)
  — a tty opened without `O_NOCTTY` could become its controlling terminal.
  Double-fork crates rule this out structurally; here the daemon must
  simply not open ttys carelessly.
  *TODO (planned; implementation TODOs sit at the `setsid()` call in
  `app/daemon_child.rs` and the failed-spawn cleanup in `ipc/spawn/process.rs`, and must land
  together): add the second fork. The daemon-child arm runs in a fresh
  single-threaded post-exec image, so it can safely fork once more right
  after `setsid()` and let the session-leader intermediate exit 0; the
  surviving grandchild can never acquire a controlling terminal. The
  parent's `Child` handle then points at the already-dead intermediate,
  so the failed-spawn cleanup must signal the process group instead —
  `kill(-child_pid)`, which stays race-free because `setsid()` made the
  intermediate's pid the group id and a pid is not recycled while it
  names a live process group (`ESRCH` fallback to `kill(child_pid)`
  covers deaths before `setsid`). The process contract flips too: the
  daemon is orphaned to init immediately instead of remaining a child of
  the spawner — which also removes the zombie caveat for long-lived
  parents. (A Linux-only variant could even keep direct parenthood via
  `clone3(CLONE_PARENT)`.)*
- **Spawn before tokio, still.** The parent-side restriction remains (see
  the process contract below) — it's just transient instead of permanent.
  *TODO: fixable on Linux. The restriction exists because the pipe fds
  get `FD_CLOEXEC` a moment after creation instead of atomically, so a
  concurrent fork on another thread can leak them; creating the pipes
  with `pipe2(O_CLOEXEC)` closes that window (tracked in a TODO in
  `lib.rs`), and migrating from `command-fds`' `pre_exec` to std's
  planned fd mappings
  ([rust#145687](https://github.com/rust-lang/rust/pull/145687)) removes
  the rest. macOS has no atomic equivalent and keeps the rule.*
- **No batteries (yet).** Pid files, privilege drop, chroot, umask,
  signal-mask reset, and log-file stdio redirection are currently the
  application's job.
  *TODO (planned): add these as opt-in options, applied in the daemon
  child between the handshake and the bootstrap ack, so that every
  failure — an "already running" pid-file lock conflict, a failed
  `setuid`, an unwritable log path — surfaces as a typed error in the
  parent and a non-zero CLI exit. That is exactly what the fork-based
  crates structurally cannot offer: they perform these same steps after
  their parent already exited 0, with errors going to `/dev/null`. The
  planned set, following `daemon(7)` and the `daemonize` feature list:
  an `flock`-locked pid file written with the final daemon pid (the
  kernel drops the lock on process death, so stale pid files are
  harmless; the lock can even be taken in the parent before spawning —
  `flock` belongs to the open file description, which the daemon inherits
  across the exec — so "already running" fails before a child is ever
  spawned), `initgroups`/`setgid`/`setuid` privilege drop, optional
  `chroot`, explicit `umask` (currently silently inherited — it survives
  `execve`), signal-mask reset (the mask, unlike handlers, also survives
  `execve`), fd hygiene for non-CLOEXEC fds inherited from the CLI's own
  environment (`close_range(5, ~0)` on Linux, sparing the pipe fds 3/4),
  and `detach_stdio` gaining redirect-to-log-file targets (log files
  opened before the privilege drop, so root-owned log directories work).
  Defaults stay policy-free: every battery is opt-in.*
- **Initialization runs twice.** The daemon re-runs the dynamic loader and
  everything before `run` (with `#[daemonizable::main]`, that's nothing);
  parent state must be shipped explicitly via the bootstrap payload.
- **If systemd manages your process, don't daemonize at all.**
  `daemon(7)`'s "new-style daemons" doctrine is that services should run
  in the foreground and report readiness via `sd_notify(3)`; SysV-style
  self-daemonization "interfere[s] with process monitoring, file
  descriptor passing, and other functionality of the service manager".
  That applies to this library too. daemonizable is for processes a *user*
  launches — mount helpers, agents started from a shell — which is exactly
  the niche it was extracted from.

That's the design in one sentence: fork+exec buys the daemon a clean
process image, and the typed channel turns daemonization from a leap of
faith into an operation that can fail loudly.

## Process contract

- There is **no double-fork**: a successfully spawned daemon remains a child
  of the spawning process. If the parent exits promptly (the typical CLI
  pattern), the daemon is reparented to init; a long-lived parent will see a
  zombie once the daemon exits (reap it, or accept it).
- A **failed** spawn (handshake mismatch, bootstrap failure) is killed and
  reaped by `spawn_daemon` itself before the error is returned.
- `spawn_daemon` must be called **before** starting a tokio runtime (it
  panics otherwise; fork and threads don't mix — see
  [tokio#4301](https://github.com/tokio-rs/tokio/issues/4301)).

## Features

- `macros` *(default)*: re-exports `#[daemonizable::main]` from the
  `daemonizable-macros` companion crate.
- `testutils`: test-only helpers (e.g. `RpcConnection::into_server_and_client`)
  so downstream crates can drive the IPC primitives in their own unit tests.
  Not part of the stable surface.

Unix-only (Linux is the primary target; macOS works with caveats documented
in the source).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
