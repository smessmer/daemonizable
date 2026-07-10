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
