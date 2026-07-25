//! A renamed dependency (`dz = { package = "daemonizable", ... }` — see this
//! crate's Cargo.toml for why it needs its own crate) must work when the
//! attribute is told the new name via its one supported argument:
//! `#[dz::main(crate = "dz")]` substitutes `dz::run` for the default
//! `::daemonizable::run` in the generated `main`. Compiling this binary is
//! the regression test; running it just dispatches to `run_foreground` (no
//! framework channel token on fd 3) and exits 0.

use std::process::ExitCode;

use dz::{Daemonizable, Daemonizer, RpcServer};

struct App;

#[dz::main(crate = "dz")]
impl Daemonizable for App {
    type Request = ();
    type Response = ();

    fn build_id() -> String {
        "rename-test 1.0.0".to_string()
    }

    fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn run_daemon(_rpc: RpcServer<(), ()>) -> ! {
        std::process::exit(0)
    }
}
