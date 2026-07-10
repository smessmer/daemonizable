//! The attribute on a minimal valid impl must expand to the impl plus a
//! working `fn main` (trybuild also runs the produced binary; with no
//! daemon-child marker set it dispatches to `run_foreground` and exits 0).

use std::process::ExitCode;

use daemonizable::{Daemonizable, Daemonizer, RpcServer};

struct App;

#[daemonizable::main]
impl Daemonizable for App {
    type Request = ();
    type Response = ();
    type BootstrapPayload = ();

    fn build_id() -> String {
        "pass-minimal 1.0.0".to_string()
    }

    fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn run_daemon(_payload: (), _rpc: RpcServer<(), ()>) -> ! {
        std::process::exit(0)
    }
}
