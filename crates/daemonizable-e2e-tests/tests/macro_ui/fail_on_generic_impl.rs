//! Generic impls must be rejected with the macro's own diagnostic: the
//! generated `run::<App<T>>()` would have an unbound `T`, and the resulting
//! rustc error would point inside macro-generated code instead of here.

#![allow(dead_code)]

use std::marker::PhantomData;
use std::process::ExitCode;

use daemonizable::{Daemonizable, Daemonizer, RpcServer};

struct App<T>(PhantomData<T>);

#[daemonizable::main]
impl<T: 'static> Daemonizable for App<T> {
    type Request = ();
    type Response = ();

    fn build_id() -> String {
        "fail-generic 1.0.0".to_string()
    }

    fn run_foreground(_daemonizer: Daemonizer<Self>) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn run_daemon(_rpc: RpcServer<(), ()>) -> ! {
        std::process::exit(0)
    }
}

fn main() {}
