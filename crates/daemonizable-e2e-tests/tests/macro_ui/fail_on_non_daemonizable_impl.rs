//! Attaching the attribute to an impl of some other trait must be rejected
//! (the trait path has to end in the segment `Daemonizable`).

#![allow(dead_code)]

trait SomeOtherTrait {}

struct App;

#[daemonizable::main]
impl SomeOtherTrait for App {}

fn main() {}
