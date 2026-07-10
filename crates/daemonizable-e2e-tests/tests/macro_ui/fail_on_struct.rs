//! Attaching the attribute to anything that isn't an impl block must produce
//! the macro's own diagnostic, not a confusing parser error.

#![allow(dead_code)]

#[daemonizable::main]
struct NotAnImpl;

fn main() {}
