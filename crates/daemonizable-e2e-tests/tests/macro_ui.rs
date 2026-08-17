//! Compile-time UI tests for the `#[daemonizable::main]` attribute.
//!
//! The fail cases compare rustc's stderr against checked-in snapshots, and
//! diagnostic rendering drifts across compiler releases. CI runs this suite
//! on stable, nightly AND the version-pinned MSRV toolchain (1.90), so the
//! fail cases must be pinned to a SINGLE toolchain — rustversion's bare
//! `stable` predicate matches the release *channel*, which the MSRV leg is
//! also on, and no one snapshot could satisfy a current stable and a frozen
//! 1.90 once their renderings diverge. The `since(1.91)` gate below therefore
//! runs the snapshots only on current stable (>= 1.91), never on the frozen
//! MSRV leg: snapshots are blessed on current stable (`TRYBUILD=overwrite`),
//! and only ever need re-blessing when a new stable changes rendering. Keep
//! the gate one minor above the workspace `rust-version` when bumping the
//! MSRV. The pass cases compare no diagnostics and run everywhere.

// The `crate = "..."` renamed-dependency pass case lives in the sibling
// `daemonizable-rename-test` crate instead: Cargo rejects one crate depending on
// the same package twice under different names.
#[test]
fn macro_expands_on_a_valid_impl() {
    let t = trybuild::TestCases::new();
    t.pass("tests/macro_ui/pass_minimal.rs");
}

#[rustversion::attr(not(all(stable, since(1.91))), ignore)]
#[test]
fn macro_rejects_invalid_attachments() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/macro_ui/fail_*.rs");
}
