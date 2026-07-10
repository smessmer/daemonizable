//! Compile-time UI tests for the `#[daemonizable::main]` attribute.
//!
//! The fail cases compare rustc's stderr against checked-in snapshots, and
//! diagnostic rendering drifts across compiler releases. CI runs this suite
//! on stable, nightly AND the MSRV toolchain, so the fail cases are pinned
//! to stable (rustversion-gated); no single snapshot could satisfy all
//! three. The pass case compares no diagnostics and runs everywhere.

#[test]
fn macro_expands_on_a_valid_impl() {
    let t = trybuild::TestCases::new();
    t.pass("tests/macro_ui/pass_minimal.rs");
}

// TODO `not(stable)` does not actually pin these to ONE toolchain:
//   rustversion's `stable` predicate matches the release CHANNEL, and the CI
//   test matrix runs toolchains ["stable", "nightly", "1.95"] — 1.95 is a
//   stable-channel release, so the compile_fail snapshots currently have to
//   satisfy BOTH current stable and the pinned 1.95 MSRV leg. The first
//   post-1.95 stable release that changes the diagnostic rendering observed
//   by these snapshots makes CI unfixably red (no snapshot can satisfy both
//   legs). Fix: gate to a single version, e.g.
//   `#[rustversion::attr(not(all(stable, since(1.96))), ignore)]` (runs only
//   on stable >= 1.96, never on the version-frozen MSRV leg) or
//   `#[rustversion::attr(not(stable(1.95)), ignore)]` (bless snapshots on
//   the MSRV toolchain and bump the pin together with rust-version in the
//   workspace Cargo.toml); then update the doc comment above to say which
//   toolchain the snapshots are blessed on.
#[rustversion::attr(not(stable), ignore)]
#[test]
fn macro_rejects_invalid_attachments() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/macro_ui/fail_*.rs");
}
