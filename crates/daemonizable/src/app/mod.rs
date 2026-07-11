//! The minimal, policy-free application API: the [`Daemonizable`] trait, the
//! [`Daemonizer`] capability token, and the [`run`] entry point.
//!
//! This API makes no policy decisions at all. The library only handles the
//! process mechanics: detecting whether this invocation *is* the re-exec'd
//! daemon child (via an environment-variable marker — no argv flag, so apps
//! aren't forced onto any particular argument parser), the fork+exec spawn,
//! and the build-id handshake. Everything else — CLI parsing, logging, panic
//! hooks, banners — is the application's business, inside
//! [`Daemonizable::run_foreground`] and [`Daemonizable::run_daemon`].
//!
//! The surface is split by responsibility:
//! - [`mod@daemonizable`] — the [`Daemonizable`] trait (the app contract).
//! - [`mod@daemonizer`] — the [`Daemonizer`] capability token and the
//!   `spawn_daemon` it grants.
//! - [`mod@run`] — the [`run`] entry point and its process-role dispatch.
//! - [`mod@daemon_child`] — the re-exec'd daemon child's startup sequence.

mod daemon_child;
mod daemonizable;
mod daemonizer;
mod run;

pub use daemonizable::Daemonizable;
pub use daemonizer::Daemonizer;
pub use run::run;
