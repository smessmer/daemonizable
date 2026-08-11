# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - unreleased

### Added

- `in_process_rpc_pair::<Request, Response>()` (`testutils` feature): builds a
  connected `RpcServer`/`RpcClient` pair in one call, for downstream crates
  testing their own typed request/response wiring against the real socketpair
  and the real postcard framing.

### Removed

- **Breaking (`testutils` feature only):** `RpcConnection` is no longer exported
  from the crate root, and with it the `new_channel` + `into_server_and_client`
  sequence that was the previous way to build a test pair. That type is the
  fork+exec path's intermediate — it exists so the parent can keep the client
  and surrender the child's raw fd — and nothing outside this crate should have
  to name it.

  Migration:

  ```rust
  // before
  let (server, client) = RpcConnection::<Req, Resp>::new_channel()?
      .into_server_and_client()?;
  // after
  let (server, client) = in_process_rpc_pair::<Req, Resp>()?;
  ```

  The stable (non-`testutils`) API is unchanged; this affects only crates that
  opted into `testutils`.

## Earlier releases

0.1.0 (2026-08-10) and the 0.0.x series predate this file; see the git history
and the release tags for what changed in them.
