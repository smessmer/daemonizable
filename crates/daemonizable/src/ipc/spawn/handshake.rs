//! The build-id handshake exchanged before any typed RPC: the daemon child
//! sends its build id ([`send_handshake`]); the parent validates it against
//! what it expected and refuses the spawn on mismatch
//! ([`validate_handshake_and_build_client`]).

use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

use crate::ipc::error::{ChannelSendError, HandshakeError};
use crate::ipc::{RpcClient, RpcServer};

/// How long the spawning parent will wait for the daemon to send its
/// build-id handshake after fork+exec. The daemon handshakes before any app
/// code runs, but the window now spans the *whole two-stage startup*: two
/// full exec + dynamic-loader passes (stage 1, then the final daemon image),
/// two runs of any pre-main constructors the application links, plus the
/// stages' few syscalls (the token peek/consume, `setsid`, the second `fork`,
/// the stage-2 peer-credential check and fd claim, `chdir`).
/// Tens of milliseconds on a cold cache, low single-digit milliseconds warm;
/// the generous bound is for loaded CI machines and apps with heavy
/// constructors (which pay their cost twice inside this window). The timeout
/// also matters when the parent accidentally exec'd a wrong binary that
/// opens the channel fd but never writes (or hangs); without a bound the spawn
/// would hang forever in that case.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Parent-side counterpart to [`send_handshake`]: read the build-id the
/// daemon sent and reject the spawn if it doesn't match
/// `expected_build_id`. Returns the client unchanged on match.
///
/// Must run before any postcard-typed RPC: a mismatch would otherwise let
/// the parent deserialize structured data from a daemon whose
/// Request/Response schemas may not agree.
pub(super) fn validate_handshake_and_build_client<Request, Response>(
    mut client: RpcClient<Request, Response>,
    expected_build_id: &str,
) -> Result<RpcClient<Request, Response>, HandshakeError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    let received = client
        .recv_raw_handshake_with_timeout(HANDSHAKE_TIMEOUT)
        .map_err(HandshakeError::Recv)?;
    let received_str = std::str::from_utf8(&received).map_err(HandshakeError::InvalidUtf8)?;
    if received_str != expected_build_id {
        return Err(HandshakeError::Mismatch {
            expected: expected_build_id.to_string(),
            received: received_str.to_string(),
        });
    }
    Ok(client)
}

/// Daemon-side counterpart to `validate_handshake_and_build_client`: send
/// `build_id` to the parent so the parent can confirm it exec'd the binary
/// it intended to. Must be called before any postcard-typed RPC on `server`.
pub fn send_handshake<Request, Response>(
    server: &mut RpcServer<Request, Response>,
    build_id: &str,
) -> Result<(), ChannelSendError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    server.send_raw_handshake(build_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ChannelRecvError, RpcConnection};
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize)]
    struct Req(u32);
    #[derive(Debug, Serialize, Deserialize)]
    struct Resp(u32);

    /// Stand-in for a real binary's build id. The handshake just compares
    /// bytes; the framework doesn't care what string the application
    /// supplies as long as it's deterministic across the parent/child pair.
    const TEST_BUILD_ID: &str = "test-build-id-1.2.3";

    #[test]
    fn accepts_matching_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        send_handshake(&mut server, TEST_BUILD_ID).unwrap();
        validate_handshake_and_build_client(client, TEST_BUILD_ID).expect("matching build_id");
    }

    #[test]
    fn rejects_mismatched_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        send_handshake(&mut server, "some-other-version-1.2.3").unwrap();
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("mismatched build_id should be rejected");
        match err {
            HandshakeError::Mismatch { expected, received } => {
                assert_eq!(TEST_BUILD_ID, expected);
                assert_eq!("some-other-version-1.2.3", received);
            }
            other => panic!("expected Mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_utf8_build_id() {
        let (mut server, client) = RpcConnection::<Req, Resp>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        // 0xff is never valid as a leading UTF-8 byte.
        server.send_raw_handshake(&[0xff, 0xfe]).unwrap();
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("non-UTF-8 should be rejected");
        assert!(
            matches!(err, HandshakeError::InvalidUtf8(_)),
            "expected InvalidUtf8, got: {err:?}",
        );
    }

    #[test]
    fn rejects_when_daemon_closes_before_handshake() {
        // Daemon dies (or was a non-application binary that just exited)
        // before writing the handshake. Parent's `recv_raw_timeout` sees
        // EOF and bails — must surface as an error rather than hang.
        let (server, client) = RpcConnection::<Req, Resp>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        drop(server);
        let err = validate_handshake_and_build_client(client, TEST_BUILD_ID)
            .err()
            .expect("missing handshake should be rejected");
        assert!(
            matches!(err, HandshakeError::Recv(ChannelRecvError::SenderClosed)),
            "expected Recv(SenderClosed), got: {err:?}",
        );
    }

    #[test]
    fn rejects_when_daemon_hangs_without_sending() {
        // Daemon (or a wrong binary like a hung `/bin/cat`) holds the channel
        // fd open but never writes. Without a timeout the parent would hang forever;
        // bounded `recv_raw_handshake_with_timeout` surfaces a timeout error
        // instead. Tiny timeout so the test doesn't actually wait 10s.
        let (_server_keepalive, mut client) = RpcConnection::<Req, Resp>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        let err = client
            .recv_raw_handshake_with_timeout(Duration::from_millis(50))
            .expect_err("hung daemon should be rejected via timeout");
        assert!(
            matches!(err, ChannelRecvError::Timeout),
            "expected Timeout, got: {err:?}",
        );
    }
}
