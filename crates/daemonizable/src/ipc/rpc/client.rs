//! [`RpcClient`]: the parent-side endpoint. Sends typed requests to the daemon
//! and receives typed responses, plus the out-of-band framework frames
//! (build-id handshake, bootstrap) that precede typed RPC.

use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

use crate::ipc::error::{BootstrapAckError, PipeRecvError, PipeSendError};
use crate::ipc::pipe::{Receiver, Sender};

pub struct RpcClient<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    sender: Sender<Request>,
    receiver: Receiver<Response>,
}

impl<Request, Response> RpcClient<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    pub(super) fn new(sender: Sender<Request>, receiver: Receiver<Response>) -> Self {
        Self { sender, receiver }
    }

    pub fn send_request(&mut self, request: &Request) -> Result<(), PipeSendError> {
        self.sender.send(request)
    }

    // TODO After a `Timeout` (or `MessageTooLarge`) error the underlying
    //   stream may be desynchronized and this client must currently be
    //   abandoned, but nothing enforces or documents that — see the
    //   desync TODO on `Receiver::recv_timeout` in ipc/pipe/receiver.rs for the full
    //   analysis and the preferred poisoning fix.
    pub fn recv_response(&mut self, timeout: Duration) -> Result<Response, PipeRecvError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Block until a response arrives or the daemon closes its end of the pipe.
    ///
    /// Unlike [`recv_response`](Self::recv_response), this has no timeout: it is
    /// for waiting on an operation of genuinely unbounded duration (e.g. a
    /// mount of a large vault on slow storage), where a fixed deadline would
    /// spuriously fail a slow-but-healthy daemon. Liveness still holds — if the
    /// daemon dies, its send end closes and this returns
    /// [`PipeRecvError::SenderClosed`] immediately rather than hanging. A
    /// daemon that is alive but wedged will block the caller; the caller stays
    /// interruptible via signals.
    pub fn recv_response_blocking(&mut self) -> Result<Response, PipeRecvError> {
        self.receiver.recv()
    }

    /// Receive the build-id handshake from the daemon, bounded by `timeout`.
    /// Must be the very first read on this client, before any postcard-typed
    /// RPC. Bypasses postcard so the parent never deserializes structured
    /// data from a daemon it hasn't yet validated.
    ///
    /// Direction note: see [`RpcServer::send_raw_handshake`] for why the
    /// handshake is daemon→parent. Timeout is the parent's safety net for a
    /// child binary that hangs without writing — bare `recv_raw` would block
    /// forever in that case.
    ///
    /// [`RpcServer::send_raw_handshake`]: super::RpcServer::send_raw_handshake
    pub(crate) fn recv_raw_handshake_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, PipeRecvError> {
        self.receiver.recv_raw_timeout(timeout)
    }

    /// Send the framework's bootstrap message — raw length-prefixed bytes
    /// (typically postcard-encoded by the caller). Runs after the build-id
    /// handshake is validated and before any typed RPC; the typed channel
    /// stays clean.
    pub(crate) fn send_raw_bootstrap(&mut self, bytes: &[u8]) -> Result<(), PipeSendError> {
        self.sender.send_raw(bytes)
    }

    /// Receive the daemon's empty-payload ack for the bootstrap, bounded by
    /// `timeout`. Returns Ok on a zero-length payload, errors otherwise
    /// (timeout, EOF, or a non-empty payload — all of which mean the daemon
    /// didn't acknowledge bootstrap successfully).
    pub(crate) fn recv_raw_bootstrap_ack_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<(), BootstrapAckError> {
        let bytes = self.receiver.recv_raw_timeout(timeout)?;
        if !bytes.is_empty() {
            return Err(BootstrapAckError::NonEmptyAck { len: bytes.len() });
        }
        Ok(())
    }
}
