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

    /// Receive one response, bounded by `timeout`.
    ///
    /// If a `Timeout` fires mid-frame (or a `MessageTooLarge` leaves an unread
    /// payload on the wire), the underlying receiver is poisoned: this and every
    /// later `recv_response` return [`PipeRecvError::Desynchronized`], so a
    /// desynced stream surfaces as a loud typed error instead of silently
    /// misframed data. A clean idle timeout does not poison, so poll-with-short-
    /// timeout loops on an idle channel keep working.
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
    ///
    /// A daemon response that exceeds the wire-format cap returns
    /// [`PipeRecvError::MessageTooLarge`] and poisons the receiver; every later
    /// receive (here or via [`recv_response`](Self::recv_response)) then returns
    /// [`PipeRecvError::Desynchronized`]. Both are terminal — abandon the client.
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
    /// (typically postcard-encoded by the caller), bounded by `timeout`. Runs
    /// after the build-id handshake is validated and before any typed RPC; the
    /// typed channel stays clean.
    ///
    /// The timeout is the parent's safety net for a child that passed the
    /// handshake and then wedged without draining the pipe: without it, a
    /// payload larger than the kernel pipe buffer would block `spawn_daemon`
    /// forever and its failure cleanup would never run.
    pub(crate) fn send_raw_bootstrap_with_timeout(
        &mut self,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), PipeSendError> {
        self.sender.send_raw_with_timeout(bytes, timeout)
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
