//! [`RpcServer`]: the daemon-side endpoint. Receives typed requests from the
//! parent and sends typed responses back, plus the out-of-band framework
//! frames (build-id handshake, bootstrap) that precede typed RPC.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

use crate::ipc::error::{PipeRecvError, PipeSendError};
use crate::ipc::pipe::{Receiver, Sender};

pub struct RpcServer<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    sender: Sender<Response>,
    receiver: Receiver<Request>,
}

impl<Request, Response> RpcServer<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    pub(super) fn new(sender: Sender<Response>, receiver: Receiver<Request>) -> Self {
        Self { sender, receiver }
    }

    /// Reconstruct an `RpcServer` from inherited raw file descriptors. The
    /// fork+exec daemon child receives its pipe ends as fds 3 (request-recv)
    /// and 4 (response-send) and calls this to rebuild its typed RPC handle.
    ///
    /// # Safety
    /// `in_fd` must be the read end of a pipe whose write end is held by the
    /// parent's `RpcClient`. `out_fd` must be the corresponding write end.
    /// Both fds must be owned (not shared) — calling this twice on the same
    /// fd numbers is a use-after-free.
    pub unsafe fn from_raw_fds(in_fd: RawFd, out_fd: RawFd) -> Self {
        let receiver = unsafe { Receiver::from_owned_fd(OwnedFd::from_raw_fd(in_fd)) };
        let sender = unsafe { Sender::from_owned_fd(OwnedFd::from_raw_fd(out_fd)) };
        Self::new(sender, receiver)
    }

    /// Receive the next request from the parent. Blocks until a request
    /// arrives; returns [`PipeRecvError::SenderClosed`] once the parent drops
    /// its client — the daemon's signal to shut down its request loop.
    pub fn next_request(&mut self) -> Result<Request, PipeRecvError> {
        self.receiver.recv()
    }

    pub fn send_response(&mut self, response: &Response) -> Result<(), PipeSendError> {
        self.sender.send(response)
    }

    /// Send the build-id handshake to the parent. Must be the very first write
    /// on this server, before any postcard-typed RPC. Bypasses postcard so the
    /// parent can validate the daemon binary identity before either side
    /// deserializes anything typed.
    ///
    /// Direction note: the handshake is daemon→parent (not parent→daemon) so
    /// that a parent which accidentally exec'd a non-application binary
    /// surfaces the mistake — a non-application child won't write the
    /// expected bytes (or any bytes), and the parent's matching
    /// [`RpcClient::recv_raw_handshake_with_timeout`] detects this via EOF /
    /// garbage / timeout.
    ///
    /// [`RpcClient::recv_raw_handshake_with_timeout`]: super::RpcClient::recv_raw_handshake_with_timeout
    pub(crate) fn send_raw_handshake(&mut self, bytes: &[u8]) -> Result<(), PipeSendError> {
        self.sender.send_raw(bytes)
    }

    /// Receive the framework's bootstrap message — raw length-prefixed bytes
    /// (typically postcard-encoded by the caller of `send_raw_bootstrap` on
    /// the parent side). Runs after the build-id handshake and before any
    /// typed RPC; the typed channel is left untouched.
    pub(crate) fn recv_raw_bootstrap_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, PipeRecvError> {
        self.receiver.recv_raw_timeout(timeout)
    }

    /// Ack the framework's bootstrap message. Empty-payload raw send — the
    /// parent's `recv_raw_bootstrap_ack_with_timeout` reads it as a marker
    /// that the daemon has applied the bootstrap and is ready for typed RPC.
    pub(crate) fn send_raw_bootstrap_ack(&mut self) -> Result<(), PipeSendError> {
        self.sender.send_raw(&[])
    }
}
