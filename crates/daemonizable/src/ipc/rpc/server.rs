//! [`RpcServer`]: the daemon-side endpoint. Receives typed requests from the
//! parent and sends typed responses back, plus the out-of-band build-id
//! handshake that precedes typed RPC.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};

use crate::ipc::error::{InheritedFdsError, PipeRecvError, PipeSendError};
use crate::ipc::pipe::{Receiver, Sender, endpoint_from_stream};

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

    /// Reconstruct an `RpcServer` from the daemon's single inherited channel
    /// fd, already adopted into an owning [`OwnedFd`]. The fork+exec daemon child
    /// receives its full-duplex channel as fd 3 (`DAEMON_CHANNEL_FD`);
    /// `rpc_server_from_inherited_fds` validates and takes ownership of it (the
    /// one raw-fd `unsafe`), then hands the `OwnedFd` here.
    ///
    /// Splits the one socket into the server's send/recv halves via
    /// [`endpoint_from_stream`] (an internal `dup`), so the daemon can serve a
    /// response while awaiting the next request. The `dup` can fail
    /// (EMFILE/ENFILE) → [`InheritedFdsError::CloneFd`]; on that error the
    /// adopted fd is closed as the `OwnedFd` drops.
    ///
    /// Crate-internal: the daemon child never constructs its own `RpcServer`
    /// (it receives one, already built, in `Daemonizable::run_daemon`). This
    /// constructor exists only for the one internal caller
    /// `rpc_server_from_inherited_fds`, so it stays off the public API rather
    /// than exposing an fd-adopting constructor on a type every daemon app holds.
    pub(crate) fn from_owned_fd(fd: OwnedFd) -> Result<Self, InheritedFdsError> {
        Self::from_stream(UnixStream::from(fd))
            .map_err(|source| InheritedFdsError::CloneFd { source })
    }

    /// Build a server from one full-duplex socket endpoint, cloning it into the
    /// send/recv halves. Shared by [`from_owned_fd`](Self::from_owned_fd) (the
    /// fork+exec claim) and the in-process `RpcConnection::into_server_and_client`.
    pub(crate) fn from_stream(stream: UnixStream) -> std::io::Result<Self> {
        // The server SENDS `Response` and RECEIVES `Request` over the shared fd.
        let (sender, receiver) = endpoint_from_stream::<Response, Request>(stream)?;
        Ok(Self::new(sender, receiver))
    }

    /// Receive the next request from the parent. Blocks until a request
    /// arrives; returns [`PipeRecvError::SenderClosed`] once the parent drops
    /// its client — the daemon's signal to shut down its request loop.
    ///
    /// A parent frame that exceeds the wire-format cap returns
    /// [`PipeRecvError::MessageTooLarge`] and desynchronizes the stream; every
    /// later call then returns [`PipeRecvError::Desynchronized`]. Both are
    /// terminal — the daemon should exit its loop, just as it does on
    /// `SenderClosed`.
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
}
