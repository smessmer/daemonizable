//! [`RpcConnection`]: owns one full-duplex channel and splits it into the typed
//! parent-side ([`RpcClient`]) and daemon-side ([`RpcServer`]) endpoints.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};

use super::RpcClient;
#[cfg(any(test, feature = "testutils"))]
use super::RpcServer;
use crate::ipc::channel::{Receiver, Sender, endpoint_from_stream};
use crate::ipc::error::ChannelCreateError;

pub struct RpcConnection<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    /// The parent/client endpoint, pre-split into its two typed halves. Both
    /// halves are `dup`-clones of one end of the socketpair, so the client can
    /// send a request while concurrently awaiting a response.
    client_sender: Sender<Request>,
    client_receiver: Receiver<Response>,
    /// The child/server end of the same socketpair, still one raw socket. It is
    /// either handed to the fork+exec child as a single fd
    /// ([`into_client_and_child_fd`](Self::into_client_and_child_fd)) or turned
    /// into an in-process server
    /// ([`into_server_and_client`](Self::into_server_and_client)).
    child_end: UnixStream,
}

impl<Request, Response> RpcConnection<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    pub fn new_channel() -> Result<Self, ChannelCreateError> {
        // One full-duplex socketpair: the parent keeps one end (split into the
        // client's send/recv halves), the child gets the other.
        let (parent_end, child_end) =
            UnixStream::pair().map_err(ChannelCreateError::CreateSocket)?;
        let (client_sender, client_receiver) =
            endpoint_from_stream(parent_end).map_err(ChannelCreateError::CreateSocket)?;
        Ok(Self {
            client_sender,
            client_receiver,
            child_end,
        })
    }

    /// Split for fork+exec: keep the parent-side `RpcClient` and surrender the
    /// single child-side raw file descriptor. The caller `dup2`s the returned
    /// fd onto `DAEMON_CHANNEL_FD` (3) in a `pre_exec` closure, then drops the
    /// original after `Command::spawn` returns.
    ///
    /// Crate-internal: this is the parent-side fork+exec plumbing, used only by
    /// the spawn machinery. The `testutils` in-process path uses
    /// `into_server_and_client` instead, so this stays off even the `testutils`
    /// surface.
    pub(crate) fn into_client_and_child_fd(self) -> (RpcClient<Request, Response>, OwnedFd) {
        let client = RpcClient::new(self.client_sender, self.client_receiver);
        (client, OwnedFd::from(self.child_end))
    }

    // The Result-of-tuple return is inherent (both endpoints, or a clone
    // failure); a type alias for a single testutils constructor would obscure
    // more than it clarifies.
    #[allow(clippy::type_complexity)]
    #[cfg(any(test, feature = "testutils"))]
    pub fn into_server_and_client(
        self,
    ) -> Result<(RpcServer<Request, Response>, RpcClient<Request, Response>), ChannelCreateError>
    {
        // The in-process server clones the child end internally; a `dup` failure
        // surfaces as a channel-creation error, same class as `new_channel`'s.
        let server =
            RpcServer::from_stream(self.child_end).map_err(ChannelCreateError::CreateSocket)?;
        let client = RpcClient::new(self.client_sender, self.client_receiver);
        Ok((server, client))
    }
}
