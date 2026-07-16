//! [`RpcConnection`]: owns both IPC pipes and splits them into the typed
//! parent-side ([`RpcClient`]) and daemon-side ([`RpcServer`]) endpoints.

use std::os::fd::OwnedFd;

use serde::{Serialize, de::DeserializeOwned};

use super::RpcClient;
#[cfg(any(test, feature = "testutils"))]
use super::RpcServer;
use crate::ipc::error::PipeCreateError;
use crate::ipc::pipe::{Receiver, Sender, pipe};

pub struct RpcConnection<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    request_sender: Sender<Request>,
    request_receiver: Receiver<Request>,
    response_sender: Sender<Response>,
    response_receiver: Receiver<Response>,
}

impl<Request, Response> RpcConnection<Request, Response>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned + Send,
{
    pub fn new_pipe() -> Result<Self, PipeCreateError> {
        let (request_sender, request_receiver) = pipe::<Request>()?;
        let (response_sender, response_receiver) = pipe::<Response>()?;
        Ok(Self {
            request_sender,
            request_receiver,
            response_sender,
            response_receiver,
        })
    }

    /// Split for fork+exec: keep the parent-side `RpcClient` and surrender
    /// the two child-side raw file descriptors. The caller is expected to
    /// `dup2` the returned fds onto `CHILD_REQUEST_RECV_FD` and
    /// `CHILD_RESPONSE_SEND_FD` (3 and 4) in a `pre_exec` closure, then drop
    /// the originals after `Command::spawn` returns.
    ///
    /// Crate-internal: this is the parent-side fork+exec plumbing, used only by
    /// the spawn machinery. The `testutils` in-process path uses
    /// `into_server_and_client` instead, so this stays off even the `testutils`
    /// surface.
    pub(crate) fn into_client_and_child_fds(
        self,
    ) -> (RpcClient<Request, Response>, OwnedFd, OwnedFd) {
        let client = RpcClient::new(self.request_sender, self.response_receiver);
        let child_request_recv = self.request_receiver.into_owned_fd();
        let child_response_send = self.response_sender.into_owned_fd();
        (client, child_request_recv, child_response_send)
    }

    #[cfg(any(test, feature = "testutils"))]
    pub fn into_server_and_client(
        self,
    ) -> (RpcServer<Request, Response>, RpcClient<Request, Response>) {
        (
            RpcServer::new(self.response_sender, self.request_receiver),
            RpcClient::new(self.request_sender, self.response_receiver),
        )
    }
}
