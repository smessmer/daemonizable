use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

use super::error::{BootstrapAckError, PipeCreateError, PipeRecvError, PipeSendError};
use super::pipe::{Receiver, Sender, pipe};

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
    pub fn into_client_and_child_fds(self) -> (RpcClient<Request, Response>, OwnedFd, OwnedFd) {
        let client = RpcClient {
            sender: self.request_sender,
            receiver: self.response_receiver,
        };
        let child_request_recv = self.request_receiver.into_owned_fd();
        let child_response_send = self.response_sender.into_owned_fd();
        (client, child_request_recv, child_response_send)
    }

    #[cfg(any(test, feature = "testutils"))]
    pub fn into_server_and_client(
        self,
    ) -> (RpcServer<Request, Response>, RpcClient<Request, Response>) {
        (
            RpcServer {
                sender: self.response_sender,
                receiver: self.request_receiver,
            },
            RpcClient {
                sender: self.request_sender,
                receiver: self.response_receiver,
            },
        )
    }
}

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
        Self { sender, receiver }
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
    pub fn send_request(&mut self, request: &Request) -> Result<(), PipeSendError> {
        self.sender.send(request)
    }

    // TODO After a `Timeout` (or `MessageTooLarge`) error the underlying
    //   stream may be desynchronized and this client must currently be
    //   abandoned, but nothing enforces or documents that — see the
    //   desync TODO on `Receiver::recv_timeout` in pipe.rs for the full
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn rpc() {
        #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
        struct Request {
            v: u32,
        }
        #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
        struct Response {
            v: u32,
        }

        let connection = RpcConnection::<Request, Response>::new_pipe().unwrap();
        let (mut server, mut client) = connection.into_server_and_client();

        client.send_request(&Request { v: 42 }).unwrap();
        assert_eq!(Request { v: 42 }, server.next_request().unwrap());

        server.send_response(&Response { v: 10 }).unwrap();
        assert_eq!(
            Response { v: 10 },
            client.recv_response(Duration::from_secs(2)).unwrap()
        );
    }

    #[test]
    fn recv_response_blocking_returns_the_response() {
        let (mut server, mut client) = RpcConnection::<u32, u32>::new_pipe()
            .unwrap()
            .into_server_and_client();

        let server = std::thread::spawn(move || {
            let req = server.next_request().unwrap();
            server.send_response(&(req + 1)).unwrap();
        });

        client.send_request(&41).unwrap();
        assert_eq!(42, client.recv_response_blocking().unwrap());
        server.join().unwrap();
    }

    #[test]
    fn recv_response_blocking_errors_when_the_daemon_drops_its_end() {
        // Liveness: if the daemon dies, its send end closes and the parent's
        // blocking receive returns an error immediately instead of hanging.
        let (server, mut client) = RpcConnection::<u32, u32>::new_pipe()
            .unwrap()
            .into_server_and_client();
        drop(server); // daemon "dies": closes the response pipe's write end

        let err = client
            .recv_response_blocking()
            .expect_err("a blocking receive must fail once the daemon's end is closed, not hang");
        assert!(
            matches!(err, PipeRecvError::SenderClosed),
            "expected SenderClosed (normalized blocking-path EOF), got: {err:?}"
        );
    }
}
