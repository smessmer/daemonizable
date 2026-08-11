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

// Direction-correct bounds: this type owns the PARENT/client side pre-split
// (`Sender<Request>` + `Receiver<Response>`), so it needs exactly the client's
// bounds. The child end is a raw socket with no typed obligations until it is
// turned into a server — `into_server_and_client` adds the server-side bounds
// on that method alone.
pub struct RpcConnection<Request, Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
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

impl<Request, Response> std::fmt::Debug for RpcConnection<Request, Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    // Manual impl (like `Daemonizer`'s) so no `Debug` bounds leak into the API.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcConnection")
            .field("client_sender", &self.client_sender)
            .field("client_receiver", &self.client_receiver)
            .field("child_end", &self.child_end)
            .finish()
    }
}

/// Set `SO_NOSIGPIPE` on `socket` (Apple targets only — the option does not
/// exist on Linux, where `MSG_NOSIGNAL` on the writes covers the same need).
/// nix has no wrapper for this option, hence raw libc.
#[cfg(target_vendor = "apple")]
fn set_nosigpipe(socket: &UnixStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let one: libc::c_int = 1;
    // SAFETY: `setsockopt` reads exactly `optlen` bytes from `optval`; here
    // that is size_of::<c_int>() bytes of `one`, a live, correctly aligned
    // c_int on this frame. The fd is borrowed from a live `UnixStream` (not
    // closed or retained by the call), SOL_SOCKET/SO_NOSIGPIPE is a plain
    // int-valued option, and no pointer outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&raw const one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl<Request, Response> RpcConnection<Request, Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    pub fn new_channel() -> Result<Self, ChannelCreateError> {
        // One full-duplex socketpair: the parent keeps one end (split into the
        // client's send/recv halves), the child gets the other.
        let (parent_end, child_end) =
            UnixStream::pair().map_err(ChannelCreateError::CreateSocket)?;
        // Apple targets: set SO_NOSIGPIPE on both ends OURSELVES — std does
        // not for socketpairs, and Apple has no MSG_NOSIGNAL to put on the
        // writes instead. The option lives on the socket, so the daemon's
        // inherited fd-3 end and every `try_clone` dup share it. This is what
        // makes the dead-peer-send guarantee disposition-independent on Apple;
        // see the SIGPIPE note on `channel_pair` in `channel/mod.rs`.
        #[cfg(target_vendor = "apple")]
        for end in [&parent_end, &child_end] {
            set_nosigpipe(end).map_err(ChannelCreateError::CreateSocket)?;
        }
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
    /// `ipc`-internal: this is the parent-side fork+exec plumbing, used only by
    /// the spawn machinery. The `testutils` in-process path uses
    /// `into_server_and_client` instead, so this stays off even the `testutils`
    /// surface.
    pub(in crate::ipc) fn into_client_and_child_fd(
        self,
    ) -> (RpcClient<Request, Response>, OwnedFd) {
        let client = RpcClient::new(self.client_sender, self.client_receiver);
        (client, OwnedFd::from(self.child_end))
    }

    // The Result-of-tuple return is inherent (both endpoints, or a clone
    // failure); a type alias for a single testutils constructor would obscure
    // more than it clarifies. The extra bounds are the SERVER side's: this is
    // the one method that builds both endpoints in-process, so it is the one
    // place both directions of both types are needed.
    #[allow(clippy::type_complexity)]
    #[cfg(any(test, feature = "testutils"))]
    pub fn into_server_and_client(
        self,
    ) -> Result<(RpcServer<Request, Response>, RpcClient<Request, Response>), ChannelCreateError>
    where
        Request: DeserializeOwned,
        Response: Serialize,
    {
        // The in-process server clones the child end internally; a `dup` failure
        // surfaces as a channel-creation error, same class as `new_channel`'s.
        let server =
            RpcServer::from_stream(self.child_end).map_err(ChannelCreateError::CreateSocket)?;
        let client = RpcClient::new(self.client_sender, self.client_receiver);
        Ok((server, client))
    }
}

/// Build a connected in-process [`RpcServer`]/[`RpcClient`] pair for tests —
/// the whole `testutils` RPC surface in one call.
///
/// This is what downstream crates want when they test their own typed
/// `Request`/`Response` wiring: it exercises the real socketpair and the real
/// postcard framing, so a payload the wire format cannot represent fails here
/// rather than in production. No process is spawned and no handshake runs —
/// for that, drive the spawn helpers instead.
///
/// ```
/// // (this item only exists with the `testutils` feature enabled)
/// use daemonizable::in_process_rpc_pair;
///
/// let (mut server, mut client) = in_process_rpc_pair::<u32, u32>().unwrap();
/// client.send_request(&41).unwrap();
/// assert_eq!(41, server.next_request().unwrap());
/// ```
///
/// A free function rather than a constructor on `RpcConnection`: that type is
/// the fork+exec path's intermediate — it exists so the parent can keep the
/// client and surrender the child's raw fd — and nothing outside this crate
/// should have to name it, let alone know that the split step is where the
/// `dup` happens. Keeping it unexported is what lets the two-step
/// `new_channel` + [`RpcConnection::into_server_and_client`] sequence stay a
/// private implementation detail.
#[allow(clippy::type_complexity)]
#[cfg(any(test, feature = "testutils"))]
pub fn in_process_rpc_pair<Request, Response>()
-> Result<(RpcServer<Request, Response>, RpcClient<Request, Response>), ChannelCreateError>
where
    Request: Serialize + DeserializeOwned,
    Response: Serialize + DeserializeOwned,
{
    RpcConnection::<Request, Response>::new_channel()?.into_server_and_client()
}
