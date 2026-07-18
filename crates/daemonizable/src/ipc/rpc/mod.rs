//! Typed request/response RPC over one full-duplex IPC channel.
//!
//! An [`RpcConnection`] owns one socketpair and splits it into the two endpoints
//! that actually talk: the parent-side [`RpcClient`] (sends requests, receives
//! responses) and the daemon-side [`RpcServer`] (receives requests, sends
//! responses). Each endpoint drives its own `dup`-clone of its side of the
//! socket, so a send and a receive can be in flight at once. Each lives in its
//! own module so the parent and daemon halves of the protocol read
//! independently.

mod client;
mod connection;
mod server;

pub use client::RpcClient;
pub use connection::RpcConnection;
pub use server::RpcServer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::error::ChannelRecvError;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

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

        let connection = RpcConnection::<Request, Response>::new_channel().unwrap();
        let (mut server, mut client) = connection.into_server_and_client().unwrap();

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
        let (mut server, mut client) = RpcConnection::<u32, u32>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();

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
        // Liveness: if the daemon dies, its end of the socket closes and the
        // parent's blocking receive returns an error immediately instead of
        // hanging. Both `dup`-clones that make up the server endpoint must close
        // for the client to see EOF; dropping the whole `RpcServer` closes both.
        let (server, mut client) = RpcConnection::<u32, u32>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        drop(server); // daemon "dies": closes both clones of the server's end

        let err = client
            .recv_response_blocking()
            .expect_err("a blocking receive must fail once the daemon's end is closed, not hang");
        assert!(
            matches!(err, ChannelRecvError::SenderClosed),
            "expected SenderClosed (normalized blocking-path EOF), got: {err:?}"
        );
    }

    #[test]
    fn next_request_errors_when_the_client_drops_its_end() {
        // Mirror liveness (the phase-2 centerpiece for a single shared fd): when
        // the parent drops its `RpcClient`, BOTH clones of the client's end
        // close, so the daemon's blocking `next_request` sees EOF promptly
        // rather than hanging. This is what lets a daemon shut its request loop
        // down when its foreground peer exits.
        let (mut server, client) = RpcConnection::<u32, u32>::new_channel()
            .unwrap()
            .into_server_and_client()
            .unwrap();
        drop(client); // foreground "exits": closes both clones of the client's end

        let err = server
            .next_request()
            .expect_err("next_request must fail once the client's end is closed, not hang");
        assert!(
            matches!(err, ChannelRecvError::SenderClosed),
            "expected SenderClosed, got: {err:?}"
        );
    }
}
