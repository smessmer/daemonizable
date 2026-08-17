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

#[cfg(any(test, feature = "testutils"))]
pub use connection::in_process_rpc_pair;

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
    fn in_process_rpc_pair_round_trips_a_request_and_response() {
        let (mut server, mut client) = in_process_rpc_pair::<u32, u32>().unwrap();

        client.send_request(&41).unwrap();
        assert_eq!(41, server.next_request().unwrap());

        server.send_response(&42).unwrap();
        assert_eq!(42, client.recv_response_blocking().unwrap());
    }

    #[test]
    fn recv_response_blocking_returns_the_response() {
        let (mut server, mut client) = in_process_rpc_pair::<u32, u32>().unwrap();

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
        // Both `dup`-clones of the server endpoint must close for the client to
        // see EOF; dropping the whole `RpcServer` closes both.
        let (server, mut client) = in_process_rpc_pair::<u32, u32>().unwrap();
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
        // The mirror image: this is what lets a daemon shut its request loop
        // down when its foreground peer exits.
        let (mut server, client) = in_process_rpc_pair::<u32, u32>().unwrap();
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
