//! Typed request/response RPC over a pair of IPC pipes.
//!
//! An [`RpcConnection`] owns both pipes and splits into the two endpoints that
//! actually talk: the parent-side [`RpcClient`] (sends requests, receives
//! responses) and the daemon-side [`RpcServer`] (receives requests, sends
//! responses). Each endpoint lives in its own module so the parent and daemon
//! halves of the protocol read independently.

mod client;
mod connection;
mod server;

pub use client::RpcClient;
pub use connection::RpcConnection;
pub use server::RpcServer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::error::PipeRecvError;
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
